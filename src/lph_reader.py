"""Helpers for decoding standalone LPH payload blobs.

The :func:`read_lph_blob` helper mirrors the light-weight tooling bundled with
the upstream CLI.  It inspects a payload, applies a handful of common
transformations (plain XOR, rolling XOR, RC4) using the provided script key, and
returns a structured metadata dictionary that can be serialised directly into
the CLI JSON report.

The module is intentionally self contained so it can run in restricted
environments such as Windows 11 CMD shells without requiring additional tools
or native dependencies.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import string
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from .utils.luraph_vm import canonicalise_opcode_name
from .utils.opcode_inference import DEFAULT_OPCODE_NAMES

LOG = logging.getLogger(__name__)

__all__ = ["read_lph_blob"]


def _normalise_base64(raw: bytes) -> Tuple[bytes, bool]:
    """Return *(data, used_base64)* for ``raw``.

    The helper accepts raw binary as well as textual base64 payloads.  When the
    input looks like base64 the decoded bytes are returned, otherwise the input
    is preserved verbatim so later transforms can run on it.
    """

    stripped = b"".join(raw.split())
    if not stripped:
        return raw, False
    # Heuristic: restrict the alphabet to printable base64 characters and
    # require a length that would round trip cleanly.
    alphabet = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if any(byte not in alphabet for byte in stripped):
        return raw, False
    if len(stripped) % 4 not in {0, 2, 3}:
        return raw, False
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return raw, False
    return decoded if decoded else raw, bool(decoded)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes((b ^ key[i % key_len]) & 0xFF for i, b in enumerate(data))


def _rolling_xor_bytes(data: bytes, key: bytes) -> bytes:
    """Apply a simple rolling XOR using ``key``.

    The scheme mirrors the variant Luraph uses in several bootstrap helpers
    where each byte is XORed with the previous decoded byte before the key is
    applied again on the next iteration.
    """

    if not key:
        return data
    key_len = len(key)
    out = bytearray(len(data))
    prev = 0
    for idx, byte in enumerate(data):
        key_byte = key[idx % key_len]
        plain = (byte ^ key_byte ^ prev) & 0xFF
        out[idx] = plain
        prev = plain
    return bytes(out)


def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(byte ^ k)
    return bytes(out)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(32 <= byte < 127 or byte in {9, 10, 13} for byte in data)
    return printable / len(data)


def _ascii_preview(data: bytes, limit: int = 96) -> str:
    snippet = data[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)


def _parse_int(token: str) -> Optional[int]:
    text = token.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


_OPCODE_KV_RE = re.compile(
    r"(0x[0-9A-Fa-f]+|\d+)\s*[:=]\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
)
_OPCODE_VK_RE = re.compile(
    r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*[:=]\s*(0x[0-9A-Fa-f]+|\d+)"
)
_ALPHABET_RE = re.compile(r"['\"]([0-9A-Za-z!#$%&()*+,\-./:;<=>?@\[\]^_`{|}~]{40,})['\"]")


def _iter_opcode_pairs(text: str) -> Iterable[Tuple[int, str]]:
    for match in _OPCODE_KV_RE.finditer(text):
        opcode, name = match.groups()
        parsed = _parse_int(opcode)
        if parsed is None:
            continue
        yield parsed & 0x3F, name
    for match in _OPCODE_VK_RE.finditer(text):
        name, opcode = match.groups()
        parsed = _parse_int(opcode)
        if parsed is None:
            continue
        yield parsed & 0x3F, name


def _extract_opcode_map(data: bytes, text: str) -> Dict[int, str]:
    mapping: Dict[int, str] = {}

    def _apply(pair_iter: Iterable[Tuple[int, str]]) -> None:
        for opcode, name in pair_iter:
            canonical = canonicalise_opcode_name(name)
            if not canonical:
                continue
            mapping.setdefault(opcode, canonical)

    # JSON payloads -----------------------------------------------------
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    if isinstance(parsed, Mapping):
        op_map = parsed.get("opcode_map") or parsed.get("opcodes")
        if isinstance(op_map, Mapping):
            pairs: List[Tuple[int, str]] = []
            for key, value in op_map.items():
                opcode = _parse_int(str(key))
                if opcode is None:
                    continue
                pairs.append((opcode & 0x3F, str(value)))
            _apply(pairs)
    elif isinstance(parsed, list):
        for entry in parsed:
            if isinstance(entry, Mapping):
                op_map = entry.get("opcode_map")
                if isinstance(op_map, Mapping):
                    pairs = []
                    for key, value in op_map.items():
                        opcode = _parse_int(str(key))
                        if opcode is None:
                            continue
                        pairs.append((opcode & 0x3F, str(value)))
                    _apply(pairs)

    if len(mapping) < 4:
        _apply(_iter_opcode_pairs(text))

    if not mapping and data:
        # Fallback to defaults when no metadata present; ensures downstream
        # stages still receive canonical mnemonics for core opcodes.
        mapping.update(DEFAULT_OPCODE_NAMES)

    return mapping


def _extract_alphabet(text: str) -> Optional[str]:
    candidates: List[str] = []
    for match in _ALPHABET_RE.finditer(text):
        value = match.group(1)
        if len(set(value)) == len(value) and len(value) >= 40:
            candidates.append(value)
    if candidates:
        return max(candidates, key=len)
    return None


def _dword_sample(data: bytes) -> Mapping[str, List[str]]:
    little: List[str] = []
    big: List[str] = []
    for offset in range(0, min(len(data), 16), 4):
        chunk = data[offset : offset + 4]
        if len(chunk) < 4:
            break
        little.append(f"0x{int.from_bytes(chunk, 'little'):08X}")
        big.append(f"0x{int.from_bytes(chunk, 'big'):08X}")
    return {"little_endian": little, "big_endian": big}


def _collect_candidates(data: bytes, key: bytes) -> List[Tuple[str, bytes, float]]:
    attempts: List[Tuple[str, bytes]] = [("raw", data)]
    if key:
        attempts.extend(
            (
                ("xor", _xor_bytes(data, key)),
                ("rolling_xor", _rolling_xor_bytes(data, key)),
                ("rc4", _rc4_crypt(data, key)),
            )
        )
    scored: List[Tuple[str, bytes, float]] = []
    for name, payload in attempts:
        ratio = _printable_ratio(payload)
        scored.append((name, payload, ratio))
    return scored


def read_lph_blob(blob_path: str | Path, key: Optional[str]) -> MutableMapping[str, object]:
    """Return decoding metadata for an LPH blob located at ``blob_path``.

    Parameters
    ----------
    blob_path:
        Path-like object pointing at the blob that should be analysed.

    key:
        Script key extracted from the bootstrapper or supplied on the command
        line.  The key is used when applying XOR, rolling XOR, and RC4
        transforms.  An empty or ``None`` key is accepted – in that case only
        the raw payload is reported.
    """

    path = Path(blob_path)
    try:
        raw = path.read_bytes()
    except OSError as exc:  # pragma: no cover - defensive guard
        raise RuntimeError(f"unable to read LPH blob {path}: {exc}") from exc

    LOG.debug("LPH parser: analysing blob at %s (size=%d)", path, len(raw))
    normalised, used_base64 = _normalise_base64(raw)
    if used_base64:
        LOG.debug("LPH parser: %s looked like base64 – decoded %d bytes", path, len(normalised))

    key_bytes = key.encode("utf-8", errors="ignore") if key else b""
    if key_bytes:
        LOG.debug(
            "LPH parser: attempting XOR/rolling/RC4 decryptors with key length %d for %s",
            len(key_bytes),
            path,
        )
    else:
        LOG.debug("LPH parser: no key supplied for %s – reporting raw payload", path)

    attempts = _collect_candidates(normalised, key_bytes)
    best_name, best_payload, best_ratio = max(attempts, key=lambda item: item[2])

    LOG.debug(
        "LPH parser: best decryption for %s was %s (printable_ratio=%.3f)",
        path,
        best_name,
        best_ratio,
    )

    header = {
        "hex": best_payload[:16].hex(),
        "ascii": _ascii_preview(best_payload, limit=32),
    }
    header.update(_dword_sample(best_payload))

    preview_text = best_payload[:96].decode("utf-8", errors="replace")
    utf8_text = best_payload.decode("utf-8", errors="ignore")

    opcode_map = _extract_opcode_map(best_payload, utf8_text)
    alphabet = _extract_alphabet(utf8_text)
    if not alphabet:
        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits

    result: MutableMapping[str, object] = {
        "path": str(path),
        "size": len(best_payload),
        "source_size": len(raw),
        "source_encoding": "base64" if used_base64 else "binary",
        "decryption_method": best_name,
        "header_sample": header,
        "decoded_bytes_preview": preview_text,
        "printable_ratio": round(best_ratio, 3),
        "alphabet": alphabet,
        "alphabet_length": len(alphabet),
        "alphabet_source": "bootstrap",
        "opcode_map": opcode_map,
        "opcode_map_count": len(opcode_map),
    }

    if key_bytes:
        result["key_length"] = len(key_bytes)

    return result

