"""Constant pool recovery helpers for Luraph payloads.

The bootstrap and VM pipelines frequently store decoded constant pools as
encoded byte streams.  Depending on the build the payload may apply multiple
transformations: base encodings (``base64`` / ``base85``), PRGA style byte
scramblers, block permutations and XOR masks.  This module provides a
best-effort decoder that detects those patterns and produces a structured
manifest with human readable values.

The workflow is intentionally conservative: stages are only applied when a
heuristic suggests that decoding improved the payload.  Multi-stage recovery is
supported – for example ``base64`` → ``PRGA`` → ``permutation`` – and each step
records metadata so analysts can reason about the produced output.

The public API exposes :func:`decode_constants` which returns the decoded bytes
and accompanying metadata, and :func:`write_constant_manifest` which persists
JSON artefacts under ``out/constants``.  A small CLI is available via
``python -m src.decoders.constant_recover`` for ad-hoc analysis.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .initv4_prga import apply_prga
from ..tools.heuristics import detect_endianness, score_base64_string

logger = logging.getLogger(__name__)

__all__ = [
    "ConstantStage",
    "ConstantEntry",
    "ConstantDecodeResult",
    "decode_constants",
    "write_constant_manifest",
    "main",
]

_BASE64_PATTERN = re.compile(br"^[A-Za-z0-9+/=\s]+$")
_PRINTABLE_RATIO_THRESHOLD = 0.85
_MAX_STRING_LENGTH = 2 ** 12


@dataclass(frozen=True)
class ConstantStage:
    """Description of a stage that was applied during decoding."""

    name: str
    description: str
    input_length: int
    output_length: int
    metadata: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_length": self.input_length,
            "output_length": self.output_length,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ConstantEntry:
    """Individual constant recovered from the pool."""

    index: int
    type: str
    value: Any
    offset: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "type": self.type,
            "value": self.value,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class ConstantDecodeResult:
    """Aggregate decoding result returned by :func:`decode_constants`."""

    data: bytes
    stages: Sequence[ConstantStage]
    constants: Sequence[ConstantEntry]
    stats: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "stages": [stage.as_dict() for stage in self.stages],
            "constants": [entry.as_dict() for entry in self.constants],
            "stats": dict(self.stats),
        }


def _score_printable(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data)


def _maybe_base_decode(data: bytes, *, profile: Mapping[str, Any]) -> Optional[Tuple[str, bytes, Mapping[str, Any]]]:
    if not data:
        return None
    stripped = data.strip()
    if not stripped:
        return None
    printable_ratio = _score_printable(stripped)
    original_score = _score_printable(data)
    if printable_ratio < _PRINTABLE_RATIO_THRESHOLD:
        hints = profile.get("base_encodings") or []
        if not hints:
            return None
    candidates: List[Tuple[str, bytes, Mapping[str, Any]]] = []
    cleaned = re.sub(br"\s+", b"", stripped)
    hints = profile.get("base_encodings") or ("base64", "base85", "hex")
    for encoding in hints:
        encoding = str(encoding).lower()
        try:
            if encoding == "base64":
                if not _BASE64_PATTERN.fullmatch(cleaned):
                    continue
                decoded = base64.b64decode(cleaned, validate=True)
                score = _score_printable(decoded)
                meta = {
                    "encoding": "base64",
                    "printable_score": round(score, 3),
                    "input_preview": stripped[:48].decode("latin1", "replace"),
                }
                candidates.append(("base64", decoded, meta))
            elif encoding == "base85":
                decoded = base64.b85decode(cleaned)
                meta = {
                    "encoding": "base85",
                    "printable_score": round(_score_printable(decoded), 3),
                }
                candidates.append(("base85", decoded, meta))
            elif encoding == "hex":
                decoded = bytes.fromhex(cleaned.decode("ascii"))
                meta = {
                    "encoding": "hex",
                    "printable_score": round(_score_printable(decoded), 3),
                }
                candidates.append(("hex", decoded, meta))
        except (ValueError, UnicodeDecodeError):  # pragma: no cover - defensive
            logger.debug("base decoding failed", exc_info=True)
    if not candidates:
        # try an opportunistic base64 decode when the text looks plausible
        b64_score = score_base64_string(stripped.decode("latin1", "replace"))
        if b64_score >= 0.6:
            try:
                decoded = base64.b64decode(cleaned, validate=True)
            except ValueError:
                decoded = b""
            else:
                printable = _score_printable(decoded)
                return (
                    "base64",
                    decoded,
                    {
                        "encoding": "base64",
                        "printable_score": round(printable, 3),
                        "heuristic": "score_base64_string",
                    },
                )
        return None
    # Prefer the candidate that improved printability the most.
    best = max(candidates, key=lambda item: item[2]["printable_score"])
    if best[1] == data:
        return None
    if best[2].get("encoding") not in {"base64", "hex"} and best[2].get("printable_score", 0.0) <= original_score:
        return None
    return best


def _maybe_prga_decode(
    data: bytes,
    *,
    profile: Mapping[str, Any],
) -> Optional[Tuple[str, bytes, Mapping[str, Any]]]:
    prga_cfg = profile.get("prga")
    if not prga_cfg:
        return None
    mode = str(prga_cfg.get("mode", "initv4")).lower()
    if mode == "xor":
        value = prga_cfg.get("value")
        if value is None:
            return None
        mask = int(value) & 0xFF
        decoded = bytes(byte ^ mask for byte in data)
        return (
            "prga-xor",
            decoded,
            {
                "mode": "xor",
                "mask": mask,
            },
        )
    key = prga_cfg.get("key")
    if not key:
        logger.debug("prga stage skipped – no key supplied")
        return None
    params = dict(prga_cfg.get("params") or {})
    debug = bool(prga_cfg.get("debug"))
    key_bytes = bytearray(key if isinstance(key, (bytes, bytearray)) else str(key).encode("latin1"))
    try:
        decoded = apply_prga(data, key_bytes, params=params)
    finally:
        # zeroise key material
        for index in range(len(key_bytes)):
            key_bytes[index] = 0
    meta: Dict[str, Any] = {
        "mode": "initv4",
        "key_length": len(prga_cfg.get("key", b"")),
    }
    if params:
        safe_params = {k: v for k, v in params.items() if k not in {"key", "secret", "stream"}}
        meta["params"] = safe_params
    if debug:
        meta["debug"] = True
    return ("prga-initv4", decoded, meta)


def _apply_permutation(
    data: bytes,
    *,
    profile: Mapping[str, Any],
) -> Optional[Tuple[str, bytes, Mapping[str, Any]]]:
    perm_cfg = profile.get("permutation")
    if not perm_cfg:
        return None
    table = perm_cfg.get("table")
    block_size = perm_cfg.get("block_size")
    if table:
        table_list = [int(x) for x in table]
        if len(table_list) != len(data):
            logger.debug("permutation length mismatch – expected %d got %d", len(table_list), len(data))
            return None
        mode = str(perm_cfg.get("mode", "inverse")).lower()
        if mode not in {"inverse", "forward"}:
            raise ValueError(f"unsupported permutation mode: {mode}")
        if mode == "inverse":
            output = bytearray(len(table_list))
            for encoded_index, original_index in enumerate(table_list):
                if not 0 <= original_index < len(table_list):
                    raise ValueError("permutation index out of range")
                output[original_index] = data[encoded_index]
            reordered = bytes(output)
            return (
                "permute-table",
                reordered,
                {
                    "mode": "inverse",
                    "length": len(output),
                },
            )
        reordered = bytes(data[table_list[i]] for i in range(len(table_list)))
        return (
            "permute-table",
            reordered,
            {
                "mode": "forward",
                "length": len(table_list),
            },
        )
    if block_size:
        block_size = int(block_size)
        table = perm_cfg.get("block_table")
        if not table:
            return None
        table_list = [int(x) for x in table]
        if len(table_list) != block_size:
            raise ValueError("block permutation table must match block size")
        output = bytearray(len(data))
        for offset in range(0, len(data), block_size):
            block = data[offset : offset + block_size]
            for index, perm_index in enumerate(table_list):
                if offset + perm_index >= len(data):
                    continue
                if index < len(block):
                    output[offset + index] = block[perm_index]
        return (
            "permute-block",
            bytes(output),
            {
                "mode": "block",
                "block_size": block_size,
            },
        )
    return None


def _extract_strings(data: bytes) -> List[ConstantEntry]:
    entries: List[ConstantEntry] = []
    parts = data.split(b"\x00")
    offset = 0
    index = 0
    for part in parts:
        length = len(part)
        if not part:
            offset += 1
            continue
        if length > _MAX_STRING_LENGTH:
            offset += length + 1
            continue
        try:
            text = part.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = part.decode("latin1")
            except UnicodeDecodeError:  # pragma: no cover - defensive
                offset += length + 1
                continue
        printable = _score_printable(part)
        if printable < 0.7:
            offset += length + 1
            continue
        entries.append(ConstantEntry(index=index, type="string", value=text, offset=offset))
        index += 1
        offset += length + 1
    return entries


def _extract_numbers(data: bytes) -> List[ConstantEntry]:
    if len(data) % 4 != 0:
        return []
    le_values = [int.from_bytes(data[i : i + 4], "little", signed=False) for i in range(0, len(data), 4)]
    be_values = [int.from_bytes(data[i : i + 4], "big", signed=False) for i in range(0, len(data), 4)]
    variance_le = _variance(le_values)
    variance_be = _variance(be_values)
    if variance_le <= variance_be:
        values = le_values
        endian = "little"
    else:
        values = be_values
        endian = "big"
    entries: List[ConstantEntry] = []
    for index, value in enumerate(values):
        entries.append(
            ConstantEntry(
                index=index,
                type=f"int32-{endian}",
                value=value,
                offset=index * 4,
            )
        )
    return entries


def _variance(values: Sequence[int]) -> float:
    if not values:
        return math.inf
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def decode_constants(
    raw_bytes: bytes,
    profile: Optional[Mapping[str, Any]] = None,
) -> ConstantDecodeResult:
    """Decode *raw_bytes* according to the hints provided in *profile*.

    Parameters
    ----------
    raw_bytes:
        Byte payload extracted from bootstrap artefacts.
    profile:
        Optional mapping with hints.  Supported keys:

        ``base_encodings``
            Iterable describing base encoding candidates (``base64``, ``base85``, ``hex``).
        ``prga``
            Mapping describing PRGA style decoding.  Supported keys: ``mode`` (``xor`` or
            ``initv4``), ``key`` (bytes-like), ``params`` (passed to :func:`apply_prga`).
        ``permutation``
            Mapping describing permutation undoing.  Supported keys: ``table`` (full inverse or
            forward table), ``mode`` (``inverse`` / ``forward``) and ``block_table`` for block
            permutations combined with ``block_size``.
    """

    profile = profile or {}
    stages: List[ConstantStage] = []
    current = bytes(raw_bytes)

    base_stage = _maybe_base_decode(current, profile=profile)
    if base_stage:
        name, decoded, meta = base_stage
        stages.append(
            ConstantStage(
                name=name,
                description=f"Decoded using {meta.get('encoding', name)}",
                input_length=len(current),
                output_length=len(decoded),
                metadata=meta,
            )
        )
        current = decoded

    prga_stage = _maybe_prga_decode(current, profile=profile)
    if prga_stage:
        name, decoded, meta = prga_stage
        stages.append(
            ConstantStage(
                name=name,
                description="PRGA style recovery",
                input_length=len(current),
                output_length=len(decoded),
                metadata=meta,
            )
        )
        current = decoded

    perm_stage = _apply_permutation(current, profile=profile)
    if perm_stage:
        name, decoded, meta = perm_stage
        stages.append(
            ConstantStage(
                name=name,
                description="Permutation recovery",
                input_length=len(current),
                output_length=len(decoded),
                metadata=meta,
            )
        )
        current = decoded

    strings = _extract_strings(current)
    if strings:
        constants: List[ConstantEntry] = strings
    else:
        numbers = _extract_numbers(current)
        constants = numbers

    if not constants:
        constants.append(
            ConstantEntry(
                index=0,
                type="bytes",
                value=current.hex(),
                offset=0,
            )
        )

    endianness, endian_confidence = detect_endianness(current)
    stats = {
        "length": len(current),
        "printable_ratio": round(_score_printable(current), 3),
        "endianness_hint": endianness,
        "endianness_confidence": round(endian_confidence, 3),
        "stage_count": len(stages),
        "constant_count": len(constants),
    }

    return ConstantDecodeResult(data=current, stages=stages, constants=constants, stats=stats)


def _slugify(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
    return slug or "constants"


def write_constant_manifest(
    candidate: str,
    result: ConstantDecodeResult,
    output_dir: Path | str = Path("out") / "constants",
) -> Path:
    """Persist *result* to ``out/constants`` returning the written path."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{_slugify(candidate)}.json"
    payload = {
        "candidate": candidate,
        **result.as_dict(),
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    logger.info("wrote constant manifest -> %s (%d constants)", path, len(result.constants))
    return path


def _load_profile(path: Optional[Path]) -> Mapping[str, Any]:
    if not path:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Recover constant pools from encoded payloads")
    parser.add_argument("input", type=Path, help="File containing raw constant bytes")
    parser.add_argument("--profile", type=Path, help="Optional JSON profile with hints")
    parser.add_argument("--candidate", default="constants", help="Candidate name for output")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out") / "constants",
        help="Output directory for JSON manifest",
    )
    args = parser.parse_args(argv)
    raw_bytes = args.input.read_bytes()
    profile = _load_profile(args.profile)
    result = decode_constants(raw_bytes, profile)
    path = write_constant_manifest(args.candidate, result, args.output_dir)
    print(f"wrote {path} with {len(result.constants)} constants")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
