"""Version handler for the Luraph v14.2 JSON payload variant."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, Iterable, List, Optional

from ..utils_pkg import strings as string_utils
from . import ConstDecoder, OpSpec, PayloadInfo, VersionHandler, register_handler

_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=]{180,}")
_INIT_RE = re.compile(r"\binit_fn\s*\(")
_SCRIPT_KEY_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*getgenv\(\)\.script_key",
    re.IGNORECASE,
)
_JSON_BLOCKS = (
    re.compile(r"\[\[(\s*\{.*?\})\]\]", re.DOTALL),
    re.compile(r'"(\{\s*\"constants\".*?\})"', re.DOTALL),
)


class JSONConstDecoder(ConstDecoder):
    """Decode layered encodings commonly used in JSON payloads."""

    _DEFAULT_KEY = b"hxsk0st7cyvjkicxnibhbm"
    _ROTATIONS = (0, 3, 5, 7)

    def __init__(self) -> None:
        self._cache: Dict[int, Any] = {}
        self._prepared = False
        self._keys: list[bytes] = [b"", self._DEFAULT_KEY]
        self._index_combo: Dict[int, tuple[bytes, int]] = {}
        self._last_combo: tuple[bytes, int] | None = None

    def decode_pool(self, values: Iterable[Any]) -> list[Any]:
        constants = list(values)
        self._prepare_keys(constants)
        decoded: list[Any] = []
        for index, value in enumerate(constants):
            decoded.append(self._decode_literal(index, value))
        return decoded

    def decode_string(self, data: bytes, *, index: int | None = None) -> str:
        text = self._decode_bytes_pipeline(data, index=index)
        if text is not None:
            return text
        fallback = string_utils.decode_utf8(data)
        if fallback is not None and string_utils.is_probably_text(fallback):
            return fallback
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="ignore")

    def decode_number(self, value: int | bytes, *, index: int | None = None) -> int | float:
        if isinstance(value, int):
            return value
        raw = bytes(value)
        decoded = self._decode_bytes_pipeline(raw, index=index)
        if decoded is not None:
            cleaned = decoded.strip()
            if cleaned:
                try:
                    return int(cleaned, 0)
                except ValueError:
                    try:
                        return float(cleaned)
                    except ValueError:
                        pass
        length = len(raw)
        if length in {0, 1}:
            return int.from_bytes(raw or b"\x00", "little")
        return int.from_bytes(raw, "little", signed=False)

    # ------------------------------------------------------------------
    def _decode_literal(self, index: int | None, value: Any) -> Any:
        if index is not None and index in self._cache:
            return self._cache[index]

        result: Any
        if isinstance(value, str):
            result = self.decode_string(value.encode("utf-8"), index=index)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            result = self.decode_string(bytes(value), index=index)
        elif isinstance(value, int):
            result = self.decode_number(value, index=index)
        elif isinstance(value, list):
            result = [self._decode_literal(None, item) for item in value]
        elif isinstance(value, dict):
            result = {key: self._decode_literal(None, item) for key, item in value.items()}
        else:
            result = value

        if index is not None:
            self._cache[index] = result
        return result

    def _prepare_keys(self, constants: Iterable[Any]) -> None:
        if self._prepared:
            return
        derived: list[bytes] = []
        for value in constants:
            candidate = self._derive_key(value)
            if candidate:
                derived.append(candidate)
            if len(derived) >= 6:
                break
        if derived:
            self._keys = self._dedupe_keys(self._keys + derived)
        else:
            self._keys = self._dedupe_keys(self._keys)
        self._prepared = True

    def _derive_key(self, value: Any) -> bytes | None:
        if isinstance(value, str):
            candidate = string_utils.sanitise_key_candidate(value)
            if candidate and any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value):
                return candidate
        if isinstance(value, dict):
            for nested in value.values():
                candidate = self._derive_key(nested)
                if candidate:
                    return candidate
        return None

    def _decode_bytes_pipeline(self, data: bytes, *, index: int | None) -> Optional[str]:
        ascii_text: Optional[str]
        try:
            ascii_text = data.decode("ascii")
        except UnicodeDecodeError:
            ascii_text = None

        candidates: list[bytes] = []
        seen_blob: set[bytes] = set()

        if ascii_text:
            stripped = ascii_text.strip()
            if stripped:
                maybe = string_utils.maybe_base64(stripped)
                if maybe:
                    candidates.append(maybe)
                maybe_hex = string_utils.maybe_hex(stripped)
                if maybe_hex:
                    candidates.append(maybe_hex)
                candidates.append(stripped.encode("utf-8"))

        candidates.append(data)

        best_text: Optional[str] = None
        best_score = -1.0
        best_combo: tuple[bytes, int] | None = None

        for blob in candidates:
            if not blob or blob in seen_blob:
                continue
            seen_blob.add(blob)
            for combo, text in self._decode_candidate(blob, ascii_text, index):
                score = string_utils.text_score(text)
                if score > best_score:
                    best_score = score
                    best_text = text
                    best_combo = combo

        if best_text and index is not None and best_combo is not None:
            self._index_combo[index] = best_combo
            self._last_combo = best_combo

        return best_text

    def _decode_candidate(
        self,
        blob: bytes,
        ascii_text: Optional[str],
        index: int | None,
    ) -> Iterable[tuple[tuple[bytes, int], str]]:
        seen: set[bytes] = set()
        if ascii_text and string_utils.is_probably_text(ascii_text):
            yield (b"", 0), ascii_text
        for key, rotation in self._iter_combos(index):
            transformed = blob
            if key:
                transformed = string_utils.xor_bytes(transformed, key)
            if rotation:
                transformed = string_utils.rotate_left_bytes(transformed, rotation)
            if transformed in seen:
                continue
            seen.add(transformed)
            text = string_utils.decode_utf8(transformed)
            if text and string_utils.is_probably_text(text):
                yield (key, rotation), text

    def _iter_combos(self, index: int | None) -> Iterable[tuple[bytes, int]]:
        combos: list[tuple[bytes, int]] = []
        if index is not None:
            combo = self._index_combo.get(index)
            if combo:
                combos.append(combo)
        if self._last_combo:
            combos.append(self._last_combo)
        for key in self._keys:
            for rotation in self._ROTATIONS:
                combos.append((key, rotation))
        seen: set[tuple[bytes, int]] = set()
        for entry in combos:
            if entry in seen:
                continue
            seen.add(entry)
            yield entry

    def _dedupe_keys(self, keys: Iterable[bytes]) -> list[bytes]:
        seen: set[bytes] = set()
        ordered: list[bytes] = []
        for key in keys:
            if key in seen:
                continue
            seen.add(key)
            ordered.append(key)
        return ordered


class LuraphV142JSON(VersionHandler):
    name = "luraph_v14_2_json"
    priority = 70

    def matches(self, text: str) -> bool:
        if "luarmor" in text.lower():
            return False
        return (
            _SCRIPT_KEY_RE.search(text) is not None
            and _INIT_RE.search(text) is not None
            and _HIGH_ENTROPY_RE.search(text) is not None
        )

    def locate_payload(self, text: str) -> PayloadInfo | None:
        for pattern in _JSON_BLOCKS:
            match = pattern.search(text)
            if not match:
                continue
            candidate = match.group(1).strip()
            try:
                data = json.loads(candidate)
            except Exception:
                continue
            start, end = match.span(1)
            return PayloadInfo(candidate, start, end, data=data, metadata={"format": "json"})
        return None

    def extract_bytecode(self, payload: PayloadInfo) -> bytes:
        data = self._ensure_data(payload)
        code = data.get("bytecode") or data.get("code")
        if isinstance(code, list):
            flattened: List[int] = []
            for entry in code:
                if isinstance(entry, int):
                    flattened.append(entry & 0xFF)
                elif isinstance(entry, list):
                    for value in entry:
                        if isinstance(value, int):
                            flattened.append(value & 0xFF)
            if flattened:
                return bytes(flattened)
        if isinstance(code, str):
            raw = self._decode_byte_string(code)
            if raw is not None:
                return raw
        raise ValueError("unsupported bytecode layout for luraph_v14_2_json")

    def opcode_table(self) -> Dict[int, OpSpec]:
        return {
            0x00: OpSpec("MOVE", ("a", "b")),
            0x01: OpSpec("LOADK", ("a", "b")),
            0x02: OpSpec("LOADNIL", ("a", "b")),
            0x03: OpSpec("LOADBOOL", ("a", "b", "c")),
            0x04: OpSpec("LOADN", ("a", "b")),
            0x05: OpSpec("PUSHK", ("a",)),
            0x06: OpSpec("NEWTABLE", ("a", "b", "c")),
            0x07: OpSpec("SETTABLE", ("a", "b", "c")),
            0x08: OpSpec("GETTABLE", ("a", "b", "c")),
            0x09: OpSpec("SELF", ("a", "b", "c")),
            0x0A: OpSpec("SETLIST", ("a", "b", "c")),
            0x0B: OpSpec("GETUPVAL", ("a", "b")),
            0x0C: OpSpec("SETUPVAL", ("a", "b")),
            0x0D: OpSpec("GETGLOBAL", ("a", "b")),
            0x0E: OpSpec("SETGLOBAL", ("a", "b")),
            0x0F: OpSpec("CAPTURE", ("a", "b")),
            0x10: OpSpec("NEWCLOSURE", ("a", "b")),
            0x11: OpSpec("CLOSURE", ("a", "b")),
            0x12: OpSpec("VARARG", ("a", "b")),
            0x13: OpSpec("CALL", ("a", "b", "c")),
            0x14: OpSpec("TAILCALL", ("a", "b", "c")),
            0x15: OpSpec("RETURN", ("a", "b")),
            0x16: OpSpec("ADD", ("a", "b", "c")),
            0x17: OpSpec("SUB", ("a", "b", "c")),
            0x18: OpSpec("MUL", ("a", "b", "c")),
            0x19: OpSpec("DIV", ("a", "b", "c")),
            0x1A: OpSpec("MOD", ("a", "b", "c")),
            0x1B: OpSpec("POW", ("a", "b", "c")),
            0x1C: OpSpec("UNM", ("a", "b")),
            0x1D: OpSpec("BAND", ("a", "b", "c")),
            0x1E: OpSpec("BOR", ("a", "b", "c")),
            0x1F: OpSpec("BXOR", ("a", "b", "c")),
            0x20: OpSpec("BNOT", ("a", "b")),
            0x21: OpSpec("SHL", ("a", "b", "c")),
            0x22: OpSpec("SHR", ("a", "b", "c")),
            0x23: OpSpec("EQ", ("a", "b", "c")),
            0x24: OpSpec("LT", ("a", "b", "c")),
            0x25: OpSpec("LE", ("a", "b", "c")),
            0x26: OpSpec("TEST", ("a", "b", "c")),
            0x27: OpSpec("TESTSET", ("a", "b", "c")),
            0x28: OpSpec("JMP", ("offset",)),
            0x29: OpSpec("FORPREP", ("a", "offset")),
            0x2A: OpSpec("FORLOOP", ("a", "offset")),
            0x2B: OpSpec("CLOSE", ("a",)),
        }

    def const_decoder(self) -> ConstDecoder:
        return JSONConstDecoder()

    def process(self, vm):
        super().process(vm)

    # ------------------------------------------------------------------
    def _ensure_data(self, payload: PayloadInfo) -> Dict[str, Any]:
        if payload.data is not None:
            return payload.data
        try:
            data = json.loads(payload.text)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid payload") from exc
        payload.data = data
        return data

    def _decode_byte_string(self, blob: str) -> Optional[bytes]:
        padded = blob + "=" * (-len(blob) % 4)
        try:
            data = base64.b64decode(padded, validate=False)
        except Exception:
            data = None
        if data:
            key = b"hxsk0st7cyvjkicxnibhbm"
            decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            return decoded
        try:
            return bytes(int(part.strip(), 16) & 0xFF for part in blob.split())
        except Exception:
            return None


register_handler(LuraphV142JSON)

# Provide a module level handle for legacy code paths expecting ``process``.
HANDLER = LuraphV142JSON()
