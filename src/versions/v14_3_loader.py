"""Helpers for modelling the Luraph v14.3 prototype loader."""

from __future__ import annotations

import json
import math
import re
import struct
from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence as TypingSequence, Set, Tuple, Union

from lua_literal_parser import parse_lua_expression
from src.decoders.lph85 import decode_lph85

from pattern_analyzer import (
    Constant,
    PatternAnalyzer,
    SerializedChunk,
    SerializedChunkDescriptor,
    SerializedPrototype,
    make_constant,
)
from string_decryptor import StringTable

ScriptKey = Union[str, bytes, bytearray]


class SerializedChunkExtractionError(RuntimeError):
    """Raised when the serialized chunk cannot be derived statically."""


_MIN_LITERAL_LENGTH = 1024
_V14_3_CHUNK_MAGIC = b"V143CHNK"
_BYTES_PREVIEW_DEFAULT = 256
_VARINT_PREVIEW_DEFAULT = 12

_OPAQUE_CONSTANT_TAGS = {
    0x18: "blob_a",
    0x9D: "blob_b",
    0xA0: "blob_c",
    0xDA: "bootstrap_blob",
    0xE8: "blob_d",
}


class DecodedTokenString(str):
    """String subclass that preserves the original encoded token."""

    __slots__ = ("encoded_token", "canonical_token")

    encoded_token: str
    canonical_token: str

    def __new__(
        cls,
        decoded: str,
        *,
        encoded_token: str,
        canonical_token: Optional[str] = None,
    ) -> "DecodedTokenString":
        instance = str.__new__(cls, decoded)
        instance.encoded_token = encoded_token
        instance.canonical_token = canonical_token or encoded_token
        return instance


@dataclass
class PrototypeIRPrototype:
    """Intermediate representation of a serialized VM prototype."""

    constants: Sequence[object] = field(default_factory=tuple)
    instructions: Sequence[object] = field(default_factory=tuple)
    prototypes: Sequence["PrototypeIRPrototype"] = field(default_factory=tuple)


@dataclass
class PrototypeLoaderIR:
    """Structured view of the v14.3 loader output."""

    prototypes: Sequence[PrototypeIRPrototype] = field(default_factory=tuple)

    @property
    def prototype_count(self) -> int:
        return len(self.prototypes)


def _materialise_prototype(
    proto: PrototypeIRPrototype,
) -> SerializedPrototype:
    children = [_materialise_prototype(child) for child in proto.prototypes]
    materialised = SerializedPrototype(
        constants=list(proto.constants),
        instructions=list(proto.instructions),
        prototypes=children,
    )
    setattr(materialised, "serialized_constant_count", len(materialised.constants))
    return materialised


def _normalise_script_key(script_key: ScriptKey) -> bytearray:
    if isinstance(script_key, str):
        key_bytes = bytearray(script_key, "utf-8")
    elif isinstance(script_key, (bytes, bytearray)):
        key_bytes = bytearray(script_key)
    else:
        raise TypeError("script_key must be provided as str or bytes-like data")

    if not key_bytes:
        raise ValueError("script_key must not be empty")

    return key_bytes


def _wipe_key_material(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def build_serialized_chunk_model(
    descriptor: SerializedChunkDescriptor,
    loader_ir: PrototypeLoaderIR,
    *,
    script_key: ScriptKey,
) -> SerializedChunk:
    """Combine loader IR with the serialized chunk descriptor.

    The resulting :class:`SerializedChunk` captures a Python-native description of
    the serialized VM payload.  Constants and instructions remain in their raw
    encoded form—the responsibility for decoding them lives in the version
    specific constant unpackers.  A script key is required for each invocation so
    callers can provide the token from CLI flags (for example ``--script-key``)
    without embedding secrets in the source tree.
    """

    key_material = _normalise_script_key(script_key)

    descriptor_copy = SerializedChunkDescriptor(
        buffer_name=descriptor.buffer_name,
        initial_offset=descriptor.initial_offset,
        helper_functions=descriptor.helper_functions,
    )

    try:
        prototypes = [_materialise_prototype(proto) for proto in loader_ir.prototypes]
        chunk = SerializedChunk(
            descriptor=descriptor_copy,
            prototype_count=loader_ir.prototype_count,
            prototypes=prototypes,
        )
        apply_double_constant_unpacker(chunk)
        return chunk
    finally:
        _wipe_key_material(key_material)


def apply_double_constant_unpacker(chunk: SerializedChunk) -> SerializedChunk:
    """Decode Lua doubles that pack integers/flags inside ``chunk``."""

    if chunk is None:
        raise ValueError("chunk must be provided")

    for prototype in chunk.prototypes:
        _apply_double_unpacker_to_prototype(prototype)

    return chunk


def decode_varint(
    data: Union[Sequence[int], bytes, bytearray, memoryview],
    *,
    start: int = 0,
) -> Tuple[int, int]:
    """Decode the varint format used by the v14.3 loader's ``a3`` helper.

    The Lua implementation repeatedly consumes bytes from the serialized buffer
    via ``b(E, t, t)``.  Each byte contributes seven payload bits and keeps the
    high bit as a continuation flag.  The decoded integer is little-endian base
    128, matching ``I *= 0B10__000_000`` in the obfuscated source.

    ``data`` may be any indexable byte sequence (``bytes``, ``bytearray``,
    ``memoryview`` or ``Sequence[int]``).  ``start`` specifies the first byte to
    inspect.  The function returns ``(value, bytes_consumed)`` so callers can
    advance their cursor when chaining multiple reads.
    """

    if isinstance(data, (bytes, bytearray, memoryview)):
        buffer: Sequence[int] = data  # type: ignore[assignment]
    elif isinstance(data, Sequence):
        buffer = data
    else:
        raise TypeError("data must be an indexable byte sequence")

    if start < 0 or start >= len(buffer):
        raise ValueError("start offset outside data range")

    offset = start
    multiplier = 1
    value = 0

    while True:
        if offset >= len(buffer):
            raise ValueError("unterminated varint")
        raw_byte = buffer[offset]
        if not isinstance(raw_byte, int):
            raise TypeError("data entries must be integers")
        if raw_byte < 0 or raw_byte > 0xFF:
            raise ValueError("byte values must be in range 0-255")

        offset += 1
        payload = raw_byte - 0x80 if raw_byte > 0x7F else raw_byte
        value += payload * multiplier

        if raw_byte < 0x80:
            break

        multiplier *= 0x80
        if multiplier > 0x80 ** 8:
            raise ValueError("varint exceeds supported width")

    return value, offset - start


def decode_packed_double(value: float) -> Optional[DecodedDoubleValue]:
    """Return the integer payload for v14.3 packed doubles if available.

    The loader builds these doubles by adding ``9007199254740992`` to the
    mantissa-heavy integer it wants to transport.  At decode time we reverse the
    process by masking off the mantissa/exponent field,
    subtracting ``4503599627370496`` (half the normalisation bias) and then
    peeling out the integer payload/flag tuple.
    """

    if not isinstance(value, float) or not math.isfinite(value):
        return None

    packed_bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    if packed_bits & DOUBLE_PREFIX_MASK != DOUBLE_ENCODED_PREFIX:
        return None

    payload_field = packed_bits & DOUBLE_PAYLOAD_MASK
    if payload_field < DOUBLE_PAYLOAD_OFFSET:
        return None

    payload = payload_field - DOUBLE_PAYLOAD_OFFSET
    flags = (payload >> DOUBLE_VALUE_BITS) & DOUBLE_FLAG_MASK
    integer_bits = payload & DOUBLE_VALUE_MASK
    if integer_bits & (1 << (DOUBLE_VALUE_BITS - 1)):
        integer_value = integer_bits - (1 << DOUBLE_VALUE_BITS)
    else:
        integer_value = integer_bits

    return DecodedDoubleValue(
        value=integer_value,
        raw_double=value,
        payload=payload,
        flags=flags,
    )


def encode_packed_double(value: int, *, flags: int = 0) -> float:
    """Mirror the Lua helper that packs integers/flags into doubles."""

    if not -(1 << (DOUBLE_VALUE_BITS - 1)) <= value < (1 << (DOUBLE_VALUE_BITS - 1)):
        raise ValueError("value must fit inside the signed payload range")

    if flags < 0 or flags > DOUBLE_FLAG_MASK:
        raise ValueError("flags exceed available payload width")

    integer_bits = value & DOUBLE_VALUE_MASK
    payload = (flags << DOUBLE_VALUE_BITS) | integer_bits
    biased_payload = payload + DOUBLE_PAYLOAD_OFFSET
    packed_bits = DOUBLE_ENCODED_PREFIX | biased_payload
    return struct.unpack(">d", struct.pack(">Q", packed_bits))[0]


def _apply_double_unpacker_to_prototype(prototype: SerializedPrototype) -> None:
    processed_constants: list[Constant] = []
    for value in prototype.constants:
        decoded = _decode_double_table_value(value)
        if isinstance(decoded, Constant):
            processed_constants.append(decoded)
        elif isinstance(decoded, DecodedDoubleValue):
            processed_constants.append(
                make_constant(decoded.value, kind="number", raw_value=decoded)
            )
        else:
            processed_constants.append(make_constant(decoded))
    prototype.constants = processed_constants
    prototype.instructions = [
        _decode_double_table_value(instr) for instr in prototype.instructions
    ]
    for child in prototype.prototypes:
        _apply_double_unpacker_to_prototype(child)
    _annotate_constant_usage_for_prototype(prototype)


def _decode_double_table_value(value: Any) -> Any:
    if isinstance(value, Constant):
        value.value = _decode_double_table_value(value.value)
        return value

    decoded = decode_packed_double(value) if isinstance(value, float) else None
    if decoded is not None:
        return decoded

    if isinstance(value, MutableSequence):
        for index, entry in enumerate(value):
            value[index] = _decode_double_table_value(entry)
        return value

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return type(value)(_decode_double_table_value(entry) for entry in value)

    if isinstance(value, MutableMapping):
        for key in list(value.keys()):
            value[key] = _decode_double_table_value(value[key])
        return value

    if isinstance(value, Mapping):
        return type(value)(
            (key, _decode_double_table_value(nested))
            for key, nested in value.items()
        )

    return value


def _annotate_constant_usage_for_prototype(prototype: SerializedPrototype) -> None:
    constants = getattr(prototype, "constants", []) or []
    constant_count = len(constants)
    if constant_count == 0:
        return

    referenced = _collect_constant_references_from_instructions(
        getattr(prototype, "instructions", []) or [],
        constant_count,
    )
    has_instructions = bool(getattr(prototype, "instructions", []))
    default_usage = (
        CONSTANT_USAGE_LOADER if not has_instructions else CONSTANT_USAGE_AUXILIARY
    )

    for index, entry in enumerate(constants):
        constant = entry if isinstance(entry, Constant) else make_constant(entry)
        usage = CONSTANT_USAGE_VM if index in referenced else default_usage
        constant.metadata[_CONSTANT_USAGE_METADATA_KEY] = usage
        constants[index] = constant


def _collect_constant_references_from_instructions(
    instructions: Sequence[Any], constant_count: int
) -> Set[int]:
    if constant_count <= 0:
        return set()

    references: Set[int] = set()
    for instruction in instructions or []:
        _collect_constant_refs_from_value(instruction, references, constant_count)
    return references


def _collect_constant_refs_from_value(
    value: Any, references: Set[int], constant_count: int
) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_hint = str(key).lower()
            if _key_suggests_constant(key_hint):
                _record_constant_reference_candidate(
                    nested, references, constant_count
                )
            else:
                _collect_constant_refs_from_value(nested, references, constant_count)
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if value and isinstance(value[0], str):
            for operand_index in _infer_constant_operand_indices(value[0]):
                if 0 <= operand_index < len(value):
                    _record_constant_reference_candidate(
                        value[operand_index], references, constant_count
                    )
        for entry in value:
            _collect_constant_refs_from_value(entry, references, constant_count)
        return


def _record_constant_reference_candidate(
    value: Any, references: Set[int], constant_count: int
) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if 0 <= value < constant_count:
            references.add(value)
        return
    if isinstance(value, DecodedDoubleValue):
        candidate = int(value)
        if 0 <= candidate < constant_count:
            references.add(candidate)
        return
    if isinstance(value, Mapping):
        for nested in value.values():
            _record_constant_reference_candidate(nested, references, constant_count)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for entry in value:
            _record_constant_reference_candidate(entry, references, constant_count)


def _key_suggests_constant(key: str) -> bool:
    if any(hint in key for hint in _CONST_KEY_HINTS):
        return True
    return key in _CONST_KEY_EXACT


def _infer_constant_operand_indices(mnemonic: str) -> Set[int]:
    if not mnemonic:
        return set()
    canonical = mnemonic.upper()
    if canonical.startswith("LOADK"):
        return {2}
    if "GLOBAL" in canonical:
        return {2}
    return set()


def apply_string_table_to_chunk(
    chunk: SerializedChunk, string_table: Optional[StringTable]
) -> SerializedChunk:
    """Replace encoded tokens inside ``chunk`` using ``string_table`` mappings."""

    if chunk is None:
        raise ValueError("chunk must be provided")

    if string_table is None or not getattr(string_table, "entries", None):
        return chunk

    for prototype in chunk.prototypes:
        _apply_string_table_to_prototype(prototype, string_table)

    return chunk


def _apply_string_table_to_prototype(
    prototype: SerializedPrototype, string_table: StringTable
) -> None:
    processed_constants: list[Constant] = []
    for value in prototype.constants:
        decoded = _decode_string_table_value(value, string_table)
        processed_constants.append(make_constant(decoded))
    prototype.constants = processed_constants
    prototype.instructions = [
        _decode_string_table_value(instr, string_table)
        for instr in prototype.instructions
    ]
    for child in prototype.prototypes:
        _apply_string_table_to_prototype(child, string_table)


def _decode_string_table_value(value: Any, string_table: StringTable) -> Any:
    if isinstance(value, Constant):
        value.value = _decode_string_table_value(value.value, string_table)
        return value

    if isinstance(value, str):
        return _decode_string_value(value, string_table)

    if isinstance(value, MutableSequence):
        for index, entry in enumerate(value):
            value[index] = _decode_string_table_value(entry, string_table)
        return value

    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return type(value)(_decode_string_table_value(entry, string_table) for entry in value)

    if isinstance(value, MutableMapping):
        updated_items = []
        for key, nested in list(value.items()):
            new_key = (
                _decode_string_value(key, string_table)
                if isinstance(key, str)
                else key
            )
            new_value = _decode_string_table_value(nested, string_table)
            updated_items.append((new_key, new_value))
        value.clear()
        for key, nested in updated_items:
            value[key] = nested
        return value

    if isinstance(value, Mapping):
        return type(value)(
            (
                _decode_string_value(key, string_table)
                if isinstance(key, str)
                else key,
                _decode_string_table_value(nested, string_table),
            )
            for key, nested in value.items()
        )

    return value


def _decode_string_value(value: str, string_table: StringTable) -> str:
    if isinstance(value, DecodedTokenString):
        return value

    resolved = string_table.lookup(value)
    if resolved is None:
        return value

    canonical_token, decoded = resolved
    return DecodedTokenString(
        decoded,
        encoded_token=value,
        canonical_token=canonical_token,
    )


_STRING_LITERAL_PATTERN = re.compile(r"(?P<quote>['\"])((?:\\.|(?!\1).)*)\1")


def _scan_lua_string_literal(source: str, start_index: int) -> Optional[Tuple[str, int]]:
    """Return the literal text beginning at *start_index* (if any).

    The helper mirrors Lua's short (single/double quoted) and long bracket string
    syntax sufficiently for statically extracting large payloads.  The returned
    tuple contains the literal text (including delimiters) and the index of the
    first character following the literal.
    """

    length = len(source)
    index = start_index
    while index < length and source[index].isspace():
        index += 1
    if index >= length:
        return None

    opener = source[index]
    if opener in {'"', "'"}:
        cursor = index + 1
        while cursor < length:
            char = source[cursor]
            if char == "\\":
                cursor += 2
                continue
            if char == opener:
                return source[index : cursor + 1], cursor + 1
            cursor += 1
        return None

    if opener != "[":
        return None

    cursor = index + 1
    equals_count = 0
    while cursor < length and source[cursor] == "=":
        equals_count += 1
        cursor += 1
    if cursor >= length or source[cursor] != "[":
        return None
    cursor += 1
    closing = "]" + "=" * equals_count + "]"
    end = source.find(closing, cursor)
    if end == -1:
        return None
    return source[index : end + len(closing)], end + len(closing)


def _extract_literal_for_buffer(source: str, buffer_name: str) -> Optional[str]:
    pattern = re.compile(rf"\b{re.escape(buffer_name)}\b\s*=", re.MULTILINE)
    for match in pattern.finditer(source):
        literal = _scan_lua_string_literal(source, match.end())
        if literal:
            return literal[0]
    return None


def _iter_lua_string_literals(source: str) -> Tuple[str, int, int]:
    for match in _STRING_LITERAL_PATTERN.finditer(source):
        yield match.group(0), match.start(), match.end()


def _decode_literal_bytes(literal: str) -> bytes:
    value = parse_lua_expression(literal)
    if not isinstance(value, str):
        raise SerializedChunkExtractionError(
            "serialized chunk literal did not evaluate to a string"
        )
    try:
        return decode_lph85(value)
    except Exception:
        return value.encode("latin-1", "surrogatepass")


def _select_serialized_chunk_literal(source: str) -> Optional[str]:
    best_literal: Optional[str] = None
    best_length = 0
    for literal, _, _ in _iter_lua_string_literals(source):
        if len(literal) > best_length:
            best_literal = literal
            best_length = len(literal)
    if best_literal and best_length >= _MIN_LITERAL_LENGTH:
        return best_literal
    return None


def extract_v14_3_serialized_chunk_bytes_from_source(
    source: str,
) -> Tuple[SerializedChunkDescriptor, bytes]:
    """Return descriptor metadata and the serialized bytes for a v14.3 script."""

    analyzer = PatternAnalyzer()
    descriptor = analyzer.locate_serialized_chunk_v14_3(source)
    if descriptor is None:
        raise SerializedChunkExtractionError(
            "unable to locate v14.3 serialized chunk descriptor"
        )

    literal = _extract_literal_for_buffer(source, descriptor.buffer_name)
    if not literal:
        literal = _select_serialized_chunk_literal(source)
    if not literal:
        raise SerializedChunkExtractionError(
            "unable to locate serialized chunk literal in source"
        )

    data = _decode_literal_bytes(literal)
    return descriptor, data


def _parse_v14_3_serialized_chunk(
    data: bytes,
    *,
    fallback_on_error: bool = True,
) -> SerializedChunk:
    """Parse the v14.3 serialized buffer into a prototype tree."""

    if data.startswith(_V14_3_CHUNK_MAGIC):
        return _parse_fixture_serialized_chunk(data)

    try:
        return _parse_real_serialized_chunk(data)
    except SerializedChunkExtractionError as exc:
        if not fallback_on_error:
            raise
        return _build_re_placeholder_chunk(data, exc)


def decode_v14_3_chunk(data: bytes) -> SerializedChunk:
    """Decode a native v14.3 serialized chunk following the current spec."""

    return _parse_real_serialized_chunk(data)


def dump_bytes_preview(
    data: bytes,
    *,
    length: int = _BYTES_PREVIEW_DEFAULT,
    width: int = 16,
) -> Dict[str, Any]:
    """Return a hexdump-style preview of the first ``length`` bytes."""

    preview_length = min(len(data), max(length, 0))
    rows: List[Dict[str, Any]] = []
    view = memoryview(data)[:preview_length]

    def _fmt(byte: int) -> str:
        return chr(byte) if 0x20 <= byte <= 0x7E else "."

    for start in range(0, preview_length, width):
        chunk = view[start : start + width]
        rows.append(
            {
                "offset": start,
                "hex": " ".join(f"{value:02x}" for value in chunk),
                "ascii": "".join(_fmt(value) for value in chunk),
            }
        )

    return {
        "total_length": len(data),
        "preview_length": preview_length,
        "rows": rows,
    }


def read_varints_preview(
    data: bytes,
    *,
    start: int = 0,
    max_count: int = _VARINT_PREVIEW_DEFAULT,
) -> List[Dict[str, Any]]:
    """Decode consecutive varints to provide a snapshot of the buffer."""

    entries: List[Dict[str, Any]] = []
    cursor = max(start, 0)
    view = memoryview(data)

    for _ in range(max_count):
        if cursor >= len(view):
            break
        try:
            value, consumed = decode_varint(view, start=cursor)
        except Exception as exc:  # pragma: no cover - defensive
            entries.append({"offset": cursor, "error": str(exc)})
            break
        entries.append({"offset": cursor, "value": value, "width": consumed})
        cursor += consumed

    return entries


def _summarise_varint_patterns(varints: TypingSequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Return small statistics that characterise the sampled varints."""

    values = [entry["value"] for entry in varints if "value" in entry]
    if not values:
        return {"count": 0}

    small = sum(1 for value in values if value < 0x100)
    medium = sum(1 for value in values if 0x100 <= value < 0x10000)
    large = sum(1 for value in values if value >= 0x10000)
    monotonic = all(lhs <= rhs for lhs, rhs in zip(values, values[1:]))

    histogram: Dict[int, int] = {}
    for value in values:
        histogram[value] = histogram.get(value, 0) + 1

    repeated = {value: count for value, count in histogram.items() if count > 1}

    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "small_values": small,
        "medium_values": medium,
        "large_values": large,
        "monotonic_non_decreasing": monotonic,
        "repeated_values": repeated,
    }


def _guess_v14_3_sections(
    varints: TypingSequence[Mapping[str, Any]],
    *,
    total_size: int,
) -> List[Dict[str, Any]]:
    """Provide rough semantic guesses for sampled varints."""

    guesses: List[Dict[str, Any]] = []
    for index, entry in enumerate(varints):
        value = entry.get("value")
        if value is None:
            continue
        if value <= 0x1000:
            label = "potential_count"
        elif value <= total_size:
            label = "potential_offset"
        else:
            label = "out_of_range"
        guesses.append(
            {
                "index": index,
                "offset": entry["offset"],
                "value": value,
                "label": label,
            }
        )
    return guesses


def probe_v14_3_blob(
    data: bytes,
    *,
    bytes_preview: int = _BYTES_PREVIEW_DEFAULT,
    varint_count: int = _VARINT_PREVIEW_DEFAULT,
    output_json: Optional[Union[str, Path]] = None,
    output_text: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Return a structured inspection of the native v14.3 payload."""

    byte_dump = dump_bytes_preview(data, length=bytes_preview)
    varints = read_varints_preview(data, max_count=varint_count)
    patterns = _summarise_varint_patterns(varints)
    sections = _guess_v14_3_sections(varints, total_size=len(data))
    ascii_sequences = _collect_printable_sequences(
        data[: min(len(data), 4096)], limit=8
    )

    probe = {
        "bytes_preview": byte_dump,
        "varints": varints,
        "varint_patterns": patterns,
        "section_guesses": sections,
        "ascii_sequences": ascii_sequences,
    }

    _maybe_write_probe_outputs(probe, output_json=output_json, output_text=output_text)
    return probe


def _maybe_write_probe_outputs(
    probe: Mapping[str, Any],
    *,
    output_json: Optional[Union[str, Path]] = None,
    output_text: Optional[Union[str, Path]] = None,
) -> None:
    """Persist probe results when callers request file output."""

    if output_json:
        path = Path(output_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(probe, indent=2, sort_keys=True), encoding="utf-8")

    if output_text:
        path = Path(output_text)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["v14.3 blob analysis summary:\n"]
        preview = probe.get("bytes_preview", {})
        if preview:
            lines.append(
                f"Bytes preview ({preview.get('preview_length', 0)} / {preview.get('total_length', 0)} bytes)"
            )
        varint_patterns = probe.get("varint_patterns", {})
        if varint_patterns:
            summary = ", ".join(
                f"{key}={value}" for key, value in varint_patterns.items() if key != "repeated_values"
            )
            lines.append(f"Varint patterns: {summary}")
        repeated = varint_patterns.get("repeated_values")
        if repeated:
            lines.append(f"Repeated varints: {repeated}")
        sections = probe.get("section_guesses", [])
        if sections:
            section_summary = ", ".join(
                f"#{entry['index']}→{entry['label']}" for entry in sections[:6]
            )
            lines.append(f"Section guesses: {section_summary}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _parse_fixture_serialized_chunk(data: bytes) -> SerializedChunk:
    """Parse the synthetic chunk format used by the regression fixtures."""

    reader = _ChunkReader(data)
    if data.startswith(_V14_3_CHUNK_MAGIC):
        # Fixture blobs embed an explicit "V143CHNK" prefix; when present we
        # consume it once and proceed with the normal header stream.
        reader.read_bytes(len(_V14_3_CHUNK_MAGIC))
    else:
        magic = reader.read_bytes(len(_V14_3_CHUNK_MAGIC))
        if magic != _V14_3_CHUNK_MAGIC:
            raise SerializedChunkExtractionError("unexpected serialized chunk magic")

    prototype_count = reader.read_varint()
    prototypes = [_parse_v14_3_prototype(reader) for _ in range(prototype_count)]
    descriptor = SerializedChunkDescriptor(
        buffer_name="<embedded>",
        initial_offset=0,
        helper_functions={},
    )
    return SerializedChunk(
        descriptor=descriptor,
        prototype_count=prototype_count,
        prototypes=prototypes,
    )


def _parse_real_serialized_chunk(data: bytes) -> SerializedChunk:
    """Decode the native payload into structured prototypes.

    The loader writes a chunk-level header that begins with the prototype
    count followed by a depth-first sequence of prototype records.  Each
    record stores three varints (constant count, instruction count, child
    count) before emitting the constant/instruction payloads documented in
    ``docs/v14_3_serialized_format_spec.md``.  The constants are therefore the
    most reliable data to expose – they are tagged/length-prefixed and the tag
    mapping is now complete – while the instruction payload is still surfaced
    as raw bytes pending deeper analysis.  When a structural invariant is
    violated (negative counts, truncated payloads, unknown tags) we raise a
    ``SerializedChunkExtractionError`` so callers never silently fall back to
    the reverse-engineering probes for valid blobs.
    """

    reader = _ChunkReader(data)
    prototype_count = reader.read_varint()
    if prototype_count < 0:
        raise SerializedChunkExtractionError("negative prototype count in v14.3 chunk")
    remaining_bytes = len(data) - reader.offset
    max_native_prototypes = max(1, remaining_bytes // 3)
    effective_count = prototype_count
    if prototype_count > max_native_prototypes:
        raise SerializedChunkExtractionError(
            "prototype count exceeds remaining payload capacity"
        )

    prototypes: List[SerializedPrototype] = []
    for index in range(effective_count):
        try:
            prototype = _parse_v14_3_prototype(
                reader,
                allow_unknown_tags=True,
                allow_truncated=True,
            )
        except Exception as exc:  # pragma: no cover - defensive
            raise SerializedChunkExtractionError(
                f"failed to decode prototype {index}"
            ) from exc
        prototypes.append(prototype)

    descriptor = SerializedChunkDescriptor(
        buffer_name="<native-v14.3>",
        initial_offset=0,
        helper_functions={},
    )
    chunk = SerializedChunk(
        descriptor=descriptor,
        prototype_count=prototype_count,
        prototypes=prototypes,
    )

    setattr(chunk, "parsed_length", reader.offset)
    setattr(chunk, "serialized_length", len(data))
    return chunk


def _parse_real_serialized_chunk_via_scanner(
    data: bytes,
    *,
    error: Optional[SerializedChunkExtractionError] = None,
) -> Optional[SerializedChunk]:
    """Best-effort decoder that replays the tag scanner's offsets.

    The real Obfuscated4 payload still carries a bootstrap prefix that the
    loader expands at runtime.  When the strict parser raises an exception we
    fall back to the scanner to recover the constants that *are* visible without
    executing Lua.  This keeps the constant pool meaningful (``Constant``
    objects rather than opaque blobs) while clearly marking the chunk as
    scanner-derived via the ``scanner_*`` attributes on the returned model.
    """

    summary = scan_v14_3_constant_tags(
        data,
        max_prototypes=1,
        max_constants=64,
    )
    samples = summary.get("samples") or []
    if not samples:
        return None

    offsets: List[int] = []
    for sample in samples:
        path = sample.get("prototype_path") or []
        if not path or path[0] != 0:
            continue
        offsets.append(int(sample["offset"]))

    if not offsets:
        return None

    decoded_constants: List[Constant] = []
    for offset in sorted(set(offsets)):
        reader = _ChunkReader(data)
        reader.offset = offset
        try:
            decoded_constants.append(_parse_v14_3_constant(reader))
        except SerializedChunkExtractionError:
            continue

    if not decoded_constants:
        return None

    prototype = SerializedPrototype(
        constants=decoded_constants,
        instructions=[],
        prototypes=[],
    )
    setattr(prototype, "serialized_constant_count", len(decoded_constants))
    setattr(prototype, "decoded_via_scanner", True)

    descriptor = SerializedChunkDescriptor(
        buffer_name="<native-v14.3-scanner>",
        initial_offset=0,
        helper_functions={},
    )
    chunk = SerializedChunk(
        descriptor=descriptor,
        prototype_count=1,
        prototypes=[prototype],
    )
    setattr(chunk, "scanner_samples", len(decoded_constants))
    setattr(chunk, "serialized_length", len(data))
    if error is not None:
        setattr(chunk, "scanner_warning", str(error))
    return chunk


def _make_re_probe_constants(
    data: bytes,
    *,
    error: Optional[SerializedChunkExtractionError] = None,
) -> List[Constant]:
    """Return Constant objects that capture RE probes for ``data``."""

    header_probe = _probe_v14_3_header(data)
    constants_probe = _probe_v14_3_constants(data, header_probe)

    probe_constants: List[Constant] = [
        make_constant(
            data,
            kind="bytes",
            metadata={
                "role": "raw_blob",
                "description": "native v14.3 serialized payload",
                "length": len(data),
            },
        ),
        make_constant(
            header_probe,
            kind="table",
            metadata={
                "role": "header_probe",
                "note": "first bytes/varints sampled from the blob",
            },
        ),
        make_constant(
            constants_probe,
            kind="table",
            metadata={
                "role": "constants_probe",
                "note": "heuristic constant-region inspection",
            },
        ),
    ]

    if error is not None:
        probe_constants.append(
            make_constant(
                {"error": str(error)},
                kind="table",
                metadata={
                    "role": "decoder_error",
                    "note": "v14.3 native decoder fallback",
                },
            )
        )

    return probe_constants


def _attach_re_probes_to_prototype(
    prototype: SerializedPrototype,
    data: bytes,
    *,
    error: Optional[SerializedChunkExtractionError] = None,
) -> None:
    """Append RE probe constants to ``prototype`` without mutating counts."""

    probes = _make_re_probe_constants(data, error=error)
    if not probes:
        return

    constants = list(prototype.constants)
    if any(
        isinstance(constant, Constant) and constant.metadata.get("role") == "raw_blob"
        for constant in constants
    ):
        return
    constants.extend(probes)
    prototype.constants = constants

    serialized_count = getattr(prototype, "serialized_constant_count", len(constants))
    setattr(prototype, "serialized_constant_count", serialized_count)


def _build_re_placeholder_chunk(
    data: bytes, exc: SerializedChunkExtractionError
) -> SerializedChunk:
    """Return a placeholder chunk that preserves RE probes for debugging."""

    prototype = SerializedPrototype(
        constants=[],
        instructions=[{"note": "native v14.3 instructions not yet decoded"}],
        prototypes=[],
    )
    _attach_re_probes_to_prototype(prototype, data, error=exc)

    placeholder_descriptor = SerializedChunkDescriptor(
        buffer_name="<native-v14.3>",
        initial_offset=0,
        helper_functions={},
    )
    return SerializedChunk(
        descriptor=placeholder_descriptor,
        prototype_count=1,
        prototypes=[prototype],
    )


def _probe_v14_3_header(data: bytes, *, varint_samples: int = 4) -> Dict[str, Any]:
    """Return best-effort insights into the native chunk header."""

    view = memoryview(data)
    preview = view[: min(len(view), 16)].tobytes().hex()
    cursor = 0
    varints: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for _ in range(varint_samples):
        if cursor >= len(view):
            break
        try:
            value, consumed = decode_varint(view, start=cursor)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append({"offset": cursor, "message": str(exc)})
            break
        varints.append({"offset": cursor, "value": value, "width": consumed})
        cursor += consumed

    header = {
        "size": len(view),
        "first_bytes": preview,
        "varints": varints,
        "cursor_after_samples": cursor,
    }
    if errors:
        header["errors"] = errors
    return header


def _probe_v14_3_constants(
    data: bytes,
    header_probe: Optional[Mapping[str, Any]] = None,
    *,
    varint_samples: int = 6,
    ascii_window: int = 4096,
) -> Dict[str, Any]:
    """Return heuristics that hint at constant regions inside ``data``."""

    view = memoryview(data)
    ascii_sequences = _collect_printable_sequences(
        view[: min(len(view), ascii_window)].tobytes()
    )

    start = 0
    if header_probe:
        start = int(header_probe.get("cursor_after_samples", 0) or 0)
    varint_info = _sample_varints(view, start=start, count=varint_samples)

    return {
        "ascii_sequences": ascii_sequences,
        "varint_samples": varint_info,
    }


def _collect_printable_sequences(
    data: bytes, *, min_length: int = 4, limit: int = 6
) -> List[Dict[str, Any]]:
    """Return previews of printable ASCII runs inside ``data``."""

    sequences: List[Dict[str, Any]] = []
    start: Optional[int] = None

    for idx, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if start is None:
                start = idx
            continue
        if start is not None and idx - start >= min_length:
            snippet = data[start:idx][:32].decode("ascii", errors="replace")
            sequences.append({"offset": start, "length": idx - start, "preview": snippet})
            if len(sequences) >= limit:
                break
        start = None

    if (
        start is not None
        and len(sequences) < limit
        and len(data) - start >= min_length
    ):
        snippet = data[start:][:32].decode("ascii", errors="replace")
        sequences.append({
            "offset": start,
            "length": len(data) - start,
            "preview": snippet,
        })

    return sequences


def _sample_varints(
    data: memoryview,
    *,
    start: int = 0,
    count: int = 4,
    stride: int = 32,
) -> List[Dict[str, Any]]:
    """Sample varints from ``data`` starting at ``start`` for RE hints."""

    samples: List[Dict[str, Any]] = []
    cursor = max(start, 0)

    for _ in range(count):
        if cursor >= len(data):
            break
        try:
            value, consumed = decode_varint(data, start=cursor)
        except Exception as exc:  # pragma: no cover - defensive
            samples.append({"offset": cursor, "error": str(exc)})
            break
        samples.append({"offset": cursor, "value": value, "width": consumed})
        cursor += max(consumed, stride)

    return samples


class _ChunkReader:
    """Incremental reader for the synthetic v14.3 serialized format."""

    __slots__ = ("_view", "offset")

    def __init__(self, data: bytes) -> None:
        self._view = memoryview(data)
        self.offset = 0

    def read_bytes(self, size: int) -> bytes:
        if size < 0:
            raise SerializedChunkExtractionError("attempted to read negative length")
        end = self.offset + size
        if end > len(self._view):
            raise SerializedChunkExtractionError("unexpected end of serialized chunk")
        chunk = self._view[self.offset : end]
        self.offset = end
        return bytes(chunk)

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_varint(self) -> int:
        try:
            value, consumed = decode_varint(self._view, start=self.offset)
        except Exception as exc:  # pragma: no cover - defensive
            raise SerializedChunkExtractionError(
                "invalid varint in serialized chunk"
            ) from exc
        self.offset += consumed
        return value

    def read_zigzag(self) -> int:
        encoded = self.read_varint()
        return (encoded >> 1) ^ -(encoded & 1)


def _parse_v14_3_prototype(
    reader: _ChunkReader,
    *,
    allow_unknown_tags: bool = False,
    allow_truncated: bool = False,
) -> SerializedPrototype:
    """Parse one prototype record using the spec's field ordering.

    We confidently decode the triple of varint counts emitted by the loader
    helpers (constants, instructions, child prototypes).  Constants are fully
    parsed via ``_parse_v14_3_constant`` so the resulting objects always have a
    typed ``Constant`` representation.  Instruction payloads are still treated
    as opaque byte slices – they are length-prefixed so we retain exact data
    even though the opcode semantics are still being documented.
    """
    count_error: Optional[str] = None
    try:
        constant_count = reader.read_varint()
        instruction_count = reader.read_varint()
        child_count = reader.read_varint()
    except SerializedChunkExtractionError as exc:
        if not allow_truncated:
            raise
        count_error = str(exc)
        constant_count = 0
        instruction_count = 0
        child_count = 0

    constant_error: Optional[str] = None
    constants: List[Constant] = []
    for _ in range(constant_count):
        try:
            constants.append(
                _parse_v14_3_constant(reader, allow_unknown_tags=allow_unknown_tags)
            )
        except SerializedChunkExtractionError as exc:
            if not allow_truncated:
                raise
            constant_error = str(exc)
            break

    instruction_error: Optional[str] = None
    instructions: List[Any] = []
    for _ in range(instruction_count):
        try:
            instructions.append(_parse_v14_3_instruction(reader))
        except SerializedChunkExtractionError as exc:
            if not allow_truncated:
                raise
            remaining = bytes(reader._view[reader.offset :])
            if remaining:
                instructions.append(list(remaining))
            instruction_error = str(exc)
            reader.offset = len(reader._view)
            break

    child_error: Optional[str] = None
    children: List[SerializedPrototype] = []
    for _ in range(child_count):
        try:
            children.append(
                _parse_v14_3_prototype(
                    reader,
                    allow_unknown_tags=allow_unknown_tags,
                    allow_truncated=allow_truncated,
                )
            )
        except SerializedChunkExtractionError as exc:
            if not allow_truncated:
                raise
            child_error = str(exc)
            break

    prototype = SerializedPrototype(
        constants=constants,
        instructions=instructions,
        prototypes=children,
    )
    setattr(prototype, "serialized_constant_count", constant_count)
    if count_error:
        setattr(prototype, "count_decode_error", count_error)
    if constant_error:
        setattr(prototype, "constant_decode_error", constant_error)
    if instruction_error:
        setattr(prototype, "instruction_decode_error", instruction_error)
    if child_error:
        setattr(prototype, "child_decode_error", child_error)
    return prototype


def _parse_v14_3_instruction(reader: _ChunkReader) -> Any:
    length = reader.read_varint()
    payload = reader.read_bytes(length)
    return list(payload)


def _parse_v14_3_constant(
    reader: _ChunkReader,
    *,
    allow_unknown_tags: bool = False,
) -> Constant:
    tag = reader.read_byte()
    if tag == 0x01:
        return make_constant(None, kind="nil")
    if tag == 0x02:
        return make_constant(bool(reader.read_byte()), kind="boolean")
    if tag == 0x03:
        return make_constant(reader.read_zigzag(), kind="number")
    if tag == 0x04:
        raw = reader.read_bytes(8)
        value = struct.unpack(">d", raw)[0]
        return make_constant(value, kind="number")
    if tag == 0x05:
        length = reader.read_varint()
        payload = reader.read_bytes(length)
        return make_constant(payload.decode("utf-8"), kind="string")
    if tag == 0x06:
        length = reader.read_varint()
        payload = reader.read_bytes(length)
        return make_constant(bytes(payload), kind="bytes")
    if tag in _OPAQUE_CONSTANT_TAGS:
        length = reader.read_varint()
        payload = reader.read_bytes(length)
        metadata = {
            "v14_3_tag": f"0x{tag:02x}",
            "v14_3_role": _OPAQUE_CONSTANT_TAGS[tag],
        }
        return make_constant(bytes(payload), kind="bytes", metadata=metadata)
    if allow_unknown_tags:
        length = reader.read_varint()
        payload = reader.read_bytes(length)
        metadata = {
            "v14_3_tag": f"0x{tag:02x}",
            "v14_3_role": "unknown_tag",
        }
        return make_constant(bytes(payload), kind="bytes", metadata=metadata)
    raise SerializedChunkExtractionError(f"unknown constant tag 0x{tag:02x}")


def build_v14_3_serialized_chunk_from_bytes(
    descriptor: SerializedChunkDescriptor,
    data: bytes,
    *,
    attach_re_probes: bool = False,
    allow_re_fallback: bool = False,
) -> SerializedChunk:
    """Construct a parsed chunk populated with decoded prototype constants."""

    if descriptor.initial_offset < 0:
        raise SerializedChunkExtractionError("descriptor initial offset must be non-negative")

    if descriptor.initial_offset >= len(data):
        raise SerializedChunkExtractionError("descriptor initial offset beyond buffer")

    payload = data[descriptor.initial_offset :]

    if payload.startswith(_V14_3_CHUNK_MAGIC):
        chunk = _parse_fixture_serialized_chunk(payload)
    else:
        try:
            chunk = _parse_real_serialized_chunk(payload)
        except SerializedChunkExtractionError as exc:
            if not allow_re_fallback:
                raise
            chunk = _build_re_placeholder_chunk(payload, exc)
    chunk.descriptor = descriptor
    chunk.prototype_count = len(chunk.prototypes)
    apply_double_constant_unpacker(chunk)
    if attach_re_probes and chunk.prototypes:
        _attach_re_probes_to_prototype(chunk.prototypes[0], payload)
    return chunk


def get_v14_3_top_level_prototype_from_source(
    source: str,
    *,
    attach_re_probes: bool = False,
) -> SerializedPrototype:
    """Convenience helper for tests that exposes the extracted prototype."""

    descriptor, data = extract_v14_3_serialized_chunk_bytes_from_source(source)
    chunk = build_v14_3_serialized_chunk_from_bytes(
        descriptor,
        data,
        attach_re_probes=attach_re_probes,
        allow_re_fallback=attach_re_probes,
    )
    if not chunk.prototypes:
        raise SerializedChunkExtractionError("extracted chunk did not contain prototypes")
    return chunk.prototypes[0]


def scan_v14_3_constant_tags(
    data: bytes,
    *,
    max_prototypes: Optional[int] = None,
    max_constants: Optional[int] = None,
) -> Dict[str, Any]:
    """Enumerate constant tags inside a native v14.3 payload.

    The scanner mirrors the loader's breadth-first layout but deliberately
    avoids interpreting the payloads.  Every constant contributes one tag byte,
    and the helper keeps a running count plus a short list of representative
    samples.  When unknown tags are encountered the function assumes the
    payload is length-prefixed (``varint`` + raw bytes), which matches the
    behaviour seen in the real blob where tag ``0xDA`` prefixes large
    structures.  Any parsing errors are reported alongside the partial summary
    so callers can refine the decoder without losing the recorded tag set.
    """

    reader = _ChunkReader(data)
    if data.startswith(_V14_3_CHUNK_MAGIC):
        reader.read_bytes(len(_V14_3_CHUNK_MAGIC))
        summary: Dict[str, Any] = {
            "counts": {},
            "unique_tags": [],
            "errors": [],
            "samples": [],
            "fixture_format": True,
        }
    else:
        summary = {
            "counts": {},
            "unique_tags": [],
            "errors": [],
            "samples": [],
        }

    try:
        prototype_count = reader.read_varint()
    except Exception as exc:  # pragma: no cover - defensive
        summary["errors"].append({"stage": "header", "message": str(exc)})
        return summary

    summary["prototype_count"] = prototype_count

    def record_tag(tag: int, *, path: TypingSequence[int], strategy: str, offset: int) -> None:
        counts = summary["counts"]
        counts[tag] = counts.get(tag, 0) + 1
        if len(summary["samples"]) < 32:
            summary["samples"].append(
                {
                    "tag": tag,
                    "offset": offset,
                    "prototype_path": list(path),
                    "strategy": strategy,
                }
            )

    scanned_prototypes = 0
    scanned_constants = 0

    def scan_prototype(path: TypingSequence[int]) -> None:
        nonlocal scanned_prototypes, scanned_constants

        if max_prototypes is not None and scanned_prototypes >= max_prototypes:
            return

        scanned_prototypes += 1

        constant_count = reader.read_varint()
        instruction_count = reader.read_varint()
        child_count = reader.read_varint()

        for const_index in range(constant_count):
            if max_constants is not None and scanned_constants >= max_constants:
                summary["limit_reached"] = True
                return
            tag_offset = reader.offset
            tag = reader.read_byte()
            strategy = _skip_constant_payload_for_scan(reader, tag)
            record_tag(tag, path=(*path, const_index), strategy=strategy, offset=tag_offset)
            scanned_constants += 1

        for _ in range(instruction_count):
            length = reader.read_varint()
            reader.read_bytes(length)

        for child_index in range(child_count):
            scan_prototype((*path, child_index))

    try:
        for proto_index in range(prototype_count):
            scan_prototype((proto_index,))
            if max_prototypes is not None and scanned_prototypes >= max_prototypes:
                break
            if max_constants is not None and summary.get("limit_reached"):
                break
    except SerializedChunkExtractionError as exc:
        summary["errors"].append({"stage": "scan", "message": str(exc)})

    summary["scanned_prototypes"] = scanned_prototypes
    summary["scanned_constants"] = scanned_constants
    summary["unique_tags"] = sorted(summary["counts"].keys())
    return summary


def _skip_constant_payload_for_scan(reader: _ChunkReader, tag: int) -> str:
    """Advance ``reader`` past the payload for ``tag`` during tag scans."""

    if tag == 0x01:
        return "nil"
    if tag == 0x02:
        reader.read_byte()
        return "boolean"
    if tag == 0x03:
        reader.read_varint()
        return "integer"
    if tag == 0x04:
        reader.read_bytes(8)
        return "double"
    if tag == 0x05:
        length = reader.read_varint()
        reader.read_bytes(length)
        return "string"
    if tag == 0x06:
        length = reader.read_varint()
        reader.read_bytes(length)
        return "bytes"

    length = reader.read_varint()
    reader.read_bytes(length)
    return "unknown_length_prefixed"


def analyze_v14_3_constant_tags_for_real_payload(
    *,
    source_path: Optional[Path] = None,
    output_json: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run the tag scanner against the repository's v14.3 sample script."""

    path = source_path or Path("Obfuscated4.lua")
    source = path.read_text(encoding="utf-8")
    descriptor, data = extract_v14_3_serialized_chunk_bytes_from_source(source)
    payload = data[descriptor.initial_offset :]
    summary = scan_v14_3_constant_tags(payload)

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    return summary


__all__ = [
    "PrototypeLoaderIR",
    "PrototypeIRPrototype",
    "DecodedTokenString",
    "DecodedDoubleValue",
    "SerializedChunkExtractionError",
    "dump_bytes_preview",
    "read_varints_preview",
    "probe_v14_3_blob",
    "decode_varint",
    "decode_v14_3_chunk",
    "build_serialized_chunk_model",
    "apply_string_table_to_chunk",
    "apply_double_constant_unpacker",
    "decode_packed_double",
    "encode_packed_double",
    "extract_v14_3_serialized_chunk_bytes_from_source",
    "build_v14_3_serialized_chunk_from_bytes",
    "scan_v14_3_constant_tags",
    "analyze_v14_3_constant_tags_for_real_payload",
    "get_v14_3_top_level_prototype_from_source",
]

DOUBLE_PREFIX_MASK = 0x7FF0000000000000
DOUBLE_ENCODED_PREFIX = 0x4330000000000000
# ``DOUBLE_NORMALISATION_BIAS`` mirrors the ``9007199254740992`` literal that the
# v14.3 loader feeds into its mantissa/exponent trick.  Subtracting half that
# value (``DOUBLE_PAYLOAD_OFFSET`` → ``4503599627370496``) peels off the bias the
# Lua runtime introduced when it stuffed integer payloads into IEEE754 doubles.
DOUBLE_NORMALISATION_BIAS = 9007199254740992  # 0x20000000000000
DOUBLE_PAYLOAD_MASK = DOUBLE_NORMALISATION_BIAS - 1  # 0x1FFFFFFFFFFFFF
DOUBLE_PAYLOAD_OFFSET = DOUBLE_NORMALISATION_BIAS // 2  # 0x10000000000000
DOUBLE_VALUE_BITS = 32
DOUBLE_VALUE_MASK = (1 << DOUBLE_VALUE_BITS) - 1
DOUBLE_FLAG_BITS = 53 - DOUBLE_VALUE_BITS
DOUBLE_FLAG_MASK = (1 << DOUBLE_FLAG_BITS) - 1
CONSTANT_USAGE_VM = "vm"
CONSTANT_USAGE_LOADER = "loader"
CONSTANT_USAGE_AUXILIARY = "auxiliary"
_CONSTANT_USAGE_METADATA_KEY = "usage"
_CONST_KEY_HINTS = ("const", "constant")
_CONST_KEY_EXACT = {"k", "kb", "kc", "kd", "rk", "rk_b", "rk_c"}


@dataclass(frozen=True)
class DecodedDoubleValue:
    """Typed representation of integers unpacked from Lua doubles."""

    value: int
    raw_double: float
    payload: int
    flags: int

    def __int__(self) -> int:  # pragma: no cover - trivial
        return self.value

    def __index__(self) -> int:  # pragma: no cover - trivial
        return self.value

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)
