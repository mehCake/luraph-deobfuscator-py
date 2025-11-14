"""Synthetic sample generator for pipeline regression tests.

This module consumes a YAML pipeline specification describing how to transform
plain payload bytes into a synthetic obfuscated stream.  The generated samples
are used by integration tests to exercise the loader → extractor → collector
pipeline without requiring sensitive or proprietary material.

The specification focuses on the transformations commonly observed in Luraph
v14.4.x payloads: PRGA style byte mixing, small-block permutations, and
packaging into Lua friendly representations (``string.char`` and numeric
arrays).  The implementation deliberately avoids executing any untrusted Lua
code and never persists secret keys – any key-like values in the specification
are redacted from emitted metadata.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, MutableMapping, Sequence

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore

LOGGER = logging.getLogger(__name__)


@dataclass
class GenerationResult:
    """Paths for generated artefacts."""

    name: str
    binary_path: Path
    lua_path: Path
    metadata_path: Path


def _load_spec(path: Path) -> MutableMapping[str, object]:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text)
    else:  # pragma: no cover - exercised when PyYAML unavailable
        data = json.loads(text)
    if not isinstance(data, MutableMapping):
        raise ValueError(f"Expected mapping at root of spec: {path}")
    return data


def _normalise_bytes(value: object, *, field: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("0x"):
            stripped = stripped[2:]
        stripped = stripped.replace(" ", "")
        if len(stripped) % 2:
            raise ValueError(f"Hex string for {field} must contain an even number of characters")
        return bytes.fromhex(stripped)
    if isinstance(value, Iterable):
        ints: List[int] = []
        for item in value:
            if not isinstance(item, int):
                raise TypeError(f"Expected integers in {field} list")
            if not 0 <= item <= 0xFF:
                raise ValueError(f"Byte value out of range for {field}: {item}")
            ints.append(item)
        return bytes(ints)
    raise TypeError(f"Unsupported payload format for {field}: {type(value)!r}")


def _resolve_payload(spec: MutableMapping[str, object]) -> bytes:
    payload_spec = spec.get("base_payload")
    if not isinstance(payload_spec, MutableMapping):
        raise ValueError("Spec missing 'base_payload' mapping")
    kind = str(payload_spec.get("kind", "text")).lower()
    if kind == "text":
        value = payload_spec.get("value", "")
        if not isinstance(value, str):
            raise TypeError("Text payload requires string 'value'")
        return value.encode("utf-8")
    if kind == "hex":
        value = payload_spec.get("value", "")
        return _normalise_bytes(value, field="base_payload.value")
    if kind == "bytes":
        value = payload_spec.get("value", [])
        return _normalise_bytes(value, field="base_payload.value")
    raise ValueError(f"Unsupported base_payload.kind: {kind}")


def _apply_prga(data: bytes, config: MutableMapping[str, object]) -> bytes:
    key_bytes = _normalise_bytes(config.get("key", []), field="operations[].key")
    if not key_bytes:
        raise ValueError("PRGA operation requires a non-empty key")
    rotate = int(config.get("rotate", 0)) % 8
    xor_seed = int(config.get("xor", 0)) & 0xFF
    bias = int(config.get("bias", 0)) & 0xFF

    result = bytearray(len(data))
    for index, value in enumerate(data):
        key_value = key_bytes[index % len(key_bytes)]
        mixed = (value ^ key_value) & 0xFF
        if rotate:
            mixed = ((mixed << rotate) | (mixed >> (8 - rotate))) & 0xFF
        if xor_seed:
            mixed ^= xor_seed
        if bias:
            mixed = (mixed + bias) & 0xFF
        result[index] = mixed
    return bytes(result)


def _apply_permutation(data: bytes, config: MutableMapping[str, object]) -> bytes:
    table = config.get("table")
    if not isinstance(table, Sequence) or not table:
        raise ValueError("Permutation requires 'table' sequence")
    indices = [int(item) for item in table]
    block_size = int(config.get("block", len(indices)))
    if block_size != len(indices):
        raise ValueError("Permutation 'block' size must match table length")
    pad_value = int(config.get("pad", 0)) & 0xFF
    block_count, remainder = divmod(len(data), block_size)
    padded = bytearray(data)
    if remainder:
        LOGGER.debug("Padding permutation input with %s byte(s)", block_size - remainder)
        padded.extend([pad_value] * (block_size - remainder))
        block_count += 1
    output = bytearray(len(padded))
    for block_index in range(block_count):
        offset = block_index * block_size
        block = padded[offset : offset + block_size]
        for dest_index, source_index in enumerate(indices):
            if not 0 <= source_index < block_size:
                raise ValueError("Permutation index out of range")
            output[offset + dest_index] = block[source_index]
    return bytes(output)


@dataclass
class PackResult:
    lua_source: str
    metadata: Dict[str, object]


def _chunk_values(values: Sequence[int], chunk_size: int) -> Iterable[Sequence[int]]:
    for index in range(0, len(values), chunk_size):
        yield values[index : index + chunk_size]


def _pack_payload(data: bytes, config: MutableMapping[str, object], *, sample_name: str) -> PackResult:
    style = str(config.get("style", "string_char")).lower()
    chunk_size = max(1, int(config.get("chunk", 32)))
    variable = str(config.get("variable", "payload"))
    header = ["-- Synthetic sample generated by generate_sample.py", f"-- sample: {sample_name}"]
    provenance = config.get("provenance")
    if provenance:
        header.append(f"-- provenance: {provenance}")

    values = list(data)
    if style == "string_char":
        chunks = [
            f"string.char({', '.join(str(v) for v in chunk)})"
            for chunk in _chunk_values(values, chunk_size)
        ]
        expression = " ..\n    ".join(chunks) if len(chunks) > 1 else (chunks[0] if chunks else "''")
        body = [f"local {variable} = {expression}"]
    elif style == "numeric_table":
        rows = []
        for chunk in _chunk_values(values, chunk_size):
            rows.append(", ".join(str(v) for v in chunk))
        body = [f"local {variable} = {{"]
        for row in rows:
            body.append(f"    {row},")
        body.append("}")
    else:
        raise ValueError(f"Unsupported pack style: {style}")

    footer = ["return {" + f"payload={variable}" + "}"]
    lua_source = "\n".join(header + body + footer) + "\n"
    metadata = {
        "style": style,
        "variable": variable,
        "chunk_size": chunk_size,
        "byte_count": len(values),
    }
    return PackResult(lua_source=lua_source, metadata=metadata)


def _sanitise_for_metadata(value: object) -> object:
    if isinstance(value, MutableMapping):
        cleaned: Dict[str, object] = {}
        for key, val in value.items():
            if key.lower() == "key":
                try:
                    length = len(_normalise_bytes(val, field="metadata"))  # type: ignore[arg-type]
                except Exception:  # pragma: no cover - defensive fallback
                    length = len(str(val))
                cleaned[key] = {"redacted": True, "length": length}
            else:
                cleaned[key] = _sanitise_for_metadata(val)
        return cleaned
    if isinstance(value, list):
        return [_sanitise_for_metadata(item) for item in value]
    return value


def generate_sample_from_spec(spec_path: Path, output_dir: Path) -> GenerationResult:
    spec = _load_spec(spec_path)
    name = str(spec.get("name") or spec_path.stem)
    description = spec.get("description")
    LOGGER.info("Generating synthetic sample: %s", name)

    data = _resolve_payload(spec)
    operations = spec.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("Spec must define non-empty 'operations' list")

    pack_result: PackResult | None = None
    for position, operation in enumerate(operations, start=1):
        if not isinstance(operation, MutableMapping):
            raise TypeError("Each operation must be a mapping")
        op_type = str(operation.get("type", "")).lower()
        if op_type == "prga":
            data = _apply_prga(data, operation)
        elif op_type == "permute":
            data = _apply_permutation(data, operation)
        elif op_type == "pack":
            pack_result = _pack_payload(data, operation, sample_name=name)
        else:
            raise ValueError(f"Unsupported operation type: {op_type}")
        LOGGER.debug("Operation %s (%s) complete", position, op_type)

    if pack_result is None:
        raise ValueError("Pipeline must include a 'pack' operation to produce Lua output")

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = spec.get("outputs", {}).get("base_name") if isinstance(spec.get("outputs"), MutableMapping) else None
    base_name = str(base_name or name)
    binary_path = output_dir / f"{base_name}.bin"
    lua_path = output_dir / f"{base_name}.lua"
    metadata_path = output_dir / f"{base_name}_metadata.json"

    binary_path.write_bytes(data)
    lua_path.write_text(pack_result.lua_source, encoding="utf-8")

    raw_metadata: Dict[str, object] = {
        "name": name,
        "description": description,
        "byte_length": len(data),
        "operations": spec.get("operations"),
        "pack": pack_result.metadata,
    }
    metadata_path.write_text(
        json.dumps(_sanitise_for_metadata(raw_metadata), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    LOGGER.info("Generated artefacts: %s", {
        "binary": str(binary_path),
        "lua": str(lua_path),
        "metadata": str(metadata_path),
    })
    return GenerationResult(name=name, binary_path=binary_path, lua_path=lua_path, metadata_path=metadata_path)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate synthetic obfuscated sample from YAML spec")
    parser.add_argument("spec", type=Path, help="Path to YAML/JSON pipeline specification")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tests/samples/generated"),
        help="Directory for generated artefacts (default: tests/samples/generated)",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Load the specification and print a summary without writing artefacts",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser


def _summarise_spec(spec_path: Path) -> str:
    spec = _load_spec(spec_path)
    name = spec.get("name", spec_path.stem)
    description = spec.get("description", "")
    operations = spec.get("operations", [])
    lines = [f"Sample: {name}"]
    if description:
        lines.append(f"  {description}")
    for index, operation in enumerate(operations, start=1):
        if isinstance(operation, MutableMapping):
            op_type = operation.get("type", "unknown")
            lines.append(f"  [{index}] {op_type}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    if args.list_only:
        print(_summarise_spec(args.spec))
        return 0

    result = generate_sample_from_spec(args.spec, args.output_dir)
    print(
        json.dumps(
            {
                "name": result.name,
                "binary": str(result.binary_path),
                "lua": str(result.lua_path),
                "metadata": str(result.metadata_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
