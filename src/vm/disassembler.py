"""Configurable instruction stream disassembler scaffolding.

This module started as a lightweight helper that simply split 32-bit words
according to a provided mask mapping.  The loader now needs richer behaviour
to support real Luraph payloads, so the module also offers:

* Built-in mask presets for several Luraph versions (v14.4.1 – v14.4.3).
* Helpers that try multiple field splits automatically and rank the results.
* Operand statistics that hint if an operand looks like a register or a
  constant index.
* A CLI entry-point (``python -m src.vm.disassembler``) for quick inspection
  of raw VM byte streams.

All analysis is static – no obfuscated code is executed.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

LOGGER = logging.getLogger(__name__)

Word = int


@dataclass(frozen=True)
class FieldConfig:
    """Describe how a single operand field is encoded within a word."""

    mask: int
    shift: int

    def extract(self, word: Word) -> int:
        return (word & self.mask) >> self.shift

    @property
    def width(self) -> int:
        """Return the number of bits covered by the mask."""

        mask = self.mask >> self.shift
        width = 0
        while mask:
            width += 1
            mask >>= 1
        return width

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object] | object) -> "FieldConfig":
        if not isinstance(mapping, Mapping):
            mask = _coerce_int(mapping)
            if mask is None:
                raise TypeError(f"Unsupported field spec: {mapping!r}")
            return cls(mask=mask, shift=_infer_shift(mask))

        mask = _coerce_int(mapping.get("mask")) if "mask" in mapping else None
        shift = _coerce_int(mapping.get("shift")) if "shift" in mapping else None
        width = _coerce_int(mapping.get("width")) if "width" in mapping else None
        lsb = _coerce_int(mapping.get("lsb")) if "lsb" in mapping else None
        bits = mapping.get("bits")

        if bits is not None and mask is None:
            if not isinstance(bits, Sequence) or len(bits) < 2:
                raise ValueError(f"bits field must provide a range: {bits!r}")
            start = int(bits[0])
            end = int(bits[1])
            lower = min(start, end)
            upper = max(start, end)
            width = (upper - lower) + 1
            shift = lower if shift is None else shift
            mask = ((1 << width) - 1) << shift
        if width is not None and mask is None:
            use_shift = lsb if lsb is not None else (shift if shift is not None else 0)
            mask = ((1 << width) - 1) << use_shift
            shift = use_shift
        if mask is None:
            raise ValueError(f"mask missing in field mapping: {mapping}")
        if shift is None:
            shift = _infer_shift(mask)
        return cls(mask=mask, shift=shift)


@dataclass
class Instruction:
    """Represents a decoded instruction word."""

    index: int
    raw: Word
    opcode: int
    a: int
    b: int
    c: int

    def as_tuple(self) -> Tuple[int, int, int, int]:
        return self.opcode, self.a, self.b, self.c

    def as_dict(self) -> Dict[str, int]:
        return {
            "index": self.index,
            "raw": self.raw,
            "opcode": self.opcode,
            "a": self.a,
            "b": self.b,
            "c": self.c,
        }


@dataclass(frozen=True)
class OperandStats:
    """Summary describing how an operand behaves across a trace."""

    name: str
    total: int
    distinct: int
    zero_count: int
    constant_like: int
    register_like: int
    max_value: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "total": self.total,
            "distinct": self.distinct,
            "zero_count": self.zero_count,
            "constant_like": self.constant_like,
            "register_like": self.register_like,
            "max_value": self.max_value,
            "constant_ratio": self.constant_ratio,
            "register_ratio": self.register_ratio,
            "distinct_ratio": self.distinct_ratio,
        }

    @property
    def constant_ratio(self) -> float:
        if not self.total:
            return 0.0
        return self.constant_like / self.total

    @property
    def register_ratio(self) -> float:
        if not self.total:
            return 0.0
        return self.register_like / self.total

    @property
    def distinct_ratio(self) -> float:
        if not self.total:
            return 0.0
        return self.distinct / self.total


@dataclass
class DisassemblyCandidate:
    """A ranked disassembly run using a single configuration."""

    name: str
    config: DisassemblerConfig
    split: Tuple[int, int, int, int]
    instructions: List[Instruction]
    operand_stats: Mapping[str, OperandStats]
    score: float

    def as_dict(self, include_instructions: bool = False) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "name": self.name,
            "split": self.split,
            "score": self.score,
            "operand_stats": {
                key: stats.as_dict() for key, stats in self.operand_stats.items()
            },
        }
        if include_instructions:
            payload["instructions"] = [inst.as_dict() for inst in self.instructions]
        return payload


@dataclass
class DisassemblerConfig:
    fields: Mapping[str, FieldConfig]
    word_size: int = 32
    endianness: str = "little"
    order: Tuple[str, ...] = ("opcode", "a", "b", "c")

    def split(self, word: Word) -> Tuple[int, int, int, int]:
        values = []
        for name in self.order:
            try:
                config = self.fields[name]
            except KeyError as exc:  # pragma: no cover - defensive
                raise KeyError(f"Unknown field '{name}' in disassembler order") from exc
            values.append(config.extract(word))
        return tuple(values)  # type: ignore[return-value]

    def field_width(self, name: str) -> int:
        try:
            field = self.fields[name]
        except KeyError as exc:  # pragma: no cover - defensive
            raise KeyError(f"Unknown field '{name}' in disassembler config") from exc
        return field.width

    def split_signature(self) -> Tuple[int, int, int, int]:
        """Return the bit-width for (opcode, a, b, c)."""

        return tuple(self.field_width(part) for part in self.order)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "DisassemblerConfig":
        if "fields" in payload:
            field_mapping = payload["fields"]
        else:
            field_mapping = payload
        if not isinstance(field_mapping, Mapping):
            raise TypeError("Field mapping must be a mapping")
        fields = {
            name: FieldConfig.from_mapping(spec)
            for name, spec in field_mapping.items()
        }
        word_size = _coerce_int(payload.get("word_size"), default=32)
        endianness = str(payload.get("endianness", "little"))
        order = tuple(str(part) for part in payload.get("order", ("opcode", "a", "b", "c")))
        if len(order) != 4:
            raise ValueError("Disassembler order must include exactly four fields: opcode, a, b, c")
        return cls(fields=fields, word_size=word_size, endianness=endianness, order=order)

    @classmethod
    def from_pipeline_candidates(
        cls,
        candidates: Mapping[str, object],
        profile: Optional[str] = None,
        key_hints: Sequence[str] = ("vm", "disassembler", "field_masks", "fields"),
    ) -> "DisassemblerConfig":
        if not isinstance(candidates, Mapping):
            raise TypeError("Pipeline candidates payload must be a mapping")
        data: Mapping[str, object] = candidates
        if profile:
            next_data = candidates.get(profile)
            if not isinstance(next_data, Mapping):
                raise KeyError(f"Profile '{profile}' missing or not a mapping")
            data = next_data
        for hint in key_hints:
            candidate = data.get(hint) if isinstance(data, Mapping) else None
            if isinstance(candidate, Mapping) and {"opcode", "a", "b", "c"} <= set(candidate.keys()):
                return cls.from_dict({"fields": candidate, **{k: data.get(k) for k in ("word_size", "endianness", "order") if k in data}})
        if {"opcode", "a", "b", "c"} <= set(data.keys()):
            return cls.from_dict(data)
        raise KeyError("Unable to locate opcode field mapping inside pipeline candidates")


class Disassembler:
    """Decode VM instruction words according to a configuration."""

    def __init__(self, config: DisassemblerConfig):
        self.config = config

    def words_from_bytes(self, blob: bytes) -> List[Word]:
        step = self.config.word_size // 8
        if len(blob) % step:
            raise ValueError("Byte blob length must be divisible by word size")
        words: List[Word] = []
        for start in range(0, len(blob), step):
            chunk = blob[start : start + step]
            words.append(int.from_bytes(chunk, self.config.endianness))
        return words

    def disassemble_words(self, words: Iterable[Word]) -> List[Instruction]:
        instructions: List[Instruction] = []
        for index, word in enumerate(words):
            opcode, a, b, c = self.config.split(word)
            instructions.append(Instruction(index=index, raw=word, opcode=opcode, a=a, b=b, c=c))
        return instructions

    def disassemble_bytes(self, blob: bytes) -> List[Instruction]:
        words = self.words_from_bytes(blob)
        return self.disassemble_words(words)

    @staticmethod
    def load_pipeline_config(path: Path, **kwargs: object) -> "Disassembler":
        with Path(path).open("r", encoding="utf8") as fh:
            payload = json.load(fh)
        config = DisassemblerConfig.from_pipeline_candidates(payload, **kwargs)
        return Disassembler(config)


def build_config_from_split(
    split: Sequence[int],
    *,
    word_size: int = 32,
    endianness: str = "little",
    order: Sequence[str] = ("opcode", "a", "b", "c"),
) -> DisassemblerConfig:
    """Create a :class:`DisassemblerConfig` from a split description.

    ``split`` contains the bit-width for each operand starting from the least
    significant bits.  The helper mirrors the logic used by :mod:`disasm_driver`
    but keeps the functionality local to this module so it can be reused by
    the CLI and unit tests without creating import cycles.
    """

    if len(split) != 4:
        raise ValueError("Split must provide four widths for opcode/a/b/c")
    if len(order) != 4:
        raise ValueError("Order must contain four entries to match the split")
    if sum(split) != word_size:
        raise ValueError("Split widths must add up to the configured word size")

    offset = 0
    fields: Dict[str, FieldConfig] = {}
    for width, name in zip(split, order):
        if width <= 0:
            raise ValueError("Split widths must be positive integers")
        mask = ((1 << width) - 1) << offset
        fields[str(name)] = FieldConfig(mask=mask, shift=offset)
        offset += width

    return DisassemblerConfig(
        fields=fields,
        word_size=word_size,
        endianness=endianness,
        order=tuple(str(part) for part in order),
    )


def parse_split_spec(spec: str | Sequence[int]) -> Tuple[int, int, int, int]:
    """Normalise a user supplied split specification."""

    if isinstance(spec, str):
        cleaned = spec.replace(",", "/")
        parts = [part for part in cleaned.split("/") if part]
        if len(parts) != 4:
            raise ValueError(f"Split specification must contain four parts: {spec!r}")
        try:
            return tuple(int(part, 10) for part in parts)  # type: ignore[return-value]
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid integer inside split specification {spec!r}") from exc
    if isinstance(spec, Sequence):
        if len(spec) != 4:
            raise ValueError(f"Split sequence must contain four entries: {spec!r}")
        return tuple(int(part) for part in spec)  # type: ignore[return-value]
    raise TypeError(f"Unsupported split specification type: {type(spec)!r}")


def _clone_config(config: DisassemblerConfig, *, endianness: Optional[str] = None) -> DisassemblerConfig:
    if endianness is None or endianness == config.endianness:
        return config
    return DisassemblerConfig(
        fields={name: FieldConfig(mask=field.mask, shift=field.shift) for name, field in config.fields.items()},
        word_size=config.word_size,
        endianness=endianness,
        order=config.order,
    )


DEFAULT_PROFILE_SPLITS: Dict[str, Tuple[int, int, int, int]] = {
    # Mask presets gathered from commonly observed layouts.  These cover the
    # most frequent 14.4.x variants and act as quick starting points.
    "v14.4.1": (6, 8, 9, 9),
    "v14.4.2": (8, 8, 8, 8),
    "v14.4.3": (6, 8, 8, 10),
}


DEFAULT_CONFIGS: Dict[str, DisassemblerConfig] = {
    profile: build_config_from_split(split)
    for profile, split in DEFAULT_PROFILE_SPLITS.items()
}


COMMON_SPLITS: Tuple[Tuple[int, int, int, int], ...] = (
    DEFAULT_PROFILE_SPLITS["v14.4.1"],
    DEFAULT_PROFILE_SPLITS["v14.4.2"],
    DEFAULT_PROFILE_SPLITS["v14.4.3"],
    (10, 8, 8, 6),
    (12, 8, 6, 6),
)


def compute_operand_statistics(
    instructions: Sequence[Instruction],
    *,
    constant_threshold: int = 256,
    register_threshold: int = 64,
) -> Dict[str, OperandStats]:
    """Build :class:`OperandStats` for opcode/a/b/c."""

    buckets: Dict[str, List[int]] = {
        "opcode": [],
        "a": [],
        "b": [],
        "c": [],
    }
    for inst in instructions:
        buckets["opcode"].append(inst.opcode)
        buckets["a"].append(inst.a)
        buckets["b"].append(inst.b)
        buckets["c"].append(inst.c)

    stats: Dict[str, OperandStats] = {}
    for name, values in buckets.items():
        total = len(values)
        zero_count = sum(1 for value in values if value == 0)
        constant_like = sum(1 for value in values if 0 <= value < constant_threshold)
        register_like = sum(1 for value in values if 0 <= value < register_threshold)
        distinct = len(set(values))
        max_value = max(values) if values else 0
        stats[name] = OperandStats(
            name=name,
            total=total,
            distinct=distinct,
            zero_count=zero_count,
            constant_like=constant_like,
            register_like=register_like,
            max_value=max_value,
        )
    return stats


def _score_candidate(operand_stats: Mapping[str, OperandStats]) -> float:
    if not operand_stats:
        return 0.0
    total = next(iter(operand_stats.values())).total
    if not total:
        return 0.0
    opcode_ratio = operand_stats.get("opcode", OperandStats("opcode", 0, 0, 0, 0, 0, 0)).distinct_ratio
    a_reg = operand_stats.get("a", OperandStats("a", 0, 0, 0, 0, 0, 0)).register_ratio
    b_const = operand_stats.get("b", OperandStats("b", 0, 0, 0, 0, 0, 0)).constant_ratio
    c_const = operand_stats.get("c", OperandStats("c", 0, 0, 0, 0, 0, 0)).constant_ratio
    return opcode_ratio + a_reg + b_const + c_const


def analyse_disassembly(
    blob: bytes,
    configs: Sequence[Tuple[str, DisassemblerConfig]] | Mapping[str, DisassemblerConfig],
    *,
    constant_threshold: int = 256,
    register_threshold: int = 64,
    top: Optional[int] = None,
) -> List[DisassemblyCandidate]:
    """Run the disassembler for multiple configs and rank the results."""

    if isinstance(configs, Mapping):
        iterator: Iterable[Tuple[str, DisassemblerConfig]] = configs.items()
    else:
        iterator = configs

    results: List[DisassemblyCandidate] = []
    for name, config in iterator:
        disassembler = Disassembler(config)
        try:
            instructions = disassembler.disassemble_bytes(blob)
        except ValueError as exc:
            LOGGER.debug("Skipping config %s due to error: %s", name, exc)
            continue
        stats = compute_operand_statistics(
            instructions,
            constant_threshold=constant_threshold,
            register_threshold=register_threshold,
        )
        split = config.split_signature()
        score = _score_candidate(stats)
        results.append(
            DisassemblyCandidate(
                name=name,
                config=config,
                split=split,
                instructions=instructions,
                operand_stats=stats,
                score=score,
            )
        )

    results.sort(key=lambda item: item.score, reverse=True)
    if top is not None:
        results = results[:top]
    return results


def _collect_named_configs(
    *,
    profiles: Optional[Sequence[str]],
    splits: Optional[Sequence[str]],
    endianness: str,
    include_defaults: bool,
) -> List[Tuple[str, DisassemblerConfig]]:
    entries: MutableMapping[Tuple[Tuple[int, int, int, int], str], Tuple[str, DisassemblerConfig]] = {}

    def add(name: str, config: DisassemblerConfig) -> None:
        key = (config.split_signature(), config.endianness)
        if key not in entries:
            entries[key] = (name, config)

    if profiles:
        for profile in profiles:
            if profile not in DEFAULT_CONFIGS:
                raise KeyError(f"Unknown profile: {profile}")
            base = DEFAULT_CONFIGS[profile]
            add(f"profile:{profile}", _clone_config(base, endianness=endianness))

    if splits:
        for raw in splits:
            split = parse_split_spec(raw)
            config = build_config_from_split(split, endianness=endianness)
            name = f"split:{split[0]}/{split[1]}/{split[2]}/{split[3]}"
            add(name, config)

    if include_defaults and not entries:
        for profile, config in DEFAULT_CONFIGS.items():
            add(f"profile:{profile}", _clone_config(config, endianness=endianness))
        for split in COMMON_SPLITS:
            config = build_config_from_split(split, endianness=endianness)
            name = f"auto:{split[0]}/{split[1]}/{split[2]}/{split[3]}"
            add(name, config)

    return list(entries.values())


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Disassemble Luraph VM byte streams")
    parser.add_argument("input", help="Path to the raw byte stream to decode")
    parser.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        choices=sorted(DEFAULT_CONFIGS.keys()),
        help="Use a built-in profile (can be supplied multiple times)",
    )
    parser.add_argument(
        "--split",
        dest="splits",
        action="append",
        help="Custom split specification such as 8/8/8/8",
    )
    parser.add_argument("--endianness", choices=("little", "big"), default="little")
    parser.add_argument("--top", type=int, default=None, help="Only show the top N ranked results")
    parser.add_argument("--json-out", type=Path, help="Optional JSON output path")
    parser.add_argument(
        "--include-instructions",
        action="store_true",
        help="Include full instruction dumps in the JSON report",
    )
    parser.add_argument(
        "--constant-threshold",
        type=int,
        default=256,
        help="Values below this count as constant-like (default: 256)",
    )
    parser.add_argument(
        "--register-threshold",
        type=int,
        default=64,
        help="Values below this count as register-like (default: 64)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    blob_path = Path(args.input)
    data = blob_path.read_bytes()

    named_configs = _collect_named_configs(
        profiles=args.profiles,
        splits=args.splits,
        endianness=args.endianness,
        include_defaults=True,
    )

    if not named_configs:
        parser.error("No disassembler configurations were generated")

    LOGGER.info("Analysing %s with %d configuration(s)", blob_path, len(named_configs))

    results = analyse_disassembly(
        data,
        named_configs,
        constant_threshold=args.constant_threshold,
        register_threshold=args.register_threshold,
        top=args.top,
    )

    if not results:
        LOGGER.warning("No successful disassemblies produced results")
        return 1

    for candidate in results:
        print(
            f"[{candidate.name}] split={candidate.split} score={candidate.score:.3f} "
            f"instructions={len(candidate.instructions)}"
        )
        for operand, stats in candidate.operand_stats.items():
            print(
                f"  {operand:<6} distinct={stats.distinct_ratio:.2f} const={stats.constant_ratio:.2f} "
                f"reg={stats.register_ratio:.2f} max={stats.max_value}"
            )

    if args.json_out:
        payload = [
            candidate.as_dict(include_instructions=args.include_instructions)
            for candidate in results
        ]
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf8")
        LOGGER.info("Wrote JSON report to %s", args.json_out)

    return 0


def _coerce_int(value: Optional[object], default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        if value.startswith("0b") or value.startswith("0B"):
            return int(value, 2)
        return int(value, 10)
    return int(value)


def _infer_shift(mask: int) -> int:
    shift = 0
    while mask and mask & 1 == 0:
        shift += 1
        mask >>= 1
    return shift


__all__ = [
    "Disassembler",
    "DisassemblerCandidate",
    "DisassemblerConfig",
    "FieldConfig",
    "Instruction",
    "OperandStats",
    "DEFAULT_CONFIGS",
    "DEFAULT_PROFILE_SPLITS",
    "COMMON_SPLITS",
    "analyse_disassembly",
    "build_config_from_split",
    "compute_operand_statistics",
    "main",
    "parse_split_spec",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
