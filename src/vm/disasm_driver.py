"""Disassembly driver that experiments with field mask splits for VM words."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .disassembler import Disassembler, DisassemblerConfig, FieldConfig, Instruction

LOGGER = logging.getLogger(__name__)

DEFAULT_SPLITS = ("8/8/8/8", "6/8/18", "10/6/8/8")

__all__ = [
    "DEFAULT_SPLITS",
    "DisassemblyCandidate",
    "build_config_from_split",
    "generate_disassembly_candidates",
    "inspect_candidates",
    "main",
]


@dataclass(frozen=True)
class DisassemblyCandidate:
    """Capture a disassembly attempt, its score, and metadata."""

    name: str
    score: float
    instructions: List[Instruction]
    config: DisassemblerConfig
    split: Optional[Tuple[int, int, int, int]] = None
    stats: Mapping[str, object] | None = None


def _field_width(field: FieldConfig) -> int:
    mask = field.mask >> field.shift
    return mask.bit_count()


def _config_snapshot(config: DisassemblerConfig) -> MutableMapping[str, object]:
    return {
        "word_size": config.word_size,
        "endianness": config.endianness,
        "order": list(config.order),
        "fields": {
            name: {
                "mask": field.mask,
                "shift": field.shift,
                "width": _field_width(field),
            }
            for name, field in config.fields.items()
        },
    }


def _parse_split(split: str, *, word_size: int = 32) -> Tuple[int, int, int, int]:
    tokens = [token for token in split.replace("-", "/").split("/") if token]
    if not tokens:
        raise ValueError("Empty split specification")
    values = [int(token, 10) for token in tokens]
    if len(values) == 4:
        result = tuple(values)
    elif len(values) == 3:
        remaining = values[2]
        lower = remaining // 2
        upper = remaining - lower
        if lower == 0 or upper == 0:
            raise ValueError(f"Cannot divide final width {remaining} into operands")
        result = (values[0], values[1], lower, upper)
    elif len(values) == 2:
        remaining = word_size - sum(values)
        if remaining <= 0:
            raise ValueError("Split does not leave room for all operands")
        half = remaining // 2
        result = (values[0], values[1], half, remaining - half)
    else:
        raise ValueError(f"Unsupported split layout: {split}")
    if sum(result) != word_size:
        raise ValueError(
            f"Split {split} must total {word_size} bits; got {sum(result)}"
        )
    return result


def build_config_from_split(
    split: Tuple[int, int, int, int],
    *,
    word_size: int = 32,
    endianness: str = "little",
    order: Sequence[str] = ("opcode", "a", "b", "c"),
) -> DisassemblerConfig:
    if len(order) != 4:
        raise ValueError("Order must include exactly four field names")
    offset = 0
    fields = {}
    for name, width in zip(order, split):
        mask = ((1 << width) - 1) << offset
        fields[name] = FieldConfig(mask=mask, shift=offset)
        offset += width
    return DisassemblerConfig(fields=fields, word_size=word_size, endianness=endianness, order=tuple(order))


def _score_instructions(instructions: Sequence[Instruction]) -> float:
    if not instructions:
        return 0.0
    small_opcodes = sum(1 for inst in instructions if inst.opcode < 0x200)
    large_opcodes = sum(1 for inst in instructions if inst.opcode >= 0x4000)
    operand_small = sum(
        1
        for inst in instructions
        for operand in (inst.a, inst.b, inst.c)
        if operand < 0x1000
    )
    operand_large = sum(
        1
        for inst in instructions
        for operand in (inst.a, inst.b, inst.c)
        if operand >= 0x20000
    )
    unique_opcodes = len({inst.opcode for inst in instructions})
    smooth_transitions = sum(
        1
        for prev, curr in zip(instructions, instructions[1:])
        if abs(curr.opcode - prev.opcode) <= 4
    )
    return (
        small_opcodes * 2.0
        + operand_small * 0.25
        + unique_opcodes * 1.5
        + smooth_transitions * 0.5
        - large_opcodes * 1.5
        - operand_large * 0.5
    )


def _stats_for(values: Iterable[int]) -> Mapping[str, object]:
    seq = list(values)
    if not seq:
        return {"count": 0}
    return {
        "count": len(seq),
        "min": min(seq),
        "max": max(seq),
        "unique": len(set(seq)),
    }


def _collect_stats(instructions: Sequence[Instruction]) -> Mapping[str, object]:
    return {
        "instruction_count": len(instructions),
        "opcode": _stats_for(inst.opcode for inst in instructions),
        "a": _stats_for(inst.a for inst in instructions),
        "b": _stats_for(inst.b for inst in instructions),
        "c": _stats_for(inst.c for inst in instructions),
    }


def generate_disassembly_candidates(
    blob: bytes,
    configs: Sequence[Tuple[str, DisassemblerConfig, Optional[Tuple[int, int, int, int]]]],
) -> List[DisassemblyCandidate]:
    results: List[DisassemblyCandidate] = []
    for name, config, split in configs:
        disassembler = Disassembler(config)
        try:
            instructions = disassembler.disassemble_bytes(blob)
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.debug("Failed disassembly for %s: %s", name, exc)
            continue
        score = _score_instructions(instructions)
        stats = _collect_stats(instructions)
        results.append(
            DisassemblyCandidate(
                name=name,
                score=score,
                instructions=list(instructions),
                config=config,
                split=split,
                stats=stats,
            )
        )
    results.sort(key=lambda item: item.score, reverse=True)
    return results


def _load_candidate_config(path: Optional[Path]) -> Optional[DisassemblerConfig]:
    if not path:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - filesystem
        LOGGER.warning("Unable to read candidate config %s: %s", path, exc)
        return None
    try:
        return DisassemblerConfig.from_pipeline_candidates(payload)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("Candidate config did not yield disassembler settings: %s", exc)
        return None


def _derive_split_from_config(config: DisassemblerConfig) -> Tuple[int, int, int, int]:
    widths = []
    for name in config.order:
        field = config.fields[name]
        widths.append(_field_width(field))
    return tuple(widths)  # type: ignore[return-value]


def _unique_configs(
    entries: Sequence[Tuple[str, DisassemblerConfig, Optional[Tuple[int, int, int, int]]]]
) -> List[Tuple[str, DisassemblerConfig, Optional[Tuple[int, int, int, int]]]]:
    seen = set()
    unique: List[Tuple[str, DisassemblerConfig, Optional[Tuple[int, int, int, int]]]] = []
    for name, config, split in entries:
        key = (
            tuple(sorted((field.mask, field.shift, key_name) for key_name, field in config.fields.items())),
            config.word_size,
            config.endianness,
            config.order,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append((name, config, split))
    return unique


def _candidate_to_dict(candidate: DisassemblyCandidate, *, limit: int) -> Mapping[str, object]:
    return {
        "name": candidate.name,
        "score": candidate.score,
        "split": list(candidate.split) if candidate.split else None,
        "config": _config_snapshot(candidate.config),
        "stats": candidate.stats,
        "instructions": [
            inst.as_dict() for inst in candidate.instructions[:limit]
        ],
    }


def run_driver(
    blob: bytes,
    *,
    candidate_config: Optional[DisassemblerConfig],
    splits: Sequence[str],
    top: int,
) -> List[DisassemblyCandidate]:
    configs: List[Tuple[str, DisassemblerConfig, Optional[Tuple[int, int, int, int]]]] = []
    base_order: Sequence[str] = (
        candidate_config.order if candidate_config else ("opcode", "a", "b", "c")
    )
    base_word_size = candidate_config.word_size if candidate_config else 32
    base_endianness = candidate_config.endianness if candidate_config else "little"

    if candidate_config is not None:
        split = _derive_split_from_config(candidate_config)
        configs.append(("candidate", candidate_config, split))

    for split_text in splits:
        try:
            split = _parse_split(split_text, word_size=base_word_size)
        except ValueError as exc:
            LOGGER.debug("Ignoring invalid split %s: %s", split_text, exc)
            continue
        config = build_config_from_split(
            split,
            word_size=base_word_size,
            endianness=base_endianness,
            order=base_order,
        )
        configs.append((f"split_{'-'.join(map(str, split))}", config, split))

    configs = _unique_configs(configs)
    candidates = generate_disassembly_candidates(blob, configs)
    return candidates[:top]


def inspect_candidates(
    candidates: Sequence[DisassemblyCandidate],
    *,
    limit: int,
) -> None:
    """Interactive helper that prints rich details for scored candidates.

    Parameters
    ----------
    candidates:
        Ranked candidates to inspect. The sequence is not modified.
    limit:
        Number of instructions from each candidate to render when selected.
    """

    if not candidates:
        print("No candidates available for inspection.")
        return

    print("\nInteractive inspection mode. Enter an index to expand details or 'q' to exit.")
    while True:
        print("\nAvailable candidates:")
        for index, candidate in enumerate(candidates, start=1):
            split = "/".join(map(str, candidate.split)) if candidate.split else "?"
            print(f"  [{index}] {candidate.name} (score={candidate.score:.2f}, split={split})")

        try:
            choice = input("Select candidate (q to quit): ").strip()
        except EOFError:
            print("\nInput closed; exiting inspect mode.")
            break

        if not choice:
            continue
        if choice.lower() in {"q", "quit", "exit"}:
            break
        try:
            index = int(choice)
        except ValueError:
            print("Invalid selection. Please enter a numeric index or 'q'.")
            continue
        if not 1 <= index <= len(candidates):
            print(f"Selection {index} is out of range.")
            continue

        candidate = candidates[index - 1]
        print("\n=== Candidate Detail ===")
        print(f"Name: {candidate.name}")
        print(f"Score: {candidate.score:.2f}")
        if candidate.split:
            print(f"Split: {'/'.join(map(str, candidate.split))}")
        print("Configuration:")
        config_snapshot = _config_snapshot(candidate.config)
        print(json.dumps(config_snapshot, indent=2))
        if candidate.stats:
            print("Statistics:")
            print(json.dumps(candidate.stats, indent=2))
        if candidate.instructions:
            word_width = candidate.config.word_size // 8
            print(f"First {min(limit, len(candidate.instructions))} instructions:")
            for inst in candidate.instructions[:limit]:
                offset = inst.index * word_width
                print(
                    "  offset=0x%04x -> opcode=%s a=%s b=%s c=%s"
                    % (offset, inst.opcode, inst.a, inst.b, inst.c)
                )
        else:
            print("No decoded instructions available.")


def _write_outputs(
    output_dir: Path,
    results: Sequence[DisassemblyCandidate],
    *,
    limit: int,
    summary_name: str = "summary.json",
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for index, candidate in enumerate(results, start=1):
        filename = f"{index:02d}_{candidate.name}.json"
        path = output_dir / filename
        payload = _candidate_to_dict(candidate, limit=limit)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        summary.append({"name": candidate.name, "score": candidate.score, "file": filename})
    (output_dir / summary_name).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Experiment with VM disassembly mask splits")
    parser.add_argument("binary", type=Path, help="Binary payload to disassemble")
    parser.add_argument(
        "--candidates",
        type=Path,
        default=None,
        help="Pipeline candidate JSON containing disassembler hints",
    )
    parser.add_argument(
        "--split",
        dest="splits",
        action="append",
        default=list(DEFAULT_SPLITS),
        help="Split specification (e.g. 8/8/8/8). May be repeated",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=3,
        help="Number of highest scoring disassemblies to write",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=256,
        help="Maximum instructions to dump per result",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out") / "disasm_candidates",
        help="Directory for JSON disassembly dumps",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Enter interactive inspection mode after generating candidates",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not args.binary.exists():
        LOGGER.error("Binary payload %s does not exist", args.binary)
        return 1

    blob = args.binary.read_bytes()
    candidate_config = _load_candidate_config(args.candidates)
    if candidate_config:
        LOGGER.info(
            "Loaded candidate disassembler config with split %s",
            "/".join(map(str, _derive_split_from_config(candidate_config))),
        )

    results = run_driver(
        blob,
        candidate_config=candidate_config,
        splits=args.splits,
        top=args.top,
    )

    if not results:
        LOGGER.error("No viable disassembly results produced")
        return 1

    for candidate in results:
        LOGGER.info("%s -> score %.2f", candidate.name, candidate.score)

    _write_outputs(args.output_dir, results, limit=args.limit)
    LOGGER.info("Wrote disassembly candidates to %s", args.output_dir)

    if args.inspect:
        inspect_candidates(results, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

