"""Generate Markdown annotations for opcode map candidates.

The annotate-opcodes helper inspects opcode map candidates produced by the
analysis pipeline and renders a reviewer friendly Markdown document.  Each
candidate section lists the proposed mnemonic assignments together with the
confidence score, handler evidence, and a handful of instruction examples.  The
output is wrapped in an auto-managed block so analysts can keep personal notes
outside the generated section without losing them on subsequent runs.

The generator never executes untrusted code and it never persists session keys;
all data is sourced from JSON artefacts already written to ``out/``.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from ..vm.disassembler import Instruction
from ..vm.opcode_proposer import OpcodeMapCandidate, OpcodeProposal, load_disassembly_instructions

LOGGER = logging.getLogger(__name__)

__all__ = [
    "OpcodeAnnotationEntry",
    "OpcodeAnnotation",
    "generate_opcode_annotations",
    "render_annotation_block",
    "write_opcode_annotations",
    "load_instruction_samples",
    "main",
]


_BEGIN_MARKER = "<!-- OPCODE-ANNOTATIONS:BEGIN -->"
_END_MARKER = "<!-- OPCODE-ANNOTATIONS:END -->"
_DEFAULT_PREAMBLE = (
    "# Opcode Annotation Notes\n\n"
    "This document summarises the currently available opcode map candidates. "
    "Manual notes outside the marked auto-generated block are preserved across reruns.\n\n"
)


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.debug("Opcode candidate %s missing", path)
        return {}
    except OSError as exc:  # pragma: no cover - defensive
        LOGGER.warning("Failed to read %s: %s", path, exc)
        return {}

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Failed to decode JSON from %s: %s", path, exc)
        return {}

    if not isinstance(payload, Mapping):
        LOGGER.warning("Expected JSON object in %s, received %s", path, type(payload).__name__)
        return {}
    return payload


def _load_candidate(path: Path) -> Optional[OpcodeMapCandidate]:
    payload = _read_json(path)
    mapping_raw = payload.get("mapping", {})
    if not isinstance(mapping_raw, Mapping):
        return None

    mapping: MutableMapping[int, str] = {}
    for opcode, mnemonic in mapping_raw.items():
        try:
            mapping[int(opcode)] = str(mnemonic)
        except Exception:  # pragma: no cover - coercion guard
            continue

    selections_raw = payload.get("selections", {})
    selections: MutableMapping[int, OpcodeProposal] = {}
    if isinstance(selections_raw, Mapping):
        for opcode, entry in selections_raw.items():
            if not isinstance(entry, Mapping):
                continue
            try:
                opnum = int(opcode)
            except Exception:  # pragma: no cover - coercion guard
                continue
            mnemonic = str(entry.get("mnemonic", mapping.get(opnum, ""))).upper()
            try:
                confidence = float(entry.get("confidence", 0.0))
            except Exception:
                confidence = 0.0
            handler_values = entry.get("handlers", [])
            if isinstance(handler_values, Sequence):
                handlers = tuple(str(handler) for handler in handler_values if isinstance(handler, str))
            else:
                handlers = ()
            reasons = entry.get("reasons", [])
            reason_tokens = tuple(str(reason) for reason in reasons if isinstance(reason, str))
            selections[opnum] = OpcodeProposal(
                opcode=opnum,
                mnemonic=mnemonic or mapping.get(opnum, f"OP_{opnum}"),
                confidence=max(0.0, min(1.0, confidence)),
                handlers=handlers,
                reasons=reason_tokens,
            )

    try:
        confidence = float(payload.get("confidence", 0.0))
    except Exception:
        confidence = 0.0

    if not mapping:
        return None
    return OpcodeMapCandidate(mapping=dict(mapping), confidence=confidence, selections=dict(selections))


def _group_instructions(instructions: Sequence[Instruction]) -> Mapping[int, List[Instruction]]:
    grouped: MutableMapping[int, List[Instruction]] = {}
    for inst in instructions:
        grouped.setdefault(inst.opcode, []).append(inst)
    for opcode in grouped:
        grouped[opcode].sort(key=lambda inst: inst.index)
    return grouped


def load_instruction_samples(paths: Sequence[Path]) -> List[Instruction]:
    """Load instruction samples from *paths* using the opcode proposer helpers."""

    if not paths:
        return []
    return load_disassembly_instructions(paths)


@dataclass(frozen=True)
class OpcodeAnnotationEntry:
    opcode: int
    mnemonic: str
    confidence: Optional[float]
    handlers: Tuple[str, ...]
    reasons: Tuple[str, ...]
    occurrences: int
    snippet: str


@dataclass(frozen=True)
class OpcodeAnnotation:
    title: str
    confidence: float
    entries: Tuple[OpcodeAnnotationEntry, ...]


def _format_snippet(
    opcode: int,
    mnemonic: str,
    examples: Sequence[Instruction],
    *,
    max_examples: int,
) -> Tuple[str, int]:
    if not examples:
        return "_No instruction samples available._", 0

    lines: List[str] = ["```"]
    for inst in examples[:max_examples]:
        raw = f"0x{inst.raw:08x}" if isinstance(inst.raw, int) else str(inst.raw)
        lines.append(
            f"{inst.index:04d}: {mnemonic} A={inst.a:>3} B={inst.b:>3} C={inst.c:>3} | raw={raw}"
        )
    lines.append("```")
    remaining = max(0, len(examples) - max_examples)
    if remaining:
        lines.append(f"_{remaining} additional occurrence(s) not shown._")
    return "\n".join(lines), len(examples)


def generate_opcode_annotations(
    candidate_paths: Sequence[Path],
    instructions: Sequence[Instruction],
    *,
    max_examples: int = 3,
) -> List[OpcodeAnnotation]:
    """Return annotations for the supplied opcode map candidates."""

    grouped_instructions = _group_instructions(instructions)
    annotations: List[OpcodeAnnotation] = []
    for index, path in enumerate(sorted(candidate_paths), start=1):
        candidate = _load_candidate(path)
        if candidate is None:
            LOGGER.debug("Skipping opcode candidate %s; no mapping available", path)
            continue
        entries: List[OpcodeAnnotationEntry] = []
        for opcode in sorted(candidate.mapping):
            mnemonic = candidate.mapping[opcode]
            selection = candidate.selections.get(opcode)
            confidence = selection.confidence if selection else None
            handlers = selection.handlers if selection else ()
            reasons = selection.reasons if selection else ()
            snippet, occurrences = _format_snippet(
                opcode,
                mnemonic,
                grouped_instructions.get(opcode, ()),
                max_examples=max_examples,
            )
            entries.append(
                OpcodeAnnotationEntry(
                    opcode=opcode,
                    mnemonic=mnemonic,
                    confidence=confidence,
                    handlers=handlers,
                    reasons=reasons,
                    occurrences=occurrences,
                    snippet=snippet,
                )
            )
        title = f"Candidate {index} — {path.name}"
        annotations.append(
            OpcodeAnnotation(
                title=title,
                confidence=candidate.confidence,
                entries=tuple(entries),
            )
        )
    return annotations


def render_annotation_block(annotations: Sequence[OpcodeAnnotation]) -> str:
    lines: List[str] = [_BEGIN_MARKER, ""]
    if not annotations:
        lines.append("_No opcode map candidates were discovered._")
        lines.append("")
        lines.append(_END_MARKER)
        lines.append("")
        return "\n".join(lines)

    for annotation in annotations:
        lines.append(f"## {annotation.title} (confidence {annotation.confidence:.2f})")
        lines.append("")
        lines.append("| Opcode | Mnemonic | Confidence | Handlers | Reasons | Occurrences |")
        lines.append("|:-----:|:---------|:-----------:|:---------|:--------|:-----------:|")
        for entry in annotation.entries:
            handler_text = ", ".join(entry.handlers) if entry.handlers else "—"
            reason_text = ", ".join(entry.reasons) if entry.reasons else "—"
            if entry.confidence is None:
                conf_text = "—"
            else:
                conf_text = f"{entry.confidence:.2f}"
            lines.append(
                f"| 0x{entry.opcode:02X} | {entry.mnemonic} | {conf_text} | {handler_text} | {reason_text} | {entry.occurrences} |"
            )
        lines.append("")
        for entry in annotation.entries:
            lines.append(f"### Opcode 0x{entry.opcode:02X} — {entry.mnemonic}")
            lines.append(entry.snippet)
            lines.append("")
    lines.append(_END_MARKER)
    lines.append("")
    return "\n".join(lines)


def _update_document(path: Path, block: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        original = path.read_text(encoding="utf-8")
        if _BEGIN_MARKER in original and _END_MARKER in original:
            start = original.index(_BEGIN_MARKER)
            end = original.index(_END_MARKER) + len(_END_MARKER)
            prefix = original[:start]
            suffix = original[end:]
            if prefix and not prefix.endswith("\n"):
                prefix += "\n"
            if suffix and not suffix.startswith("\n"):
                suffix = "\n" + suffix
            content = prefix + block + suffix
        else:
            content = original.rstrip() + "\n\n" + block
    else:
        content = _DEFAULT_PREAMBLE + block
    path.write_text(content, encoding="utf-8")


def write_opcode_annotations(path: Path, annotations: Sequence[OpcodeAnnotation]) -> Path:
    block = render_annotation_block(annotations)
    _update_document(path, block)
    LOGGER.info("Wrote opcode annotation document %s", path)
    return path


def _discover_candidate_paths(directory: Path) -> List[Path]:
    if not directory.exists():
        LOGGER.debug("Opcode map directory %s is missing", directory)
        return []
    return sorted(p for p in directory.glob("*.json") if p.is_file())


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate opcode annotation markdown")
    parser.add_argument(
        "--opcode-maps",
        type=Path,
        default=Path("out/opcode_maps"),
        help="Directory containing opcode map candidate JSON files",
    )
    parser.add_argument(
        "--instructions",
        type=Path,
        action="append",
        default=None,
        help="Instruction JSON path(s) used to derive disassembly snippets",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out/opcode_annotations.md"),
        help="Destination Markdown file",
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=3,
        help="Maximum instruction examples per opcode",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print output without writing")
    args = parser.parse_args(list(argv) if argv is not None else None)

    candidate_paths = _discover_candidate_paths(args.opcode_maps)
    instruction_paths = args.instructions or []
    if not instruction_paths:
        default_lift = args.opcode_maps.parent / "lift_ir.json"
        if default_lift.exists():
            instruction_paths = [default_lift]
    instructions = load_instruction_samples(instruction_paths)

    annotations = generate_opcode_annotations(
        candidate_paths,
        instructions,
        max_examples=max(1, args.max_examples),
    )

    block = render_annotation_block(annotations)
    if args.dry_run:
        print(block.strip())
        return 0

    write_opcode_annotations(args.output, annotations)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
