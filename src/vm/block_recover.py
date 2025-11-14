"""Dispatcher basic block recovery helpers.

This module reconstructs a lightweight control-flow graph for the virtual
machine dispatcher found in Luraph payloads.  The dispatcher is typically a
large ``if/elseif`` ladder that chooses a handler function based on the opcode
value.  By analysing the textual structure that :mod:`src.tools.parser_tracer`
identifies we can rebuild the branching structure without executing the
payload.

The recovery is intentionally conservative – it only follows obvious control
transfers such as fall-through branches and ``goto`` statements.  The resulting
graph is designed for human consumption and for downstream tooling that needs
to understand how handlers are reached during static analysis.

For Luraph v14.4.x payloads the dispatcher often embeds opaque predicates and
dedicated trap handlers to frustrate analysis.  The heuristics in this module
aim to flag those cases so that downstream tooling can isolate the traps and
avoid folding the opaque branches back into the normal control flow graph.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
import re
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from src.tools.parser_tracer import HandlerMatch, match_handler_patterns

__all__ = [
    "DispatcherBlock",
    "DispatcherCFG",
    "recover_dispatcher_cfg",
    "write_dispatcher_cfg",
]

LOGGER = logging.getLogger(__name__)

_LABEL_PATTERN = re.compile(r"::([A-Za-z_][\w]*)::")
_GOTO_PATTERN = re.compile(r"\bgoto\s+([A-Za-z_][\w]*)", re.IGNORECASE)
_RETURN_PATTERN = re.compile(r"\b(return|break)\b", re.IGNORECASE)

_OPAQUE_PREDICATE_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bif\s+\(?\s*([A-Za-z_][\w]*)\s*[~=]=\s*\1\b", re.IGNORECASE),
        "self-comparison predicate",
    ),
    (
        re.compile(
            r"\bif\s+\(?\s*\(\s*([A-Za-z_][\w]*)\s*[-+*/%^]\s*\1\s*\)\s*[~=]=",
            re.IGNORECASE,
        ),
        "self-arithmetic predicate",
    ),
    (
        re.compile(r"bit32\.(?:band|bxor)\s*\(\s*([A-Za-z_][\w]*)\s*,\s*\1\s*\)", re.IGNORECASE),
        "bit32 self-operation predicate",
    ),
)

_TRAP_KEYWORDS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\berror\s*\(", re.IGNORECASE), "error-call"),
    (re.compile(r"assert\s*\(\s*false", re.IGNORECASE), "assert-false"),
    (re.compile(r"\bos\.exit\s*\(", re.IGNORECASE), "os.exit"),
    (re.compile(r"\bdebug\.traceback\s*\(", re.IGNORECASE), "debug.traceback"),
    (
        re.compile(r"while\s+true\s+do[\s\S]*?break", re.IGNORECASE),
        "infinite-loop-trap",
    ),
    (
        re.compile(r"goto\s+(?:trap|fail|panic)", re.IGNORECASE),
        "explicit-trap-goto",
    ),
)


@dataclass
class DispatcherBlock:
    """A basic block recovered from dispatcher control-flow."""

    block_id: str
    kind: str
    start: int
    end: int
    opcode: Optional[int] = None
    handler: Optional[str] = None
    successors: Tuple[str, ...] = ()
    hints: Tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "id": self.block_id,
            "kind": self.kind,
            "start": self.start,
            "end": self.end,
            "opcode": self.opcode,
            "handler": self.handler,
            "successors": list(self.successors),
            "hints": list(self.hints),
            "metadata": dict(self.metadata),
        }


@dataclass
class DispatcherCFG:
    """Control-flow graph reconstructed from dispatcher branches."""

    entry: str
    blocks: Tuple[DispatcherBlock, ...]

    def as_dict(self) -> Dict[str, object]:
        return {"entry": self.entry, "blocks": [block.as_dict() for block in self.blocks]}


def _dedupe(sequence: Iterable[str]) -> Tuple[str, ...]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in sequence:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return tuple(ordered)


def _label_block_id(name: str) -> str:
    return f"label:{name}"


def _extract_labels(text: str) -> List[Tuple[str, int]]:
    return [(match.group(1), match.start()) for match in _LABEL_PATTERN.finditer(text)]


def _collect_gotos(snippet: str) -> List[str]:
    return [match.group(1) for match in _GOTO_PATTERN.finditer(snippet)]


def _terminates(snippet: str) -> bool:
    return bool(_RETURN_PATTERN.search(snippet))


def _detect_opaque_predicate(snippet: str) -> Optional[str]:
    """Return a description if *snippet* looks like an opaque predicate."""

    for pattern, reason in _OPAQUE_PREDICATE_PATTERNS:
        if pattern.search(snippet):
            return reason
    return None


def _detect_trap(snippet: str) -> Optional[str]:
    """Return a description if *snippet* appears to trap execution."""

    for pattern, reason in _TRAP_KEYWORDS:
        if pattern.search(snippet):
            return reason
    return None


def recover_dispatcher_cfg(text: str, handlers: Sequence[HandlerMatch]) -> DispatcherCFG:
    """Recover a dispatcher CFG from *text* using parsed handler matches.

    The recovery annotates blocks with hints when heuristics match Luraph
    v14.4.x opaque predicates or trap-style handler bodies so downstream tools
    can isolate those flows.
    """

    if not handlers:
        return DispatcherCFG(entry="entry", blocks=(DispatcherBlock("entry", "entry", 0, 0),))

    ordered_handlers = sorted(handlers, key=lambda item: (item.start, item.end, item.opcode))
    label_positions = _extract_labels(text)

    block_data: Dict[str, Dict[str, object]] = {}

    branch_ids: List[str] = []
    handler_ids: List[str] = []

    for index, handler in enumerate(ordered_handlers):
        branch_id = f"branch_{index:02d}"
        handler_id = f"handler_{index:02d}"
        snippet = text[handler.start : handler.end]
        goto_targets = _collect_gotos(snippet)
        terminates = _terminates(snippet)
        hints: List[str] = [f"opcode=={handler.opcode}"]
        hints.append(f"handler:{handler.handler}")
        for mnemonic in handler.mnemonics:
            hints.append(f"mnemonic:{mnemonic}")

        branch_metadata: Dict[str, object] = {
            "goto_targets": goto_targets,
            "terminates": terminates,
        }
        opaque_reason = _detect_opaque_predicate(snippet)
        if opaque_reason:
            branch_metadata["opaque_predicate"] = opaque_reason
            branch_metadata["heuristic_version"] = "v14.4.2"
            hints.extend(["opaque-predicate", "v14.4.2-pattern"])

        branch_payload: Dict[str, object] = {
            "block_id": branch_id,
            "kind": "branch",
            "start": handler.start,
            "end": handler.end,
            "opcode": handler.opcode,
            "handler": handler.handler,
            "successors": [],
            "metadata": branch_metadata,
            "hints": hints,
        }

        handler_body = handler.body if handler.body is not None else snippet
        trap_reason = _detect_trap(handler_body)
        handler_metadata: Dict[str, object] = {
            "mnemonics": list(handler.mnemonics),
            "terminates": terminates,
        }
        handler_hints: List[str] = [f"handler:{handler.handler}"]
        handler_kind = "handler"
        if trap_reason:
            handler_kind = "trap"
            handler_metadata.update(
                {
                    "trap_reason": trap_reason,
                    "heuristic_version": "v14.4.2",
                    "isolated": True,
                }
            )
            handler_hints.extend(["trap", "v14.4.2-trap"])
            branch_metadata["trap_reason"] = trap_reason
            branch_metadata["trap_successor"] = handler_id

        handler_payload: Dict[str, object] = {
            "block_id": handler_id,
            "kind": handler_kind,
            "start": handler.start,
            "end": handler.end,
            "opcode": handler.opcode,
            "handler": handler.handler,
            "successors": [],
            "metadata": handler_metadata,
            "hints": handler_hints,
        }

        block_data[branch_id] = branch_payload
        block_data[handler_id] = handler_payload
        branch_ids.append(branch_id)
        handler_ids.append(handler_id)

    for label, position in label_positions:
        block_id = _label_block_id(label)
        block_data[block_id] = {
            "block_id": block_id,
            "kind": "label",
            "start": position,
            "end": position,
            "opcode": None,
            "handler": None,
            "successors": [],
            "metadata": {"label": label},
            "hints": ["label"],
        }

    def ensure_label_block(name: str) -> str:
        block_id = _label_block_id(name)
        if block_id not in block_data:
            block_data[block_id] = {
                "block_id": block_id,
                "kind": "label",
                "start": -1,
                "end": -1,
                "opcode": None,
                "handler": None,
                "successors": [],
                "metadata": {"label": name, "synthetic": True},
                "hints": ["label", "synthetic"],
            }
        return block_id

    first_branch = branch_ids[0] if branch_ids else None

    loop_target: Optional[str] = None
    if label_positions:
        loop_target = _label_block_id(label_positions[0][0])
    elif first_branch:
        loop_target = first_branch

    block_data["entry"] = {
        "block_id": "entry",
        "kind": "entry",
        "start": 0,
        "end": 0,
        "opcode": None,
        "handler": None,
        "successors": [],
        "metadata": {"description": "dispatcher entry"},
        "hints": ["entry"],
    }

    entry_successors: List[str] = []
    if loop_target:
        entry_successors.append(loop_target)
    elif first_branch:
        entry_successors.append(first_branch)
    block_data["entry"]["successors"] = entry_successors

    for branch_id, handler_id in zip(branch_ids, handler_ids):
        branch_payload = block_data[branch_id]
        handler_payload = block_data[handler_id]
        metadata = branch_payload.get("metadata", {})
        goto_targets = metadata.get("goto_targets", []) if isinstance(metadata, Mapping) else []
        terminates = bool(metadata.get("terminates")) if isinstance(metadata, Mapping) else False

        successors: List[str] = []
        successors.append(handler_id)
        next_branch_index = branch_ids.index(branch_id) + 1
        if next_branch_index < len(branch_ids):
            successors.append(branch_ids[next_branch_index])
        elif loop_target and not terminates:
            successors.append(loop_target)

        for target in goto_targets:
            target_id = ensure_label_block(target)
            if target_id not in successors:
                successors.append(target_id)

        branch_payload["successors"] = successors

        handler_metadata = handler_payload.get("metadata", {})
        handler_is_trap = bool(handler_metadata.get("isolated")) if isinstance(handler_metadata, Mapping) else False

        handler_successors: List[str] = []
        for target in goto_targets:
            handler_successors.append(ensure_label_block(target))
        if not handler_successors and loop_target and not terminates and not handler_is_trap:
            handler_successors.append(loop_target)
        handler_payload["successors"] = handler_successors

    if label_positions:
        for label, position in label_positions:
            block_id = _label_block_id(label)
            payload = block_data.get(block_id)
            if not isinstance(payload, dict):
                continue
            successors = payload.setdefault("successors", [])
            next_branch = None
            for branch_id, handler in zip(branch_ids, ordered_handlers):
                if handler.start >= position:
                    next_branch = branch_id
                    break
            if next_branch is None:
                next_branch = first_branch
            if next_branch and next_branch not in successors:
                successors.append(next_branch)

    blocks: List[DispatcherBlock] = []
    for payload in sorted(block_data.values(), key=lambda item: (item.get("start", -1), item["block_id"])):
        blocks.append(
            DispatcherBlock(
                block_id=str(payload.get("block_id")),
                kind=str(payload.get("kind", "unknown")),
                start=int(payload.get("start", 0)),
                end=int(payload.get("end", 0)),
                opcode=payload.get("opcode"),
                handler=payload.get("handler"),
                successors=_dedupe(payload.get("successors", [])),
                hints=_dedupe(payload.get("hints", [])),
                metadata=dict(payload.get("metadata", {})),
            )
        )

    return DispatcherCFG(entry="entry", blocks=tuple(blocks))


def write_dispatcher_cfg(cfg: DispatcherCFG, output_dir: Path, candidate: str) -> Path:
    """Write *cfg* to ``output_dir/candidate.json`` and return the written path."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{candidate}.json"
    output_path.write_text(json.dumps(cfg.as_dict(), indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("dispatcher CFG written to %s", output_path)
    return output_path


def _load_source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        raise SystemExit(f"dispatcher source not found: {path}") from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for dispatcher CFG recovery."""

    parser = argparse.ArgumentParser(description="Recover dispatcher CFGs from bootstrap text")
    parser.add_argument("source", type=Path, help="Lua bootstrap snippet containing the dispatcher")
    parser.add_argument(
        "--candidate",
        default="dispatcher",
        help="Candidate name used for the CFG JSON filename (default: dispatcher)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/cfg"),
        help="Directory that receives the CFG JSON artefact (default: out/cfg)",
    )
    parser.add_argument(
        "--opcode-name",
        default=None,
        help="Explicit opcode variable name if the dispatcher uses multiple identifiers",
    )
    args = parser.parse_args(argv)

    source_path: Path = args.source
    text = _load_source(source_path)
    handlers = match_handler_patterns(text, opcode_name=args.opcode_name)
    if not handlers:
        LOGGER.warning("no dispatcher handlers detected in %s", source_path)

    cfg = recover_dispatcher_cfg(text, handlers)
    output_path = write_dispatcher_cfg(cfg, args.output_dir, args.candidate)
    LOGGER.info("%d blocks recovered for %s", len(cfg.blocks), args.candidate)
    print(output_path)  # pragma: no cover - convenience for shell usage
    return 0


if __name__ == "__main__":  # pragma: no cover - module CLI
    raise SystemExit(main())

