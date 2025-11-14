"""Generate sandboxed Lua test snippets for detected opcode handlers.

This module inspects the handler metadata collected by
``src.tools.collector.collect_pipeline_candidates`` and creates runnable test
snippets that analysts can execute inside the existing sandbox harness
(``src.tools.resolve_with_testcases``).  Each generated snippet captures a
minimal virtual-machine state, executes the handler inside a ``pcall`` and
returns a structured observation describing stack/register mutations.  A JSON
manifest is emitted alongside the snippets so that downstream tooling – or
humans – can easily run and interpret the tests.

The generator is intentionally conservative: if no handler bodies are present
the module simply skips creation.  All artefacts live inside
``out/handler_tests`` (configurable via the CLI) and avoid ever persisting
session keys or other sensitive material.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "HandlerTestCase",
    "HandlerTestSuite",
    "generate_handler_tests",
    "main",
]


class HandlerTestGenerationError(RuntimeError):
    """Raised when handler test generation cannot proceed."""


@dataclass(frozen=True)
class HandlerTestCase:
    """Description of a generated handler test."""

    handler: str
    opcode: Optional[int]
    mnemonics: Tuple[str, ...]
    snippet_path: Path
    entrypoint: str
    instructions: Tuple[str, ...]
    notes: Tuple[str, ...]

    def to_manifest(self) -> Mapping[str, object]:
        return {
            "handler": self.handler,
            "opcode": self.opcode,
            "mnemonics": list(self.mnemonics),
            "snippet": self.snippet_path.name,
            "entrypoint": self.entrypoint,
            "instructions": list(self.instructions),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class HandlerTestSuite:
    """Collection of generated handler tests and manifest locations."""

    cases: Tuple[HandlerTestCase, ...]
    manifest_path: Path
    definitions_path: Path
    instructions: Tuple[str, ...]

    def summary(self) -> Mapping[str, object]:
        return {
            "count": len(self.cases),
            "manifest": str(self.manifest_path),
            "definitions": str(self.definitions_path),
        }


_SANITISE_PATTERN = re.compile(r"[^A-Za-z0-9]+")


_MNEMONIC_NOTES: Mapping[str, str] = {
    "LOADK": "Expect vm.stack[ra+1] to mirror vm.constants[rb+1] after execution.",
    "CALL": "Inspect vm.top and vm.stack mutations to infer call semantics.",
    "RETURN": "Observe returned values and stack cleanup to confirm return behaviour.",
    "JMP": "Check vm.pc for the updated program counter.",
    "EQ": "Compare vm.pc changes to determine conditional branching.",
}

_GLOBAL_INSTRUCTIONS = (
    "Run: python -m src.tools.resolve_with_testcases out/handler_tests/tests.json --assume-yes --output out/handler_tests/results.json",
    "Inspect the JSON observations for 'returns', 'after.stack', 'after.registers', and 'after.pc' to deduce handler semantics.",
)

_KNOWN_STUBS: Mapping[str, str] = {
    "state": "local state = vm",
    "vm": "local vm_ref = vm  -- compatibility alias",
    "stack": "local stack = vm.stack",
    "registers": "local registers = vm.registers",
    "regs": "local regs = vm.registers",
    "constants": "local constants = vm.constants",
    "proto": "local proto = vm.proto",
    "upvalues": "local upvalues = vm.upvalues",
    "env": "local env = vm.env or {}",
    "instruction": "local instruction = { A = 0, B = 1, C = 2 }",
    "ra": "local ra = 0",
    "rb": "local rb = 1",
    "rc": "local rc = 2",
    "rd": "local rd = 3",
    "rk": "local rk = 0",
    "pc": "local pc = vm.pc",
    "base": "local base = vm.base",
    "top": "local top = vm.top",
    "nresults": "local nresults = 0",
}


def _sanitise_name(text: str) -> str:
    name = _SANITISE_PATTERN.sub("_", text.strip().lower()).strip("_")
    return name or "handler"


def _collect_handlers(report: Mapping[str, object]) -> List[Mapping[str, object]]:
    handlers: List[Mapping[str, object]] = []
    chunks = report.get("chunks")
    if isinstance(chunks, Sequence):
        for chunk in chunks:
            if not isinstance(chunk, Mapping):
                continue
            handler_map = chunk.get("handler_map")
            if not isinstance(handler_map, Sequence):
                continue
            for entry in handler_map:
                if isinstance(entry, Mapping) and entry.get("body"):
                    handlers.append(entry)
    return handlers


def _detect_stub_names(body: str) -> Sequence[str]:
    observed: MutableMapping[str, bool] = {key: False for key in _KNOWN_STUBS}
    for match in re.finditer(r"\b([A-Za-z_][\w]*)\b", body):
        name = match.group(1)
        if name in observed:
            observed[name] = True
    return [name for name, present in observed.items() if present]


def _indent_body(body: str, *, indent: str = "    ") -> str:
    stripped = body.strip("\n")
    lines = stripped.splitlines()
    return "\n".join(f"{indent}{line.rstrip()}" for line in lines)


def _mnemonic_notes(mnemonics: Sequence[str]) -> List[str]:
    notes: List[str] = []
    for mnemonic in mnemonics:
        hint = _MNEMONIC_NOTES.get(mnemonic.upper())
        if hint and hint not in notes:
            notes.append(hint)
    if not notes:
        notes.append(
            "Review observation.before/after tables to understand stack, register and pc side-effects."
        )
    return notes


def _render_snippet(
    handler_name: str,
    opcode: Optional[int],
    body: str,
    mnemonics: Sequence[str],
) -> str:
    stub_lines = [
        "local vm = {",
        "    stack = { [0] = 'slot0', [1] = 'slot1', [2] = 'slot2' },",
        "    registers = { [0] = 0, [1] = 0, [2] = 0 },",
        "    constants = { [0] = 0, [1] = 1, [2] = 'alpha', [3] = 'beta' },",
        "    proto = { k = { 0, 1, 'alpha', 'beta' }, code = {} },",
        "    upvalues = {},",
        "    env = {},",
        "    base = 0,",
        "    top = 0,",
        "    pc = 0,",
        "}",
    ]

    required = _detect_stub_names(body)
    for name in required:
        stub_lines.append(_KNOWN_STUBS[name])

    if opcode is not None:
        stub_lines.append(f"local opcode = {opcode}")

    stub_lines.append("local observation = {")
    stub_lines.append(f"    handler = '{handler_name}',")
    stub_lines.append(
        f"    opcode = {opcode if opcode is not None else 'nil'},"
    )
    stub_lines.append(
        f"    mnemonics = {{ {', '.join(repr(m) for m in mnemonics)} }},"
    )
    stub_lines.append("}")

    stub_lines.append(
        "local function shallow_copy(tbl)\n"
        "    if type(tbl) ~= 'table' then return tbl end\n"
        "    local copy = {}\n"
        "    local count = 0\n"
        "    for key, value in pairs(tbl) do\n"
        "        count = count + 1\n"
        "        if count > 64 then break end\n"
        "        if type(value) == 'table' then\n"
        "            copy[key] = shallow_copy(value)\n"
        "        else\n"
        "            copy[key] = value\n"
        "        end\n"
        "    end\n"
        "    return copy\n"
        "end"
    )

    stub_lines.append(
        "local function snapshot_vm()\n"
        "    return {\n"
        "        pc = vm.pc,\n"
        "        base = vm.base,\n"
        "        top = vm.top,\n"
        "        stack = shallow_copy(vm.stack),\n"
        "        registers = shallow_copy(vm.registers),\n"
        "    }\n"
        "end"
    )

    stub_lines.append("local function handler_under_test()")
    stub_lines.append(_indent_body(body))
    stub_lines.append("end")

    stub_lines.append("local function run_handler_test()")
    stub_lines.append("    observation.before = snapshot_vm()")
    stub_lines.append("    local returns = {}")
    stub_lines.append("    local ok, err = pcall(function()")
    stub_lines.append("        returns = { handler_under_test() }")
    stub_lines.append("    end)")
    stub_lines.append("    observation.ok = ok")
    stub_lines.append("    if not ok then")
    stub_lines.append("        observation.error = tostring(err)")
    stub_lines.append("    end")
    stub_lines.append("    observation.after = snapshot_vm()")
    stub_lines.append("    observation.returns = returns")
    stub_lines.append("    return observation")
    stub_lines.append("end")

    stub_lines.append("return run_handler_test()")

    return "\n".join(stub_lines) + "\n"


def _write_snippet(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_manifest(
    path: Path,
    suite: HandlerTestSuite,
    *,
    pipeline_path: Optional[Path],
) -> None:
    payload = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
        "pipeline_source": str(pipeline_path) if pipeline_path else None,
        "global_instructions": list(suite.instructions),
        "tests": [case.to_manifest() for case in suite.cases],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_definitions(path: Path, cases: Sequence[HandlerTestCase]) -> None:
    definitions = {
        "instructions": list(_GLOBAL_INSTRUCTIONS),
        "testcases": [
            {
                "name": f"{case.handler}_opcode_{case.opcode}" if case.opcode is not None else case.handler,
                "lua_path": case.snippet_path.name,
                "entrypoint": case.entrypoint,
                "args": [],
                "metadata": {
                    "handler": case.handler,
                    "opcode": case.opcode,
                    "mnemonics": list(case.mnemonics),
                },
            }
            for case in cases
        ],
    }
    path.write_text(json.dumps(definitions, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_handler_tests(
    report: Mapping[str, object],
    *,
    output_dir: Path,
    pipeline_path: Optional[Path] = None,
    limit: Optional[int] = None,
) -> Optional[HandlerTestSuite]:
    """Generate handler tests from a pipeline report mapping."""

    handlers = _collect_handlers(report)
    if not handlers:
        LOGGER.debug("No handler bodies found in pipeline report; skipping test generation")
        return None

    cases: List[HandlerTestCase] = []
    for index, handler in enumerate(handlers):
        if limit is not None and index >= limit:
            break
        name = str(handler.get("handler") or f"handler_{index}")
        body = str(handler.get("body") or "")
        if not body.strip():
            continue
        opcode_raw = handler.get("opcode")
        opcode = None
        try:
            if opcode_raw is not None:
                opcode = int(opcode_raw)
        except (TypeError, ValueError):
            opcode = None
        mnemonics = tuple(str(value) for value in handler.get("mnemonics") or [])
        snippet_name = f"{index:03d}_{_sanitise_name(name)}.lua"
        snippet_path = output_dir / snippet_name
        snippet = _render_snippet(name, opcode, body, mnemonics)
        _write_snippet(snippet_path, snippet)

        instructions = (
            "Execute via resolve_with_testcases and inspect observation fields.",
        )
        notes = tuple(_mnemonic_notes(mnemonics))
        cases.append(
            HandlerTestCase(
                handler=name,
                opcode=opcode,
                mnemonics=mnemonics,
                snippet_path=snippet_path,
                entrypoint="run_handler_test",
                instructions=instructions,
                notes=notes,
            )
        )

    if not cases:
        LOGGER.debug("Handler bodies present but snippets could not be generated")
        return None

    definitions_path = output_dir / "tests.json"
    manifest_path = output_dir / "tests_manifest.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    suite = HandlerTestSuite(
        cases=tuple(cases),
        manifest_path=manifest_path,
        definitions_path=definitions_path,
        instructions=_GLOBAL_INSTRUCTIONS,
    )
    _write_definitions(definitions_path, cases)
    _write_manifest(manifest_path, suite, pipeline_path=pipeline_path)
    LOGGER.info("Generated %d handler test snippet(s) in %s", len(cases), output_dir)
    return suite


def _load_report(path: Path) -> Mapping[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:  # pragma: no cover - filesystem error
        raise HandlerTestGenerationError(f"Failed to read pipeline report {path}: {exc}") from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - invalid JSON
        raise HandlerTestGenerationError(f"Invalid JSON in pipeline report {path}: {exc}") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate sandboxed Lua tests for VM handlers")
    parser.add_argument("--pipeline", type=Path, required=True, help="Path to pipeline_candidates.json")
    parser.add_argument("--out-dir", type=Path, default=Path("out") / "handler_tests", help="Output directory")
    parser.add_argument("--limit", type=int, help="Optional maximum number of handlers to process")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    report = _load_report(args.pipeline)
    suite = generate_handler_tests(
        report,
        output_dir=args.out_dir,
        pipeline_path=args.pipeline,
        limit=args.limit,
    )
    if suite is None:
        LOGGER.info("No handler tests generated")
        return 0

    LOGGER.info(
        "Handler tests ready: manifest=%s definitions=%s count=%d",
        suite.manifest_path,
        suite.definitions_path,
        len(suite.cases),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

