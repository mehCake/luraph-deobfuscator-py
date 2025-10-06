from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from src.lifter.cfg import CFGBuilder
from src.lifter.emit_structured import IfNode, StructuredEmitter, WhileNode


@dataclass
class FakeTranslation:
    lines: List[str] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)


def build_and_emit(instructions: List[Dict[str, object]], translations: Iterable[FakeTranslation]):
    translations_list = list(translations)
    builder = CFGBuilder(instructions, translations_list)
    cfg = builder.build()
    emitter = StructuredEmitter(cfg, translations_list)
    lines, instruction_lua = emitter.emit()
    return emitter, lines, instruction_lua


def test_emit_if_structure():
    instructions = [
        {"mnemonic": "EQ"},
        {"mnemonic": "JMP"},
        {"mnemonic": "LOADK"},
        {"mnemonic": "RETURN"},
    ]
    translations = [
        FakeTranslation(),
        FakeTranslation(
            metadata={
                "control": {
                    "type": "cond",
                    "condition": "a < b",
                    "true_target": 3,
                    "false_target": 2,
                    "guard_index": 0,
                }
            }
        ),
        FakeTranslation(lines=["result = 1"]),
        FakeTranslation(lines=["return result"]),
    ]
    emitter, lines, _ = build_and_emit(instructions, translations)
    assert any(isinstance(stmt, IfNode) for stmt in emitter.ast)
    assert any(line.strip().startswith("if a < b then") for line in lines)
    assert any("result = 1" in line for line in lines)


def test_emit_while_loop():
    instructions = [
        {"mnemonic": "LT"},
        {"mnemonic": "JMP"},
        {"mnemonic": "LOADK"},
        {"mnemonic": "JMP"},
        {"mnemonic": "RETURN"},
    ]
    translations = [
        FakeTranslation(),
        FakeTranslation(
            metadata={
                "control": {
                    "type": "cond",
                    "condition": "i < limit",
                    "true_target": 2,
                    "false_target": 4,
                    "guard_index": 0,
                }
            }
        ),
        FakeTranslation(lines=["i = i + 1"]),
        FakeTranslation(metadata={"control": {"type": "jump", "target": 0}}),
        FakeTranslation(lines=["return i"]),
    ]
    emitter, lines, _ = build_and_emit(instructions, translations)
    assert any(isinstance(stmt, WhileNode) for stmt in emitter.ast)
    assert any(line.strip().startswith("while i < limit do") for line in lines)
    assert "goto" not in " ".join(lines)


def _collect_whiles(statements, acc):
    for stmt in statements:
        if isinstance(stmt, WhileNode):
            acc.append(stmt)
            _collect_whiles(stmt.body, acc)
        elif isinstance(stmt, IfNode):
            _collect_whiles(stmt.then_branch, acc)
            _collect_whiles(stmt.else_branch, acc)


def test_nested_loops_emit():
    instructions = [
        {"mnemonic": "LT"},
        {"mnemonic": "JMP"},
        {"mnemonic": "LT"},
        {"mnemonic": "JMP"},
        {"mnemonic": "LOADK"},
        {"mnemonic": "JMP"},
        {"mnemonic": "LOADK"},
        {"mnemonic": "JMP"},
        {"mnemonic": "RETURN"},
    ]
    translations = [
        FakeTranslation(),
        FakeTranslation(
            metadata={
                "control": {
                    "type": "cond",
                    "condition": "outer < bound",
                    "true_target": 2,
                    "false_target": 8,
                    "guard_index": 0,
                }
            }
        ),
        FakeTranslation(),
        FakeTranslation(
            metadata={
                "control": {
                    "type": "cond",
                    "condition": "inner < limit",
                    "true_target": 4,
                    "false_target": 6,
                    "guard_index": 2,
                }
            }
        ),
        FakeTranslation(lines=["inner = inner + 1"]),
        FakeTranslation(metadata={"control": {"type": "jump", "target": 2}}),
        FakeTranslation(lines=["outer = outer + 1"]),
        FakeTranslation(metadata={"control": {"type": "jump", "target": 0}}),
        FakeTranslation(lines=["return outer"]),
    ]
    emitter, lines, _ = build_and_emit(instructions, translations)
    loops: List[WhileNode] = []
    _collect_whiles(emitter.ast, loops)
    assert len(loops) >= 2
    assert any(line.strip().startswith("while outer < bound do") for line in lines)
    assert any(line.strip().startswith("while inner < limit do") for line in lines)
