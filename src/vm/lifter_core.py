"""Instruction lifting helpers that translate VM bytecode into readable Lua."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from src.utils.luraph_vm import canonicalise_opcode_name

RK_MASK = 0xFF
RK_FLAG = 0x100


@dataclass
class LiftOutput:
    """Container returned by :func:`lift_program`."""

    lua_source: str
    ir_entries: List[Dict[str, Any]]


def lift_program(
    instructions: Iterable[Mapping[str, Any]],
    constants: Sequence[Any] | None,
    opcode_map: Optional[Mapping[int, str]] = None,
) -> LiftOutput:
    """Convert *instructions* into a textual IR listing and structured JSON."""

    context = _LiftContext(instructions, constants or [], opcode_map or {})
    return context.build()


class _LiftContext:
    def __init__(
        self,
        instructions: Iterable[Mapping[str, Any]],
        constants: Sequence[Any],
        opcode_map: Mapping[int, str],
    ) -> None:
        self._original: List[Dict[str, Any]] = [dict(row) for row in instructions]
        self._constants = list(constants)
        self._opcode_map = {
            int(key): canonicalise_opcode_name(value)
            for key, value in opcode_map.items()
            if canonicalise_opcode_name(value)
        }
        self._lines: List[str] = []
        self._ir_rows: List[Dict[str, Any]] = []
        self._register_state: Dict[int, str] = {}
        self._stack_depth = 0
        self._frame_depth = 0
        self._labels: Dict[int, str] = {}
        self._block_order: Dict[int, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> LiftOutput:
        self._prepare_instructions()
        self._prepare_labels()
        self._render()
        lua_source = "\n".join(self._lines).rstrip() + "\n"
        return LiftOutput(lua_source=lua_source, ir_entries=self._ir_rows)

    # ------------------------------------------------------------------
    # Preparation helpers
    # ------------------------------------------------------------------

    def _prepare_instructions(self) -> None:
        for entry in self._original:
            opnum = entry.get("opcode")
            if opnum is None:
                opnum = entry.get("opnum")
            mnemonic: Optional[str] = None
            if isinstance(opnum, int):
                mnemonic = self._opcode_map.get(opnum)
            if not mnemonic:
                mnemonic = entry.get("mnemonic") or entry.get("op")
            mnemonic = canonicalise_opcode_name(mnemonic) or (
                f"OP_{int(opnum):02X}" if isinstance(opnum, int) else "OP_UNKNOWN"
            )
            entry["mnemonic"] = mnemonic
            if "opcode" not in entry and isinstance(opnum, int):
                entry["opcode"] = opnum
            if "opnum" not in entry and isinstance(opnum, int):
                entry["opnum"] = opnum
            if "pc" not in entry:
                index = entry.get("index")
                if isinstance(index, int):
                    entry["pc"] = index + 1

    def _prepare_labels(self) -> None:
        block_starts: set[int] = {0}
        for index, entry in enumerate(self._original):
            mnemonic = str(entry.get("mnemonic") or "").upper()
            if mnemonic in {"JMP", "RETURN"} and index + 1 < len(self._original):
                block_starts.add(index + 1)
            if mnemonic in {"EQ", "LT"} and index + 1 < len(self._original):
                block_starts.add(index + 1)
            if mnemonic == "JMP":
                target = self._jump_target(index, entry)
                if target is not None:
                    block_starts.add(target)
            next_entry = self._peek(index + 1)
            if mnemonic in {"EQ", "LT"} and next_entry:
                target = self._jump_target(index + 1, next_entry)
                if target is not None:
                    block_starts.add(target)

        ordered = sorted(i for i in block_starts if 0 <= i < len(self._original))
        self._labels = {idx: f"label_{idx + 1:04d}" for idx in ordered}
        self._block_order = {idx: pos + 1 for pos, idx in enumerate(ordered)}

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self) -> None:
        self._lines.extend(
            [
                "-- lift_ir.lua (auto-generated)",
                "local R = {}",
                "local stack = {}",
                "local frames = {}",
                "",
            ]
        )

        for index, entry in enumerate(self._original):
            if index in self._labels:
                block_id = self._block_order.get(index)
                pc_val = entry.get("pc", (index + 1) * 4)
                self._lines.append(f"-- block {block_id} (pc {pc_val})")
                self._lines.append(f"::{self._labels[index]}::")

            lua_line, comment = self._translate(entry, index)
            record = dict(entry)
            record.setdefault("comment", comment)
            record["lua"] = lua_line
            self._ir_rows.append(record)
            self._lines.append(lua_line)

        self._lines.extend(
            [
                "",
                "return { registers = R, stack = stack, frames = frames }",
            ]
        )

    # ------------------------------------------------------------------
    # Translation helpers
    # ------------------------------------------------------------------

    def _translate(self, entry: Mapping[str, Any], index: int) -> tuple[str, str]:
        mnemonic = str(entry.get("mnemonic") or "").upper()
        translator = {
            "MOVE": self._translate_move,
            "LOADK": self._translate_loadk,
            "CALL": self._translate_call,
            "RETURN": self._translate_return,
            "GETTABLE": self._translate_gettable,
            "SETTABLE": self._translate_settable,
            "CLOSURE": self._translate_closure,
            "ADD": lambda e, i: self._translate_arith(e, i, "+"),
            "SUB": lambda e, i: self._translate_arith(e, i, "-"),
            "MUL": lambda e, i: self._translate_arith(e, i, "*"),
            "DIV": lambda e, i: self._translate_arith(e, i, "/"),
            "EQ": self._translate_eq,
            "LT": self._translate_lt,
            "JMP": self._translate_jmp,
        }.get(mnemonic)

        if translator is None:
            return self._translate_unknown(entry)
        return translator(entry, index)

    def _translate_move(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        dest = self._reg(A)
        src = self._reg(B)
        self._register_state[A] = self._register_state.get(B, src)
        line = f"  {dest} = {src}  -- MOVE"
        return line, f"MOVE {dest} <- {src}"

    def _translate_loadk(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        const_index = self._infer_constant(entry)
        literal = self._format_constant(const_index)
        dest = self._reg(A)
        self._register_state[A] = literal
        if const_index is None:
            comment = f"LOADK {dest} <- {literal}"
        else:
            comment = f"LOADK {dest} <- K[{const_index}]"
        return f"  {dest} = {literal}  -- LOADK", comment

    def _translate_call(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        func = self._reg(A)
        args = self._call_args(A, B)
        call_expr = f"{func}({', '.join(args)})" if args else f"{func}()"
        comment = f"CALL {func}"
        self._frame_depth += 1
        self._stack_depth = max(self._stack_depth, self._frame_depth)
        if C == 0:
            line = f"  {call_expr}  -- CALL (variadic returns)"
            return line, comment + " -> variadic"
        if C == 1:
            return f"  {call_expr}  -- CALL", comment
        targets = [self._reg(A + offset) for offset in range(C - 1)]
        for offset, target in enumerate(targets):
            self._register_state[A + offset] = f"ret{offset}"
        assign = ", ".join(targets)
        line = f"  {assign} = {call_expr}  -- CALL"
        return line, comment + f" -> {assign}"

    def _translate_return(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        self._frame_depth = max(0, self._frame_depth - 1)
        if B == 0:
            return "  return ...  -- RETURN", "RETURN varargs"
        if B == 1:
            return "  return  -- RETURN", "RETURN"
        values = [self._reg(A + offset) for offset in range(B - 1)]
        return f"  return {', '.join(values)}  -- RETURN", f"RETURN {values}"

    def _translate_gettable(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        dest = self._reg(A)
        table = self._reg(B)
        key = self._rk(C)
        expr = f"{table}[{key}]"
        self._register_state[A] = expr
        return f"  {dest} = {expr}  -- GETTABLE", f"GETTABLE {dest} <- {expr}"

    def _translate_settable(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        table = self._reg(A)
        key = self._rk(B)
        value = self._rk(C)
        return (
            f"  {table}[{key}] = {value}  -- SETTABLE",
            f"SETTABLE {table}[{key}] = {value}",
        )

    def _translate_closure(self, entry: Mapping[str, Any], _: int) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        proto = self._as_int(entry.get("Bx"))
        dest = self._reg(A)
        literal = f"closure(proto_{proto if proto is not None else '???'})"
        self._register_state[A] = literal
        return f"  {dest} = {literal}  -- CLOSURE", f"CLOSURE {dest}"

    def _translate_arith(self, entry: Mapping[str, Any], _: int, op: str) -> tuple[str, str]:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        left = self._rk(B)
        right = self._rk(C)
        dest = self._reg(A)
        expr = f"{left} {op} {right}"
        self._register_state[A] = expr
        mnemonic = entry.get("mnemonic", op)
        return f"  {dest} = {expr}  -- {mnemonic}", f"{mnemonic} {dest}"

    def _translate_eq(self, entry: Mapping[str, Any], index: int) -> tuple[str, str]:
        condition = self._comparison_condition(entry, "==")
        target = self._conditional_target(index)
        line = f"  if {condition} then goto {target} end  -- EQ"
        return line, f"EQ -> {target}"

    def _translate_lt(self, entry: Mapping[str, Any], index: int) -> tuple[str, str]:
        condition = self._comparison_condition(entry, "<")
        target = self._conditional_target(index)
        line = f"  if {condition} then goto {target} end  -- LT"
        return line, f"LT -> {target}"

    def _translate_jmp(self, entry: Mapping[str, Any], index: int) -> tuple[str, str]:
        target = self._jump_target(index, entry)
        if target is None:
            return "  -- jump target unresolved", "JMP unresolved"
        label = self._labels.get(target, f"label_{target + 1:04d}")
        return f"  goto {label}  -- JMP", f"JMP -> {label}"

    def _translate_unknown(self, entry: Mapping[str, Any]) -> tuple[str, str]:
        opnum = entry.get("opcode") or entry.get("opnum")
        opcode_text = f"0x{int(opnum):02X}" if isinstance(opnum, int) else "<unknown>"
        return (
            f"  -- unknown opcode {opcode_text} (A={entry.get('A')}, B={entry.get('B')}, C={entry.get('C')})",
            f"UNKNOWN {opcode_text}",
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _peek(self, index: int) -> Optional[Mapping[str, Any]]:
        if 0 <= index < len(self._original):
            return self._original[index]
        return None

    def _label_for(self, index: int) -> str:
        return self._labels.get(index, f"label_{index + 1:04d}")

    def _conditional_target(self, index: int) -> str:
        next_entry = self._peek(index + 1)
        if next_entry and str(next_entry.get("mnemonic") or "").upper() == "JMP":
            target = self._jump_target(index + 1, next_entry)
            if target is not None:
                return self._label_for(target)
        return self._label_for(index + 1)

    def _jump_target(self, index: int, entry: Mapping[str, Any]) -> Optional[int]:
        sbx = entry.get("sBx")
        if not isinstance(sbx, int):
            return None
        target = index + 1 + sbx
        if 0 <= target < len(self._original):
            return target
        return None

    def _comparison_condition(self, entry: Mapping[str, Any], operator: str) -> str:
        lhs = self._rk(self._as_int(entry.get("B")))
        rhs = self._rk(self._as_int(entry.get("C")))
        expect_true = bool(self._as_int(entry.get("A")))
        if expect_true:
            return f"{lhs} {operator} {rhs}"
        return f"not ({lhs} {operator} {rhs})"

    def _call_args(self, base: int, count: Optional[int]) -> List[str]:
        if not isinstance(count, int) or count <= 1:
            return []
        return [self._reg(base + offset) for offset in range(1, count)]

    def _infer_constant(self, entry: Mapping[str, Any]) -> Optional[int]:
        bx = entry.get("Bx")
        if isinstance(bx, int) and bx >= 0:
            return bx
        b = entry.get("B")
        if isinstance(b, int) and b >= 0:
            return b
        raw = entry.get("raw")
        if isinstance(raw, list):
            for value in raw:
                if isinstance(value, int) and value >= 0:
                    return value
        if isinstance(raw, dict):
            for value in raw.values():
                if isinstance(value, int) and value >= 0:
                    return value
        return None

    def _rk(self, value: Optional[int]) -> str:
        if value is None:
            return "nil"
        if value & RK_FLAG:
            return self._format_constant(value & RK_MASK)
        return self._reg(value)

    def _format_constant(self, index: Optional[int]) -> str:
        if index is None:
            return "nil"
        candidates = []
        if isinstance(index, int):
            candidates.append(index)
            if index > 0:
                candidates.append(index - 1)
        for candidate in candidates:
            if 0 <= candidate < len(self._constants):
                return self._lua_literal(self._constants[candidate])
        return f"K[{index}]"

    def _lua_literal(self, value: Any) -> str:
        if isinstance(value, str):
            escaped = (
                value.replace("\\", "\\\\")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace('"', '\\"')
            )
            return f'"{escaped}"'
        if value is True:
            return "true"
        if value is False:
            return "false"
        if value is None:
            return "nil"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, (list, tuple)):
            items = ", ".join(self._lua_literal(v) for v in value)
            return "{" + items + "}"
        if isinstance(value, Mapping):
            parts = []
            for key, val in value.items():
                if isinstance(key, str) and key.isidentifier():
                    parts.append(f"{key} = {self._lua_literal(val)}")
                else:
                    parts.append(f"[{self._lua_literal(key)}] = {self._lua_literal(val)}")
            return "{" + ", ".join(parts) + "}"
        return json.dumps(value)

    @staticmethod
    def _as_int(value: Any) -> Optional[int]:
        return int(value) if isinstance(value, int) else None

    @staticmethod
    def _reg(index: Optional[int]) -> str:
        if index is None:
            return "R[?]"
        return f"R[{index}]"


__all__ = ["lift_program", "LiftOutput"]

