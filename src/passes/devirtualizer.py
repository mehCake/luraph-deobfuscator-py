from __future__ import annotations

"""Lightweight devirtualisation pass turning VM bytecode into pseudo Lua.

The implementation is intentionally simplified but demonstrates the core
concepts required for proper devirtualisation:

* a control flow graph built with :mod:`networkx`
* taint tracking for values originating from the obfuscated program
* symbolic execution via the ``analysis.symbolic`` helpers and SymPy based
  constant folding
* mapping the reduced IR back into readable Lua source code

It is *not* a complete Luraph devirtualiser but provides the foundations upon
which future work can build.
"""

from dataclasses import dataclass
from typing import Any, List

import networkx as nx
import sympy as sp

from src.analysis.symbolic import SymbolicExpression, SymbolicValue, SymbolicAdd
from src.vm.emulator import LuraphVM


@dataclass
class TaintValue:
    expr: Any
    var: str
    tainted: bool


class Devirtualizer:
    """Analyse a :class:`LuraphVM` trace and emit pseudo Lua code."""

    def __init__(self, vm: LuraphVM) -> None:
        self.vm = vm
        self.bytecode = vm.state.bytecode
        self.constants = vm.state.constants
        self.cfg: nx.DiGraph = nx.DiGraph()
        self._var_idx = 0
        self.lines: List[str] = []
    def build_cfg(self) -> None:
        """Build a very small control flow graph for the current bytecode."""
        bc = self.bytecode
        for i, instr in enumerate(bc):
            op = instr[0]
            args = instr[1:]
            self.cfg.add_node(i, op=op, args=args)
            if i + 1 < len(bc):
                self.cfg.add_edge(i, i + 1)
            if op == "JMP":
                offset = args[0]
                self.cfg.add_edge(i, i + 1 + offset)
            elif op in {"JMPIF", "JMPIFNOT"}:
                offset = args[0]
                self.cfg.add_edge(i, i + 1 + offset)
                # fallthrough already added above
    def _new_var(self) -> str:
        name = chr(ord("a") + self._var_idx)
        self._var_idx += 1
        return name
    def _symbolic(self, value: Any) -> SymbolicExpression:
        if isinstance(value, SymbolicExpression):
            return value
        if isinstance(value, (int, float)):
            return SymbolicValue(int(value))
        return SymbolicValue(str(value))
    def devirtualize(self) -> str:
        """Return pseudo Lua source for the VM program."""
        self.build_cfg()
        stack: List[TaintValue] = []
        for instr in self.bytecode:
            op, *args = instr
            if op == "LOADK":
                const = self.constants[args[0]]
                var = self._new_var()
                self.lines.append(f"local {var} = {const!r}")
                stack.append(TaintValue(const, var, True))
            elif op == "LOADN":
                value = args[0]
                var = self._new_var()
                self.lines.append(f"local {var} = {value}")
                stack.append(TaintValue(value, var, True))
            elif op == "GETGLOBAL":
                name = self.constants[args[0]]
                stack.append(TaintValue(name, name, False))
            elif op == "ADD":
                b = stack.pop()
                a = stack.pop()
                expr = SymbolicAdd(self._symbolic(a.expr), self._symbolic(b.expr)).simplify()
                taint = a.tainted or b.tainted
                var = self._new_var()
                if isinstance(expr, SymbolicValue):
                    simplified = sp.simplify(expr.value)
                    py_val = int(simplified) if simplified.is_Integer else float(simplified)
                    self.lines.append(f"local {var} = {py_val}")
                    stack.append(TaintValue(py_val, var, taint))
                else:
                    self.lines.append(f"local {var} = {a.var} + {b.var}")
                    stack.append(TaintValue(expr, var, taint))
            elif op == "CALL":
                argc = args[0]
                call_args = [stack.pop() for _ in range(argc)][::-1]
                func = stack.pop()
                arg_str = ", ".join(v.var for v in call_args)
                self.lines.append(f"{func.var}({arg_str})")
                stack.append(TaintValue(None, "", func.tainted or any(a.tainted for a in call_args)))
            elif op == "RETURN":
                if stack:
                    ret = stack.pop()
                    if ret.var:
                        self.lines.append(f"return {ret.var}")
        return "\n".join(self.lines)


__all__ = ["Devirtualizer"]
