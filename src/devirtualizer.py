"""Lightweight devirtualization orchestrator.

This module wires together the VM, IR, and AST layers.  It currently acts as a
placeholder that records the decoded source into the analysis context.  Future
revisions will lift VM traces into :mod:`ir` and reconstruct high level Lua AST
nodes.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import lua_ast, ir


@dataclass
class Devirtualizer:
    """Trivial devirtualizer used by the initial pipeline."""

    def run(self, ctx: "pipeline.Context") -> None:  # pragma: no cover - thin wrapper
        # In the baseline implementation we simply store the decoded text as a
        # return statement in a Chunk so later passes can pretty-print it.
        if ctx.output:
            ctx.ir = ir.BasicBlock("entry", [])
            ctx.ast = lua_ast.Chunk([lua_ast.Return(lua_ast.String(ctx.output))])


__all__ = ["Devirtualizer"]
