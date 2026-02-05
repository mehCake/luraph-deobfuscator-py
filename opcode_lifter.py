from __future__ import annotations

"""Convert raw Luraph bytecode descriptions into canonical VM IR.

The real obfuscator encodes instructions differently across versions.  The
``OpcodeLifter`` reads the configuration in ``src/versions/config.json`` to map
version specific opcode tokens to a stable set of names that the rest of the
pipeline understands.  Each lifted instruction is represented by the
``VMInstruction`` dataclass from :mod:`src.ir` and carries metadata describing
how operands should be interpreted (register, constant, immediate value).

Only a subset of opcodes are required for the bundled regression tests, but the
implementation is intentionally data driven so new handlers can be added by
augmenting ``INSTRUCTION_SIGNATURES``.
"""

from dataclasses import dataclass, field, asdict
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence
from copy import deepcopy

from src.ir import VMFunction, VMInstruction
from src.utils_pkg import ast as lua_ast

from pattern_analyzer import (
    CacheSlot,
    PatternAnalyzer,
    PrimitiveTableInfo,
    SerializedChunk,
    SerializedChunkDescriptor,
)
from string_decryptor import (
    StringDecoderDescriptor,
    detect_v14_3_string_decoder,
)


logger = logging.getLogger(__name__)


@dataclass
class InstructionSignature:
    """Describe operand semantics for a canonical opcode."""

    fields: List[str]
    modes: Mapping[str, str]


@dataclass
class LoaderCall:
    """Single helper invocation recorded while modelling the VM loader."""

    helper: str
    expression: str
    arguments: List[str] = field(default_factory=list)
    target: Optional[str] = None
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "helper": self.helper,
            "expression": self.expression,
            "arguments": list(self.arguments),
            "target": self.target,
            "context": self.context,
        }


@dataclass
class LoaderLoop:
    """Summary of a numeric loop involved in prototype rehydration."""

    loop_var: str
    limit_helper: Optional[str]
    operations: List[str] = field(default_factory=list)
    body_calls: List[LoaderCall] = field(default_factory=list)
    nested_loops: List["LoaderLoop"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "loop_var": self.loop_var,
            "limit_helper": self.limit_helper,
            "operations": list(self.operations),
            "body_calls": [call.to_dict() for call in self.body_calls],
            "nested_loops": [loop.to_dict() for loop in self.nested_loops],
        }


@dataclass
class LoaderStep:
    """High-level action recovered from the loader control-flow."""

    kind: str
    helper: Optional[str] = None
    target: Optional[str] = None
    expression: Optional[str] = None
    loop_var: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "helper": self.helper,
            "target": self.target,
            "expression": self.expression,
            "loop_var": self.loop_var,
        }


@dataclass
class PrototypeLoader:
    """High level description of how serialized VM prototypes are decoded."""

    helpers: Dict[str, str]
    loops: List[LoaderLoop]
    extra_calls: List[LoaderCall]
    helper_usage: Dict[str, int]
    operations: List[str] = field(default_factory=list)
    steps: List[LoaderStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "helpers": dict(self.helpers),
            "loops": [loop.to_dict() for loop in self.loops],
            "extra_calls": [call.to_dict() for call in self.extra_calls],
            "helper_usage": dict(self.helper_usage),
            "operations": list(self.operations),
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass
class BootstrapIR:
    """Aggregated bootstrap metadata for standalone v14.3 payloads."""

    cache_slots: List[CacheSlot] = field(default_factory=list)
    c3_primitives: Optional[Dict[str, Any]] = None
    primitive_table_info: Optional[PrimitiveTableInfo] = None
    serialized_chunk: Optional[SerializedChunkDescriptor] = None
    string_decoder: Optional[StringDecoderDescriptor] = None
    annotations: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cache_slots": [slot.to_dict() for slot in self.cache_slots],
            "c3_primitives": deepcopy(self.c3_primitives)
            if self.c3_primitives is not None
            else None,
            "primitive_table_info": self.primitive_table_info.to_dict()
            if self.primitive_table_info is not None
            else None,
            "serialized_chunk": asdict(self.serialized_chunk)
            if self.serialized_chunk is not None
            else None,
            "string_decoder": self.string_decoder.to_dict()
            if self.string_decoder is not None
            else None,
            "annotations": deepcopy(self.annotations),
        }


INSTRUCTION_SIGNATURES: Dict[str, InstructionSignature] = {
    "LOADK": InstructionSignature(["a", "b"], {"a": "register", "b": "const"}),
    "LOADN": InstructionSignature(["a", "b"], {"a": "register", "b": "immediate"}),
    "LOADB": InstructionSignature(["a", "b"], {"a": "register", "b": "immediate"}),
    "LOADBOOL": InstructionSignature(
        ["a", "b", "c"],
        {"a": "register", "b": "immediate", "c": "immediate"},
    ),
    "LOADNIL": InstructionSignature(["a"], {"a": "register"}),
    "MOVE": InstructionSignature(["a", "b"], {"a": "register", "b": "register"}),
    "GETGLOBAL": InstructionSignature(["a", "b"], {"a": "register", "b": "const"}),
    "SETGLOBAL": InstructionSignature(["a", "b"], {"a": "register", "b": "const"}),
    "GETUPVAL": InstructionSignature(["a", "b"], {"a": "register", "b": "upvalue"}),
    "SETUPVAL": InstructionSignature(["a", "b"], {"a": "register", "b": "upvalue"}),
    "NEWTABLE": InstructionSignature(["a"], {"a": "register"}),
    "SETTABLE": InstructionSignature(
        ["a", "b", "c"],
        {"a": "register", "b": "rk", "c": "rk"},
    ),
    "GETTABLE": InstructionSignature(
        ["a", "b", "c"],
        {"a": "register", "b": "register", "c": "rk"},
    ),
    "SELF": InstructionSignature(
        ["a", "b", "c"],
        {"a": "register", "b": "register", "c": "rk"},
    ),
    "ADD": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "SUB": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "MUL": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "DIV": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "MOD": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "POW": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "UNM": InstructionSignature(["a", "b"], {"a": "register", "b": "rk"}),
    "NOT": InstructionSignature(["a", "b"], {"a": "register", "b": "register"}),
    "LEN": InstructionSignature(["a", "b"], {"a": "register", "b": "register"}),
    "CONCAT": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "register", "c": "register"}),
    "BAND": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "BOR": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "BXOR": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "BNOT": InstructionSignature(["a", "b"], {"a": "register", "b": "rk"}),
    "SHL": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "SHR": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "EQ": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "NE": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "LT": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "LE": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "GT": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "GE": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "rk", "c": "rk"}),
    "JMP": InstructionSignature(["offset"], {"offset": "offset"}),
    "JMPIF": InstructionSignature(["a", "offset"], {"a": "register", "offset": "offset"}),
    "JMPIFNOT": InstructionSignature(["a", "offset"], {"a": "register", "offset": "offset"}),
    "TEST": InstructionSignature(["a", "b"], {"a": "register", "b": "immediate"}),
    "TESTSET": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "register", "c": "immediate"}),
    "FORPREP": InstructionSignature(["a", "offset"], {"a": "register", "offset": "offset"}),
    "FORLOOP": InstructionSignature(["a", "offset"], {"a": "register", "offset": "offset"}),
    "TFORLOOP": InstructionSignature(
        ["a", "offset", "c"],
        {"a": "register", "offset": "offset", "c": "immediate"},
    ),
    "CALL": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "immediate", "c": "immediate"}),
    "TAILCALL": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "immediate", "c": "immediate"}),
    "RETURN": InstructionSignature(["a", "b"], {"a": "register", "b": "immediate"}),
    "VARARG": InstructionSignature(["a", "b"], {"a": "register", "b": "immediate"}),
    "CLOSURE": InstructionSignature(["a", "b"], {"a": "register", "b": "proto"}),
    "SETLIST": InstructionSignature(["a", "b", "c"], {"a": "register", "b": "immediate", "c": "immediate"}),
    "CLOSE": InstructionSignature(["a"], {"a": "register"}),
}


_HELPER_ROLES = {
    "o": "prototype_counter",
    "M": "table_reader",
    "r": "instruction_slice",
    "t3": "double_unpacker",
    "a3": "varint_reader",
}

_HELPER_NAMES = tuple(_HELPER_ROLES.keys())

_FOR_HEADER_RE = re.compile(
    r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^,;]+?)\s*,\s*([^,;]+?)(?:\s*,\s*([^d;]+?))?\s*do",
    re.IGNORECASE,
)

_TOKEN_RE = re.compile(r"\b(for|function|if|repeat|while|end|until)\b", re.IGNORECASE)


def find_vm_loader_v14_3(ast: lua_ast.Chunk) -> Optional[PrototypeLoader]:
    """Return a :class:`PrototypeLoader` model for standalone v14.3 payloads."""

    if not isinstance(ast, lua_ast.Chunk):
        return None

    helper_usage: Dict[str, int] = {name: 0 for name in _HELPER_ROLES}
    loops, calls, operations = _analyse_block(ast.body, helper_usage)

    if not loops:
        return None

    required = {"o", "M", "r"}
    if not required <= {name for name, count in helper_usage.items() if count}:
        return None

    helpers = {
        role: name
        for name, role in _HELPER_ROLES.items()
        if helper_usage.get(name)
    }

    filtered_usage = {name: count for name, count in helper_usage.items() if count}

    steps = _derive_loader_steps(loops, calls, operations)

    loader = PrototypeLoader(
        helpers=helpers,
        loops=loops,
        extra_calls=calls,
        helper_usage=filtered_usage,
        operations=operations,
        steps=steps,
    )
    return loader


def _extract_source_from_metadata(ast: lua_ast.Chunk) -> Optional[str]:
    metadata = getattr(ast, "metadata", {})
    if not isinstance(metadata, Mapping):
        return None
    for key in ("source", "raw_source", "text", "original_text"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def build_bootstrap_ir_v14_3(ast: lua_ast.Chunk) -> Optional[BootstrapIR]:
    """Collect bootstrap metadata for standalone v14.3 VM payloads."""

    if not isinstance(ast, lua_ast.Chunk):
        return None

    source = _extract_source_from_metadata(ast)
    if not source:
        return None

    analyzer = PatternAnalyzer()
    serialized_chunk = analyzer.locate_serialized_chunk(source)
    if serialized_chunk is None:
        return None

    analyzer.analyze_cache_slots(source)
    cache_slots = list(analyzer.last_cache_slots)

    c3_primitives = analyzer.identify_c3_primitives(source)
    if c3_primitives is None:
        return None

    primitive_info = analyzer.identify_primitive_table_info(source)
    if primitive_info is None:
        return None

    decoder = detect_v14_3_string_decoder(source)
    if decoder is None:
        return None
    decoder.attach_primitive_table_info(primitive_info)

    loader_summary: Optional[Dict[str, Any]] = None
    loader_ast = _build_loader_ast_from_source(source)
    if loader_ast is not None:
        loader_model = find_vm_loader_v14_3(loader_ast)
        if loader_model is not None:
            loader_summary = _summarise_loader_for_annotations(loader_model)

    state_machine = analyzer.detect_bootstrap_state_machine(source)
    vm_entry_summary: Optional[Dict[str, Any]] = None
    if state_machine is not None:
        vm_entry_summary = {
            "control_variable": state_machine.variable,
            "state_count": len(state_machine.states),
            "states": [state.state_id for state in state_machine.states[:5]],
        }

    bootstrap = BootstrapIR(
        cache_slots=cache_slots,
        c3_primitives=c3_primitives,
        primitive_table_info=primitive_info,
        serialized_chunk=serialized_chunk,
        string_decoder=decoder,
    )

    annotations = getattr(bootstrap, "annotations", None)
    if not isinstance(annotations, dict):
        annotations = {}
        bootstrap.annotations = annotations
    if loader_summary:
        annotations["loader"] = loader_summary
    if vm_entry_summary:
        annotations["vm_entry"] = vm_entry_summary

    return bootstrap


def _analyse_block(
    statements: Sequence[lua_ast.Stmt], helper_usage: Dict[str, int]
) -> tuple[List[LoaderLoop], List[LoaderCall], List[str]]:
    loops: List[LoaderLoop] = []
    calls: List[LoaderCall] = []
    operations: List[str] = []

    for stmt in statements:
        if isinstance(stmt, lua_ast.NumericFor):
            loop = _summarise_loop(stmt, helper_usage)
            if (
                loop.limit_helper
                or loop.body_calls
                or loop.operations
                or loop.nested_loops
            ):
                loops.append(loop)
            continue

        if isinstance(stmt, lua_ast.While):
            loop = _promote_while_loop(stmt, helper_usage)
            if loop is not None:
                loops.append(loop)
                continue

        nested_loops, stmt_calls, stmt_ops = _analyse_stmt(stmt, helper_usage)
        loops.extend(nested_loops)
        calls.extend(stmt_calls)
        operations.extend(stmt_ops)

    return loops, calls, operations


def _summarise_loop(
    loop: lua_ast.NumericFor, helper_usage: Dict[str, int]
) -> LoaderLoop:
    limit_helper = _helper_from_expr(loop.stop)
    if limit_helper and limit_helper in helper_usage:
        helper_usage[limit_helper] += 1

    nested_loops, calls, operations = _analyse_block(loop.body, helper_usage)

    return LoaderLoop(
        loop_var=loop.var,
        limit_helper=limit_helper,
        operations=operations,
        body_calls=calls,
        nested_loops=nested_loops,
    )


def _promote_while_loop(
    loop: lua_ast.While, helper_usage: Dict[str, int]
) -> Optional[LoaderLoop]:
    var_name, limit_expr = _extract_loop_descriptor(loop.test)
    if var_name is None:
        return None

    if not _has_trivial_increment(loop.body, var_name):
        return None

    limit_helper = _helper_from_expr(limit_expr) if limit_expr is not None else None
    if limit_helper and limit_helper in helper_usage:
        helper_usage[limit_helper] += 1

    nested_loops, calls, operations = _analyse_block(loop.body, helper_usage)

    return LoaderLoop(
        loop_var=var_name,
        limit_helper=limit_helper,
        operations=operations,
        body_calls=calls,
        nested_loops=nested_loops,
    )


def _extract_loop_descriptor(
    expr: lua_ast.Expr,
) -> tuple[Optional[str], Optional[lua_ast.Expr]]:
    if isinstance(expr, lua_ast.BinOp) and expr.op in {"<", "<=", ">", ">="}:
        left_name = _name_from_expr(expr.left)
        right_name = _name_from_expr(expr.right)
        if left_name and not right_name:
            return left_name, expr.right
        if right_name and not left_name:
            return right_name, expr.left
    return None, None


def _has_trivial_increment(body: Sequence[lua_ast.Stmt], var_name: str) -> bool:
    for stmt in body:
        if not isinstance(stmt, lua_ast.Assignment):
            continue
        for target, value in zip(stmt.targets, stmt.values):
            if not isinstance(target, lua_ast.Name) or target.ident != var_name:
                continue
            if isinstance(value, lua_ast.BinOp) and value.op in {"+", "-"}:
                if _name_from_expr(value.left) == var_name:
                    if isinstance(value.right, lua_ast.Literal):
                        return True
    return False


def _name_from_expr(expr: lua_ast.Expr) -> Optional[str]:
    if isinstance(expr, lua_ast.Name):
        return expr.ident
    return None


def _analyse_stmt(
    stmt: lua_ast.Stmt, helper_usage: Dict[str, int]
) -> tuple[List[LoaderLoop], List[LoaderCall], List[str]]:
    nested_loops: List[LoaderLoop] = []
    calls: List[LoaderCall] = []
    operations: List[str] = _describe_statement(stmt)

    calls.extend(_collect_direct_calls(stmt, helper_usage))

    if isinstance(stmt, lua_ast.If):
        body_loops, body_calls, body_ops = _analyse_block(stmt.body, helper_usage)
        else_loops, else_calls, else_ops = _analyse_block(stmt.orelse, helper_usage)
        nested_loops.extend(body_loops)
        nested_loops.extend(else_loops)
        calls.extend(body_calls)
        calls.extend(else_calls)
        operations.extend(body_ops)
        operations.extend(else_ops)
    elif isinstance(stmt, lua_ast.While):
        body_loops, body_calls, body_ops = _analyse_block(stmt.body, helper_usage)
        nested_loops.extend(body_loops)
        calls.extend(body_calls)
        operations.extend(body_ops)
    elif isinstance(stmt, lua_ast.DoBlock):
        block_loops, block_calls, block_ops = _analyse_block(stmt.body, helper_usage)
        nested_loops.extend(block_loops)
        calls.extend(block_calls)
        operations.extend(block_ops)
    elif isinstance(stmt, lua_ast.FunctionDef):
        body_loops, body_calls, body_ops = _analyse_block(stmt.body, helper_usage)
        nested_loops.extend(body_loops)
        calls.extend(body_calls)
        operations.extend(body_ops)

    return nested_loops, calls, operations


def _collect_direct_calls(stmt: lua_ast.Stmt, helper_usage: Dict[str, int]) -> List[LoaderCall]:
    calls: List[LoaderCall] = []

    if isinstance(stmt, lua_ast.Assignment):
        prefix = "local " if stmt.is_local else ""
        for target, value in zip(stmt.targets, stmt.values):
            helper = _helper_from_expr(value)
            if helper is None:
                continue
            if helper in helper_usage:
                helper_usage[helper] += 1
            target_str = lua_ast.render_expr(target)
            expression = f"{prefix}{target_str} = {lua_ast.render_expr(value)}"
            calls.append(
                LoaderCall(
                    helper=helper,
                    expression=expression,
                    arguments=_call_arguments(value),
                    target=target_str,
                    context="assignment",
                )
            )
    elif isinstance(stmt, lua_ast.CallStmt):
        helper = _helper_from_expr(stmt.call)
        if helper is not None:
            if helper in helper_usage:
                helper_usage[helper] += 1
            calls.append(
                LoaderCall(
                    helper=helper,
                    expression=lua_ast.render_expr(stmt.call),
                    arguments=[lua_ast.render_expr(arg) for arg in stmt.call.args],
                    context="call",
                )
            )
    elif isinstance(stmt, lua_ast.Return):
        for expr in stmt.values:
            helper = _helper_from_expr(expr)
            if helper is None:
                continue
            if helper in helper_usage:
                helper_usage[helper] += 1
            rendered = lua_ast.render_expr(expr)
            calls.append(
                LoaderCall(
                    helper=helper,
                    expression=rendered,
                    arguments=_call_arguments(expr),
                    context="return",
                )
            )

    return calls


def _describe_statement(stmt: lua_ast.Stmt) -> List[str]:
    if isinstance(stmt, lua_ast.Assignment):
        prefix = "local " if stmt.is_local else ""
        return [
            f"{prefix}{lua_ast.render_expr(target)} = {lua_ast.render_expr(value)}"
            for target, value in zip(stmt.targets, stmt.values)
        ]
    if isinstance(stmt, lua_ast.CallStmt):
        return [lua_ast.render_expr(stmt.call)]
    if isinstance(stmt, lua_ast.Return):
        if not stmt.values:
            return ["return"]
        rendered = ", ".join(lua_ast.render_expr(expr) for expr in stmt.values)
        return [f"return {rendered}"]
    return []


def _helper_from_expr(expr: lua_ast.Expr) -> Optional[str]:
    if isinstance(expr, lua_ast.Call):
        func = expr.func
        if isinstance(func, lua_ast.Name):
            ident = func.ident
            if ident in _HELPER_ROLES:
                return ident
    return None


def _call_arguments(expr: lua_ast.Expr) -> List[str]:
    if isinstance(expr, lua_ast.Call):
        return [lua_ast.render_expr(arg) for arg in expr.args]
    return []


def _derive_loader_steps(
    loops: Sequence[LoaderLoop],
    extra_calls: Sequence[LoaderCall],
    operations: Sequence[str],
) -> List[LoaderStep]:
    steps: List[LoaderStep] = []
    for loop in loops:
        steps.extend(_steps_from_loop(loop))
    steps.extend(_steps_from_calls(extra_calls))
    if not steps and operations:
        # Best-effort extraction for straight-line loaders where helpers are
        # invoked outside of recognised loops.
        # We scan for helper names in the textual descriptions to map back to
        # high level actions.
        for entry in operations:
            lowered = entry.lower()
            if "m()" in lowered or "m(" in lowered:
                steps.append(
                    LoaderStep(
                        kind="read_constant_array",
                        helper="M",
                        expression=entry,
                    )
                )
            if "r(" in lowered:
                steps.append(
                    LoaderStep(
                        kind="read_opcode_array",
                        helper="r",
                        expression=entry,
                    )
                )
    return _squash_redundant_steps(steps)


def _steps_from_loop(loop: LoaderLoop) -> List[LoaderStep]:
    steps = _steps_from_calls(loop.body_calls, loop.loop_var)
    for nested in loop.nested_loops:
        steps.extend(_steps_from_loop(nested))
    return steps


def _steps_from_calls(
    calls: Sequence[LoaderCall], loop_var: Optional[str] = None
) -> List[LoaderStep]:
    steps: List[LoaderStep] = []
    for call in calls:
        step = _step_from_call(call, loop_var)
        if step is not None:
            steps.append(step)
    return steps


def _step_from_call(
    call: LoaderCall, loop_var: Optional[str]
) -> Optional[LoaderStep]:
    helper = call.helper
    target = call.target or ""
    target_lower = target.lower()
    kind: Optional[str] = None

    if helper == "r":
        kind = "read_opcode_array"
    elif helper == "M":
        if "proto" in target_lower or "child" in target_lower:
            kind = "read_child_prototype"
        else:
            kind = "read_constant_array"
    elif helper == "a3":
        kind = "read_length_field"
    elif helper == "t3":
        kind = "decode_double_constants"
    elif helper == "o":
        kind = "read_prototype_count"

    if kind is None:
        return None

    return LoaderStep(
        kind=kind,
        helper=helper,
        target=call.target,
        expression=call.expression,
        loop_var=loop_var,
    )


def _squash_redundant_steps(steps: Sequence[LoaderStep]) -> List[LoaderStep]:
    simplified: List[LoaderStep] = []
    last_key: Optional[tuple[str, Optional[str], Optional[str]]] = None
    for step in steps:
        key = (step.kind, step.target, step.loop_var)
        if last_key == key:
            continue
        simplified.append(step)
        last_key = key
    return simplified


def _sanitize_numeric_literal(text: str) -> str:
    return text.replace("_", "")


def _parse_expression(expr: str) -> lua_ast.Expr:
    expr = expr.strip()
    if not expr:
        return lua_ast.Literal(None)
    if expr.endswith(")"):
        for helper in _HELPER_NAMES:
            prefix = f"{helper}("
            if expr.startswith(prefix):
                args = _split_arguments(expr[len(prefix) : -1])
                return lua_ast.Call(
                    lua_ast.Name(helper),
                    [_parse_expression(arg) for arg in args],
                )
    table_match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\[(.+)\]", expr)
    if table_match:
        table = lua_ast.Name(table_match.group(1))
        key_expr = _parse_expression(table_match.group(2))
        return lua_ast.TableAccess(table, key_expr)
    literal = _sanitize_numeric_literal(expr)
    try:
        if literal.lower().startswith(("0x", "0b")):
            return lua_ast.Literal(int(literal, 0))
        return lua_ast.Literal(int(literal, 10))
    except ValueError:
        pass
    return lua_ast.Name(expr.strip())


def _split_arguments(argument_text: str) -> List[str]:
    args: List[str] = []
    token: List[str] = []
    depth = 0
    for ch in argument_text:
        if ch in "({[":
            depth += 1
            token.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            token.append(ch)
        elif ch == "," and depth == 0:
            arg = "".join(token).strip()
            if arg:
                args.append(arg)
            token = []
        else:
            token.append(ch)
    tail = "".join(token).strip()
    if tail:
        args.append(tail)
    return args


def _find_call_end(text: str, start: int) -> int:
    depth = 0
    index = start
    while index < len(text):
        ch = text[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


def _clean_statement(statement: str) -> str:
    stmt = statement.strip()
    if not stmt:
        return stmt
    for keyword in ("then", "else", "elseif"):
        pattern = re.compile(rf"\b{keyword}\b", re.IGNORECASE)
        stmt = pattern.sub(";", stmt)
    stmt = stmt.replace("end", "")
    return stmt.strip()


def _parse_statements(text: str) -> List[lua_ast.Stmt]:
    statements: List[lua_ast.Stmt] = []
    token: List[str] = []
    depth = 0
    for ch in text:
        if ch in "({[":
            depth += 1
            token.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            token.append(ch)
        elif ch == ";" and depth == 0:
            candidate = "".join(token).strip()
            if candidate:
                statements.append(candidate)
            token = []
        else:
            token.append(ch)
    tail = "".join(token).strip()
    if tail:
        statements.append(tail)

    parsed: List[lua_ast.Stmt] = []
    for raw in statements:
        stmt = _clean_statement(raw)
        if not stmt:
            continue
        for helper in _HELPER_NAMES:
            marker = f"{helper}("
            index = stmt.find(marker)
            if index == -1:
                continue
            paren = stmt.find("(", index)
            if paren == -1:
                continue
            end = _find_call_end(stmt, paren)
            call_text = stmt[index:end]
            call_expr = _parse_expression(call_text)
            prefix = stmt[:index].strip()
            if prefix.startswith("return"):
                parsed.append(lua_ast.Return([call_expr]))
                break
            lhs, sep, _ = prefix.rpartition("=")
            if sep:
                target_text = lhs.strip()
                is_local = False
                if target_text.startswith("local "):
                    is_local = True
                    target_text = target_text[len("local ") :].strip()
                target_expr = _parse_expression(target_text)
                parsed.append(
                    lua_ast.Assignment(
                        targets=[target_expr],
                        values=[call_expr],
                        is_local=is_local,
                    )
                )
            else:
                parsed.append(lua_ast.CallStmt(call_expr))
            break
    return parsed


def _extract_block(text: str, start: int) -> tuple[Optional[str], int]:
    depth = 1
    position = start
    while True:
        match = _TOKEN_RE.search(text, position)
        if match is None:
            return None, position
        keyword = match.group(1).lower()
        if keyword in {"for", "function", "if", "repeat", "while"}:
            depth += 1
        elif keyword in {"end", "until"}:
            depth -= 1
            if depth == 0:
                return text[start:match.start()], match.end()
        position = match.end()


def _parse_block(text: str) -> List[lua_ast.Stmt]:
    statements: List[lua_ast.Stmt] = []
    cursor = 0
    while cursor < len(text):
        match = _FOR_HEADER_RE.search(text, cursor)
        if match is None:
            statements.extend(_parse_statements(text[cursor:]))
            break
        if match.start() > cursor:
            statements.extend(_parse_statements(text[cursor:match.start()]))
        body, end_index = _extract_block(text, match.end())
        if body is None:
            cursor = match.end()
            continue
        start_expr = _parse_expression(match.group(2))
        stop_expr = _parse_expression(match.group(3))
        step_expr = _parse_expression(match.group(4) or "1")
        loop_body = _parse_block(body)
        if loop_body:
            statements.append(
                lua_ast.NumericFor(
                    var=match.group(1),
                    start=start_expr,
                    stop=stop_expr,
                    step=step_expr,
                    body=loop_body,
                )
            )
        cursor = end_index
    return statements


def _build_loader_ast_from_source(source: str) -> Optional[lua_ast.Chunk]:
    if not isinstance(source, str) or not source:
        return None
    region_start = source.find("P=(0X6c)")
    if region_start == -1:
        region_start = 0
    section = source[region_start:]
    statements = _parse_block(section)
    if not statements:
        return None
    return lua_ast.Chunk(body=statements)


def _summarise_loader_for_annotations(loader: PrototypeLoader) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "helpers": dict(loader.helpers),
        "steps": [step.kind for step in loader.steps],
        "prototype_count": 0,
        "has_constant_reader": False,
        "has_instruction_reader": False,
        "has_child_loader": False,
    }
    counter_name = loader.helpers.get("prototype_counter")
    if counter_name:
        summary["prototype_count"] = max(loader.helper_usage.get(counter_name, 0), 0)
    if not summary["prototype_count"]:
        summary["prototype_count"] = len(loader.loops) or len(summary["steps"]) or 0
    summary["has_constant_reader"] = any(
        step.kind == "read_constant_array" for step in loader.steps
    )
    summary["has_instruction_reader"] = any(
        step.kind == "read_opcode_array" for step in loader.steps
    )
    summary["has_child_loader"] = any(
        step.kind == "read_child_prototype" for step in loader.steps
    )
    if summary["prototype_count"] == 0 and summary["has_child_loader"]:
        summary["prototype_count"] = 1
    return summary


class OpcodeLifter:
    """Translate version specific bytecode into canonical VM instructions."""

    def __init__(self, config_path: Optional[Path] = None) -> None:
        if config_path is None:
            config_path = Path(__file__).resolve().parent / "src" / "versions" / "config.json"
        with config_path.open("r", encoding="utf8") as fh:
            config = json.load(fh)
        versions = config.get("versions", {})
        self._opcode_tables: Dict[str, Dict[str, str]] = {}
        for name, data in versions.items():
            mapping = data.get("opcode_map", {})
            reverse: Dict[str, str] = {}
            for canonical, token in mapping.items():
                reverse[canonical.upper()] = canonical.upper()
                token_upper = str(token).upper()
                reverse[token_upper] = canonical.upper()
                try:
                    numeric = int(token, 0)
                except Exception:
                    continue
                reverse[f"0X{numeric:X}"] = canonical.upper()
                reverse[str(numeric)] = canonical.upper()
            self._opcode_tables[name] = reverse
        self._default_tokens: Dict[str, str] = {
            mnemonic.upper(): mnemonic.upper() for mnemonic in INSTRUCTION_SIGNATURES
        }

    # ------------------------------------------------------------------
    def lift_program(
        self,
        payload: Mapping[str, Any],
        version: Optional[str] = None,
        *,
        opcode_map: Optional[Mapping[int, Any]] = None,
    ) -> VMFunction:
        """Return a :class:`VMFunction` built from ``payload``."""

        constants = list(payload.get("constants", []))
        raw_instructions: Iterable[Any] = payload.get("bytecode") or payload.get("code") or []
        prototypes = payload.get("prototypes") or []

        override_map = opcode_map if opcode_map is not None else payload.get("opcode_map")
        token_map, map_meta = self._build_token_map(version, override_map)

        lifted_instructions: List[VMInstruction] = []
        register_max = -1
        upvalue_max = -1
        ir_trace: List[Dict[str, Any]] = []

        for pc, raw in enumerate(raw_instructions):
            instr, operand_data = self._lift_instruction(raw, constants, token_map)
            instr.pc = pc
            if isinstance(operand_data.get("offset"), int):
                instr.offset = int(operand_data["offset"])
            ir_entry = {
                "pc": pc,
                "op": instr.opcode,
                "args": self._format_ir_args(instr.opcode, operand_data),
            }
            if isinstance(instr.offset, int):
                ir_entry["offset"] = instr.offset
            instr.ir = ir_entry
            ir_trace.append(ir_entry)
            lifted_instructions.append(instr)
            for reg in self._register_operands(instr):
                if reg is not None:
                    register_max = max(register_max, reg)
            uv = instr.aux.get("upvalue_index")
            if isinstance(uv, int):
                upvalue_max = max(upvalue_max, uv)

        lifted_prototypes: List[VMFunction] = []
        for proto in prototypes:
            if isinstance(proto, Mapping):
                lifted_prototypes.append(
                    self.lift_program(proto, version, opcode_map=override_map)
                )

        metadata = dict(payload.get("metadata", {}))
        metadata.setdefault("opcode_table", map_meta)
        metadata["ir_trace"] = ir_trace

        return VMFunction(
            constants=constants,
            instructions=lifted_instructions,
            prototypes=lifted_prototypes,
            num_params=int(payload.get("num_params", 0) or 0),
            is_vararg=bool(payload.get("is_vararg")),
            register_count=max(register_max + 1, int(payload.get("max_register", 0) or 0)),
            upvalue_count=max(upvalue_max + 1, int(payload.get("upvalue_count", 0) or 0)),
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    def _lift_instruction(
        self,
        raw: Any,
        constants: List[Any],
        token_map: Mapping[str, str],
    ) -> tuple[VMInstruction, MutableMapping[str, Any]]:
        opcode_token, operands = self._extract_opcode(raw)
        opcode = self._normalise_opcode(opcode_token, token_map)
        data = self._normalise_operands(opcode, operands)
        signature = INSTRUCTION_SIGNATURES.get(opcode)

        aux: Dict[str, Any] = {}
        constant_refs: List[int] = []
        if signature:
            for field in signature.fields:
                mode = signature.modes.get(field)
                if mode and field in data:
                    aux[f"{field}_mode"] = mode
                    if mode == "const":
                        index = data[field]
                        aux[f"{field}_index"] = index
                        if isinstance(index, int):
                            constant_refs.append(index)
                        if isinstance(index, int) and 0 <= index < len(constants):
                            aux[f"const_{field}"] = constants[index]
                    elif mode == "immediate":
                        aux[f"immediate_{field}"] = data[field]
                    elif mode == "offset":
                        aux["offset"] = data[field]
                    elif mode == "proto":
                        aux["proto_index"] = data[field]
                    elif mode == "upvalue":
                        aux["upvalue_index"] = data[field]
            if opcode == "CLOSURE":
                upvalues = data.get("upvalues") or []
                formatted: List[Dict[str, Any]] = []
                for entry in upvalues:
                    if isinstance(entry, Mapping):
                        formatted.append({"type": entry.get("type", "register"), "index": entry.get("index", 0)})
                    elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                        formatted.append({"type": str(entry[0]), "index": int(entry[1])})
                aux["upvalues"] = formatted
        target = data.get("target")
        if isinstance(target, int):
            aux["target"] = target
        else:
            aux["operands"] = data

        return VMInstruction(
            opcode=opcode,
            a=data.get("a"),
            b=data.get("b"),
            c=data.get("c"),
            aux=aux,
            constant_refs=constant_refs,
        ), data

    def _build_token_map(
        self,
        version: Optional[str],
        override: Optional[Mapping[int, Any]],
    ) -> tuple[Dict[str, str], Dict[str, Any]]:
        table = dict(self._opcode_tables.get(version or "", {}))
        source = "config" if table else "default"
        trusted = bool(table)

        # Ensure canonical mnemonics are always available as fallbacks.
        for mnemonic, canonical in self._default_tokens.items():
            table.setdefault(mnemonic, canonical)

        if isinstance(override, Mapping) and override:
            source = "bootstrapper"
            trusted = True
            for opcode, name in override.items():
                canonical = str(name).upper()
                table[canonical] = canonical
                for token in self._token_variants(opcode):
                    table[token] = canonical
        else:
            trusted = False

        metadata = {
            "source": source,
            "trusted": trusted,
            "entries": len({value for value in table.values() if value in self._default_tokens}),
        }
        return table, metadata

    def _token_variants(self, opcode: Any) -> List[str]:
        variants: List[str] = []
        if isinstance(opcode, int):
            variants.append(str(opcode))
            variants.append(f"0X{opcode:X}")
        else:
            text = str(opcode).strip()
            if not text:
                return variants
            upper = text.upper()
            variants.append(upper)
            try:
                numeric = int(text, 0)
            except Exception:
                return variants
            variants.append(str(numeric))
            variants.append(f"0X{numeric:X}")
        return variants

    def _format_ir_args(
        self, opcode: str, operands: Mapping[str, Any]
    ) -> List[Dict[str, Any]]:
        args: List[Dict[str, Any]] = []
        signature = INSTRUCTION_SIGNATURES.get(opcode)
        consumed: set[str] = set()
        if signature:
            for field in signature.fields:
                if field in operands:
                    args.append({"name": field, "value": operands[field]})
                    consumed.add(field)
        for key, value in operands.items():
            if key in consumed or key == "upvalues":
                continue
            args.append({"name": str(key), "value": value})
        return args

    # ------------------------------------------------------------------
    def _extract_opcode(self, raw: Any) -> tuple[Any, Any]:
        if isinstance(raw, Mapping):
            if "op" in raw:
                return raw["op"], {k: v for k, v in raw.items() if k != "op"}
            if "opcode" in raw:
                return raw["opcode"], {k: v for k, v in raw.items() if k != "opcode"}
        if isinstance(raw, (list, tuple)) and raw:
            return raw[0], list(raw[1:])
        raise ValueError(f"Unsupported instruction format: {raw!r}")

    def _normalise_opcode(self, token: Any, token_map: Mapping[str, str]) -> str:
        if isinstance(token, str):
            candidate = token.upper()
            if candidate in token_map:
                return token_map[candidate]
            try:
                numeric = int(candidate, 0)
            except Exception:
                return candidate
            variant = f"0X{numeric:X}"
            return token_map.get(variant, variant)
        if isinstance(token, int):
            variant = f"0X{token:X}"
            return token_map.get(variant, variant)
        candidate = str(token).upper()
        return token_map.get(candidate, candidate)

    def _normalise_operands(self, opcode: str, operands: Any) -> MutableMapping[str, Any]:
        if isinstance(operands, Mapping):
            data = {str(k).lower(): v for k, v in operands.items()}
        else:
            data = {}
            signature = INSTRUCTION_SIGNATURES.get(opcode)
            fields = signature.fields if signature else []
            for idx, value in enumerate(operands):
                key = fields[idx] if idx < len(fields) else f"arg{idx}"
                data[key] = value
        if "const" in data and "b" not in data:
            data["b"] = data["const"]
        if "value" in data and "b" not in data:
            data["b"] = data["value"]
        if "offset" in data:
            try:
                data["offset"] = int(data["offset"])
            except Exception:
                pass
        return data

    def _register_operands(self, instr: VMInstruction) -> Iterable[Optional[int]]:
        for name, value in ("a", instr.a), ("b", instr.b), ("c", instr.c):
            mode = instr.aux.get(f"{name}_mode", "register")
            if mode == "register" and isinstance(value, int):
                yield value


__all__ = [
    "OpcodeLifter",
    "PrototypeLoader",
    "LoaderLoop",
    "LoaderCall",
    "LoaderStep",
    "find_vm_loader_v14_3",
    "BootstrapIR",
    "build_bootstrap_ir_v14_3",
]
