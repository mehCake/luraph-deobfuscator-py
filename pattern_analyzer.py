"""Pattern and control‑flow analysis helpers.

This module originally focused on opcode frequency analysis.  It now grows a
light‑weight control–flow graph (CFG) builder used during devirtualisation to
recover high level structures from the intermediate representation (IR)."""

from __future__ import annotations

import csv
import html
import json
import logging
import os
import re
import tempfile
from bisect import bisect_right
from dataclasses import dataclass, replace, field
from functools import lru_cache
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from copy import deepcopy

from collections import Counter, defaultdict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from snapshot_manager import SnapshotManager

from lua_vm_simulator import LuaVMSimulator
from src.ir import VMFunction, VMInstruction

try:  # pragma: no cover - optional dependency import
    from luaparser import ast as _luaparser_ast
except ImportError:  # pragma: no cover - luaparser not installed
    _luaparser_ast = None


if _luaparser_ast is not None:  # pragma: no cover - exercised in tests when available
    _AstVisitorBase = _luaparser_ast.ASTRecursiveVisitor
else:  # pragma: no cover - fallback when luaparser missing

    class _AstVisitorBase:  # type: ignore[too-many-ancestors]
        def __init__(self, *args, **kwargs) -> None:
            pass

        def visit(self, node):  # pragma: no cover - not expected to be used without luaparser
            raise RuntimeError("luaparser is required for VM signature analysis")


@dataclass
class IRInstruction:
    """Simple representation of a single IR instruction."""

    index: int
    opcode: str
    args: List[str]


@dataclass
class CFG:
    """Control‑flow graph structure used for reconstruction and dumping."""

    nodes: Dict[int, IRInstruction]
    edges: Dict[int, Set[int]]


@dataclass
class DFG:
    """Simple data-flow graph capturing definitions and uses."""

    definitions: Dict[str, Set[int]]
    uses: Dict[str, Set[int]]


@dataclass
class OptimizationReport:
    """Summarise optimisation decisions performed on the IR."""

    opaque_predicates: Set[int]
    removed_blocks: Set[int]
    folded_constants: int = 0
    arithmetic_simplifications: int = 0
    concatenation_simplifications: int = 0
    eliminated_jumps: int = 0
    temporaries_eliminated: int = 0
    size_before: int = 0
    size_after: int = 0


@dataclass
class SSAInfo:
    """Metadata collected during SSA conversion."""

    instructions: List[IRInstruction]
    dest_map: Dict[int, str]
    arg_map: Dict[Tuple[int, int], str]
    definitions: Dict[str, Optional[int]]
    uses: Dict[str, Set[int]]


@dataclass
class HandlerTableInfo:
    """Lightweight description of a potential VM handler table."""

    name: str
    line: int
    function_entries: int
    total_entries: int
    sample_keys: List[str]
    snippet: str


@dataclass
class OpcodeCase:
    opcode: int | float | str
    line: int
    snippet: str


@dataclass
class CaseChain:
    variable: str
    cases: List[OpcodeCase]


@dataclass
class VMIRNode:
    """Representation of a lifted opcode branch."""

    opcode: int | float | str
    args: List[str]
    effects: List[str]


@dataclass
class VMBasicBlock:
    """Basic block for VM-level control-flow reconstruction."""

    index: int
    start_pc: int
    end_pc: int
    instructions: List[VMInstruction]


@dataclass(frozen=True)
class VMCFGEdge:
    """Typed edge emitted by the VM-level CFG builder."""

    kind: str
    target: Optional[int]
    opcode: str
    detail: Optional[str] = None


@dataclass
class VMCFG:
    """Control-flow graph built from lifted VM instructions."""

    blocks: Dict[int, VMBasicBlock]
    edges: Dict[int, List[VMCFGEdge]]


@dataclass
class VMSimulationStep:
    """Single executed opcode captured during simulation."""

    index: int
    pc: int
    opcode: str
    args: List[Dict[str, Any]]
    registers: List[Any]
    result: Any | None = None


@dataclass
class VMSimulationResult:
    """Aggregate result for :func:`simulate_vm` runs."""

    output: Any
    steps: List[VMSimulationStep]
    trace_log: List[str]

    def step(self, index: int) -> VMSimulationStep:
        """Return the recorded step at ``index`` for interactive inspection."""

        return self.steps[index]


def _compute_line_starts(text: str) -> List[int]:
    starts = [0]
    for idx, char in enumerate(text):
        if char == "\n":
            starts.append(idx + 1)
    return starts


def _offset_to_line_col(offset: int, starts: List[int]) -> Tuple[int, int]:
    index = bisect_right(starts, offset) - 1
    if index < 0:
        index = 0
    line = index + 1
    column = offset - starts[index] + 1
    return line, column


def _extract_snippet(text: str, start: Optional[int], stop: Optional[int], *, limit: int = 160) -> str:
    if start is None or stop is None or start >= stop:
        return ""
    snippet = text[start:stop].strip()
    snippet = " ".join(snippet.split())
    if len(snippet) > limit:
        snippet = snippet[: limit - 1] + "…"
    return snippet


def _field_key_repr(astnodes, key: Optional[object], index_hint: int) -> Optional[str]:
    if key is None:
        return f"#{index_hint}"
    if isinstance(key, astnodes.Number):
        value = key.n
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        return str(value)
    if isinstance(key, astnodes.String):
        return key.s
    if isinstance(key, astnodes.Name):
        return key.id
    return None


def _iter_if_chain_nodes(astnodes, node: object) -> Iterable[object]:
    current = node
    while isinstance(current, (astnodes.If, astnodes.ElseIf)):
        yield current
        orelse = getattr(current, "orelse", None)
        if isinstance(orelse, astnodes.ElseIf):
            current = orelse
            continue
        break


def _extract_number(astnodes, node: object) -> Optional[int | float]:
    if isinstance(node, astnodes.Number):
        value = node.n
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        return value
    if isinstance(node, astnodes.UMinusOp):
        inner = _extract_number(astnodes, node.operand)
        if inner is not None:
            return -inner
    return None


def _resolve_name(astnodes, node: object) -> Optional[str]:
    if isinstance(node, astnodes.Name):
        return node.id
    if isinstance(node, astnodes.String):
        return node.s
    if isinstance(node, astnodes.Index):
        base = _resolve_name(astnodes, node.value)
        notation = getattr(node, "notation", None)
        if notation == astnodes.IndexNotation.DOT:
            suffix = _resolve_name(astnodes, node.idx)
            if base and suffix:
                return f"{base}.{suffix}"
            return suffix or base
        if notation == astnodes.IndexNotation.SQUARE:
            return base
    return None


def _extract_comparison(astnodes, expr: object) -> Optional[Tuple[str, int | float]]:
    if not isinstance(expr, astnodes.RelOp):
        return None
    left = getattr(expr, "left", None)
    right = getattr(expr, "right", None)
    left_name = _resolve_name(astnodes, left)
    right_name = _resolve_name(astnodes, right)
    left_number = _extract_number(astnodes, left)
    right_number = _extract_number(astnodes, right)
    if left_name and right_number is not None:
        return left_name, right_number
    if right_name and left_number is not None:
        return right_name, left_number
    return None


def _first_statement_snippet(astnodes, block: object, source: str) -> str:
    if not isinstance(block, astnodes.Block):
        return ""
    for statement in getattr(block, "body", []) or []:
        snippet = _extract_snippet(source, getattr(statement, "start_char", None), getattr(statement, "stop_char", None))
        if snippet:
            return snippet
    return ""


def _extract_case_chain(astnodes, node: object, source: str, starts: List[int]) -> Optional[CaseChain]:
    cases: List[OpcodeCase] = []
    variable: Optional[str] = None
    for branch in _iter_if_chain_nodes(astnodes, node):
        comparison = _extract_comparison(astnodes, getattr(branch, "test", None))
        if comparison is None:
            break
        name, opcode = comparison
        if not isinstance(opcode, (int, float)):
            break
        if isinstance(opcode, float) and opcode.is_integer():
            opcode = int(opcode)
        if variable is None:
            variable = name
        elif name != variable:
            break
        line, _ = _offset_to_line_col(getattr(branch, "start_char", 0), starts)
        snippet = _first_statement_snippet(astnodes, getattr(branch, "body", None), source)
        cases.append(OpcodeCase(opcode=opcode, line=line, snippet=snippet))
    if variable and len(cases) >= 2:
        return CaseChain(variable=variable, cases=cases)
    return None


def _table_name_from_call(astnodes, call: object) -> Optional[str]:
    func = getattr(call, "func", None)
    if isinstance(func, astnodes.Index):
        notation = getattr(func, "notation", None)
        if notation == astnodes.IndexNotation.SQUARE:
            return _resolve_name(astnodes, func.value)
    return None


def _bit_operation_name(astnodes, call: object) -> Optional[str]:
    func = getattr(call, "func", None)
    if isinstance(func, astnodes.Index):
        notation = getattr(func, "notation", None)
        if notation == astnodes.IndexNotation.DOT:
            base = _resolve_name(astnodes, func.value)
            suffix = _resolve_name(astnodes, func.idx)
            if base in {"bit32", "bit"} and suffix:
                return f"{base}.{suffix}"
    return None


def _parse_numeric_literal(token: str) -> Optional[int]:
    candidate = token.strip().lower()
    try:
        if candidate.startswith("0x"):
            return int(candidate, 16)
        return int(candidate, 10)
    except ValueError:
        return None


def _unique_ordered(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _collect_identifier_names(astnodes, node: object) -> List[str]:
    if node is None:
        return []
    names: List[str] = []
    stack: List[object] = [node]
    visited: Set[int] = set()
    primitives = (str, bytes, int, float, complex, bool)
    while stack:
        current = stack.pop()
        if current is None:
            continue
        if isinstance(current, primitives):
            continue
        if isinstance(current, astnodes.Name):
            names.append(current.id)
            continue
        if isinstance(current, (list, tuple, set)):
            stack.extend(current)
            continue
        ident = id(current)
        if ident in visited:
            continue
        visited.add(ident)
        slots = getattr(current, "__slots__", None)
        if slots:
            for attr in slots:
                if attr == "ctx":
                    continue
                try:
                    value = getattr(current, attr)
                except AttributeError:
                    continue
                if value is None:
                    continue
                stack.append(value)
        else:
            for attr in dir(current):
                if attr.startswith("_"):
                    continue
                try:
                    value = getattr(current, attr)
                except AttributeError:
                    continue
                if callable(value) or value is None:
                    continue
                stack.append(value)
    return names


def _summarize_case_body(astnodes, block: object) -> Tuple[List[str], List[str]]:
    reads: List[str] = []
    writes: List[str] = []

    def record_reads(node: object) -> None:
        reads.extend(_collect_identifier_names(astnodes, node))

    def record_writes(target: object) -> None:
        name = _resolve_name(astnodes, target)
        if name:
            writes.append(name)
        record_reads(target)

    statements: Iterable[object]
    if isinstance(block, astnodes.Block):
        statements = getattr(block, "body", []) or []
    else:
        statements = [block]

    for stmt in statements:
        if isinstance(stmt, (astnodes.Assign, astnodes.LocalAssign)):
            targets = getattr(stmt, "targets", []) or []
            values = getattr(stmt, "values", []) or []
            for target in targets:
                record_writes(target)
            for value in values:
                record_reads(value)
        elif isinstance(stmt, astnodes.Return):
            for value in getattr(stmt, "values", []) or []:
                record_reads(value)
        elif isinstance(stmt, astnodes.Call):
            record_reads(stmt)
        elif isinstance(stmt, astnodes.If):
            record_reads(getattr(stmt, "test", None))
            for branch in _iter_if_chain_nodes(astnodes, stmt):
                branch_body = getattr(branch, "body", None)
                branch_reads, branch_writes = _summarize_case_body(astnodes, branch_body)
                reads.extend(branch_reads)
                writes.extend(branch_writes)
            orelse = getattr(stmt, "orelse", None)
            if orelse:
                branch_reads, branch_writes = _summarize_case_body(astnodes, orelse)
                reads.extend(branch_reads)
                writes.extend(branch_writes)
        else:
            record_reads(stmt)

    return _unique_ordered(reads), _unique_ordered(writes)


def _lift_if_chain(astnodes, node: object, seen_opcodes: Set[int | float | str]) -> List[VMIRNode]:
    ir_nodes: List[VMIRNode] = []
    for branch in _iter_if_chain_nodes(astnodes, node):
        comparison = _extract_comparison(astnodes, getattr(branch, "test", None))
        if comparison is None:
            continue
        _, opcode = comparison
        if isinstance(opcode, float) and opcode.is_integer():
            opcode = int(opcode)
        if opcode in seen_opcodes:
            continue
        body = getattr(branch, "body", None)
        args, effects = _summarize_case_body(astnodes, body)
        ir_nodes.append(VMIRNode(opcode=opcode, args=args, effects=effects))
        seen_opcodes.add(opcode)
    return ir_nodes


def lift_vm(dispatcher_ast) -> List[VMIRNode]:
    """Lift a VM dispatcher function into SSA-style IR nodes."""

    try:
        from luaparser import astnodes  # type: ignore
    except ImportError as exc:  # pragma: no cover - enforced by tests
        raise RuntimeError("lift_vm requires luaparser to be installed") from exc

    function_types = (
        astnodes.Function,
        astnodes.LocalFunction,
        astnodes.AnonymousFunction,
    )
    if not isinstance(dispatcher_ast, function_types):
        raise TypeError("lift_vm expects a luaparser function node")

    body = getattr(dispatcher_ast, "body", None)
    if body is None:
        return []

    seen_opcodes: Set[int | float | str] = set()
    ir_nodes: List[VMIRNode] = []
    if isinstance(body, astnodes.Block):
        statements = getattr(body, "body", []) or []
    else:
        statements = [body]

    for statement in statements:
        if isinstance(statement, astnodes.If):
            ir_nodes.extend(_lift_if_chain(astnodes, statement, seen_opcodes))

    return ir_nodes


def _coerce_vm_program(vm_ir: Any) -> VMFunction:
    """Normalise different IR containers into a :class:`VMFunction`."""

    if isinstance(vm_ir, VMFunction):
        return vm_ir

    if isinstance(vm_ir, Mapping):
        version = vm_ir.get("version") if isinstance(vm_ir.get("version"), str) else None
        from opcode_lifter import OpcodeLifter  # local import to avoid cycles

        return OpcodeLifter().lift_program(vm_ir, version=version)

    if isinstance(vm_ir, Iterable):
        instructions = list(vm_ir)
        if not instructions:
            return VMFunction(constants=[], instructions=[])
        if all(isinstance(entry, VMInstruction) for entry in instructions):
            return VMFunction(constants=[], instructions=instructions)

    raise TypeError(
        "simulate_vm expects a VMFunction, an iterable of VMInstruction objects, or a payload mapping"
    )


def _normalise_simulation_inputs(inputs: Any) -> tuple[List[Any], Dict[str, Any]]:
    if inputs is None:
        return [], {}

    if isinstance(inputs, Mapping):
        args_obj = inputs.get("args")
        if args_obj is None:
            args: List[Any] = []
        elif isinstance(args_obj, (list, tuple)):
            args = list(args_obj)
        else:
            args = [args_obj]
        env = {key: value for key, value in inputs.items() if key != "args"}
        return args, env

    if isinstance(inputs, (bytes, bytearray)):
        return [inputs], {}

    if isinstance(inputs, str):
        return [inputs], {}

    if isinstance(inputs, Sequence):
        return list(inputs), {}

    return [inputs], {}


def _format_instruction_args(instr: Any) -> List[Dict[str, Any]]:
    if not isinstance(instr, VMInstruction):
        return []

    if isinstance(getattr(instr, "ir", None), dict):
        raw_args = instr.ir.get("args")
        formatted: List[Dict[str, Any]] = []
        if isinstance(raw_args, list):
            for entry in raw_args:
                if isinstance(entry, Mapping):
                    name = entry.get("name")
                    formatted.append({"name": str(name), "value": entry.get("value")})
        if formatted:
            return formatted

    args: List[Dict[str, Any]] = []
    for field in ("a", "b", "c"):
        value = getattr(instr, field, None)
        if value is not None:
            args.append({"name": field, "value": value})

    for key, value in instr.aux.items():
        if key.endswith("_mode") or key.endswith("_index"):
            continue
        if key.startswith("const_") or key.startswith("immediate_") or key.startswith("proto"):
            args.append({"name": key, "value": value})
        elif key in {"offset", "target", "upvalues"}:
            args.append({"name": key, "value": value})

    return args


def simulate_vm(vm_ir: Any, inputs: Any | None = None) -> VMSimulationResult:
    """Execute canonical VM IR and capture a structured execution trace."""

    program = _coerce_vm_program(vm_ir)
    args, env = _normalise_simulation_inputs(inputs)
    steps: List[VMSimulationStep] = []

    def _trace_hook(instr: VMInstruction, frame) -> None:
        registers = list(frame.registers)
        pc = getattr(instr, "pc", len(steps))
        steps.append(
            VMSimulationStep(
                index=len(steps),
                pc=pc,
                opcode=instr.opcode,
                args=_format_instruction_args(instr),
                registers=registers,
            )
        )

    env_payload = env or None
    simulator = LuaVMSimulator(trace=True, trace_hook=_trace_hook, env=env_payload)
    output = simulator.run(program, args=args)
    if steps:
        steps[-1].result = output

    return VMSimulationResult(output=output, steps=steps, trace_log=list(simulator.trace_log))


_SEMANTIC_RULES: List[Tuple[str, float, re.Pattern[str]]] = [
    ("bit ops", 0.9, re.compile(r"\bbit32\.[A-Za-z_][A-Za-z0-9_]*\b|\bbit\.[A-Za-z_][A-Za-z0-9_]*\b")),
    ("byte/char", 0.85, re.compile(r"string\.(?:byte|char)")),
    (
        "SET/GET",
        0.75,
        re.compile(
            r"table\.(?:insert|remove|rawset|rawget)|rawset\s*\(|rawget\s*\(|\[[^\]]+\]\s*=|=\s*[^\n]*\[[^\]]+\]",
            re.S,
        ),
    ),
    ("string ops", 0.65, re.compile(r"string\.(?:sub|gsub|lower|upper|reverse|format|len)")),
    ("math ops", 0.6, re.compile(r"math\.")),
    ("concat", 0.55, re.compile(r"\.\.")),
]


_ML_METADATA_FILENAME = "opcode_ml_metadata.json"


def _iter_metadata_paths() -> List[Path]:
    paths: List[Path] = []
    env_path = os.environ.get("LURAPH_ML_METADATA")
    if env_path:
        try:
            paths.append(Path(env_path).expanduser())
        except Exception:  # pragma: no cover - defensive
            pass
    module_path = Path(__file__).resolve()
    paths.append(module_path.with_name(_ML_METADATA_FILENAME))
    paths.append(module_path.parent / "data" / _ML_METADATA_FILENAME)
    cwd = Path.cwd()
    paths.append(cwd / _ML_METADATA_FILENAME)
    paths.append(cwd / "data" / _ML_METADATA_FILENAME)
    # Deduplicate while preserving order
    seen: Set[Path] = set()
    unique: List[Path] = []
    for path in paths:
        try:
            resolved = path.resolve()
        except Exception:  # pragma: no cover - path resolution edge cases
            resolved = path
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


@lru_cache(maxsize=1)
def _load_builtin_ml_samples() -> List[Tuple[Set[str], str]]:
    samples: List[Tuple[Set[str], str]] = []
    for path in _iter_metadata_paths():
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover - malformed metadata files are ignored
            continue
        extracted: List[Tuple[Set[str], str]] = []
        for sample in payload.get("samples", []):
            label = sample.get("label")
            features = sample.get("features")
            if not isinstance(label, str) or not label.strip():
                continue
            if not isinstance(features, Iterable):
                continue
            feature_set = {
                str(feature).strip()
                for feature in features
                if isinstance(feature, str) and feature.strip()
            }
            if feature_set:
                extracted.append((feature_set, label.strip()))
        if extracted:
            samples.extend(extracted)
            break
    return samples


@dataclass
class _DecisionTreeNode:
    """Tiny decision tree node used for fuzzy opcode classification."""

    feature: Optional[str] = None
    prediction: Optional[str] = None
    probability: float = 0.0
    counts: Dict[str, int] = field(default_factory=dict)
    left: Optional["_DecisionTreeNode"] = None
    right: Optional["_DecisionTreeNode"] = None


class _SimpleDecisionTree:
    """Minimal decision tree classifier operating on feature sets."""

    def __init__(self, *, max_depth: int = 4, min_samples_split: int = 2) -> None:
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.root: Optional[_DecisionTreeNode] = None

    def fit(self, samples: Sequence[Tuple[Set[str], str]]) -> None:
        self.root = self._build_tree(list(samples), depth=0)

    def predict(self, features: Set[str]) -> Tuple[str, float]:
        node = self.root
        if node is None:
            return "unknown", 0.0
        while node.feature:
            if node.feature in features and node.left is not None:
                node = node.left
            elif node.feature not in features and node.right is not None:
                node = node.right
            else:
                break
        if not node.counts:
            return node.prediction or "unknown", node.probability
        label, prob = _majority_label(node.counts)
        return label, prob

    def _build_tree(
        self,
        samples: List[Tuple[Set[str], str]],
        *,
        depth: int,
    ) -> _DecisionTreeNode:
        counts = Counter(label for _, label in samples)
        prediction, probability = _majority_label(counts)
        node = _DecisionTreeNode(
            prediction=prediction,
            probability=probability,
            counts=dict(counts),
        )
        if depth >= self.max_depth or len(samples) < self.min_samples_split or probability >= 0.999:
            return node

        all_features: Set[str] = set()
        for feature_set, _ in samples:
            all_features.update(feature_set)

        if not all_features:
            return node

        base_impurity = _gini_impurity(counts)
        best_gain = 0.0
        best_feature: Optional[str] = None
        best_split: Optional[Tuple[List[Tuple[Set[str], str]], List[Tuple[Set[str], str]]]] = None

        for feature in sorted(all_features):
            left = [sample for sample in samples if feature in sample[0]]
            right = [sample for sample in samples if feature not in sample[0]]
            if not left or not right:
                continue
            gain = base_impurity - _weighted_impurity(left, right)
            if gain > best_gain + 1e-6:
                best_gain = gain
                best_feature = feature
                best_split = (left, right)

        if best_feature is None or best_split is None or best_gain < 1e-3:
            return node

        node.feature = best_feature
        node.left = self._build_tree(best_split[0], depth=depth + 1)
        node.right = self._build_tree(best_split[1], depth=depth + 1)
        return node


def _majority_label(counts: Mapping[str, int]) -> Tuple[str, float]:
    if not counts:
        return "unknown", 0.0
    total = sum(counts.values())
    if total <= 0:
        return "unknown", 0.0
    label, best = max(counts.items(), key=lambda item: (item[1], item[0]))
    return label, best / total


def _gini_impurity(samples: Mapping[str, int] | Sequence[Tuple[Set[str], str]]) -> float:
    if isinstance(samples, Mapping):
        counts = samples
        total = sum(counts.values())
        if total == 0:
            return 0.0
        return 1.0 - sum((count / total) ** 2 for count in counts.values())

    total = len(samples)
    if total == 0:
        return 0.0
    counts = Counter(label for _, label in samples)
    return _gini_impurity(counts)


def _weighted_impurity(
    left: Sequence[Tuple[Set[str], str]],
    right: Sequence[Tuple[Set[str], str]],
) -> float:
    total = len(left) + len(right)
    if total == 0:
        return 0.0
    return (len(left) / total) * _gini_impurity(left) + (len(right) / total) * _gini_impurity(right)


def _compute_opcode_sequence_context(candidate: Optional[Mapping[str, Any]]) -> Dict[int, Dict[str, Set[int]]]:
    context: Dict[int, Dict[str, Set[int]]] = defaultdict(lambda: {"prev": set(), "next": set()})
    if not isinstance(candidate, Mapping):
        return context
    cases = candidate.get("opcode_cases")
    if not isinstance(cases, list):
        return context
    ordered_opcodes: List[int] = []
    for case in cases:
        opcode = _normalise_numeric_opcode(case.get("opcode")) if isinstance(case, Mapping) else None
        if opcode is None:
            continue
        ordered_opcodes.append(opcode)
    for idx, opcode in enumerate(ordered_opcodes):
        if idx > 0:
            context[opcode]["prev"].add(ordered_opcodes[idx - 1])
        if idx + 1 < len(ordered_opcodes):
            context[opcode]["next"].add(ordered_opcodes[idx + 1])
    return context


def _tokenize_for_features(text: Optional[str], *, prefix: str, limit: int = 80) -> Set[str]:
    if not text:
        return set()
    tokens = set()
    for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,31}", text):
        lowered = raw.lower()
        tokens.add(f"{prefix}:{lowered}")
    if limit and len(tokens) > limit:
        trimmed = sorted(tokens)[:limit]
        return set(trimmed)
    return tokens


def _call_tokens(text: Optional[str]) -> Set[str]:
    if not text:
        return set()
    calls = set()
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        calls.add(f"call:{match.group(1).lower()}")
    return calls


def _frequency_bin(count: int, max_count: int) -> str:
    if max_count <= 0:
        return "freq:low"
    ratio = count / max_count
    if ratio >= 0.75:
        return "freq:high"
    if ratio >= 0.4:
        return "freq:mid"
    return "freq:low"


def _rank_bin(index: int, total: int) -> str:
    if total <= 0:
        return "rank:low"
    ratio = index / total
    if ratio <= 0.33:
        return "rank:top"
    if ratio >= 0.66:
        return "rank:bottom"
    return "rank:middle"


def _extract_opcode_feature_tokens(
    opcode: int,
    *,
    count: int,
    max_count: int,
    rank_index: int,
    total: int,
    handler_info: Optional[Mapping[str, Any]],
    snippet: str,
    helper_samples: Sequence[Mapping[str, Any]],
    inline_helper: Optional[Mapping[str, Any]],
    ir_node: Optional[VMIRNode],
    context: Mapping[str, Set[int]],
) -> Set[str]:
    tokens: Set[str] = set()
    tokens.add(_frequency_bin(count, max_count))
    tokens.add(_rank_bin(rank_index, total if total else 1))
    tokens.add(f"opcode_mod:{opcode % 5}")
    tokens.add(f"opcode_bucket:{opcode // 5}")

    handler_text = ""
    if handler_info and isinstance(handler_info, Mapping):
        handler_text = str(handler_info.get("text") or handler_info.get("body") or "")
        snippet_text = handler_info.get("snippet") if isinstance(handler_info.get("snippet"), str) else None
        tokens.update(_tokenize_for_features(snippet_text, prefix="handler_snip"))
    else:
        handler_text = ""

    inline_text = ""
    if inline_helper and isinstance(inline_helper, Mapping):
        inline_text = str(inline_helper.get("body") or "")

    tokens.update(_tokenize_for_features(handler_text, prefix="handler"))
    tokens.update(_tokenize_for_features(snippet, prefix="case"))
    tokens.update(_tokenize_for_features(inline_text, prefix="inline"))
    tokens.update(_call_tokens(handler_text))
    tokens.update(_call_tokens(snippet))
    tokens.update(_call_tokens(inline_text))

    for sample in helper_samples:
        helper_name = sample.get("helper") if isinstance(sample, Mapping) else None
        if isinstance(helper_name, str) and helper_name:
            tokens.add(f"helper:{helper_name.lower()}")

    if context.get("prev"):
        for prev in sorted(context["prev"]):
            tokens.add(f"prev:{prev}")
    if context.get("next"):
        for nxt in sorted(context["next"]):
            tokens.add(f"next:{nxt}")

    if ir_node is not None:
        for arg in getattr(ir_node, "args", []) or []:
            tokens.add(f"arg:{str(arg).lower()}")
        for effect in getattr(ir_node, "effects", []) or []:
            tokens.add(f"effect:{str(effect).lower()}")

    if inline_text:
        tokens.add("has_inline_helper")

    return tokens


def _apply_ml_predictions(
    entries: Mapping[int, Dict[str, Any]],
    feature_map: Mapping[int, Set[str]],
) -> None:
    samples: List[Tuple[Set[str], str]] = []
    for opcode, entry in entries.items():
        features = feature_map.get(opcode)
        if not features:
            continue
        label = entry.get("guess")
        confidence = float(entry.get("confidence", 0.0) or 0.0)
        if isinstance(label, str) and label and label.lower() != "unknown" and confidence >= 0.5:
            samples.append((set(features), label))

    unique_labels = {label for _, label in samples}
    metadata_used = False
    if len(unique_labels) < 2:
        metadata_samples = _load_builtin_ml_samples()
        if metadata_samples:
            samples.extend(metadata_samples)
            metadata_used = True
            unique_labels = {label for _, label in samples}

    if len(unique_labels) < 2:
        # Not enough diversity to train a classifier.
        for entry in entries.values():
            entry.setdefault("guess_source", "heuristic")
        return

    tree = _SimpleDecisionTree()
    tree.fit(samples)
    training_size = len(samples)

    for opcode, entry in entries.items():
        features = feature_map.get(opcode)
        if not features:
            entry.setdefault("guess_source", "heuristic")
            continue
        prediction, probability = tree.predict(set(features))
        if prediction and prediction != "unknown":
            entry["ml_guess"] = prediction
            entry["ml_confidence"] = round(probability, 2)
            entry["ml_training_size"] = training_size
            if metadata_used:
                entry["ml_metadata_source"] = "builtin"
        current_conf = float(entry.get("confidence", 0.0) or 0.0)
        current_guess = entry.get("guess") if isinstance(entry.get("guess"), str) else ""
        needs_upgrade = (not current_guess) or current_guess.lower() == "unknown" or current_conf < 0.5
        if prediction and prediction != "unknown" and probability > current_conf and needs_upgrade:
            entry["guess"] = prediction
            entry["confidence"] = round(probability, 2)
            evidence = entry.get("evidence") if isinstance(entry.get("evidence"), str) else ""
            prefix = evidence + "; " if evidence else ""
            entry["evidence"] = f"{prefix}ml classifier"
            entry["guess_source"] = "ml"
        else:
            entry.setdefault("guess_source", "heuristic")

class PatternAnalyzer:
    """
    Advanced opcode pattern analyzer for detecting custom opcode sequences
    and inferring high-level operations in obfuscated Lua scripts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.opcode_patterns = {}
        self.sequence_map = {}
        self.high_level_operations = {}

        # Initialize known patterns
        self._initialize_patterns()

        # Cached analysis artefacts populated by :meth:`optimise_ir`.
        self.last_cfg: Optional[CFG] = None
        self.last_dfg: Optional[DFG] = None
        self.last_report: Optional[OptimizationReport] = None
        self.last_ssa_chains: Optional[Dict[str, Dict[str, Any]]] = None
        self.last_ssa_info: Optional[SSAInfo] = None
        self.last_vm_optimisation: Optional[Dict[str, Any]] = None
        self.last_register_analysis: Optional[Dict[str, Any]] = None

        self._branch_ops = {
            "JMPIF",
            "JMPIFNOT",
            "JMPTRUE",
            "JMPFALSE",
            "EQ",
            "NE",
            "LT",
            "LE",
            "GT",
            "GE",
            "TEST",
            "TESTSET",
        }
        self._arithmetic_ops = {
            "ADD",
            "SUB",
            "MUL",
            "DIV",
            "MOD",
            "POW",
            "IDIV",
            "BAND",
            "BOR",
            "BXOR",
            "SHL",
            "SHR",
        }
    
    def _initialize_patterns(self):
        """Initialize known opcode patterns and their meanings."""
        
        # Common Lua opcodes and their variations
        self.standard_opcodes = {
            'MOVE', 'LOADK', 'LOADBOOL', 'LOADNIL', 'GETUPVAL', 'GETGLOBAL',
            'GETTABLE', 'SETGLOBAL', 'SETUPVAL', 'SETTABLE', 'NEWTABLE',
            'SELF', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'UNM',
            'NOT', 'LEN', 'CONCAT', 'JMP', 'EQ', 'LT', 'LE', 'TEST',
            'TESTSET', 'CALL', 'TAILCALL', 'RETURN', 'FORLOOP', 'FORPREP',
            'TFORLOOP', 'SETLIST', 'CLOSE', 'CLOSURE', 'VARARG'
        }
        
        # Known high-level operation patterns
        self.known_patterns = {
            'function_call': [
                ['LOADK', 'CALL'],
                ['GETGLOBAL', 'LOADK', 'CALL'],
                ['GETTABLE', 'LOADK', 'CALL'],
                ['SELF', 'LOADK', 'CALL']
            ],
            'table_access': [
                ['GETTABLE', 'LOADK'],
                ['SETTABLE', 'LOADK'],
                ['NEWTABLE', 'SETTABLE']
            ],
            'string_concat': [
                ['LOADK', 'LOADK', 'CONCAT'],
                ['GETGLOBAL', 'LOADK', 'CONCAT']
            ],
            'arithmetic': [
                ['LOADK', 'LOADK', 'ADD'],
                ['LOADK', 'LOADK', 'SUB'],
                ['LOADK', 'LOADK', 'MUL'],
                ['LOADK', 'LOADK', 'DIV']
            ],
            'control_flow': [
                ['TEST', 'JMP'],
                ['TESTSET', 'JMP'],
                ['EQ', 'JMP'],
                ['LT', 'JMP'],
                ['LE', 'JMP']
            ]
        }
    
    def extract_opcodes(self, content: str) -> List[str]:
        """Extract potential opcodes from the content."""
        opcodes = []
        
        # Look for opcode-like patterns
        patterns = [
            r'\b[A-Z][A-Z_]{2,}\b',  # All caps words
            r'OP_[A-Z_]+',           # OP_ prefixed opcodes
            r'\b[A-Z]{3,}\d*\b',     # Caps with optional numbers
            r'vm_[a-z_]+',           # VM operations
            r'lua_[a-z_]+',          # Lua API calls
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            opcodes.extend(matches)
        
        return opcodes
    
    def detect_sequences(self, opcodes: List[str], min_length: int = 2, max_length: int = 6) -> Dict[str, List[Tuple]]:
        """Detect repeated opcode sequences."""
        sequences = defaultdict(list)
        
        for length in range(min_length, max_length + 1):
            for i in range(len(opcodes) - length + 1):
                sequence = tuple(opcodes[i:i + length])
                sequences[length].append(sequence)
        
        # Count occurrences and filter frequent sequences
        frequent_sequences = {}
        for length, seq_list in sequences.items():
            counter = Counter(seq_list)
            # Only keep sequences that appear at least twice
            frequent = {seq: count for seq, count in counter.items() if count >= 2}
            if frequent:
                frequent_sequences[length] = frequent
        
        return frequent_sequences
    
    def infer_operation_type(self, sequence: Tuple[str]) -> Optional[str]:
        """Infer the high-level operation type from an opcode sequence."""
        sequence_list = list(sequence)
        
        # Check against known patterns
        for operation, patterns in self.known_patterns.items():
            for pattern in patterns:
                if self._matches_pattern(sequence_list, pattern):
                    return operation
        
        # Heuristic inference
        if 'CALL' in sequence_list:
            return 'function_call'
        elif 'CONCAT' in sequence_list:
            return 'string_operation'
        elif any(op in sequence_list for op in ['ADD', 'SUB', 'MUL', 'DIV', 'MOD']):
            return 'arithmetic'
        elif any(op in sequence_list for op in ['JMP', 'TEST', 'EQ', 'LT', 'LE']):
            return 'control_flow'
        elif any(op in sequence_list for op in ['GETTABLE', 'SETTABLE', 'NEWTABLE']):
            return 'table_operation'
        elif 'LOADK' in sequence_list:
            return 'constant_loading'
        
        return 'unknown'
    
    def _matches_pattern(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if a sequence matches a pattern (allowing wildcards)."""
        if len(sequence) != len(pattern):
            return False
        
        for seq_op, pat_op in zip(sequence, pattern):
            if pat_op != '*' and seq_op != pat_op:
                return False
        
        return True
    
    def detect_custom_opcodes(self, opcodes: List[str]) -> Dict[str, int]:
        """Detect custom/non-standard opcodes."""
        custom_opcodes = {}
        
        for opcode in set(opcodes):
            if opcode not in self.standard_opcodes:
                # Check if it looks like a custom opcode
                if (len(opcode) >= 3 and 
                    opcode.isupper() and 
                    not opcode.startswith(('VM_', 'LUA_', 'DEBUG_'))):
                    custom_opcodes[opcode] = opcodes.count(opcode)
        
        return custom_opcodes
    
    def analyze_control_flow(self, content: str) -> Dict[str, Any]:
        """Analyze control flow patterns."""
        control_flow = {
            'jumps': [],
            'loops': [],
            'conditions': [],
            'function_calls': []
        }
        
        # Detect jump patterns
        jump_patterns = [
            r'JMP\s+(\d+)',
            r'goto\s+(\w+)',
            r'if.*?then.*?goto\s+(\w+)',
            r'while.*?do.*?goto\s+(\w+)'
        ]
        
        for pattern in jump_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                control_flow['jumps'].append({
                    'type': 'jump',
                    'target': match.group(1),
                    'position': match.start()
                })
        
        # Detect loop patterns
        loop_patterns = [
            r'for\s+.*?do',
            r'while\s+.*?do',
            r'repeat.*?until',
            r'FORLOOP\s+\d+',
            r'FORPREP\s+\d+'
        ]
        
        for pattern in loop_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                control_flow['loops'].append({
                    'type': 'loop',
                    'pattern': match.group(0),
                    'position': match.start()
                })
        
        return control_flow
    
    def build_opcode_map(self, sequences: Dict[str, Dict[Tuple, int]]) -> Dict[str, str]:
        """Build a map from opcode sequences to high-level operations."""
        opcode_map = {}
        
        for length, seq_dict in sequences.items():
            for sequence, count in seq_dict.items():
                operation = self.infer_operation_type(sequence)
                key = ' -> '.join(sequence)
                opcode_map[key] = {
                    'operation': operation,
                    'frequency': count,
                    'confidence': min(count / 10.0, 1.0)  # Normalize confidence
                }
        
        return opcode_map
    
    def detect_encryption_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Detect potential encryption/decryption patterns."""
        patterns = []
        
        # XOR patterns
        xor_patterns = [
            r'(\w+)\s*=\s*(\w+)\s*\^\s*(\w+)',
            r'bit\.bxor\(([^)]+)\)',
            r'bit32\.bxor\(([^)]+)\)'
        ]
        
        for pattern in xor_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                patterns.append({
                    'type': 'xor',
                    'pattern': match.group(0),
                    'position': match.start()
                })
        
        # String manipulation patterns
        str_patterns = [
            r'string\.char\(([^)]+)\)',
            r'string\.byte\(([^)]+)\)',
            r'table\.concat\(([^)]+)\)',
            r'string\.sub\(([^)]+)\)'
        ]
        
        for pattern in str_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                patterns.append({
                    'type': 'string_manipulation',
                    'pattern': match.group(0),
                    'position': match.start()
                })
        
        return patterns
    
    def analyze(self, content: str) -> Dict[str, Any]:
        """Perform comprehensive pattern analysis."""
        self.logger.info("Starting comprehensive pattern analysis...")
        
        # Extract opcodes
        opcodes = self.extract_opcodes(content)
        self.logger.info(f"Extracted {len(opcodes)} potential opcodes")
        
        # Detect sequences
        sequences = self.detect_sequences(opcodes)
        total_sequences = sum(len(seq_dict) for seq_dict in sequences.values())
        self.logger.info(f"Detected {total_sequences} frequent sequences")
        
        # Build opcode map
        opcode_map = self.build_opcode_map(sequences)
        
        # Detect custom opcodes
        custom_opcodes = self.detect_custom_opcodes(opcodes)
        self.logger.info(f"Found {len(custom_opcodes)} custom opcodes")
        
        # Analyze control flow
        control_flow = self.analyze_control_flow(content)
        
        # Detect encryption patterns
        encryption_patterns = self.detect_encryption_patterns(content)
        self.logger.info(f"Found {len(encryption_patterns)} encryption patterns")
        
        return {
            'opcodes': list(set(opcodes)),
            'sequences': sequences,
            'opcode_map': opcode_map,
            'custom_opcodes': custom_opcodes,
            'control_flow': control_flow,
            'encryption_patterns': encryption_patterns,
            'analysis_summary': {
                'total_opcodes': len(opcodes),
                'unique_opcodes': len(set(opcodes)),
                'frequent_sequences': total_sequences,
                'custom_opcodes': len(custom_opcodes),
                'control_structures': sum(len(v) for v in control_flow.values()),
                'encryption_patterns': len(encryption_patterns)
            }
        }
    # Control flow graph utilities
    def parse_ir(self, code: str) -> List[IRInstruction]:
        """Parse a simple IR listing into :class:`IRInstruction` objects."""
        instructions: List[IRInstruction] = []
        for idx, line in enumerate(code.splitlines()):
            match = re.match(r"\s*(\w+)(?:\s+(.*))?", line)
            if not match:
                continue
            opcode = match.group(1).upper()
            arg_str = match.group(2) or ""
            args = [a.strip() for a in arg_str.split() if a.strip()]
            instructions.append(IRInstruction(idx, opcode, args))
        return instructions

    def build_cfg(self, instructions: Iterable[IRInstruction]) -> CFG:
        """Build a CFG from a sequence of IR instructions."""
        nodes = {ins.index: ins for ins in instructions if ins.opcode != "NOP"}
        edges: Dict[int, Set[int]] = defaultdict(set)
        ordered_indices = sorted(nodes)
        next_lookup = {
            idx: ordered_indices[pos + 1]
            for pos, idx in enumerate(ordered_indices[:-1])
        }

        for ins in instructions:
            if ins.opcode == "NOP" or ins.index not in nodes:
                continue
            next_idx = next_lookup.get(ins.index)
            if ins.opcode == "JMP" and ins.args:
                target = self._parse_int(ins.args[0])
                if target is not None:
                    edges[ins.index].add(target)
            elif ins.opcode in self._branch_ops and ins.args:
                target = self._parse_int(ins.args[-1])
                if target is not None:
                    edges[ins.index].add(target)
                if next_idx is not None:
                    edges[ins.index].add(next_idx)
            else:
                if next_idx is not None:
                    edges[ins.index].add(next_idx)

        return CFG(nodes, edges)

    def remove_dead_code(self, cfg: CFG) -> CFG:
        """Return a copy of ``cfg`` with unreachable nodes removed."""
        visited: Set[int] = set()
        stack = [0]
        while stack:
            idx = stack.pop()
            if idx in visited or idx not in cfg.nodes:
                continue
            visited.add(idx)
            stack.extend(cfg.edges.get(idx, []))

        nodes = {i: n for i, n in cfg.nodes.items() if i in visited}
        edges = {i: {t for t in cfg.edges.get(i, set()) if t in visited} for i in visited}
        return CFG(nodes, edges)

    def reconstruct_structures(self, cfg: CFG) -> str:
        """Reconstruct pseudo-Lua control structures from a CFG."""
        lines: List[str] = []
        for idx in sorted(cfg.nodes):
            ins = cfg.nodes[idx]
            if ins.opcode == "FORPREP":
                lines.append("for ... do")
            elif ins.opcode == "FORLOOP":
                lines.append("end")
            elif ins.opcode in {"JMP", "EQ", "LT", "LE", "TEST", "TESTSET"}:
                lines.append(f"-- {ins.opcode} {' '.join(ins.args)}")
            else:
                lines.append(f"-- {ins.opcode}")
        return "\n".join(lines)

    def dump_cfg(self, cfg: CFG, path: Path) -> None:
        """Write ``cfg`` to ``path`` in Graphviz DOT format."""
        with path.open("w", encoding="utf8") as fh:
            fh.write("digraph CFG {\n")
            for idx, node in cfg.nodes.items():
                label = f"{idx}: {node.opcode}"
                fh.write(f"  n{idx} [label=\"{label}\"];\n")
            for src, targets in cfg.edges.items():
                for dst in targets:
                    fh.write(f"  n{src} -> n{dst};\n")
            fh.write("}\n")

    def build_dfg(self, instructions: Iterable[IRInstruction]) -> DFG:
        """Construct a basic def-use graph for ``instructions``."""

        definitions: Dict[str, Set[int]] = defaultdict(set)
        uses: Dict[str, Set[int]] = defaultdict(set)

        for ins in instructions:
            dest = self._destination_register(ins)
            if dest is not None:
                definitions[dest].add(ins.index)
            for token in self._source_registers(ins):
                uses[token].add(ins.index)

        return DFG(dict(definitions), dict(uses))

    # SSA and data-flow helpers -------------------------------------------------

    def build_use_def_chains(self, instructions: Iterable[IRInstruction]) -> Dict[str, Dict[str, Any]]:
        """Return a mapping of SSA names to their definition/use sites."""

        ssa = self.convert_to_ssa(list(instructions))
        chains: Dict[str, Dict[str, Any]] = {}
        for name, definition in ssa.definitions.items():
            chains[name] = {
                "definition": definition,
                "uses": sorted(ssa.uses.get(name, set())),
            }
        return chains

    def convert_to_ssa(self, instructions: List[IRInstruction]) -> SSAInfo:
        """Public wrapper returning the SSA conversion metadata for ``instructions``."""

        ssa = self._convert_to_ssa(list(instructions))
        self.last_ssa_info = ssa
        return ssa

    def _convert_to_ssa(self, instructions: List[IRInstruction]) -> SSAInfo:
        version_counter: Dict[str, int] = defaultdict(int)
        current_version: Dict[str, int] = {}
        dest_map: Dict[int, str] = {}
        arg_map: Dict[Tuple[int, int], str] = {}
        definitions: Dict[str, Optional[int]] = {}
        uses: Dict[str, Set[int]] = defaultdict(set)
        ssa_instructions: List[IRInstruction] = []

        def _ssa_name(register: str, version: int) -> str:
            return f"{register}_{version}"

        for ins in instructions:
            args = list(ins.args)
            dest_reg = self._destination_register(ins)
            dest_ssa: Optional[str] = None
            prior_version: Optional[int] = None
            if dest_reg is not None:
                prior_version = current_version.get(dest_reg)
                version_counter[dest_reg] += 1
                current_version[dest_reg] = version_counter[dest_reg]
                dest_ssa = _ssa_name(dest_reg, current_version[dest_reg])
            new_args = list(args)
            for idx, token in enumerate(args):
                if dest_ssa is not None and idx == 0 and token == dest_reg:
                    new_args[idx] = dest_ssa
                    continue
                if not self._is_register(token):
                    continue
                if dest_ssa is not None and token == dest_reg and idx != 0 and prior_version is not None:
                    version = prior_version
                else:
                    version = current_version.get(token)
                if version is None:
                    version_counter[token] += 1
                    version = version_counter[token]
                    current_version[token] = version
                    definitions.setdefault(_ssa_name(token, version), None)
                ssa_token = _ssa_name(token, version)
                new_args[idx] = ssa_token
                arg_map[(ins.index, idx)] = ssa_token
                uses[ssa_token].add(ins.index)
            if dest_ssa is not None:
                new_args[0] = dest_ssa
                dest_map[ins.index] = dest_ssa
                definitions[dest_ssa] = ins.index
            ssa_instructions.append(IRInstruction(ins.index, ins.opcode, new_args))

        return SSAInfo(ssa_instructions, dest_map, arg_map, definitions, dict(uses))

    def _ssa_value(self, token: Optional[str], constants: Dict[str, Any]) -> Tuple[Any, bool]:
        if token is None:
            return None, False
        if token in constants:
            return constants[token], True
        if not self._is_register(token):
            value, known = self._parse_literal_token(token)
            return value if known else None, known
        return None, False

    def _ssa_constant_propagation(
        self,
        ssa: SSAInfo,
        report: OptimizationReport,
    ) -> Tuple[Dict[str, Any], Dict[str, Tuple[str, str]], Set[int]]:
        constants: Dict[str, Any] = {}
        replacements: Dict[str, Tuple[str, str]] = {}
        removable: Set[int] = set()

        arithmetic_ops = self._arithmetic_ops

        for ins in ssa.instructions:
            dest = self._destination_register(ins)
            if dest is None:
                continue

            opcode = ins.opcode
            args = ins.args

            def _record_literal(value: Any) -> None:
                constants[dest] = value
                replacements[dest] = ("literal", self._format_literal(value))

            def _record_alias(source: str) -> None:
                replacements[dest] = ("ssa", source)
                if source in constants:
                    constants[dest] = constants[source]
                else:
                    constants.pop(dest, None)

            if opcode in {"LOADK", "LOADN", "LOADBOOL", "LOADB", "LOADNIL"} and len(args) >= 2:
                value, known = self._parse_literal_token(args[1])
                if known:
                    _record_literal(value)
                else:
                    constants.pop(dest, None)
                    replacements.pop(dest, None)
                continue

            if opcode == "MOVE" and len(args) >= 2:
                source = args[1]
                if source in constants:
                    _record_literal(constants[source])
                elif self._is_register(source):
                    _record_alias(source)
                else:
                    value, known = self._parse_literal_token(source)
                    if known:
                        _record_literal(value)
                    else:
                        constants.pop(dest, None)
                        replacements.pop(dest, None)
                continue

            if opcode in arithmetic_ops and len(args) >= 3:
                left_token = args[1]
                right_token = args[2]
                left_val, left_known = self._ssa_value(left_token, constants)
                right_val, right_known = self._ssa_value(right_token, constants)
                if left_known and right_known:
                    try:
                        if opcode == "ADD":
                            value = left_val + right_val
                        elif opcode == "SUB":
                            value = left_val - right_val
                        elif opcode == "MUL":
                            value = left_val * right_val
                        elif opcode == "DIV":
                            value = left_val / right_val
                        elif opcode == "IDIV":
                            value = left_val // right_val
                        elif opcode == "MOD":
                            value = left_val % right_val
                        elif opcode == "POW":
                            value = left_val ** right_val
                        elif opcode == "BAND":
                            value = left_val & right_val
                        elif opcode == "BOR":
                            value = left_val | right_val
                        elif opcode == "BXOR":
                            value = left_val ^ right_val
                        elif opcode == "SHL":
                            value = left_val << right_val
                        elif opcode == "SHR":
                            value = left_val >> right_val
                        else:
                            raise ValueError
                    except Exception:
                        constants.pop(dest, None)
                        replacements.pop(dest, None)
                    else:
                        _record_literal(value)
                    continue

                if right_known and right_token is not None:
                    if opcode in {"ADD", "SUB"} and right_val == 0 and self._is_register(left_token):
                        _record_alias(left_token)
                        continue
                    if opcode == "MUL" and right_val == 1 and self._is_register(left_token):
                        _record_alias(left_token)
                        continue
                    if opcode in {"MUL", "BAND", "BOR", "BXOR"} and right_val == 0:
                        _record_literal(0)
                        continue

                if left_known and left_token is not None:
                    if opcode == "ADD" and left_val == 0 and self._is_register(right_token):
                        _record_alias(right_token)
                        continue
                    if opcode == "MUL" and left_val == 1 and self._is_register(right_token):
                        _record_alias(right_token)
                        continue
                    if opcode in {"MUL", "BAND", "BOR", "BXOR"} and left_val == 0:
                        _record_literal(0)
                        continue

                constants.pop(dest, None)
                replacements.pop(dest, None)
                continue

            if opcode in {"NOT", "UNM", "LEN"} and len(args) >= 2:
                src_token = args[1]
                value, known = self._ssa_value(src_token, constants)
                if known:
                    try:
                        if opcode == "NOT":
                            result = not bool(value)
                        elif opcode == "UNM":
                            result = -value
                        elif opcode == "LEN":
                            result = len(value)
                        else:
                            raise ValueError
                    except Exception:
                        constants.pop(dest, None)
                        replacements.pop(dest, None)
                    else:
                        _record_literal(result)
                else:
                    constants.pop(dest, None)
                    replacements.pop(dest, None)
                continue

            constants.pop(dest, None)
            replacements.pop(dest, None)

        removable_opcodes = arithmetic_ops | {"LOADK", "LOADN", "LOADBOOL", "LOADB", "LOADNIL", "MOVE", "NOT", "UNM", "LEN"}
        for ins in ssa.instructions:
            dest = self._destination_register(ins)
            if dest is None:
                continue
            if ins.opcode not in removable_opcodes:
                continue
            if dest not in replacements:
                continue
            removable.add(ins.index)

        return constants, replacements, removable

    def _resolve_ssa_token(
        self,
        token: str,
        constants: Dict[str, Any],
        replacements: Dict[str, Tuple[str, str]],
    ) -> str:
        seen: Set[str] = set()
        current = token
        while current in replacements and current not in seen:
            seen.add(current)
            kind, value = replacements[current]
            if kind == "literal":
                return value
            if kind == "ssa":
                current = value
                continue
            break
        if current in constants:
            return self._format_literal(constants[current])
        return current

    def _apply_ssa_simplifications(
        self,
        instructions: List[IRInstruction],
        ssa: SSAInfo,
        constants: Dict[str, Any],
        replacements: Dict[str, Tuple[str, str]],
        removable: Set[int],
        report: OptimizationReport,
    ) -> List[IRInstruction]:
        simplified: List[IRInstruction] = []
        for ins in instructions:
            if ins.index in removable:
                report.temporaries_eliminated += 1
                continue
            new_args = list(ins.args)
            for idx in range(len(new_args)):
                key = (ins.index, idx)
                ssa_token = ssa.arg_map.get(key)
                if ssa_token is None:
                    continue
                new_args[idx] = self._resolve_ssa_token(ssa_token, constants, replacements)
            simplified.append(IRInstruction(ins.index, ins.opcode, new_args))
        return simplified

    def _ssa_simplify(self, instructions: List[IRInstruction], report: OptimizationReport) -> List[IRInstruction]:
        if not instructions:
            self.last_ssa_chains = {}
            return []
        ssa = self._convert_to_ssa(instructions)
        self.last_ssa_info = ssa
        constants, replacements, removable = self._ssa_constant_propagation(ssa, report)
        simplified = self._apply_ssa_simplifications(instructions, ssa, constants, replacements, removable, report)
        self.last_ssa_chains = self.build_use_def_chains(simplified)
        return simplified

    def optimise_ir(self, instructions: Iterable[IRInstruction]) -> List[IRInstruction]:
        """Run peephole optimisations and dead-code elimination on ``instructions``."""

        original = list(instructions)
        folded, report = self._fold_constants(original)
        report.size_before = len(original)
        folded = self._eliminate_bogus_loops(folded)
        folded = self._remove_nops(folded)
        pruned = self.prune_unreachable(folded)

        removed = {ins.index for ins in original} - {ins.index for ins in pruned}
        report.removed_blocks = removed

        renumbered = self._renumber(pruned)
        renumbered = self._peephole_cleanup(renumbered, report)
        renumbered = self._renumber(renumbered)
        renumbered = self._ssa_simplify(renumbered, report)
        renumbered = self._renumber(renumbered)
        report.size_after = len(renumbered)

        cfg = self.build_cfg(renumbered)
        cfg = self.remove_dead_code(cfg)
        dfg = self.build_dfg(cfg.nodes.values())

        self.last_cfg = cfg
        self.last_dfg = dfg
        self.last_report = report
        self.last_ssa_chains = self.build_use_def_chains(renumbered)

        return [cfg.nodes[idx] for idx in sorted(cfg.nodes)]

    def optimise_ir_text(self, code: str) -> str:
        """Parse ``code`` into IR, optimise it and return a formatted string."""

        instructions = self.parse_ir(code)
        optimised = self.optimise_ir(instructions)
        return self.format_ir(optimised)

    def format_ir(self, instructions: Iterable[IRInstruction]) -> str:
        """Return a compact textual representation of ``instructions``."""

        lines: List[str] = []
        for ins in instructions:
            operand = " ".join(ins.args)
            operand = f" {operand}" if operand else ""
            lines.append(f"{ins.index:04d} {ins.opcode}{operand}")
        return "\n".join(lines)

    def prune_unreachable(self, instructions: Iterable[IRInstruction]) -> List[IRInstruction]:
        """Remove unreachable IR instructions using a CFG walk."""

        cfg = self.build_cfg(instructions)
        reduced = self.remove_dead_code(cfg)
        return [deepcopy(reduced.nodes[idx]) for idx in sorted(reduced.nodes)]

    def analyze_ir(self, code: str) -> Tuple[CFG, str]:
        """Convenience wrapper to parse, optimise and reconstruct IR."""

        optimised_text = self.optimise_ir_text(code)
        assert self.last_cfg is not None
        pseudo = self.reconstruct_structures(self.last_cfg)
        return self.last_cfg, pseudo

    def optimise_vm_function(self, func: VMFunction) -> Dict[str, Any]:
        """Apply peephole simplifications to a lifted :class:`VMFunction`."""

        instructions = list(getattr(func, "instructions", []) or [])
        if not instructions:
            summary = {
                "function": func,
                "original_instructions": 0,
                "optimized_instructions": 0,
                "reduction": 0,
                "size_before": 0,
                "size_after": 0,
                "reduction_ratio": 0.0,
                "reduction_percent": 0.0,
            }
            self.last_vm_optimisation = summary
            return summary

        simplified: List[VMInstruction] = []
        for instr in instructions:
            replacement = self._optimise_vm_instruction(instr)
            if replacement is None:
                continue
            simplified.append(replacement)

        simplified = self._collapse_immediate_sequences(simplified)
        simplified = self._fold_return_moves(simplified)

        size_before = len(instructions)
        size_after = len(simplified)
        reduction = size_before - size_after
        ratio = reduction / size_before if size_before else 0.0
        optimised_function = VMFunction(
            constants=list(getattr(func, "constants", []) or []),
            instructions=simplified,
            prototypes=list(getattr(func, "prototypes", []) or []),
            num_params=getattr(func, "num_params", 0),
            is_vararg=getattr(func, "is_vararg", False),
            register_count=getattr(func, "register_count", 0),
            upvalue_count=getattr(func, "upvalue_count", 0),
            metadata=dict(getattr(func, "metadata", {}) or {}),
        )

        summary = {
            "function": optimised_function,
            "original_instructions": size_before,
            "optimized_instructions": size_after,
            "reduction": reduction,
            "size_before": size_before,
            "size_after": size_after,
            "reduction_ratio": ratio,
            "reduction_percent": ratio * 100,
        }
        self.last_vm_optimisation = summary
        return summary

    # ------------------------------------------------------------------
    # Register pressure and allocation helpers

    def analyse_register_model(self, vm_ir: Any) -> Dict[str, Any]:
        """Infer the VM operand model and build a symbolic allocation plan."""

        program = _coerce_vm_program(vm_ir)
        instructions = list(getattr(program, "instructions", []) or [])

        register_usage = self._vm_register_usage(instructions)
        stack_slots, stack_ops, max_stack_depth, stack_profile = self._plan_stack_slots(instructions)
        model = self._detect_vm_model(program, register_usage, stack_ops, max_stack_depth)

        if model == "register":
            allocation = self._allocate_registers(program, register_usage)
            pseudo = self._render_register_pseudo(program, allocation)
            pressure_profile = self._register_pressure_profile(instructions, allocation)
            max_pressure = max((entry["count"] for entry in pressure_profile), default=0)
            register_details = {
                idx: {
                    "name": allocation.get(idx, f"reg{idx}"),
                    "count": count,
                    "role": "param"
                    if idx < (getattr(program, "num_params", 0) or 0)
                    else "temp",
                }
                for idx, count in sorted(register_usage.items())
            }
        else:
            allocation = {}
            pseudo = self._render_stack_pseudo(instructions, stack_slots)
            pressure_profile = []
            max_pressure = 0
            register_details = {}

        analysis = {
            "model": model,
            "register_count": len(allocation),
            "register_usage": register_details,
            "max_register": max(register_usage.keys()) if register_usage else None,
            "max_pressure": max_pressure,
            "pressure_profile": pressure_profile,
            "stack_slots": stack_slots,
            "stack_depth": max_stack_depth,
            "stack_profile": stack_profile,
            "pseudo_lua": pseudo.strip(),
        }
        self.last_register_analysis = analysis
        return analysis

    def _vm_register_usage(self, instructions: Sequence[VMInstruction]) -> Dict[int, int]:
        usage: Counter[int] = Counter()
        for instr in instructions:
            if not isinstance(instr, VMInstruction):
                continue
            for operand in ("a", "b", "c"):
                if self._vm_operand_is_register(instr, operand):
                    value = getattr(instr, operand, None)
                    if isinstance(value, int):
                        usage[value] += 1
        return dict(sorted(usage.items()))

    def _plan_stack_slots(
        self, instructions: Sequence[VMInstruction]
    ) -> Tuple[Dict[int, str], int, int, List[Dict[str, Any]]]:
        stack_slots: Dict[int, str] = {}
        depth = 0
        max_depth = 0
        stack_ops = 0
        profile: List[Dict[str, Any]] = []

        for idx, instr in enumerate(instructions):
            if not isinstance(instr, VMInstruction):
                profile.append({"pc": idx, "depth": depth})
                continue
            opcode = str(instr.opcode).upper()
            pc = getattr(instr, "pc", idx)
            if "PUSH" in opcode:
                stack_ops += 1
                stack_slots.setdefault(depth, f"stack{depth}")
                depth += 1
                max_depth = max(max_depth, depth)
                profile.append({"pc": pc, "depth": depth})
                continue
            if "POP" in opcode:
                stack_ops += 1
                if depth > 0:
                    depth -= 1
                profile.append({"pc": pc, "depth": depth})
                continue
            if "STACK" in opcode or "TOP" in opcode or "PEEK" in opcode:
                stack_ops += 1
            profile.append({"pc": pc, "depth": depth})

        return stack_slots, stack_ops, max_depth, profile

    def _detect_vm_model(
        self,
        program: VMFunction,
        register_usage: Mapping[int, int],
        stack_ops: int,
        max_stack_depth: int,
    ) -> str:
        register_count = len(register_usage)
        register_hint = getattr(program, "register_count", 0) or 0

        if register_count:
            if stack_ops == 0:
                return "register"
            if register_hint and register_hint >= register_count:
                return "register"
            if register_count >= stack_ops:
                return "register"

        if stack_ops:
            if max_stack_depth > 0:
                return "stack"

        if register_hint:
            return "register"

        return "stack" if stack_ops else "register"

    def _allocate_registers(
        self, program: VMFunction, register_usage: Mapping[int, int]
    ) -> Dict[int, str]:
        param_count = getattr(program, "num_params", 0) or 0
        allocation: Dict[int, str] = {}
        for idx in sorted(register_usage):
            if idx < param_count:
                name = f"arg{idx}"
            else:
                name = f"t{idx}"
            allocation[idx] = name
        return allocation

    def _register_pressure_profile(
        self, instructions: Sequence[VMInstruction], allocation: Mapping[int, str]
    ) -> List[Dict[str, Any]]:
        profile: List[Dict[str, Any]] = []
        for idx, instr in enumerate(instructions):
            if not isinstance(instr, VMInstruction):
                continue
            pc = getattr(instr, "pc", idx)
            registers: Set[str] = set()
            for operand in ("a", "b", "c"):
                if self._vm_operand_is_register(instr, operand):
                    value = getattr(instr, operand, None)
                    if isinstance(value, int):
                        registers.add(allocation.get(value, f"reg{value}"))
            profile.append({"pc": pc, "registers": sorted(registers), "count": len(registers)})
        return profile

    def _render_register_pseudo(
        self, program: VMFunction, allocation: Mapping[int, str]
    ) -> str:
        instructions = list(getattr(program, "instructions", []) or [])
        if not instructions:
            return ""

        lines: List[str] = []
        if allocation:
            locals_line = ", ".join(allocation[idx] for idx in sorted(allocation))
            lines.append(f"local {locals_line}")

        for instr in instructions:
            if not isinstance(instr, VMInstruction):
                continue
            rendered = self._render_register_instruction(instr, allocation)
            lines.append(rendered)

        return "\n".join(lines)

    def _render_register_instruction(
        self, instr: VMInstruction, allocation: Mapping[int, str]
    ) -> str:
        opcode = str(instr.opcode).upper()
        dest_name: Optional[str] = None
        if self._vm_operand_is_register(instr, "a"):
            value = getattr(instr, "a", None)
            if isinstance(value, int):
                dest_name = allocation.get(value, f"reg{value}")

        load_ops = {"LOADK", "LOADN", "LOADBOOL", "LOADB"}
        arithmetic = {
            "ADD": "+",
            "SUB": "-",
            "MUL": "*",
            "DIV": "/",
            "MOD": "%",
            "POW": "^",
            "BAND": "&",
            "BOR": "|",
            "BXOR": "~",
            "SHL": "<<",
            "SHR": ">>",
        }

        if opcode in load_ops and dest_name:
            value = self._format_vm_operand(instr, "b", allocation)
            if value is not None:
                return f"{dest_name} = {value}  -- {opcode}"

        if opcode == "LOADNIL" and dest_name:
            return f"{dest_name} = nil  -- LOADNIL"

        if opcode == "MOVE" and dest_name:
            source = self._format_vm_operand(instr, "b", allocation)
            if source is not None:
                return f"{dest_name} = {source}  -- MOVE"

        if opcode in arithmetic and dest_name:
            left = self._format_vm_operand(instr, "b", allocation)
            right = self._format_vm_operand(instr, "c", allocation)
            if left is not None and right is not None:
                symbol = arithmetic[opcode]
                return f"{dest_name} = {left} {symbol} {right}  -- {opcode}"

        if opcode == "CONCAT" and dest_name:
            left = self._format_vm_operand(instr, "b", allocation)
            right = self._format_vm_operand(instr, "c", allocation)
            if left is not None and right is not None:
                return f"{dest_name} = {left} .. {right}  -- CONCAT"

        if opcode in {"NOT", "UNM", "LEN"} and dest_name:
            src = self._format_vm_operand(instr, "b", allocation)
            if src is not None:
                prefix = {"NOT": "not ", "UNM": "-", "LEN": "#"}[opcode]
                return f"{dest_name} = {prefix}{src}  -- {opcode}"

        if opcode == "RETURN":
            value = self._format_vm_operand(instr, "a", allocation)
            return f"return {value}" if value is not None else "return"

        if opcode == "CALL" and dest_name:
            base_index = getattr(instr, "a", 0) or 0
            arg_count = max(0, (getattr(instr, "b", 0) or 1) - 1)
            args = []
            for offset in range(arg_count):
                reg_index = base_index + 1 + offset
                args.append(allocation.get(reg_index, f"reg{reg_index}"))
            call_text = f"{dest_name}({', '.join(args)})" if args else f"{dest_name}()"
            result_count = getattr(instr, "c", None)
            if result_count is None or result_count == 0:
                return f"{call_text}  -- CALL returns all"
            if result_count == 1:
                return f"{call_text}  -- CALL"
            return f"{dest_name} = {call_text}  -- CALL x{result_count}"

        args: List[str] = []
        for operand in ("a", "b", "c"):
            formatted = self._format_vm_operand(instr, operand, allocation)
            if formatted is not None:
                args.append(formatted)
        if args:
            return f"-- {opcode} {' '.join(args)}"
        return f"-- {opcode}"

    def _render_stack_pseudo(
        self, instructions: Sequence[VMInstruction], stack_slots: Mapping[int, str]
    ) -> str:
        instructions = list(instructions)
        if not instructions:
            return ""

        lines: List[str] = []
        if stack_slots:
            locals_line = ", ".join(stack_slots[idx] for idx in sorted(stack_slots))
            lines.append(f"local {locals_line}")

        depth = 0
        for instr in instructions:
            if not isinstance(instr, VMInstruction):
                continue
            opcode = str(instr.opcode).upper()
            if "PUSH" in opcode:
                name = stack_slots.setdefault(depth, f"stack{depth}")
                value = self._stack_value(instr) or "/* value */"
                lines.append(f"{name} = {value}  -- {opcode}")
                depth += 1
                continue
            if "POP" in opcode:
                if depth > 0:
                    depth -= 1
                name = stack_slots.get(depth, f"stack{depth}")
                lines.append(f"{name} = nil  -- {opcode}")
                continue
            if "TOP" in opcode or "PEEK" in opcode:
                name = stack_slots.get(max(depth - 1, 0), stack_slots.get(0, "stack0"))
                lines.append(f"-- {opcode} {name}")
                continue
            lines.append(f"-- {opcode}")

        return "\n".join(lines)

    def _vm_operand_is_register(self, instr: VMInstruction, operand: str) -> bool:
        if not isinstance(instr, VMInstruction):
            return False
        value = getattr(instr, operand, None)
        if not isinstance(value, int):
            return False

        aux = getattr(instr, "aux", {}) or {}
        if isinstance(aux, Mapping):
            mode = aux.get(f"{operand}_mode")
            if isinstance(mode, str) and mode.lower() in {"const", "constant", "immediate", "literal", "stack"}:
                return False
            for prefix in ("const", "immediate", "literal"):
                key = f"{prefix}_{operand}"
                if key in aux:
                    return False

        ir_meta = getattr(instr, "ir", {}) or {}
        if isinstance(ir_meta, Mapping):
            mode = ir_meta.get(f"{operand}_mode")
            if isinstance(mode, str) and mode.lower() in {"const", "constant", "immediate", "literal", "stack"}:
                return False
            for prefix in ("const", "immediate", "literal"):
                key = f"{prefix}_{operand}"
                if key in ir_meta:
                    return False

        return True

    def _format_vm_operand(self, instr: VMInstruction, operand: str, allocation: Mapping[int, str]) -> Optional[str]:
        if not isinstance(instr, VMInstruction):
            return None

        value = getattr(instr, operand, None)

        if self._vm_operand_is_register(instr, operand):
            if isinstance(value, int):
                return allocation.get(value, f"reg{value}")
            if value is not None:
                return str(value)
            return None

        aux = getattr(instr, "aux", {}) or {}
        ir_meta = getattr(instr, "ir", {}) or {}
        for container in (aux, ir_meta):
            if isinstance(container, Mapping):
                for prefix in ("const", "literal", "immediate", "value"):
                    key = f"{prefix}_{operand}" if prefix != "value" else prefix
                    if key in container:
                        return self._format_literal(container[key])

        if value is None:
            return None

        if isinstance(value, (int, float, bool)) or value is None:
            return self._format_literal(value)
        if isinstance(value, str):
            return value
        return str(value)

    def _stack_value(self, instr: VMInstruction) -> Optional[str]:
        aux = getattr(instr, "aux", {}) or {}
        if isinstance(aux, Mapping):
            for key in (
                "value",
                "const",
                "literal",
                "immediate",
                "const_b",
                "literal_b",
                "immediate_b",
            ):
                if key in aux:
                    return self._format_literal(aux[key])

        ir_meta = getattr(instr, "ir", {}) or {}
        if isinstance(ir_meta, Mapping):
            for key in ("value", "const_b", "literal_b", "immediate_b"):
                if key in ir_meta:
                    return self._format_literal(ir_meta[key])

        a_value = getattr(instr, "a", None)
        if isinstance(a_value, (int, float, bool)) or a_value is None:
            return self._format_literal(a_value)
        if isinstance(a_value, str):
            return a_value
        return None

    # ------------------------------------------------------------------
    # Peephole helpers

    def _fold_constants(self, instructions: List[IRInstruction]) -> Tuple[List[IRInstruction], OptimizationReport]:
        report = OptimizationReport(opaque_predicates=set(), removed_blocks=set())
        state: Dict[str, Any] = {}
        result: List[IRInstruction] = []

        for ins in instructions:
            op = ins.opcode.upper()
            args = list(ins.args)
            current = IRInstruction(ins.index, op, args)

            if op in {"LOADK", "LOADN", "LOADBOOL", "LOADB"} and args:
                dest = args[0]
                value_token = args[1] if len(args) > 1 else "nil"
                value, known = self._parse_literal_token(value_token)
                if known:
                    state[dest] = value
                    current.args = [dest, self._format_literal(value)]
                else:
                    state.pop(dest, None)
            elif op == "LOADNIL" and args:
                dest = args[0]
                state[dest] = None
            elif op == "MOVE" and len(args) >= 2:
                dest, src = args[0], args[1]
                value, known = self._get_value(src, state)
                if known:
                    state[dest] = value
                else:
                    state.pop(dest, None)
            elif op in self._arithmetic_ops and len(args) >= 3:
                current = self._simplify_arithmetic(current, state, report)
            elif op == "CONCAT" and len(args) >= 3:
                dest = args[0]
                left_val, left_known = self._get_value(args[1], state)
                right_val, right_known = self._get_value(args[2], state)
                if left_known and right_known:
                    concatenated = f"{left_val}{right_val}"
                    current = IRInstruction(ins.index, "LOADK", [dest, self._format_literal(concatenated)])
                    state[dest] = concatenated
                    report.concatenation_simplifications += 1
                elif right_known and right_val == "":
                    current = IRInstruction(ins.index, "MOVE", [dest, args[1]])
                    state[dest] = left_val if left_known else state.get(args[1])
                    report.concatenation_simplifications += 1
                elif left_known and left_val == "":
                    current = IRInstruction(ins.index, "MOVE", [dest, args[2]])
                    state[dest] = right_val if right_known else state.get(args[2])
                    report.concatenation_simplifications += 1
                else:
                    state.pop(dest, None)
            elif op in {"NOT", "UNM", "LEN"} and len(args) >= 2:
                current = self._simplify_unary(current, state)
            elif op in self._branch_ops and args:
                outcome = self._evaluate_branch(current, state)
                if outcome is True:
                    target = args[-1]
                    current = IRInstruction(ins.index, "JMP", [target])
                    report.opaque_predicates.add(ins.index)
                    state.clear()
                elif outcome is False:
                    current = IRInstruction(ins.index, "NOP", [])
                    report.opaque_predicates.add(ins.index)
                    state.clear()
                else:
                    state.clear()
            elif op == "JMP":
                state.clear()
            else:
                dest = self._destination_register(current)
                if dest is not None:
                    state.pop(dest, None)

            result.append(current)

        return result, report

    def _simplify_arithmetic(
        self,
        ins: IRInstruction,
        state: Dict[str, Any],
        report: OptimizationReport,
    ) -> IRInstruction:
        dest, left_token, right_token = ins.args[:3]
        left_val, left_known = self._get_value(left_token, state)
        right_val, right_known = self._get_value(right_token, state)
        op = ins.opcode

        if left_known and right_known:
            try:
                if op == "ADD":
                    value = left_val + right_val
                elif op == "SUB":
                    value = left_val - right_val
                elif op == "MUL":
                    value = left_val * right_val
                elif op == "DIV":
                    value = left_val / right_val
                elif op == "IDIV":
                    value = left_val // right_val
                elif op == "MOD":
                    value = left_val % right_val
                elif op == "POW":
                    value = left_val ** right_val
                elif op == "BAND":
                    value = left_val & right_val
                elif op == "BOR":
                    value = left_val | right_val
                elif op == "BXOR":
                    value = left_val ^ right_val
                elif op == "SHL":
                    value = left_val << right_val
                elif op == "SHR":
                    value = left_val >> right_val
                else:
                    raise ValueError
            except Exception:
                state.pop(dest, None)
                return ins
            state[dest] = value
            report.folded_constants += 1
            return IRInstruction(ins.index, "LOADK", [dest, self._format_literal(value)])

        # Arithmetic no-op rules when one operand is constant
        if right_known:
            if op in {"ADD", "SUB"} and right_val == 0:
                state[dest] = left_val if left_known else state.get(left_token)
                report.arithmetic_simplifications += 1
                return IRInstruction(ins.index, "MOVE", [dest, left_token])
            if op == "MUL" and right_val == 1:
                state[dest] = left_val if left_known else state.get(left_token)
                report.arithmetic_simplifications += 1
                return IRInstruction(ins.index, "MOVE", [dest, left_token])
            if op in {"MUL", "BAND", "BOR", "BXOR"} and right_val == 0:
                state[dest] = 0
                report.arithmetic_simplifications += 1
                return IRInstruction(ins.index, "LOADK", [dest, "0"])
        if left_known:
            if op == "ADD" and left_val == 0:
                state[dest] = right_val if right_known else state.get(right_token)
                report.arithmetic_simplifications += 1
                return IRInstruction(ins.index, "MOVE", [dest, right_token])
            if op == "MUL" and left_val == 1:
                state[dest] = right_val if right_known else state.get(right_token)
                report.arithmetic_simplifications += 1
                return IRInstruction(ins.index, "MOVE", [dest, right_token])
            if op in {"MUL", "BAND", "BOR", "BXOR"} and left_val == 0:
                state[dest] = 0
                report.arithmetic_simplifications += 1
                return IRInstruction(ins.index, "LOADK", [dest, "0"])

        state.pop(dest, None)
        return ins

    def _simplify_unary(self, ins: IRInstruction, state: Dict[str, Any]) -> IRInstruction:
        dest, src = ins.args[:2]
        value, known = self._get_value(src, state)
        op = ins.opcode

        if known:
            try:
                if op == "NOT":
                    result = not bool(value)
                elif op == "UNM":
                    result = -value
                elif op == "LEN":
                    result = len(value)
                else:
                    raise ValueError
            except Exception:
                state.pop(dest, None)
                return ins
            state[dest] = result
            return IRInstruction(ins.index, "LOADK", [dest, self._format_literal(result)])

        state.pop(dest, None)
        return ins

    def _evaluate_branch(self, ins: IRInstruction, state: Dict[str, Any]) -> Optional[bool]:
        op = ins.opcode
        args = ins.args
        operands = args[:-1] if len(args) > 1 else args

        if not operands:
            return None

        values: List[Any] = []
        for token in operands:
            value, known = self._get_value(token, state)
            if not known:
                return None
            values.append(value)

        if op in {"EQ", "NE", "LT", "LE", "GT", "GE"} and len(values) >= 2:
            left, right = values[0], values[1]
            if op == "EQ":
                return left == right
            if op == "NE":
                return left != right
            if op == "LT":
                return left < right
            if op == "LE":
                return left <= right
            if op == "GT":
                return left > right
            if op == "GE":
                return left >= right
        if op in {"TEST", "TESTSET", "JMPIF", "JMPTRUE"}:
            return bool(values[0])
        if op in {"JMPIFNOT", "JMPFALSE"}:
            return not bool(values[0])

        return None

    def _remove_nops(self, instructions: Iterable[IRInstruction]) -> List[IRInstruction]:
        return [ins for ins in instructions if ins.opcode != "NOP"]

    def _eliminate_bogus_loops(self, instructions: List[IRInstruction]) -> List[IRInstruction]:
        cleaned: List[IRInstruction] = []
        for ins in instructions:
            if ins.opcode == "JMP" and ins.args:
                target = self._parse_int(ins.args[0])
                if target is None:
                    cleaned.append(ins)
                    continue
                if target == ins.index or target == ins.index + 1:
                    cleaned.append(IRInstruction(ins.index, "NOP", []))
                    continue
            cleaned.append(ins)
        return cleaned

    def _peephole_cleanup(self, instructions: List[IRInstruction], report: OptimizationReport) -> List[IRInstruction]:
        cleaned: List[IRInstruction] = []
        last_jump_target: Optional[str] = None
        for ins in instructions:
            if ins.opcode == "JMP" and ins.args:
                target = ins.args[0]
                if target == last_jump_target:
                    report.eliminated_jumps += 1
                    continue
                last_jump_target = target
            else:
                last_jump_target = None
            cleaned.append(ins)
        return cleaned

    def _renumber(self, instructions: List[IRInstruction]) -> List[IRInstruction]:
        if not instructions:
            return []
        ordered = sorted(instructions, key=lambda ins: ins.index)
        mapping = {ins.index: new_idx for new_idx, ins in enumerate(ordered)}
        renumbered: List[IRInstruction] = []
        for original in ordered:
            new_idx = mapping[original.index]
            args = list(original.args)
            if original.opcode == "JMP" and args:
                target = self._parse_int(args[0])
                if target is not None and target in mapping:
                    args[0] = str(mapping[target])
            elif original.opcode in self._branch_ops and args:
                target = self._parse_int(args[-1])
                if target is not None and target in mapping:
                    args[-1] = str(mapping[target])
            renumbered.append(IRInstruction(new_idx, original.opcode, args))
        return renumbered

    def _destination_register(self, ins: IRInstruction) -> Optional[str]:
        if not ins.args:
            return None
        if ins.opcode in {"LOADK", "LOADN", "LOADBOOL", "LOADB", "LOADNIL", "MOVE", "NOT", "UNM", "LEN", "CONCAT"}:
            return ins.args[0]
        if ins.opcode in self._arithmetic_ops:
            return ins.args[0]
        return None

    def _source_registers(self, ins: IRInstruction) -> List[str]:
        sources: List[str] = []
        args = ins.args
        if not args:
            return sources
        if ins.opcode in {"MOVE", "NOT", "UNM", "LEN"} and len(args) >= 2:
            if self._is_register(args[1]):
                sources.append(args[1])
        elif ins.opcode in self._arithmetic_ops or ins.opcode == "CONCAT":
            for token in args[1:]:
                if self._is_register(token):
                    sources.append(token)
        elif ins.opcode in self._branch_ops:
            for token in args[:-1]:
                if self._is_register(token):
                    sources.append(token)
        return sources

    def _optimise_vm_instruction(self, instr: VMInstruction) -> Optional[VMInstruction]:
        opcode = instr.opcode.upper() if isinstance(instr.opcode, str) else str(instr.opcode)

        if opcode == "MOVE" and instr.a == instr.b:
            return None

        arithmetic_ops = {
            "ADD",
            "SUB",
            "MUL",
            "DIV",
            "MOD",
            "POW",
            "IDIV",
            "BAND",
            "BOR",
            "BXOR",
            "SHL",
            "SHR",
        }

        if opcode in arithmetic_ops:
            left_val, left_const = self._vm_operand_value(instr, "b")
            right_val, right_const = self._vm_operand_value(instr, "c")

            if left_const and right_const:
                try:
                    if opcode == "ADD":
                        value = left_val + right_val
                    elif opcode == "SUB":
                        value = left_val - right_val
                    elif opcode == "MUL":
                        value = left_val * right_val
                    elif opcode == "DIV":
                        value = left_val / right_val
                    elif opcode == "MOD":
                        value = left_val % right_val
                    elif opcode == "POW":
                        value = left_val ** right_val
                    elif opcode == "IDIV":
                        value = left_val // right_val
                    elif opcode == "BAND":
                        value = left_val & right_val
                    elif opcode == "BOR":
                        value = left_val | right_val
                    elif opcode == "BXOR":
                        value = left_val ^ right_val
                    elif opcode == "SHL":
                        value = left_val << right_val
                    elif opcode == "SHR":
                        value = left_val >> right_val
                    else:
                        raise ValueError
                except Exception:
                    pass
                else:
                    return self._vm_make_loadk(instr, value)

            if right_const and right_val == 0 and opcode in {"ADD", "SUB"} and instr.b is not None:
                return replace(instr, opcode="MOVE", c=None, aux={}, offset=None)
            if right_const and right_val == 1 and opcode == "MUL" and instr.b is not None:
                return replace(instr, opcode="MOVE", c=None, aux={}, offset=None)
            if opcode in {"MUL", "BAND", "BOR", "BXOR"} and (
                (right_const and right_val == 0) or (left_const and left_val == 0)
            ):
                return self._vm_make_loadk(instr, 0)
            if opcode == "SHL" and right_const and right_val == 0 and instr.b is not None:
                return replace(instr, opcode="MOVE", c=None, aux={}, offset=None)

        return replace(instr)

    def _collapse_immediate_sequences(self, instructions: List[VMInstruction]) -> List[VMInstruction]:
        collapsed: List[VMInstruction] = []
        last_assignment: Dict[int, Tuple[str, Any]] = {}

        for instr in instructions:
            opcode = instr.opcode.upper() if isinstance(instr.opcode, str) else str(instr.opcode)
            if opcode == "LOADK" and instr.a is not None:
                value, known = self._vm_loadk_value(instr)
                if known:
                    key = ("LOADK", value)
                    if last_assignment.get(instr.a) == key:
                        continue
                    last_assignment[instr.a] = key
                else:
                    last_assignment.pop(instr.a, None)
            elif instr.a is not None:
                last_assignment.pop(instr.a, None)
            collapsed.append(instr)

        return collapsed

    def _fold_return_moves(self, instructions: List[VMInstruction]) -> List[VMInstruction]:
        if not instructions:
            return []

        result: List[VMInstruction] = []
        index = 0
        length = len(instructions)

        while index < length:
            instr = instructions[index]
            opcode = instr.opcode.upper() if isinstance(instr.opcode, str) else str(instr.opcode)
            if (
                opcode == "MOVE"
                and instr.a is not None
                and instr.b is not None
                and index + 1 < length
            ):
                next_instr = instructions[index + 1]
                next_opcode = (
                    next_instr.opcode.upper()
                    if isinstance(next_instr.opcode, str)
                    else str(next_instr.opcode)
                )
                if next_opcode == "RETURN" and getattr(next_instr, "a", None) == instr.a:
                    replacement = replace(next_instr, a=instr.b)
                    result.append(replacement)
                    index += 2
                    continue
            result.append(instr)
            index += 1

        return result

    def _vm_operand_value(self, instr: VMInstruction, operand: str) -> Tuple[Any, bool]:
        aux = getattr(instr, "aux", {}) or {}
        if isinstance(aux, Mapping):
            mode = aux.get(f"{operand}_mode")
            if mode in {"const", "constant"}:
                key = f"const_{operand}"
                if key in aux:
                    return aux[key], True
            if mode == "immediate":
                key = f"immediate_{operand}"
                if key in aux:
                    return aux[key], True
            literal_key = f"literal_{operand}"
            if literal_key in aux:
                return aux[literal_key], True
        ir_meta = getattr(instr, "ir", {}) or {}
        if isinstance(ir_meta, Mapping):
            for prefix in ("const", "immediate", "literal"):
                key = f"{prefix}_{operand}"
                if key in ir_meta:
                    return ir_meta[key], True
        return None, False

    def _vm_loadk_value(self, instr: VMInstruction) -> Tuple[Any, bool]:
        value, known = self._vm_operand_value(instr, "b")
        return value, known

    def _vm_make_loadk(self, instr: VMInstruction, value: Any) -> VMInstruction:
        aux = {"b_mode": "const", "const_b": value}
        ir_meta = dict(getattr(instr, "ir", {}) or {})
        ir_meta["const_b"] = value
        return replace(instr, opcode="LOADK", b=None, c=None, aux=aux, offset=None, ir=ir_meta)

    def _get_value(self, token: str, state: Dict[str, Any]) -> Tuple[Any, bool]:
        if self._is_register(token):
            if token in state:
                return state[token], True
            return None, False
        return self._parse_literal_token(token)

    def _parse_literal_token(self, token: str) -> Tuple[Any, bool]:
        token = token.strip()
        lower = token.lower()
        if lower in {"true", "false"}:
            return lower == "true", True
        if lower == "nil":
            return None, True
        if token.startswith("\"") and token.endswith("\""):
            return token[1:-1], True
        if token.startswith("'") and token.endswith("'"):
            return token[1:-1], True
        try:
            if token.startswith("0x") or token.startswith("-0x"):
                return int(token, 16), True
            if any(ch in token for ch in ".eE"):
                return float(token), True
            return int(token, 10), True
        except ValueError:
            return token, False

    def _format_literal(self, value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "nil"
        if isinstance(value, str):
            return repr(value)
        return str(value)

    def _is_register(self, token: str) -> bool:
        if not token:
            return False
        if token[0] in "\"'":
            return False
        lowered = token.lower()
        if lowered in {"true", "false", "nil"}:
            return False
        if token[0] == "-" and token[1:].isdigit():
            return False
        if token.replace(".", "", 1).isdigit():
            return False
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", token))

    def _parse_int(self, token: str) -> Optional[int]:
        try:
            return int(token, 10)
        except Exception:
            return None


class _FunctionScanner(_AstVisitorBase):
    """Collect VM-dispatch heuristics from a single function body."""

    def __init__(
        self,
        source: str,
        astnodes,
        line_starts: List[int],
    ) -> None:
        super().__init__()
        self._source = source
        self._astnodes = astnodes
        self._line_starts = line_starts
        self.if_chains: List[CaseChain] = []
        self.table_calls: List[str] = []
        self.bit_ops: List[str] = []
        self._seen_if_nodes: Set[int] = set()
        self._function_depth = 0

    def enter_If(self, node):  # type: ignore[override]
        if self._function_depth > 0:
            return
        if id(node) in self._seen_if_nodes:
            return
        chain = _extract_case_chain(self._astnodes, node, self._source, self._line_starts)
        if chain:
            self.if_chains.append(chain)
            for branch in _iter_if_chain_nodes(self._astnodes, node):
                self._seen_if_nodes.add(id(branch))

    def enter_Call(self, node):  # type: ignore[override]
        if self._function_depth > 0:
            return
        table_name = _table_name_from_call(self._astnodes, node)
        if table_name and table_name not in self.table_calls:
            self.table_calls.append(table_name)
        bit_name = _bit_operation_name(self._astnodes, node)
        if bit_name and bit_name not in self.bit_ops:
            self.bit_ops.append(bit_name)

    def enter_Function(self, node):  # type: ignore[override]
        self._function_depth += 1

    def exit_Function(self, node):  # type: ignore[override]
        self._function_depth -= 1

    def enter_LocalFunction(self, node):  # type: ignore[override]
        self._function_depth += 1

    def exit_LocalFunction(self, node):  # type: ignore[override]
        self._function_depth -= 1

    def enter_AnonymousFunction(self, node):  # type: ignore[override]
        self._function_depth += 1

    def exit_AnonymousFunction(self, node):  # type: ignore[override]
        self._function_depth -= 1


class _VMVisitor(_AstVisitorBase):
    """AST visitor that aggregates VM-dispatch candidates."""

    def __init__(self, source: str, ast_module, astnodes_module) -> None:
        super().__init__()
        self._source = source
        self._ast = ast_module
        self._astnodes = astnodes_module
        self._line_starts = _compute_line_starts(source)
        self.handler_tables: Dict[str, HandlerTableInfo] = {}
        self.dispatchers: List[Dict[str, Any]] = []
        self._processed_functions: Set[int] = set()
        self._function_node_types = (
            astnodes_module.Function,
            astnodes_module.LocalFunction,
            astnodes_module.AnonymousFunction,
        )

    def enter_LocalAssign(self, node):  # type: ignore[override]
        self._handle_assignment(getattr(node, "targets", []), getattr(node, "values", []))

    def enter_Assign(self, node):  # type: ignore[override]
        self._handle_assignment(getattr(node, "targets", []), getattr(node, "values", []))

    def enter_LocalFunction(self, node):  # type: ignore[override]
        name = self._resolve_name(getattr(node, "name", None))
        self._evaluate_function_node(node, name)

    def enter_Function(self, node):  # type: ignore[override]
        name = self._resolve_name(getattr(node, "name", None))
        self._evaluate_function_node(node, name)

    def enter_Return(self, node):  # type: ignore[override]
        for value in getattr(node, "values", []) or []:
            if isinstance(value, self._function_node_types):
                self._evaluate_function_node(value, None)

    def _handle_assignment(self, targets: Iterable[object], values: Iterable[object]) -> None:
        for target, value in zip(list(targets or []), list(values or [])):
            name = self._resolve_name(target)
            if isinstance(value, self._astnodes.Table) and name:
                info = self._extract_handler_table(value)
                if info:
                    info.name = name
                    self.handler_tables[name] = info
            if isinstance(value, self._function_node_types):
                self._evaluate_function_node(value, name)

    def _resolve_name(self, node: object) -> Optional[str]:
        return _resolve_name(self._astnodes, node)

    def _line_for(self, offset: int) -> Tuple[int, int]:
        return _offset_to_line_col(offset, self._line_starts)

    def _extract_handler_table(self, table_node) -> Optional[HandlerTableInfo]:
        if not isinstance(table_node, self._astnodes.Table):
            return None
        fields = getattr(table_node, "fields", []) or []
        if not fields:
            return None
        function_keys: List[str] = []
        for index, field in enumerate(fields, start=1):
            value = getattr(field, "value", None)
            if isinstance(value, self._function_node_types):
                key_repr = _field_key_repr(self._astnodes, getattr(field, "key", None), index)
                if key_repr:
                    function_keys.append(key_repr)
        if len(function_keys) < 2 or len(function_keys) / len(fields) < 0.5:
            return None
        line, _ = self._line_for(getattr(table_node, "start_char", 0))
        snippet = _extract_snippet(
            self._source,
            getattr(table_node, "start_char", None),
            getattr(table_node, "stop_char", None),
        )
        return HandlerTableInfo(
            name="",
            line=line,
            function_entries=len(function_keys),
            total_entries=len(fields),
            sample_keys=function_keys[:5],
            snippet=snippet,
        )

    def _evaluate_function_node(self, node, name: Optional[str]) -> None:
        if id(node) in self._processed_functions:
            return
        self._processed_functions.add(id(node))
        body = getattr(node, "body", None)
        if body is None:
            return
        scanner = _FunctionScanner(
            self._source,
            self._astnodes,
            self._line_starts,
        )
        scanner.visit(body)

        best_chain = None
        if scanner.if_chains:
            best_chain = max(scanner.if_chains, key=lambda chain: len(chain.cases))
        table_hits = scanner.table_calls
        known_tables = [tbl for tbl in table_hits if tbl in self.handler_tables]

        score = 0
        if best_chain:
            score += len(best_chain.cases) * 2
        if known_tables:
            score += len(known_tables) * 2
        elif table_hits:
            score += len(table_hits)
        if scanner.bit_ops:
            score += len(scanner.bit_ops)

        if best_chain is None and not known_tables:
            return
        if score < 4:
            return

        line, _ = self._line_for(getattr(node, "start_char", 0))

        opcode_cases: List[Dict[str, object]] = []
        if best_chain:
            for case in best_chain.cases[:5]:
                opcode_cases.append(
                    {
                        "opcode": case.opcode,
                        "line": case.line,
                        "snippet": case.snippet,
                    }
                )

        handler_tables: List[Dict[str, object]] = []
        for table_name in known_tables:
            info = self.handler_tables.get(table_name)
            if info is None:
                continue
            handler_tables.append(
                {
                    "name": info.name,
                    "line": info.line,
                    "function_entries": info.function_entries,
                    "total_entries": info.total_entries,
                    "sample_keys": info.sample_keys,
                    "snippet": info.snippet,
                }
            )

        summary_parts = [f"{name or '<anonymous>'} (line {line})"]
        if best_chain:
            summary_parts.append(f"{len(best_chain.cases)}-case if-chain on `{best_chain.variable}`")
        if handler_tables:
            summary_parts.append(
                "handler tables: "
                + ", ".join(
                    f"{entry['name']} ({entry['function_entries']}/{entry['total_entries']})"
                    for entry in handler_tables
                )
            )
        elif table_hits:
            summary_parts.append("table dispatch via: " + ", ".join(table_hits))
        if scanner.bit_ops:
            summary_parts.append("bit ops: " + ", ".join(scanner.bit_ops))

        self.dispatchers.append(
            {
                "name": name,
                "line": line,
                "score": score,
                "opcode_cases": opcode_cases,
                "handler_tables": handler_tables,
                "bit_ops": list(scanner.bit_ops),
                "summary": "; ".join(summary_parts),
                "ast": node,
            }
        )


def _static_rebuild_text(source: str) -> Optional[str]:
    try:
        from version_detector import pipeline_static_rebuild
    except ImportError:  # pragma: no cover - optional fallback
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "input.lua"
        tmp_path.write_text(source, encoding="utf-8")
        output_path = Path(tmpdir) / "rebuilt.lua"
        try:
            result = pipeline_static_rebuild(tmp_path, output_path=output_path)
        except Exception:  # pragma: no cover - sanitising errors fall back to regex
            return None
        rebuilt_path = Path(result.get("output_path", output_path))
        if rebuilt_path.exists():
            return rebuilt_path.read_text(encoding="utf-8")
    return None


def _fallback_scan_text(source: str) -> List[Dict[str, Any]]:
    """Return VM dispatcher candidates using regex heuristics."""

    starts = _compute_line_starts(source)
    table_pattern = re.compile(
        r"(?P<table>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<opcode>0x[0-9A-Fa-f]+|\d+)\s*\]\s*=\s*function",
        re.S,
    )
    table_data: Dict[str, Dict[str, Any]] = {}
    for match in table_pattern.finditer(source):
        table_name = match.group("table")
        opcode_token = match.group("opcode")
        pos = match.start()
        info = table_data.setdefault(
            table_name,
            {"count": 0, "keys": [], "first_pos": pos},
        )
        info["count"] += 1
        info["keys"].append(opcode_token)
        if pos < info["first_pos"]:
            info["first_pos"] = pos

    anonymous_pattern = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function\b")
    for match in anonymous_pattern.finditer(source):
        key = match.group(1)
        pos = match.start()
        info = table_data.setdefault(
            "return_table",
            {"count": 0, "keys": [], "first_pos": pos},
        )
        info["count"] += 1
        info["keys"].append(key)
        if pos < info["first_pos"]:
            info["first_pos"] = pos

    normalized_tables: Dict[str, Dict[str, Any]] = {}
    for name, data in table_data.items():
        if data["count"] < 2:
            continue
        line, _ = _offset_to_line_col(data["first_pos"], starts)
        snippet = _extract_snippet(source, data["first_pos"], data["first_pos"] + 200)
        normalized_tables[name] = {
            "name": name,
            "line": line,
            "function_entries": data["count"],
            "total_entries": data["count"],
            "sample_keys": data["keys"][:5],
            "snippet": snippet,
        }

    func_pattern = re.compile(r"(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", re.S)
    table_call_pattern = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]]+)\s*\]")
    if_pattern = re.compile(
        r"(?:if|elseif)\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(0x[0-9A-Fa-f]+|-?\d+)\s*then",
        re.S,
    )
    bit_pattern = re.compile(r"bit32\.[A-Za-z_][A-Za-z0-9_]*|bit\.[A-Za-z_][A-Za-z0-9_]*")
    results: List[Dict[str, Any]] = []
    for func_match in func_pattern.finditer(source):
        func_pos = func_match.start()
        name = func_match.group(1)
        snippet_end = min(len(source), func_pos + 2000)
        snippet = source[func_pos:snippet_end]

        cases: List[OpcodeCase] = []
        var_name: Optional[str] = None
        for case_match in if_pattern.finditer(snippet):
            candidate_var = case_match.group(1)
            opcode_token = case_match.group(2)
            if var_name is None:
                var_name = candidate_var
            elif candidate_var != var_name:
                continue
            opcode_value = _parse_numeric_literal(opcode_token)
            abs_pos = func_pos + case_match.start()
            line, _ = _offset_to_line_col(abs_pos, starts)
            line_end = source.find("\n", abs_pos)
            case_snippet = _extract_snippet(
                source,
                abs_pos,
                line_end if line_end != -1 else abs_pos + 160,
            )
            cases.append(
                OpcodeCase(
                    opcode=opcode_value if opcode_value is not None else opcode_token,
                    line=line,
                    snippet=case_snippet,
                )
            )
            if len(cases) >= 5:
                break

        if var_name is None or len(cases) < 2:
            continue

        table_hits: List[str] = []
        for call_match in table_call_pattern.finditer(snippet):
            table_name = call_match.group(1)
            if table_name not in table_hits:
                table_hits.append(table_name)

        bit_ops: List[str] = []
        for bit_match in bit_pattern.finditer(snippet):
            bit_name = bit_match.group(0)
            if bit_name not in bit_ops:
                bit_ops.append(bit_name)

        known_tables = [tbl for tbl in table_hits if tbl in normalized_tables]

        score = len(cases) * 2
        if known_tables:
            score += len(known_tables) * 2
        elif table_hits:
            score += len(table_hits)
        if bit_ops:
            score += len(bit_ops)
        if score < 4:
            continue

        func_line, _ = _offset_to_line_col(func_pos, starts)
        handler_tables = [normalized_tables[tbl] for tbl in known_tables]
        if not handler_tables and "return_table" in normalized_tables:
            handler_tables = [normalized_tables["return_table"]]

        summary_parts = [f"{name} (line {func_line})", f"{len(cases)}-case if-chain on `{var_name}`"]
        if handler_tables:
            summary_parts.append(
                "handler tables: "
                + ", ".join(
                    f"{entry['name']} ({entry['function_entries']}/{entry['total_entries']})"
                    for entry in handler_tables
                )
            )
        elif table_hits:
            summary_parts.append("table dispatch via: " + ", ".join(table_hits))
        if bit_ops:
            summary_parts.append("bit ops: " + ", ".join(bit_ops))

        results.append(
            {
                "name": name,
                "line": func_line,
                "score": score,
                "opcode_cases": [
                    {"opcode": case.opcode, "line": case.line, "snippet": case.snippet}
                    for case in cases
                ],
                "handler_tables": handler_tables,
                "bit_ops": bit_ops,
                "summary": "; ".join(summary_parts),
            }
        )

    if not results and normalized_tables:
        for info in normalized_tables.values():
            sample_cases: List[Dict[str, object]] = []
            for idx, key in enumerate(info["sample_keys"]):
                opcode_value = _parse_numeric_literal(str(key))
                if opcode_value is None:
                    opcode_value = idx
                sample_cases.append(
                    {
                        "opcode": opcode_value,
                        "line": info["line"],
                        "snippet": str(key),
                    }
                )
            results.append(
                {
                    "name": info["name"],
                    "line": info["line"],
                    "score": info["function_entries"],
                    "opcode_cases": sample_cases,
                    "handler_tables": [info],
                    "bit_ops": [],
                    "summary": f"{info['name']} table with {info['function_entries']} handlers",
                }
            )

    return sorted(results, key=lambda item: item["score"], reverse=True)


def _normalise_numeric_opcode(opcode: object) -> Optional[int]:
    """Return an integer opcode when ``opcode`` looks numeric."""

    if isinstance(opcode, bool):  # guard against bool being an int subclass
        return None
    if isinstance(opcode, int):
        return opcode
    if isinstance(opcode, float):
        return int(opcode) if opcode.is_integer() else None
    if isinstance(opcode, str):
        return _parse_numeric_literal(opcode)
    return None


class _HandlerCollector(_AstVisitorBase):
    """Collect handler function bodies for VM tables."""

    def __init__(
        self,
        source: str,
        astnodes_module,
        table_names: Optional[Set[str]],
    ) -> None:
        super().__init__()
        self._source = source
        self._astnodes = astnodes_module
        self._table_names = set(table_names) if table_names else None
        self._line_starts = _compute_line_starts(source)
        self._function_types = (
            astnodes_module.Function,
            astnodes_module.LocalFunction,
            astnodes_module.AnonymousFunction,
        )
        self.handlers: Dict[str, Dict[int, Dict[str, str]]] = defaultdict(dict)

    def enter_Assign(self, node):  # type: ignore[override]
        self._handle_pairs(getattr(node, "targets", []), getattr(node, "values", []))

    def enter_LocalAssign(self, node):  # type: ignore[override]
        self._handle_pairs(getattr(node, "targets", []), getattr(node, "values", []))

    def _handle_pairs(self, targets: Iterable[object], values: Iterable[object]) -> None:
        for target, value in zip(list(targets or []), list(values or [])):
            if not isinstance(target, self._astnodes.Index):
                continue
            base = _resolve_name(self._astnodes, getattr(target, "value", None))
            if not base:
                continue
            if self._table_names is not None and base not in self._table_names:
                continue
            if not isinstance(value, self._function_types):
                continue
            opcode_expr = getattr(target, "idx", None)
            opcode_obj = _extract_number(self._astnodes, opcode_expr)
            if opcode_obj is None and opcode_expr is not None:
                key_repr = _resolve_name(self._astnodes, opcode_expr)
                if key_repr is not None:
                    opcode_obj = _parse_numeric_literal(str(key_repr))
                elif isinstance(opcode_expr, self._astnodes.String):
                    opcode_obj = _parse_numeric_literal(opcode_expr.s)
            if opcode_obj is None:
                continue
            if isinstance(opcode_obj, float):
                if not opcode_obj.is_integer():
                    continue
                opcode_obj = int(opcode_obj)
            if not isinstance(opcode_obj, int):
                continue
            start = getattr(value, "start_char", None)
            stop = getattr(value, "stop_char", None)
            text = self._source[start:stop] if start is not None and stop is not None else ""
            snippet = _extract_snippet(self._source, start, stop)
            line: Optional[int] = None
            column: Optional[int] = None
            if start is not None:
                line, column = _offset_to_line_col(start, self._line_starts)
            self.handlers[base][opcode_obj] = {
                "text": text,
                "snippet": snippet,
                "start": start,
                "stop": stop,
                "line": line,
                "column": column,
            }


def _collect_handler_bodies(source: str, table_names: Iterable[str]) -> Dict[str, Dict[int, Dict[str, str]]]:
    try:
        from luaparser import ast, astnodes
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise RuntimeError("opcode_semantics_guesses requires luaparser to be installed") from exc

    names = {name for name in table_names if name}
    collector = _HandlerCollector(source, astnodes, names if names else None)
    try:
        tree = ast.parse(source)
        collector.visit(tree)
        return collector.handlers
    except ast.SyntaxException:
        rebuilt = _static_rebuild_text(source)
        if not rebuilt:
            return {}
        try:
            tree = ast.parse(rebuilt)
        except ast.SyntaxException:
            return {}
        rebuilt_collector = _HandlerCollector(rebuilt, astnodes, names if names else None)
        rebuilt_collector.visit(tree)
        return rebuilt_collector.handlers


def _extract_top_level_helpers(source: str) -> Dict[str, Dict[str, object]]:
    try:
        from version_detector import _extract_returned_table_with_span
        try:
            from version_detector import _decode_short_fragment as _decode_helper_key
        except ImportError:  # pragma: no cover - fallback if helper unavailable
            _decode_helper_key = None
    except ImportError:  # pragma: no cover - version detector not present
        return {}

    located = _extract_returned_table_with_span(source)
    if not located:
        return {}

    base_offset, _, table_src = located
    helpers: Dict[str, Dict[str, object]] = {}
    line_starts = _compute_line_starts(source)

    pattern = re.compile(
        r"""
        (?P<prefix>
            \[\s*(?P<quote>['"])(?P<bracket_key>[^\]]*?)(?P=quote)\s*\]
            |
            (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
        )
        \s*=\s*function\b
        """,
        re.VERBOSE,
    )

    for match in pattern.finditer(table_src):
        name = match.group("ident")
        if not name:
            raw = match.group("bracket_key")
            quote = match.group("quote")
            if raw is None or quote is None:
                continue
            if _decode_helper_key is not None:
                try:
                    name = _decode_helper_key(f"{quote}{raw}{quote}")
                except Exception:  # pragma: no cover - defensive decoding guard
                    name = raw
            else:
                name = raw
        if not name:
            continue

        func_pos = table_src.find("function", match.start(), match.end())
        if func_pos == -1:
            continue
        rel_end = _find_function_end(table_src, func_pos + len("function"))
        if rel_end is None:
            continue

        start_rel = func_pos
        abs_start = base_offset + start_rel
        abs_end = base_offset + rel_end
        body = table_src[start_rel:rel_end]
        snippet = _extract_snippet(table_src, start_rel, rel_end)
        line, column = _offset_to_line_col(abs_start, line_starts)

        helpers[name] = {
            "body": body,
            "snippet": snippet,
            "start": abs_start,
            "stop": abs_end,
            "line": line,
            "column": column,
        }

    return helpers


def _find_helper_call_offsets(text: str, helper_name: str) -> List[int]:
    offsets: Set[int] = set()
    prefixed_patterns = [
        re.compile(rf":\s*{re.escape(helper_name)}\s*\("),
        re.compile(rf"\.\s*{re.escape(helper_name)}\s*\("),
    ]
    for pattern in prefixed_patterns:
        for match in pattern.finditer(text):
            token = match.group(0)
            inner = token.find(helper_name)
            if inner >= 0:
                offsets.add(match.start() + inner)

    direct_pattern = re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(helper_name)}(?![A-Za-z0-9_])\s*\("
    )
    for match in direct_pattern.finditer(text):
        prev_index = match.start() - 1
        if prev_index >= 0 and text[prev_index] in {":", "."}:
            continue
        token = match.group(0)
        inner = token.find(helper_name)
        if inner >= 0:
            offsets.add(match.start() + inner)

    return sorted(offsets)


def helpers_to_opcodes(
    src: str,
    *,
    output_path: Optional[Path | str] = Path("helpers_to_opcodes.json"),
) -> Dict[str, Any]:
    """Map top-level helper functions to the opcodes that invoke them."""

    try:
        import luaparser  # noqa: F401  # ensure dependency availability
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise RuntimeError("helpers_to_opcodes requires luaparser to be installed") from exc

    helpers = _extract_top_level_helpers(src)
    handler_tables: List[str] = []
    handler_map: Dict[str, Dict[int, Dict[str, object]]] = {}

    try:
        signatures = find_vm_signatures(src)
    except RuntimeError:
        signatures = []

    for candidate in signatures:
        for table in candidate.get("handler_tables", []) or []:
            name = table.get("name")
            if name and name not in handler_tables:
                handler_tables.append(name)

    try:
        handler_map = _collect_handler_bodies(src, handler_tables or [])
    except RuntimeError:
        handler_map = {}

    if not handler_map and not handler_tables:
        try:
            handler_map = _collect_handler_bodies(src, [])
        except RuntimeError:
            handler_map = {}

    line_starts = _compute_line_starts(src)
    helper_report: Dict[str, Dict[str, object]] = {}

    for name, info in helpers.items():
        helper_report[name] = {
            "body": info.get("body", ""),
            "snippet": info.get("snippet", ""),
            "line": info.get("line"),
            "column": info.get("column"),
            "call_sites": [],
        }

    for table_name, opcode_map in handler_map.items():
        for opcode, handler_info in opcode_map.items():
            text = handler_info.get("text") or ""
            start = handler_info.get("start")
            if not text or start is None:
                continue

            for helper_name in helpers.keys():
                for relative in _find_helper_call_offsets(text, helper_name):
                    absolute = start + relative
                    line, column = _offset_to_line_col(absolute, line_starts)
                    snippet_start = max(0, absolute - 24)
                    snippet_end = min(len(src), absolute + 136)
                    snippet = _extract_snippet(src, snippet_start, snippet_end)
                    entry = helper_report.setdefault(
                        helper_name,
                        {
                            "body": helpers.get(helper_name, {}).get("body", ""),
                            "snippet": helpers.get(helper_name, {}).get("snippet", ""),
                            "line": helpers.get(helper_name, {}).get("line"),
                            "column": helpers.get(helper_name, {}).get("column"),
                            "call_sites": [],
                        },
                    )
                    entry["call_sites"].append(
                        {
                            "opcode": opcode,
                            "handler_table": table_name,
                            "line": line,
                            "column": column,
                            "snippet": snippet,
                        }
                    )

    for info in helper_report.values():
        def _sort_key(entry: Dict[str, object]) -> Tuple[object, int, int]:
            opcode = entry.get("opcode")
            numeric: object
            if isinstance(opcode, (int, float)):
                numeric = int(opcode) if isinstance(opcode, float) and opcode.is_integer() else opcode
            else:
                numeric = _parse_numeric_literal(str(opcode))
                if numeric is None:
                    numeric = str(opcode)
            return numeric, entry.get("line") or 0, entry.get("column") or 0

        info["call_sites"].sort(key=_sort_key)

    result: Dict[str, Any] = {
        "helpers": helper_report,
        "handler_tables": handler_tables,
        "output_path": None,
    }

    if output_path:
        path = Path(output_path)
        path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        result["output_path"] = str(path)

    return result


def _guess_semantics_from_text(text: str) -> Tuple[str, float, str]:
    if not text:
        return "unknown", 0.2, ""
    collapsed = " ".join(text.split())
    best_guess = ("unknown", 0.2, "")
    for label, score, pattern in _SEMANTIC_RULES:
        match = pattern.search(collapsed)
        if match and score > best_guess[1]:
            evidence = match.group(0).strip()
            best_guess = (label, score, evidence)
    return best_guess


def _find_function_end(source: str, start_index: int) -> Optional[int]:
    depth = 1
    i = start_index
    length = len(source)
    in_short: Optional[str] = None
    long_string_closing: Optional[str] = None
    block_comment_closing: Optional[str] = None
    comment_mode: Optional[str] = None
    while i < length:
        if comment_mode == "line":
            if source[i] == "\n":
                comment_mode = None
            i += 1
            continue
        if comment_mode == "block":
            if block_comment_closing and source.startswith(block_comment_closing, i):
                comment_mode = None
                i += len(block_comment_closing)
                block_comment_closing = None
            else:
                i += 1
            continue
        if in_short:
            if source[i] == "\\":
                i += 2
                continue
            if source[i] == in_short:
                in_short = None
            i += 1
            continue
        if long_string_closing:
            if source.startswith(long_string_closing, i):
                i += len(long_string_closing)
                long_string_closing = None
            else:
                i += 1
            continue
        if source.startswith("--", i):
            if source.startswith("--[", i):
                eq_count = 0
                j = i + 3
                while j < length and source[j] == "=":
                    eq_count += 1
                    j += 1
                if j < length and source[j] == "[":
                    comment_mode = "block"
                    block_comment_closing = "]" + ("=" * eq_count) + "]"
                    i = j + 1
                    continue
            comment_mode = "line"
            i += 2
            continue
        ch = source[i]
        if ch in {'"', "'"}:
            in_short = ch
            i += 1
            continue
        if ch == "[":
            j = i + 1
            eq_count = 0
            while j < length and source[j] == "=":
                eq_count += 1
                j += 1
            if j < length and source[j] == "[":
                long_string_closing = "]" + ("=" * eq_count) + "]"
                i = j + 1
                continue
        if source.startswith("function", i) and (i == 0 or not source[i - 1].isalnum() and source[i - 1] != "_"):
            tail = i + 8
            if tail >= length or not source[tail].isalnum() and source[tail] != "_":
                depth += 1
                i = tail
                continue
        if source.startswith("end", i) and (i == 0 or not source[i - 1].isalnum() and source[i - 1] != "_"):
            tail = i + 3
            if tail >= length or not source[tail].isalnum() and source[tail] != "_":
                depth -= 1
                i = tail
                if depth == 0:
                    return i
                continue
        i += 1
    return None


def _extract_named_function(source: str, name: str) -> Optional[Dict[str, str]]:
    patterns = [
        re.compile(rf"{re.escape(name)}\s*=\s*function\b"),
        re.compile(rf"function\s+{re.escape(name)}\b"),
    ]
    for pattern in patterns:
        match = pattern.search(source)
        if not match:
            continue
        func_pos = source.find("function", match.start(), match.end())
        if func_pos == -1:
            continue
        end_index = _find_function_end(source, func_pos + len("function"))
        if end_index is None:
            continue
        start_index = match.start()
        text = source[start_index:end_index]
        snippet = _extract_snippet(source, start_index, end_index)
        return {"text": text, "snippet": snippet}
    return None


def _format_histogram_line(opcode: int, count: int, scale: float) -> str:
    if count <= 0:
        bar = ""
    else:
        width = max(1, int(round(count * scale))) if scale else count
        bar = "#" * width
    return f"{opcode:>5}: {bar} ({count})"


def opcode_frequency_heatmap(src: str, *, histogram_width: int = 40) -> Dict[str, Any]:
    """Build an opcode frequency report for the dominant VM dispatcher."""

    signatures = find_vm_signatures(src)
    if not signatures:
        return {"frequencies": [], "csv": "opcode,count", "histogram": ""}

    selected_cases: Optional[List[Dict[str, object]]] = None
    for candidate in signatures:
        numeric_cases = [
            case
            for case in candidate.get("opcode_cases", [])
            if _normalise_numeric_opcode(case.get("opcode")) is not None
        ]
        if numeric_cases:
            selected_cases = numeric_cases
            break
    if selected_cases is None:
        selected_cases = [
            case
            for candidate in signatures
            for case in candidate.get("opcode_cases", [])
            if _normalise_numeric_opcode(case.get("opcode")) is not None
        ]

    counts: Counter[int] = Counter()
    for case in selected_cases:
        opcode = _normalise_numeric_opcode(case.get("opcode"))
        if opcode is not None:
            counts[opcode] += 1

    if not counts:
        return {"frequencies": [], "csv": "opcode,count", "histogram": ""}

    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))

    csv_lines = ["opcode,count"]
    for opcode, count in ordered:
        csv_lines.append(f"{opcode},{count}")

    max_count = ordered[0][1]
    scale = (histogram_width / max_count) if max_count else 0.0
    histogram_lines = [_format_histogram_line(opcode, count, scale) for opcode, count in ordered]

    return {
        "frequencies": ordered,
        "csv": "\n".join(csv_lines),
        "histogram": "\n".join(histogram_lines),
    }


def opcode_semantics_guesses(
    src: str,
    *,
    top_n: int = 30,
    output_path: Optional[Path | str] = Path("opcode_guesses.json"),
) -> Dict[str, Any]:
    """Guess opcode semantics for the most frequent VM cases."""

    signatures = find_vm_signatures(src)
    if not signatures:
        result: Dict[str, Any] = {
            "top_n": 0,
            "handler_tables": [],
            "frequencies": [],
            "guesses": {},
        }
        if output_path:
            Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    chosen_candidate: Optional[Dict[str, Any]] = None
    numeric_cases: List[Dict[str, object]] = []
    for candidate in signatures:
        filtered = [
            case
            for case in candidate.get("opcode_cases", [])
            if _normalise_numeric_opcode(case.get("opcode")) is not None
        ]
        if filtered:
            chosen_candidate = candidate
            numeric_cases = filtered
            break

    if not numeric_cases:
        for candidate in signatures:
            for case in candidate.get("opcode_cases", []):
                if _normalise_numeric_opcode(case.get("opcode")) is not None:
                    numeric_cases.append(case)
        if signatures:
            chosen_candidate = signatures[0]

    counts: Counter[int] = Counter()
    for case in numeric_cases:
        opcode = _normalise_numeric_opcode(case.get("opcode"))
        if opcode is not None:
            counts[opcode] += 1

    if not counts:
        result = {
            "top_n": 0,
            "handler_tables": [],
            "frequencies": [],
            "guesses": {},
        }
        if output_path:
            Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    top_entries = ordered[:top_n]

    handler_names: List[str] = []
    if chosen_candidate:
        for table in chosen_candidate.get("handler_tables", []):
            name = table.get("name")
            if name and name not in handler_names:
                handler_names.append(name)
    if not handler_names:
        for candidate in signatures:
            for table in candidate.get("handler_tables", []):
                name = table.get("name")
                if name and name not in handler_names:
                    handler_names.append(name)

    handler_map: Dict[str, Dict[int, Dict[str, str]]] = {}
    try:
        handler_map = _collect_handler_bodies(src, handler_names)
    except RuntimeError:
        handler_map = {}

    helper_report: Dict[str, Any] = {}
    helper_samples: Dict[int, List[Dict[str, Any]]] = {}
    inline_helpers: Dict[int, Dict[str, Any]] = {}
    try:
        helper_report = helpers_to_opcodes(src, output_path=None)
        helper_samples = _collect_helper_samples(helper_report)
        inline_helpers = _collect_inlineable_helpers(helper_report)
    except RuntimeError:
        helper_report = {"helpers": {}}
        helper_samples = {}
        inline_helpers = {}

    ir_nodes = _collect_ir_nodes_from_candidate(chosen_candidate or {})
    sequence_context = _compute_opcode_sequence_context(chosen_candidate)

    case_snippets: Dict[int, str] = {}
    if chosen_candidate:
        for case in chosen_candidate.get("opcode_cases", []):
            opcode = _normalise_numeric_opcode(case.get("opcode"))
            snippet = case.get("snippet") if isinstance(case.get("snippet"), str) else ""
            if opcode is not None and snippet:
                case_snippets[opcode] = snippet

    guesses: Dict[str, Dict[str, Any]] = {}
    entry_map: Dict[int, Dict[str, Any]] = {}
    feature_map: Dict[int, Set[str]] = {}
    max_count = top_entries[0][1] if top_entries else 0

    for index, (opcode, count) in enumerate(top_entries):
        handler_info: Optional[Dict[str, str]] = None
        handler_table_name: Optional[str] = None
        if handler_map:
            for table_name in handler_names:
                table_handlers = handler_map.get(table_name, {})
                if opcode in table_handlers:
                    handler_info = table_handlers[opcode]
                    handler_table_name = table_name
                    break
            if handler_info is None:
                for table_name, table_handlers in handler_map.items():
                    if opcode in table_handlers:
                        handler_info = table_handlers[opcode]
                        handler_table_name = table_name
                        break

        snippet = case_snippets.get(opcode, "")
        if handler_info is None and snippet:
            candidate = snippet.strip().split("(")[0]
            if candidate and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate):
                extracted = _extract_named_function(src, candidate)
                if extracted:
                    handler_info = extracted
                    handler_table_name = handler_table_name or "return_table"
        text = handler_info.get("text", "") if handler_info else snippet
        guess, confidence, evidence = _guess_semantics_from_text(text)
        if not evidence and snippet:
            evidence = snippet[:80]
        entry: Dict[str, Any] = {
            "guess": guess,
            "confidence": round(confidence, 2),
            "frequency": count,
            "evidence": evidence,
            "guess_source": "heuristic",
        }
        if handler_info and handler_info.get("snippet"):
            entry["handler_snippet"] = handler_info["snippet"]
        elif snippet:
            entry["handler_snippet"] = snippet
        if handler_table_name:
            entry["handler_table"] = handler_table_name
        inline_helper = inline_helpers.get(opcode)
        features = _extract_opcode_feature_tokens(
            opcode,
            count=count,
            max_count=max_count,
            rank_index=index,
            total=len(top_entries),
            handler_info=handler_info,
            snippet=snippet,
            helper_samples=helper_samples.get(opcode, []),
            inline_helper=inline_helper,
            ir_node=ir_nodes.get(opcode),
            context=sequence_context.get(opcode, {}),
        )
        if features:
            feature_map[opcode] = features
        if inline_helper:
            entry["inline_helper"] = {
                "name": inline_helper.get("name"),
                "call_count": inline_helper.get("call_count"),
            }
        guesses[str(opcode)] = entry
        entry_map[opcode] = entry

    if entry_map:
        _apply_ml_predictions(entry_map, feature_map)

    result = {
        "top_n": len(top_entries),
        "handler_tables": handler_names,
        "frequencies": [[opcode, count] for opcode, count in top_entries],
        "guesses": guesses,
    }

    if output_path:
        Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")

    return result


def _mnemonic_from_guess(guess: Optional[str], opcode: int) -> str:
    if not guess or guess.lower() == "unknown":
        return f"OP_{opcode}"
    token = re.sub(r"[^A-Za-z0-9]+", "_", guess).strip("_")
    return token.upper() if token else f"OP_{opcode}"


def _collect_ir_nodes_from_candidate(candidate: Mapping[str, Any]) -> Dict[int, VMIRNode]:
    dispatcher_ast = candidate.get("ast") if isinstance(candidate, Mapping) else None
    if dispatcher_ast is None:
        return {}
    try:
        nodes = lift_vm(dispatcher_ast)
    except (RuntimeError, TypeError):
        return {}
    collected: Dict[int, VMIRNode] = {}
    for node in nodes:
        opcode = _normalise_numeric_opcode(getattr(node, "opcode", None))
        if opcode is None:
            continue
        collected[opcode] = node
    return collected


def _collect_helper_samples(helper_report: Mapping[str, Any]) -> Dict[int, List[Dict[str, Any]]]:
    samples: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    helpers = helper_report.get("helpers") if isinstance(helper_report, Mapping) else None
    if not isinstance(helpers, Mapping):
        return samples
    for helper_name, helper_info in helpers.items():
        call_sites = helper_info.get("call_sites") if isinstance(helper_info, Mapping) else None
        if not isinstance(call_sites, list):
            continue
        for site in call_sites:
            opcode = _normalise_numeric_opcode(site.get("opcode")) if isinstance(site, Mapping) else None
            if opcode is None:
                continue
            entry = {
                "helper": helper_name,
                "line": site.get("line") if isinstance(site, Mapping) else None,
                "column": site.get("column") if isinstance(site, Mapping) else None,
                "snippet": site.get("snippet") if isinstance(site, Mapping) else None,
                "handler_table": site.get("handler_table") if isinstance(site, Mapping) else None,
            }
            samples[opcode].append(entry)
    for entries in samples.values():
        entries.sort(key=lambda item: ((item.get("line") or 0), item.get("column") or 0))
    return samples


def _collect_inlineable_helpers(helper_report: Mapping[str, Any]) -> Dict[int, Dict[str, Any]]:
    """Return helper definitions that are exclusive to a single opcode."""

    inlineable: Dict[int, Dict[str, Any]] = {}
    helpers = helper_report.get("helpers") if isinstance(helper_report, Mapping) else None
    if not isinstance(helpers, Mapping):
        return inlineable

    for helper_name, helper_info in helpers.items():
        if not isinstance(helper_info, Mapping):
            continue

        call_sites = helper_info.get("call_sites")
        if not isinstance(call_sites, list) or not call_sites:
            continue

        opcode_set: Set[int] = set()
        for site in call_sites:
            if not isinstance(site, Mapping):
                continue
            opcode = _normalise_numeric_opcode(site.get("opcode"))
            if opcode is None:
                continue
            opcode_set.add(opcode)

        if len(opcode_set) != 1:
            continue

        body = helper_info.get("body")
        snippet = helper_info.get("snippet")
        if not isinstance(body, str) or not body.strip():
            # Fall back to snippet if the body was not captured.
            if isinstance(snippet, str) and snippet.strip():
                body = snippet
            else:
                continue

        opcode = next(iter(opcode_set))
        inlineable[opcode] = {
            "name": helper_name,
            "body": body,
            "snippet": snippet if isinstance(snippet, str) else None,
            "call_count": len(call_sites),
        }

    return inlineable


def generate_upcode_table(
    src: str,
    *,
    top_n: int = 30,
    output_json: Optional[Path | str] = Path("upcodes.json"),
    output_markdown: Optional[Path | str] = Path("upcodes.md"),
    output_csv: Optional[Path | str] = Path("upcodes.csv"),
    output_html: Optional[Path | str] = Path("upcodes.html"),
    snapshot: "SnapshotManager | None" = None,
) -> Dict[str, Any]:
    """Generate a consolidated opcode reference using VM IR and heuristics."""

    try:
        semantics = opcode_semantics_guesses(src, top_n=top_n, output_path=None)
    except RuntimeError:
        semantics = {"top_n": 0, "handler_tables": [], "frequencies": [], "guesses": {}}

    metadata: Dict[str, Any] = {}
    try:  # defer import to avoid circular dependency at import time
        from version_detector import detect_luraph_header_from_text

        metadata = detect_luraph_header_from_text(src)
    except Exception:  # pragma: no cover - metadata extraction is best-effort
        metadata = {}

    try:
        signatures = find_vm_signatures(src)
    except RuntimeError:
        signatures = []

    dispatcher_candidate: Optional[Dict[str, Any]] = None
    for candidate in signatures:
        if candidate.get("ast") is not None:
            dispatcher_candidate = candidate
            break
    if dispatcher_candidate is None and signatures:
        dispatcher_candidate = signatures[0]

    ir_nodes = _collect_ir_nodes_from_candidate(dispatcher_candidate or {})

    try:
        helper_report = helpers_to_opcodes(src, output_path=None)
    except RuntimeError:
        helper_report = {"helpers": {}}
    helper_samples = _collect_helper_samples(helper_report)
    inline_helpers = _collect_inlineable_helpers(helper_report)

    frequency_pairs = semantics.get("frequencies") if isinstance(semantics, Mapping) else None
    freq_map: Dict[int, int] = {}
    if isinstance(frequency_pairs, list):
        for entry in frequency_pairs:
            if isinstance(entry, (list, tuple)) and entry:
                opcode = _normalise_numeric_opcode(entry[0])
                count = entry[1] if len(entry) > 1 else None
                if opcode is not None and isinstance(count, int):
                    freq_map[opcode] = count

    guesses = semantics.get("guesses") if isinstance(semantics, Mapping) else {}
    entries: List[Dict[str, Any]] = []
    seen_opcodes: set[int] = set()

    def _build_entry(opcode: int, info: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        mnemonic = _mnemonic_from_guess(info.get("guess") if info else None, opcode)
        confidence = info.get("confidence") if info else None
        semantic = info.get("guess") if info else "unknown"
        evidence = info.get("evidence") if info else ""
        handler_table = info.get("handler_table") if info else None
        handler_snippet = info.get("handler_snippet") if info else None

        ir_node = ir_nodes.get(opcode)
        operand_inputs = list(ir_node.args) if ir_node else []
        operand_effects = list(ir_node.effects) if ir_node else []

        samples = list(helper_samples.get(opcode, []))
        trimmed_samples = samples[:5]
        if not trimmed_samples and handler_snippet:
            trimmed_samples = [
                {
                    "source": "handler_snippet",
                    "snippet": handler_snippet,
                    "handler_table": handler_table,
                }
            ]

        entry: Dict[str, Any] = {
            "opcode": opcode,
            "mnemonic": mnemonic,
            "frequency": freq_map.get(opcode, 0),
            "confidence": confidence,
            "semantic": semantic,
            "semantic_evidence": evidence,
            "handler_table": handler_table,
            "operand_types": {
                "inputs": operand_inputs,
                "effects": operand_effects,
            },
            "sample_usage": trimmed_samples,
        }
        if handler_snippet and (not trimmed_samples or trimmed_samples[0].get("source") != "handler_snippet"):
            entry["handler_snippet"] = handler_snippet
        inline_info = inline_helpers.get(opcode)
        if inline_info:
            entry["inlined_helper"] = inline_info
        return entry

    if isinstance(guesses, Mapping):
        for key, info in guesses.items():
            opcode = _normalise_numeric_opcode(key)
            if opcode is None or opcode in seen_opcodes:
                continue
            entries.append(_build_entry(opcode, info if isinstance(info, Mapping) else None))
            seen_opcodes.add(opcode)

    candidate_opcodes: set[int] = set(freq_map)
    candidate_opcodes.update(ir_nodes.keys())
    candidate_opcodes.update(helper_samples.keys())

    for opcode in sorted(candidate_opcodes):
        if opcode in seen_opcodes:
            continue
        entries.append(_build_entry(opcode, None))
        seen_opcodes.add(opcode)

    entries.sort(key=lambda item: (-item.get("frequency", 0), item.get("opcode", 0)))

    result: Dict[str, Any] = {
        "entries": entries,
        "top_n": semantics.get("top_n") if isinstance(semantics, Mapping) else len(entries),
        "dispatcher_summary": (dispatcher_candidate or {}).get("summary") if dispatcher_candidate else None,
        "metadata": metadata,
        "output_json": None,
        "output_markdown": None,
        "output_csv": None,
        "output_html": None,
    }

    json_payload = {
        "entries": entries,
        "top_n": result["top_n"],
        "dispatcher_summary": result["dispatcher_summary"],
        "metadata": metadata,
    }

    if snapshot is not None:
        snapshot.record_opcode_mappings(json_payload)
        snapshot.save()

    if output_json:
        path = Path(output_json)
        path.write_text(json.dumps(json_payload, indent=2, sort_keys=True), encoding="utf-8")
        result["output_json"] = str(path)

    header = "# Upcode Reference"
    version = metadata.get("version") if isinstance(metadata, Mapping) else None
    if isinstance(version, str) and version:
        header = f"{header} (Luraph v{version})"

    markdown_lines: List[str] = [header, ""]

    if isinstance(metadata, Mapping) and (metadata.get("structure") or metadata.get("top_keys")):
        structure = metadata.get("structure", "unknown")
        markdown_lines.append(f"> Detected structure: ``{structure}``")
        top_keys = metadata.get("top_keys")
        if isinstance(top_keys, list) and top_keys:
            preview = ", ".join(top_keys[:8])
            markdown_lines.append(f"> Top-level keys: {preview}")
        markdown_lines.append("")
    if entries:
        markdown_lines.append("| Opcode | Mnemonic | Frequency | Confidence | Semantic |")
        markdown_lines.append("| --- | --- | --- | --- | --- |")
        for entry in entries:
            confidence = entry.get("confidence")
            conf_text = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "-"
            markdown_lines.append(
                f"| {entry['opcode']} | {entry['mnemonic']} | {entry['frequency']} | {conf_text} | {entry['semantic']} |"
            )
        for entry in entries:
            confidence = entry.get("confidence")
            conf_text = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "unknown"
            markdown_lines.extend(
                [
                    "",
                    f"## Opcode {entry['opcode']} – {entry['mnemonic']}",
                    "",
                    f"* Frequency: {entry['frequency']}",
                    f"* Semantic: {entry['semantic']} (confidence {conf_text})",
                ]
            )
            evidence = entry.get("semantic_evidence")
            if evidence:
                markdown_lines.append(f"* Evidence: `{evidence}`")
            inputs = entry.get("operand_types", {}).get("inputs")
            effects = entry.get("operand_types", {}).get("effects")
            if inputs or effects:
                markdown_lines.append("* Operands:")
                if inputs:
                    markdown_lines.append(f"  * Inputs: {', '.join(inputs)}")
                if effects:
                    markdown_lines.append(f"  * Effects: {', '.join(effects)}")
            samples = entry.get("sample_usage") or []
            if samples:
                markdown_lines.append("* Sample usage:")
                for sample in samples:
                    parts: List[str] = []
                    helper = sample.get("helper") if isinstance(sample, Mapping) else None
                    if helper:
                        parts.append(f"helper `{helper}`")
                    handler_table = sample.get("handler_table") if isinstance(sample, Mapping) else None
                    if handler_table:
                        parts.append(f"table `{handler_table}`")
                    line = sample.get("line") if isinstance(sample, Mapping) else None
                    column = sample.get("column") if isinstance(sample, Mapping) else None
                    if isinstance(line, int):
                        location = f"line {line}"
                        if isinstance(column, int):
                            location += f", col {column}"
                        parts.append(location)
                    source = sample.get("source") if isinstance(sample, Mapping) else None
                    if source and source != "handler_snippet":
                        parts.append(f"source `{source}`")
                    snippet = sample.get("snippet") if isinstance(sample, Mapping) else None
                    details = ", ".join(parts) if parts else "sample"
                    if snippet:
                        trimmed = snippet.strip()
                        if len(trimmed) > 160:
                            trimmed = f"{trimmed[:157]}…"
                        markdown_lines.append(f"  * {details}: `{trimmed}`")
                    else:
                        markdown_lines.append(f"  * {details}")
            handler_snippet = entry.get("handler_snippet")
            if handler_snippet:
                snippet = handler_snippet.strip()
                if len(snippet) > 160:
                    snippet = f"{snippet[:157]}…"
                markdown_lines.append(f"* Handler snippet: `{snippet}`")
            inline_info = entry.get("inlined_helper")
            if isinstance(inline_info, Mapping):
                name = inline_info.get("name")
                call_count = inline_info.get("call_count")
                markdown_lines.append(
                    f"* Inlined helper: `{name}` (unique to this opcode{f', {call_count} call(s)' if isinstance(call_count, int) else ''})"
                )
                body = inline_info.get("body")
                if isinstance(body, str) and body.strip():
                    snippet_text = body.strip()
                    if len(snippet_text) > 280:
                        snippet_text = f"{snippet_text[:277]}…"
                    markdown_lines.append("```lua")
                    markdown_lines.append(snippet_text)
                    markdown_lines.append("```")
            markdown_lines.append("")
    else:
        markdown_lines.append("No opcode candidates were identified.")

    if output_markdown:
        path = Path(output_markdown)
        path.write_text("\n".join(markdown_lines), encoding="utf-8")
        result["output_markdown"] = str(path)

    if output_csv:
        path = Path(output_csv)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "opcode",
            "mnemonic",
            "frequency",
            "confidence",
            "semantic",
            "semantic_evidence",
            "handler_table",
            "sample_count",
        ]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow(
                    {
                        "opcode": entry.get("opcode"),
                        "mnemonic": entry.get("mnemonic"),
                        "frequency": entry.get("frequency"),
                        "confidence": entry.get("confidence"),
                        "semantic": entry.get("semantic"),
                        "semantic_evidence": entry.get("semantic_evidence"),
                        "handler_table": entry.get("handler_table"),
                        "sample_count": len(entry.get("sample_usage") or []),
                    }
                )
        result["output_csv"] = str(path)

    if output_html:
        path = Path(output_html)
        path.parent.mkdir(parents=True, exist_ok=True)
        html_lines = [
            "<!DOCTYPE html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"utf-8\" />",
            "  <title>Upcode Reference</title>",
            "  <style>",
            "    body { font-family: sans-serif; margin: 1.5rem; }",
            "    table { border-collapse: collapse; width: 100%; }",
            "    th, td { border: 1px solid #ccc; padding: 0.4rem; text-align: left; vertical-align: top; }",
            "    tbody tr:nth-child(odd) { background: #f7f7f7; }",
            "    code { background: #f0f0f0; padding: 0 0.2rem; }",
            "    details { margin-top: 0.5rem; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>Upcode Reference</h1>",
        ]
        if isinstance(metadata, Mapping) and metadata:
            html_lines.append("  <section>")
            html_lines.append("    <h2>Metadata</h2>")
            html_lines.append("    <ul>")
            for key, value in sorted(metadata.items()):
                html_lines.append(
                    f"      <li><strong>{html.escape(str(key))}</strong>: {html.escape(json.dumps(value, ensure_ascii=False))}</li>"
                )
            html_lines.append("    </ul>")
            html_lines.append("  </section>")

        html_lines.append("  <table>")
        html_lines.append("    <thead>")
        html_lines.append(
            "      <tr><th>Opcode</th><th>Mnemonic</th><th>Frequency</th><th>Confidence</th><th>Semantic</th><th>Samples</th></tr>"
        )
        html_lines.append("    </thead>")
        html_lines.append("    <tbody>")
        for entry in entries:
            confidence = entry.get("confidence")
            conf_text = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "-"
            samples = entry.get("sample_usage") or []
            sample_items: List[str] = []
            for sample in samples:
                if not isinstance(sample, Mapping):
                    continue
                details: List[str] = []
                helper = sample.get("helper")
                if helper:
                    details.append(f"helper <code>{html.escape(str(helper))}</code>")
                handler_table = sample.get("handler_table")
                if handler_table:
                    details.append(f"table <code>{html.escape(str(handler_table))}</code>")
                location_bits: List[str] = []
                if isinstance(sample.get("line"), int):
                    location_bits.append(f"line {sample['line']}")
                if isinstance(sample.get("column"), int):
                    location_bits.append(f"col {sample['column']}")
                if location_bits:
                    details.append("@ " + " ".join(location_bits))
                snippet = sample.get("snippet")
                snippet_html = ""
                if isinstance(snippet, str) and snippet.strip():
                    trimmed = snippet.strip()
                    if len(trimmed) > 200:
                        trimmed = trimmed[:197] + "…"
                    snippet_html = f"<pre><code>{html.escape(trimmed)}</code></pre>"
                detail_text = ", ".join(details) if details else "sample"
                sample_items.append(f"<li>{detail_text}{snippet_html}</li>")
            sample_html = "<ul>" + "".join(sample_items) + "</ul>" if sample_items else ""
            html_lines.append(
                "      <tr>"
                f"<td>{html.escape(str(entry.get('opcode')))}</td>"
                f"<td>{html.escape(str(entry.get('mnemonic')))}</td>"
                f"<td>{entry.get('frequency', 0)}</td>"
                f"<td>{html.escape(conf_text)}</td>"
                f"<td>{html.escape(str(entry.get('semantic')))}</td>"
                f"<td>{sample_html}</td>"
                "</tr>"
            )
        html_lines.append("    </tbody>")
        html_lines.append("  </table>")
        html_lines.append("</body>")
        html_lines.append("</html>")
        path.write_text("\n".join(html_lines), encoding="utf-8")
        result["output_html"] = str(path)

    return result


_VM_UNCONDITIONAL_BRANCHES = {"JMP", "FORPREP"}
_VM_TWO_WAY_BRANCHES = {"JMPIF", "JMPIFNOT", "JMPTRUE", "JMPFALSE", "TEST", "TESTSET", "FORLOOP", "TFORLOOP"}
_VM_TERMINATORS = {"RETURN", "TAILCALL"}
_VM_CALL_KEYWORDS = ("CALL", "INVOKE")


def _is_call_opcode(opcode: str) -> bool:
    upper = opcode.upper()
    if upper in _VM_TERMINATORS:
        return False
    if upper.startswith("TAIL") and upper.endswith("CALL"):
        return False
    return any(keyword in upper for keyword in _VM_CALL_KEYWORDS)


def _gather_vm_functions(root: VMFunction) -> List[Tuple[str, VMFunction]]:
    functions: List[Tuple[str, VMFunction]] = []

    def _walk(func: VMFunction, label: str) -> None:
        functions.append((label, func))
        for index, proto in enumerate(getattr(func, "prototypes", []) or []):
            if isinstance(proto, VMFunction):
                _walk(proto, f"{label}_{index}")

    _walk(root, "root")
    return functions


def _resolve_branch_target(instr: VMInstruction, index: int) -> Optional[int]:
    offset_candidates = [
        getattr(instr, "offset", None),
        instr.aux.get("offset") if isinstance(instr.aux, Mapping) else None,
        instr.ir.get("offset") if isinstance(instr.ir, Mapping) else None,
    ]
    for candidate in offset_candidates:
        if isinstance(candidate, int):
            return index + 1 + candidate
    return None


def _build_vm_cfg_for_function(func: VMFunction) -> VMCFG:
    instructions = list(getattr(func, "instructions", []) or [])
    if not instructions:
        return VMCFG(blocks={}, edges={})

    for idx, instr in enumerate(instructions):
        if not isinstance(getattr(instr, "pc", None), int):
            instr.pc = idx

    leaders: Set[int] = {0}
    length = len(instructions)

    for idx, instr in enumerate(instructions):
        target = _resolve_branch_target(instr, idx)
        if target is not None and 0 <= target < length:
            leaders.add(target)
        opcode = instr.opcode.upper() if isinstance(instr.opcode, str) else str(instr.opcode)
        if opcode in _VM_UNCONDITIONAL_BRANCHES | _VM_TWO_WAY_BRANCHES | _VM_TERMINATORS:
            if idx + 1 < length:
                leaders.add(idx + 1)

    ordered_leaders = sorted(leaders)
    blocks: List[VMBasicBlock] = []
    pc_to_block: Dict[int, int] = {}

    for start in ordered_leaders:
        if start >= length:
            continue
        next_candidates = [candidate for candidate in ordered_leaders if candidate > start]
        end = min(next_candidates) if next_candidates else length
        if end <= start:
            continue
        block_instructions = instructions[start:end]
        if not block_instructions:
            continue
        block_index = len(blocks)
        block = VMBasicBlock(
            index=block_index,
            start_pc=start,
            end_pc=end - 1,
            instructions=block_instructions,
        )
        blocks.append(block)
        for pc in range(start, end):
            pc_to_block[pc] = block_index

    edges: Dict[int, List[VMCFGEdge]] = defaultdict(list)

    for position, block in enumerate(blocks):
        if not block.instructions:
            continue
        last_pc = block.end_pc
        instr = block.instructions[-1]
        opcode = instr.opcode.upper() if isinstance(instr.opcode, str) else str(instr.opcode)
        call_opcode = None
        for candidate in block.instructions:
            name = candidate.opcode.upper() if isinstance(candidate.opcode, str) else str(candidate.opcode)
            if _is_call_opcode(name):
                call_opcode = name
        target = _resolve_branch_target(instr, last_pc)
        next_block = blocks[position + 1] if position + 1 < len(blocks) else None

        if opcode in _VM_TERMINATORS:
            edge_kind = "tailcall" if opcode == "TAILCALL" else "return"
            edges[block.index].append(VMCFGEdge(edge_kind, None, opcode))
            continue

        if opcode in _VM_UNCONDITIONAL_BRANCHES:
            if target is not None and target in pc_to_block:
                edges[block.index].append(
                    VMCFGEdge("jump", pc_to_block[target], opcode)
                )
            continue

        if opcode in _VM_TWO_WAY_BRANCHES:
            if target is not None and target in pc_to_block:
                edges[block.index].append(
                    VMCFGEdge("branch", pc_to_block[target], opcode, detail="true")
                )
            if next_block is not None:
                edges[block.index].append(
                    VMCFGEdge("branch", next_block.index, opcode, detail="false")
                )
            continue

        if next_block is not None:
            if call_opcode:
                edges[block.index].append(VMCFGEdge("call", next_block.index, call_opcode))
            else:
                edges[block.index].append(VMCFGEdge("fallthrough", next_block.index, opcode))

    return VMCFG(
        blocks={block.index: block for block in blocks},
        edges={k: list(v) for k, v in edges.items()},
    )


def _write_vm_cfg_dot(cfg: VMCFG, path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        fh.write("digraph VM_CFG {\n")
        needs_exit = any(
            edge.target is None
            for edges in cfg.edges.values()
            for edge in edges
        )

        if needs_exit:
            fh.write("  exit [shape=doublecircle label=\"exit\"];\n")

        for index, block in sorted(cfg.blocks.items()):
            label_lines = [f"{pc}: {instr.opcode}" for pc, instr in zip(range(block.start_pc, block.end_pc + 1), block.instructions)]
            label = "\\l".join(label_lines) + "\\l"
            fh.write(f"  b{index} [label=\"{label}\" shape=box];\n")
        for src, edges in sorted(cfg.edges.items()):
            for edge in edges:
                target = f"b{edge.target}" if edge.target is not None else "exit"
                label_parts = [edge.kind]
                if edge.detail:
                    label_parts.append(edge.detail)
                if edge.opcode and edge.opcode not in label_parts:
                    label_parts.append(edge.opcode)
                label = "\\n".join(label_parts)
                attr = f" [label=\"{label}\"]" if label else ""
                fh.write(f"  b{src} -> {target}{attr};\n")
        fh.write("}\n")


def build_vm_cfg(
    vm_ir: Any,
    *,
    output_dir: Optional[Path | str] = Path("cfg"),
    max_functions: int = 3,
) -> Dict[str, Any]:
    """Build CFGs for the largest lifted VM functions and optionally emit DOT files."""

    program = _coerce_vm_program(vm_ir)
    functions = _gather_vm_functions(program)
    functions.sort(key=lambda item: len(getattr(item[1], "instructions", []) or []), reverse=True)

    selected = functions[: max_functions if max_functions > 0 else len(functions)]
    output_entries: List[Dict[str, Any]] = []

    dot_dir: Optional[Path] = None
    if output_dir:
        dot_dir = Path(output_dir)
        dot_dir.mkdir(parents=True, exist_ok=True)

    for label, func in selected:
        cfg = _build_vm_cfg_for_function(func)
        entry: Dict[str, Any] = {
            "label": label,
            "instruction_count": len(getattr(func, "instructions", []) or []),
            "block_count": len(cfg.blocks),
            "edge_count": sum(len(targets) for targets in cfg.edges.values()),
            "cfg": cfg,
        }
        if dot_dir is not None:
            safe_label = re.sub(r"[^A-Za-z0-9_]+", "_", label)
            path = dot_dir / f"{safe_label or 'function'}.dot"
            _write_vm_cfg_dot(cfg, path)
            entry["dot_path"] = str(path)
        output_entries.append(entry)

    return {
        "functions": output_entries,
        "output_dir": str(dot_dir) if dot_dir is not None else None,
    }


def find_vm_signatures(src: str) -> List[Dict[str, Any]]:
    """Return candidate VM dispatcher summaries for ``src``."""

    try:
        from luaparser import ast
        from luaparser import astnodes
    except ImportError as exc:  # pragma: no cover - guarded by tests
        raise RuntimeError("find_vm_signatures requires luaparser to be installed") from exc

    try:
        visitor = _VMVisitor(src, ast, astnodes)
        tree = ast.parse(src)
        visitor.visit(tree)
        results = sorted(visitor.dispatchers, key=lambda item: item["score"], reverse=True)
        if results:
            return results
    except ast.SyntaxException:
        rebuilt = _static_rebuild_text(src)
        if rebuilt:
            try:
                visitor = _VMVisitor(rebuilt, ast, astnodes)
                tree = ast.parse(rebuilt)
                visitor.visit(tree)
                rebuilt_results = sorted(visitor.dispatchers, key=lambda item: item["score"], reverse=True)
                if rebuilt_results:
                    return rebuilt_results
            except ast.SyntaxException:
                pass
            rebuilt_fallback = _fallback_scan_text(rebuilt)
            if rebuilt_fallback:
                return rebuilt_fallback
        return _fallback_scan_text(src)

    fallback = _fallback_scan_text(src)
    return fallback if fallback else results
