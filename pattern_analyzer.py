"""Pattern and control‑flow analysis helpers.

This module originally focused on opcode frequency analysis.  It now grows a
light‑weight control–flow graph (CFG) builder used during devirtualisation to
recover high level structures from the intermediate representation (IR)."""

from __future__ import annotations

import csv
import json
import logging
import re
from html import escape
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Mapping, Union, Callable, Sequence

from copy import deepcopy

from collections import defaultdict, Counter
from collections.abc import Iterable as IterableABC, Mapping as MappingABC


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


@dataclass
class Constant:
    """Typed wrapper around prototype constant entries."""

    kind: str
    value: Any
    raw_value: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:  # pragma: no cover - debugging helper
        return {
            "kind": self.kind,
            "value": self.value,
            "raw_value": self.raw_value,
            "metadata": dict(self.metadata),
        }


def infer_constant_kind(value: Any) -> str:
    """Best-effort guess of a constant's Lua type."""

    if isinstance(value, Constant):
        return value.kind

    if isinstance(value, bool):
        return "boolean"

    if value is None:
        return "nil"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"

    if isinstance(value, str):
        return "string"

    if isinstance(value, (bytes, bytearray)):
        return "bytes"

    if isinstance(value, MappingABC):
        return "table"

    if isinstance(value, IterableABC) and not isinstance(value, (str, bytes, bytearray)):
        return "table"

    return type(value).__name__


def make_constant(
    value: Any,
    *,
    kind: Optional[str] = None,
    raw_value: Any = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Constant:
    """Return a :class:`Constant` while preserving metadata when possible."""

    if isinstance(value, Constant):
        if kind and value.kind != kind:
            value.kind = kind
        if raw_value is not None:
            value.raw_value = raw_value
        if metadata:
            value.metadata.update(metadata)
        return value

    resolved_kind = kind or infer_constant_kind(value)
    stored_metadata = dict(metadata or {})
    return Constant(kind=resolved_kind, value=value, raw_value=raw_value, metadata=stored_metadata)


@dataclass
class SerializedPrototype:
    """Raw prototype payload extracted from the serialized chunk."""

    constants: List[Any]
    instructions: List[Any]
    prototypes: List["SerializedPrototype"] = field(default_factory=list)


@dataclass
class SerializedChunkDescriptor:
    """Metadata describing where the serialized VM chunk lives."""

    buffer_name: str
    initial_offset: int
    helper_functions: Dict[str, str]

    def __post_init__(self) -> None:
        self.helper_functions = dict(self.helper_functions)


@dataclass
class SerializedChunk:
    """High-level model of the serialized VM payload."""

    descriptor: SerializedChunkDescriptor
    prototype_count: int = 0
    prototypes: List[SerializedPrototype] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, SerializedChunkDescriptor):
            if isinstance(self.descriptor, Mapping):
                self.descriptor = SerializedChunkDescriptor(**self.descriptor)
            else:
                raise TypeError("descriptor must be a SerializedChunkDescriptor")
        self.prototypes = list(self.prototypes)
        if not self.prototype_count:
            self.prototype_count = len(self.prototypes)

    @property
    def buffer_name(self) -> str:
        return self.descriptor.buffer_name

    @property
    def initial_offset(self) -> int:
        return self.descriptor.initial_offset

    @property
    def helper_functions(self) -> Dict[str, str]:
        return self.descriptor.helper_functions

    def to_descriptor(self) -> SerializedChunkDescriptor:
        return SerializedChunkDescriptor(
            buffer_name=self.descriptor.buffer_name,
            initial_offset=self.descriptor.initial_offset,
            helper_functions=dict(self.descriptor.helper_functions),
        )


@dataclass
class PrimitiveTableInfo:
    """Captured parameters used by the v14.3 primitive helpers."""

    token_width: Optional[int] = None
    base_offset: Optional[int] = None
    radix: Optional[int] = None
    weights: List[int] = field(default_factory=list)
    accumulator_expression: str = ""
    alphabet_literal: Optional[str] = None
    xor_pairs: List[Tuple[str, str]] = field(default_factory=list)
    shift_counts: Dict[str, List[str]] = field(default_factory=dict)
    key_schedule_slots: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_width": self.token_width,
            "base_offset": self.base_offset,
            "radix": self.radix,
            "weights": list(self.weights),
            "accumulator_expression": self.accumulator_expression,
            "alphabet_literal": self.alphabet_literal,
            "xor_pairs": [list(pair) for pair in self.xor_pairs],
            "shift_counts": {key: list(values) for key, values in self.shift_counts.items()},
            "key_schedule_slots": list(self.key_schedule_slots),
        }


@dataclass
class BootstrapTransition:
    """Directed edge in the numeric ``x`` state machine."""

    expression: str
    target: Optional[int] = None


@dataclass
class BootstrapState:
    """Single state discovered inside the bootstrap dispatcher."""

    state_id: str
    state_numeric: Optional[int]
    operations: List[str]
    transitions: List[BootstrapTransition]


@dataclass
class BootstrapStateMachine:
    """Model of the numeric dispatcher used during bootstrap."""

    variable: str
    states: List[BootstrapState]


@dataclass
class CacheSlot:
    """Summary of writes to a ``F3[slot]`` cache entry."""

    index_literal: str
    index_value: Optional[int]
    expressions: List[str]
    classification: str
    semantic_role: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation of the cache slot."""

        return {
            "index_literal": self.index_literal,
            "index_value": self.index_value,
            "expressions": list(self.expressions),
            "classification": self.classification,
            "semantic_role": self.semantic_role,
        }

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
        self.last_cache_slots: List[CacheSlot] = []

        # Structured metadata suitable for serialisation alongside reports.
        self.side_band: Dict[str, Any] = {}

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

        self._state_branch_pattern = re.compile(
            r"\bif\s+x==\s*([0-9A-Za-z_]+)\s*then",
            re.IGNORECASE,
        )
        self._assignment_pattern = re.compile(r"([A-Za-z0-9_().\[\]]+)\s*=\s*")
    
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

    def locate_serialized_chunk(
        self, source: str
    ) -> Optional[SerializedChunkDescriptor]:
        """Locate the serialized bytecode blob in ``source`` if recognised."""

        chunk = self.locate_serialized_chunk_v14_3(source)
        if chunk is not None:
            return chunk
        return None

    def detect_bootstrap_state_machine(
        self, source: str
    ) -> Optional[BootstrapStateMachine]:
        """Return a model of the numeric bootstrap dispatcher when recognised."""

        machine = self._detect_bootstrap_state_machine_v14_3(source)
        if machine is not None and machine.states:
            return machine
        return None

    def analyze_cache_slots(self, source: str) -> Dict[str, Any]:
        """Summarise writes to ``F3[...]`` cache slots and classify their roles."""

        slots = self._collect_cache_slots(source)
        self.last_cache_slots = slots

        payload = {
            "slots": [slot.to_dict() for slot in slots],
            "slot_count": len(slots),
        }

        self.side_band["cache_slots"] = payload
        return payload

    def identify_c3_primitives(self, source: str) -> Optional[Dict[str, Any]]:
        """Identify the ``C3`` primitive table in known payloads."""

        payload = self._identify_c3_primitive_table_v14_3(source)
        if payload is None:
            return None

        self.side_band["c3_primitives"] = payload
        return payload

    def identify_primitive_table_info(
        self, source: str
    ) -> Optional[PrimitiveTableInfo]:
        """Recover primitive helper parameters for supported payloads."""

        info = self._build_primitive_table_info_v14_3(source)
        if info is None:
            return None

        self.side_band["primitive_table_info"] = info.to_dict()
        return info

    def _collect_cache_slots(self, source: str) -> List[CacheSlot]:
        assignment_pattern = re.compile(
            r"F3\[(?P<index>[^\]]+)\]\s*=\s*(?P<expr>[^;]+)",
            re.IGNORECASE,
        )

        entries: Dict[str, Dict[str, Any]] = {}

        for match in assignment_pattern.finditer(source):
            index_literal = self._normalise_expression(match.group("index"))
            expression = self._cleanup_cache_expression(match.group("expr"))

            classification = self._classify_cache_expression(expression)

            entry = entries.setdefault(
                index_literal,
                {
                    "index_literal": index_literal,
                    "index_value": self._try_parse_numeric_literal(index_literal),
                    "expressions": [],
                    "classification_counts": Counter(),
                    "samples": {},
                },
            )

            entry["expressions"].append(expression)
            entry["classification_counts"][classification] += 1
            entry["samples"].setdefault(classification, expression)

        slots: List[CacheSlot] = []
        for entry in entries.values():
            expressions = entry["expressions"]
            if not expressions:
                continue

            classification_counts: Counter = entry["classification_counts"]
            classification = (
                classification_counts.most_common(1)[0][0]
                if classification_counts
                else "unknown"
            )
            sample = entry["samples"].get(classification, expressions[0])

            semantic_role = self._guess_cache_slot_role(
                entry["index_value"], sample, classification
            )

            slots.append(
                CacheSlot(
                    index_literal=entry["index_literal"],
                    index_value=entry["index_value"],
                    expressions=expressions,
                    classification=classification,
                    semantic_role=semantic_role,
                )
            )

        slots.sort(
            key=lambda slot: (
                slot.index_value if slot.index_value is not None else float("inf"),
                slot.index_literal,
            )
        )

        return slots

    def _cleanup_cache_expression(self, expression: str) -> str:
        token = expression.strip()
        while token and token[0] == "=":
            token = token[1:].lstrip()

        token = re.sub(r"\bthen\s*$", "", token, flags=re.IGNORECASE)
        token = re.sub(r"\bend\s*$", "", token, flags=re.IGNORECASE)

        return self._normalise_expression(token)

    def _classify_cache_expression(self, expression: str) -> str:
        if not expression:
            return "unknown"

        if self._try_parse_numeric_literal(expression) is not None:
            return "constant"

        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression):
            return "passthrough"

        lowered = expression.lower()
        has_bitwise = bool(re.search(r"bit32\.|bit\.b", lowered))
        has_table_ref = "f3[" in lowered or "F3[" in expression
        has_helper = bool(re.search(r"\bC3\.", expression))
        has_arithmetic = bool(re.search(r"[+\-*/%^]", expression))

        if has_bitwise:
            return "bitwise"
        if has_arithmetic or has_helper:
            return "arithmetic combo"
        if has_table_ref:
            return "table reference"
        if "(" in expression and ")" in expression:
            return "function"

        return "computed"

    def _guess_cache_slot_role(
        self, index_value: Optional[int], expression: str, classification: str
    ) -> str:
        lowered = expression.lower()
        numeric_tokens = re.findall(r"0[xX][0-9A-Fa-f_]+|0[bB][01_]+|\d+", expression)
        numeric_values: List[int] = []
        for token in numeric_tokens:
            try:
                numeric_values.append(self._parse_numeric_literal(token))
            except ValueError:
                continue

        max_value = max((abs(value) for value in numeric_values), default=0)

        if any(
            marker in lowered
            for marker in {"9007199254740992", "0x20000000000000", "0x1fffffffffffff"}
        ):
            return "double mantissa mask"

        if "C3.T(" in expression and "C3.o(" in expression:
            return "double mantissa mask"

        if any(token in lowered for token in {"string.len", "string.byte", "string.sub"}):
            return "string length limit"

        if re.search(r"C3\.(?:a|b|s|z)\(", expression):
            if any(value >= 0x7F for value in numeric_values):
                return "string length limit"

        if any(value in {0x7F, 0xFF, 0x100} for value in numeric_values):
            return "string length limit"

        if classification == "constant":
            if max_value >= 0x1000:
                return "threshold value"
            return "literal constant"

        if classification == "arithmetic combo":
            if max_value >= 0x1000:
                return "threshold value"
            if any(value >= 0x100 for value in numeric_values):
                return "scaled parameter"
            return "derived value"

        if classification == "bitwise":
            return "bitmask"

        if classification == "table reference":
            return "lookup table reference"

        if classification == "passthrough":
            return "state passthrough"

        return "unknown"

    def _identify_c3_primitive_table_v14_3(
        self, source: str
    ) -> Optional[Dict[str, Any]]:
        """Return ordered mapping for the standalone v14.3 ``C3`` primitives."""

        if "protected using Luraph Obfuscator v14.3" not in source:
            return None

        table_pattern = re.compile(
            r"\{[^{}]*string\.unpack[^{}]*bit32\.[^{}]*table\.[^{}]*\}",
            re.DOTALL,
        )

        for match in table_pattern.finditer(source):
            literal = match.group(0)
            entries = self._parse_c3_primitive_entries(literal)
            if not entries:
                continue

            modules = {entry["module"] for entry in entries}
            if not {"bit32", "string"} <= modules:
                continue
            if "table" not in modules:
                continue

            payload = {
                "count": len(entries),
                "entries": entries,
                "modules": sorted(modules),
            }
            return payload

        return None

    def _build_primitive_table_info_v14_3(
        self, source: str
    ) -> Optional[PrimitiveTableInfo]:
        if "protected using Luraph Obfuscator v14.3" not in source:
            return None

        descriptor = self._extract_token_math_descriptor_v14_3(source)
        if descriptor is None:
            return None

        info = PrimitiveTableInfo(
            token_width=descriptor.get("token_width"),
            base_offset=descriptor.get("base_offset"),
            radix=descriptor.get("radix"),
            weights=descriptor.get("weights", []),
            accumulator_expression=descriptor.get("expression", ""),
            alphabet_literal=descriptor.get("alphabet_literal"),
        )

        info.xor_pairs = self._collect_helper_pairs_v14_3(source, "C3.u", limit=3)
        info.shift_counts = self._collect_shift_argument_payloads_v14_3(source)
        info.key_schedule_slots = self._collect_key_schedule_slots_v14_3(source)
        return info

    def _extract_token_math_descriptor_v14_3(
        self, source: str
    ) -> Optional[Dict[str, Any]]:
        pattern = re.compile(
            r"local\s+(?P<byte_locals>[A-Za-z0-9_,\s]+)=\s*"
            r"(?P<byte_helper>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<byte_args>[^)]*)\)\s*;\s*"
            r"local\s+(?P<accum_var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<accum_expr>[^;]+);\s*"
            r"(?P<result_var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?P<alphabet_helper>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<alphabet_args>[^)]*)\)",
            re.DOTALL,
        )

        match = pattern.search(source)
        if not match:
            return None

        byte_args = self._split_argument_list(match.group("byte_args"))
        if len(byte_args) < 3:
            return None

        token_width = self._try_parse_numeric_literal(byte_args[2])
        accumulator_expr = match.group("accum_expr").strip()
        alphabet_args = self._split_argument_list(match.group("alphabet_args"))
        alphabet_literal = alphabet_args[0].strip() if alphabet_args else None

        weights, offsets = self._parse_token_accumulator(accumulator_expr)
        base_offset = offsets[0] if offsets else None
        radix = self._infer_radix(weights)

        return {
            "token_width": token_width,
            "base_offset": base_offset,
            "radix": radix,
            "weights": weights,
            "expression": accumulator_expr,
            "alphabet_literal": alphabet_literal,
        }

    def _parse_token_accumulator(self, expression: str) -> Tuple[List[int], List[int]]:
        weights: List[int] = []
        offsets: List[int] = []
        for part in expression.split("+"):
            part = part.strip()
            if not part:
                continue
            match = re.fullmatch(
                r"\(\s*[A-Za-z_][A-Za-z0-9_]*\s*-\s*([^)]+?)\s*\)\s*(?:\*\s*([^)]+))?",
                part,
            )
            if not match:
                continue
            offset_literal, weight_literal = match.groups()
            offset_value = self._try_parse_numeric_literal(offset_literal)
            if offset_value is not None:
                offsets.append(offset_value)
            weight_value = 1
            if weight_literal:
                parsed = self._try_parse_numeric_literal(weight_literal)
                if parsed is not None:
                    weight_value = parsed
            weights.append(weight_value)
        return weights, offsets

    def _infer_radix(self, weights: Sequence[int]) -> Optional[int]:
        if len(weights) < 2 or not weights[0]:
            return None

        ratios: Set[int] = set()
        for previous, current in zip(weights, weights[1:]):
            if previous == 0 or current % previous != 0:
                return None
            ratios.add(current // previous)

        if len(ratios) != 1:
            return None

        radix = ratios.pop()
        if radix <= 1:
            return None
        return radix

    def _collect_helper_pairs_v14_3(
        self, source: str, helper: str, limit: int
    ) -> List[Tuple[str, str]]:
        calls = self._collect_helper_argument_lists(source, helper, limit)
        pairs: List[Tuple[str, str]] = []
        for args in calls:
            if len(args) >= 2:
                pairs.append((args[0].strip(), args[1].strip()))
        return pairs

    def _collect_shift_argument_payloads_v14_3(
        self, source: str
    ) -> Dict[str, List[str]]:
        payload: Dict[str, List[str]] = {}
        helper_map = {
            "lshift": "C3.a",
            "rshift": "C3.s",
            "lrotate": "C3.b",
            "rrotate": "C3._",
        }

        for label, helper in helper_map.items():
            args_lists = self._collect_helper_argument_lists(source, helper, limit=4)
            if not args_lists:
                continue
            counts = [args[1].strip() for args in args_lists if len(args) >= 2]
            if counts:
                payload[label] = counts
        return payload

    def _collect_key_schedule_slots_v14_3(self, source: str) -> List[str]:
        marker = "N(u,0x5)"
        end_idx = source.find(marker)
        if end_idx == -1:
            return []

        snippet = source[max(0, end_idx - 2000) : end_idx]
        pattern = re.compile(r"([Ff]3)\s*\[\s*([^\]]+)\s*\]")
        slots: List[str] = []
        seen: Set[str] = set()

        for match in pattern.finditer(snippet):
            literal = f"{match.group(1)}[{match.group(2).strip()}]"
            if literal in seen:
                continue
            seen.add(literal)
            slots.append(literal)
            if len(slots) >= 12:
                break
        return slots

    def _collect_helper_argument_lists(
        self, source: str, helper: str, limit: int
    ) -> List[List[str]]:
        pattern = re.compile(rf"{re.escape(helper)}\s*\(")
        calls: List[List[str]] = []
        start = 0
        while len(calls) < limit:
            match = pattern.search(source, start)
            if not match:
                break
            open_idx = match.end() - 1
            segment = self._extract_parenthesised_segment(source, open_idx)
            if segment is None:
                break
            args_text, close_idx = segment
            calls.append(self._split_argument_list(args_text))
            start = close_idx
        return calls

    def _split_argument_list(self, args: str) -> List[str]:
        args = args.strip()
        if not args:
            return []

        values: List[str] = []
        depth = 0
        start = 0
        index = 0
        while index < len(args):
            ch = args[index]
            if ch in {"'", '"'}:
                index = self._skip_string_literal(args, index)
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                values.append(args[start:index].strip())
                start = index + 1
            index += 1

        tail = args[start:].strip()
        if tail:
            values.append(tail)
        return values

    def _extract_parenthesised_segment(
        self, text: str, open_index: int
    ) -> Optional[Tuple[str, int]]:
        if open_index >= len(text) or text[open_index] != "(":
            return None

        depth = 0
        index = open_index
        while index < len(text):
            ch = text[index]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[open_index + 1 : index], index + 1
            elif ch in {"'", '"'}:
                index = self._skip_string_literal(text, index)
                continue
            index += 1
        return None

    def _skip_string_literal(self, text: str, start: int) -> int:
        quote = text[start]
        index = start + 1
        while index < len(text):
            ch = text[index]
            if ch == "\\":
                index += 2
                continue
            if ch == quote:
                return index + 1
            index += 1
        return len(text)

    def _parse_c3_primitive_entries(self, literal: str) -> List[Dict[str, Any]]:
        literal = literal.strip()
        if not literal.startswith("{") or not literal.endswith("}"):
            return []

        body = literal[1:-1]
        fields = self._split_table_fields(body)

        entries: List[Dict[str, Any]] = []

        for field in fields:
            if "=" not in field:
                continue

            key_part, value_part = field.split("=", 1)
            key_part = key_part.strip()
            value_part = value_part.strip()

            if not key_part or not value_part:
                continue

            if not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*", value_part
            ):
                continue

            module, symbol = value_part.split(".", 1)

            slot_type = "key"
            slot_literal = key_part
            slot_value = key_part
            accessor: str
            entry: Dict[str, Any]

            if key_part.startswith("[") and key_part.endswith("]"):
                slot_type = "index"
                slot_value = key_part[1:-1].strip()
                accessor = f"C3[{slot_value}]" if slot_value else "C3[]"
                index_value = self._try_parse_numeric_literal(slot_value)
                entry = {
                    "slot": slot_value,
                    "slot_literal": slot_literal,
                    "slot_type": slot_type,
                    "accessor": accessor,
                    "builtin": value_part,
                    "module": module,
                    "symbol": symbol,
                }
                if index_value is not None:
                    entry["index_value"] = index_value
            else:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_part):
                    continue
                accessor = f"C3.{key_part}"
                entry = {
                    "slot": key_part,
                    "slot_literal": slot_literal,
                    "slot_type": slot_type,
                    "accessor": accessor,
                    "builtin": value_part,
                    "module": module,
                    "symbol": symbol,
                }

            entry["position"] = len(entries)
            entries.append(entry)

        return entries

    def _split_table_fields(self, body: str) -> List[str]:
        fields: List[str] = []
        token: List[str] = []
        depth = 0
        in_string = False
        escape = False
        quote_char = ""

        for ch in body:
            if in_string:
                token.append(ch)
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote_char:
                    in_string = False
                continue

            if ch in {'"', "'"}:
                in_string = True
                quote_char = ch
                token.append(ch)
            elif ch in "([{":
                depth += 1
                token.append(ch)
            elif ch in ")]}":
                depth = max(0, depth - 1)
                token.append(ch)
            elif ch == "," and depth == 0:
                field = "".join(token).strip()
                if field:
                    fields.append(field)
                token = []
            else:
                token.append(ch)

        tail = "".join(token).strip()
        if tail:
            fields.append(tail)

        return fields

    def locate_serialized_chunk_v14_3(
        self, source: str
    ) -> Optional[SerializedChunkDescriptor]:
        """Return metadata for the standalone Luraph v14.3 VM serializer."""

        if "9007199254740992" not in source:
            return None

        state_match = re.search(
            r"local\s+[A-Za-z0-9_,]+\s*=\s*\(9007199254740992\)", source
        )
        if not state_match:
            return None

        region_start = max(0, state_match.start() - 1024)
        region_end = min(len(source), state_match.end() + 4096)
        region = source[region_start:region_end]

        format_call_pattern = re.compile(
            r"I\(\s*(['\"])((?:\\.|(?!\1).)+)\1\s*,\s*([A-Za-z0-9_]+)\s*,\s*t"
        )

        def match_format(body: str, predicate: Callable[[str], bool]) -> Optional[str]:
            for fmt_match in format_call_pattern.finditer(body):
                fmt = fmt_match.group(2)
                if predicate(fmt):
                    return fmt_match.group(3)
            return None

        header_match = re.search(
            r"\bo\s*=\s*\(function\(\)(?P<body>.*?)end\)", region, re.DOTALL
        )
        if not header_match:
            return None
        header_body = header_match.group("body")
        buffer_name = match_format(header_body, lambda fmt: "<I\\52" in fmt)
        if not buffer_name:
            return None

        double_match = re.search(
            r"\bt3\s*=\s*function\(\)(?P<body>.*?)end;", region, re.DOTALL
        )
        if not double_match:
            return None
        double_body = double_match.group("body")
        double_buffer = match_format(
            double_body, lambda fmt: "\\z" in fmt and "\\56" in fmt
        )
        if double_buffer != buffer_name:
            return None

        varint_match = re.search(
            r"\ba3\s*=\s*\(function\(\)(?P<body>.*?)end\)", region, re.DOTALL
        )
        if not varint_match:
            return None
        varint_body = varint_match.group("body")
        if not re.search(
            rf"b\(\s*{re.escape(buffer_name)}\s*,\s*t\s*,\s*t\s*\)", varint_body
        ):
            return None
        if "0X7F" not in varint_body.upper():
            return None

        table_match = re.search(
            r"\bM\s*=\s*\(function\(\)(?P<body>.*?)end\)", region, re.DOTALL
        )
        if not table_match:
            return None
        table_body = table_match.group("body")
        table_buffer = match_format(table_body, lambda fmt: "<\\d" in fmt)
        if table_buffer != buffer_name:
            return None

        slice_match = re.search(
            r"\br\s*=\s*\(function\(\)(?P<body>.*?)end\)", region, re.DOTALL
        )
        if not slice_match:
            return None
        slice_body = slice_match.group("body")
        if not re.search(
            rf"N\(\s*{re.escape(buffer_name)}\s*,\s*t-Y\s*,\s*t-0[Xx]0*1\s*\)",
            slice_body,
        ):
            return None

        offset_match = re.search(
            r"\bt\s*=\s*(0[Xx][0-9A-Fa-f_]+|0[Bb][01_]+|\d+)\s*;", source
        )
        if not offset_match:
            return None

        offset_literal = offset_match.group(1)
        initial_offset = self._parse_numeric_literal(offset_literal)

        helpers = {
            "o": "o",
            "t3": "t3",
            "a3": "a3",
            "M": "M",
            "r": "r",
        }

        return SerializedChunkDescriptor(
            buffer_name=buffer_name,
            initial_offset=initial_offset,
            helper_functions=helpers,
        )

    def _detect_bootstrap_state_machine_v14_3(
        self, source: str
    ) -> Optional[BootstrapStateMachine]:
        if "protected using Luraph Obfuscator v14.3" not in source:
            return None

        if "if x==" not in source:
            return None

        states: List[BootstrapState] = []
        search_pos = 0

        while True:
            branch_match = self._state_branch_pattern.search(source, search_pos)
            if not branch_match:
                break

            state_literal = branch_match.group(1)
            body, branch_end = self._extract_branch_body(source, branch_match.end())
            if body is None:
                search_pos = branch_match.end()
                continue

            operations, transitions = self._summarise_state_body(body)
            state_numeric = self._try_parse_numeric_literal(state_literal)

            states.append(
                BootstrapState(
                    state_id=state_literal,
                    state_numeric=state_numeric,
                    operations=operations,
                    transitions=transitions,
                )
            )
            search_pos = branch_end

        if len(states) < 2:
            return None

        return BootstrapStateMachine(variable="x", states=states)

    def _extract_branch_body(
        self, source: str, start_index: int
    ) -> Tuple[Optional[str], int]:
        body_start = start_index

        keyword_pattern = re.compile(
            r"\b(if|elseif|else|end|function|while|for|repeat|until|do)\b",
            re.IGNORECASE,
        )

        stack: List[str] = []
        position = body_start

        while True:
            keyword_match = keyword_pattern.search(source, position)
            if keyword_match is None:
                return None, position

            token = keyword_match.group(1).lower()

            if token in {"if", "function", "while", "for", "do"}:
                stack.append("end")
                position = keyword_match.end()
                continue

            if token == "repeat":
                stack.append("until")
                position = keyword_match.end()
                continue

            if token in {"elseif", "else"} and not stack:
                body_end = keyword_match.start()
                return source[body_start:body_end], keyword_match.start()

            if token == "end":
                if stack:
                    stack.pop()
                    position = keyword_match.end()
                    continue
                body_end = keyword_match.start()
                return source[body_start:body_end], keyword_match.end()

            if token == "until":
                if stack and stack[-1] == "until":
                    stack.pop()
                    position = keyword_match.end()
                    continue
                if not stack:
                    body_end = keyword_match.start()
                    return source[body_start:body_end], keyword_match.end()

            position = keyword_match.end()

    def _summarise_state_body(
        self, body: str
    ) -> Tuple[List[str], List[BootstrapTransition]]:
        operations: List[str] = []
        transitions: List[BootstrapTransition] = []

        statements = [stmt.strip() for stmt in body.split(";") if stmt.strip()]

        for statement in statements:
            if statement in {"end", "else", "elseif"}:
                continue

            lower = statement.lower()
            if lower in {"continue", "break"}:
                transitions.append(BootstrapTransition(expression=statement))
                continue

            assignments = self._extract_assignments_from_statement(statement)
            if not assignments:
                operations.append(statement)
                continue

            for lhs, rhs in assignments:
                rhs = self._normalise_expression(rhs)
                if lhs == "x":
                    transitions.append(
                        BootstrapTransition(
                            expression=rhs,
                            target=self._try_parse_numeric_literal(rhs),
                        )
                    )
                else:
                    operations.append(f"{lhs}={rhs}")

        return operations, transitions

    def _extract_assignments_from_statement(
        self, statement: str
    ) -> List[Tuple[str, str]]:
        assignments: List[Tuple[str, str]] = []
        position = 0
        while True:
            match = self._assignment_pattern.search(statement, position)
            if not match:
                break

            lhs = match.group(1).strip()
            rhs_start = match.end()
            next_match = self._assignment_pattern.search(statement, rhs_start)
            if next_match:
                rhs = statement[rhs_start:next_match.start()].strip()
                position = next_match.start()
            else:
                rhs = statement[rhs_start:].strip()
                position = len(statement)

            if "==" in rhs or lhs.endswith("=="):
                continue

            assignments.append((lhs, rhs))

        return assignments

    def _try_parse_numeric_literal(self, literal: str) -> Optional[int]:
        token = self._normalise_expression(literal)

        if not token:
            return None

        numeric_pattern = re.compile(
            r"^[+-]?(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|\d+)$"
        )
        if numeric_pattern.match(token):
            try:
                return self._parse_numeric_literal(token)
            except ValueError:
                return None

        return None

    def _normalise_expression(self, expression: str) -> str:
        token = expression.strip()
        while token.startswith("(") and token.endswith(")"):
            depth = 0
            balanced = True
            for index, ch in enumerate(token):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and index != len(token) - 1:
                        balanced = False
                        break
            if balanced and depth == 0:
                token = token[1:-1].strip()
            else:
                break
        return token

    @staticmethod
    def _parse_numeric_literal(literal: str) -> int:
        token = literal.replace("_", "")
        try:
            return int(token, 0)
        except ValueError:
            return int(token, 10)

    def generate_upcode_table(
        self,
        raw_entries: Optional[Mapping[int, Any]] = None,
    ) -> Dict[int, Dict[str, Any]]:
        """Return a normalised opcode table with ``OP_``-prefixed mnemonics.

        Parameters
        ----------
        raw_entries:
            Mapping of opcode numbers to metadata dictionaries.  Non-dictionary
            values are interpreted as shorthand for the mnemonic field.

        The function guarantees that every returned entry contains a
        ``mnemonic`` key whose value is an upper-case string beginning with the
        ``OP_`` prefix.  Missing or false-y mnemonics are replaced with the
        fallback ``OP_{opcode:02X}`` format.
        """

        if raw_entries is None:
            raw_entries = {}

        helper_pattern = re.compile(r"\bhelper[A-Za-z0-9_]*\b", re.IGNORECASE)

        def detect_helper_name(value: Any) -> Optional[str]:
            """Return the first helper name embedded in ``value`` if present."""

            if isinstance(value, str):
                match = helper_pattern.search(value)
                if match:
                    return match.group(0)
                return None

            if isinstance(value, MappingABC):
                for candidate in value.values():
                    found = detect_helper_name(candidate)
                    if found:
                        return found
                return None

            if (
                isinstance(value, IterableABC)
                and not isinstance(value, (bytes, bytearray, str, MappingABC))
            ):
                for candidate in value:
                    found = detect_helper_name(candidate)
                    if found:
                        return found

            return None

        def normalise_mnemonic(
            raw: Optional[Any], opcode: int, payload: Any
        ) -> str:
            """Normalise ``raw`` to the canonical ``OP_`` prefixed form."""

            candidate: Optional[str]
            if raw is not None and str(raw).strip():
                candidate = str(raw)
            else:
                candidate = detect_helper_name(payload)
                if not candidate:
                    return f"OP_{opcode:02X}"

            upper = str(candidate).strip().upper()
            cleaned = re.sub(r"[^A-Z0-9_]", "", upper)
            cleaned = cleaned.lstrip("_")

            if not cleaned:
                return f"OP_{opcode:02X}"

            if cleaned.startswith("OP_"):
                canonical = cleaned
            elif cleaned.startswith("OP"):
                suffix = cleaned[2:].lstrip("_")
                canonical = f"OP_{suffix}" if suffix else f"OP_{opcode:02X}"
            else:
                canonical = f"OP_{cleaned}"

            if canonical in {"OP", "OP_"}:
                return f"OP_{opcode:02X}"

            return canonical

        def validate_entry(entry: Mapping[str, Any]) -> None:
            """Ensure ``entry`` satisfies the expected opcode schema."""

            required_fields = ("opcode", "mnemonic", "operand_types", "sample_usage")
            missing = [field for field in required_fields if field not in entry]
            if missing:
                opcode_value = entry.get("opcode", "<unknown>")
                try:
                    opcode_display = f"0x{int(opcode_value):02X}"
                except (TypeError, ValueError):
                    opcode_display = opcode_value
                missing_display = ", ".join(sorted(missing))
                raise ValueError(
                    f"Opcode {opcode_display} entry missing required fields: {missing_display}"
                )

        table: Dict[int, Dict[str, Any]] = {}
        for opcode, entry in raw_entries.items():
            opcode_int = int(opcode)
            if isinstance(entry, dict):
                processed = dict(entry)
                payload = processed
            else:
                processed = {}
                if entry is not None:
                    processed["mnemonic"] = entry
                payload = entry

            canonical = normalise_mnemonic(
                processed.get("mnemonic"), opcode_int, payload
            )
            processed["mnemonic"] = canonical

            frequency_raw = processed.get("frequency", 0)
            try:
                frequency_value = int(frequency_raw)
            except (TypeError, ValueError):
                frequency_value = 0
            if frequency_value < 0:
                frequency_value = 0
            processed["frequency"] = frequency_value

            processed.setdefault("opcode", opcode_int)

            validate_entry(processed)

            table[opcode_int] = processed

        return table

    def generate_upcode_table_outputs_docs(
        self,
        raw_entries: Optional[Mapping[int, Any]] = None,
        output_dir: Union[str, Path] = Path("out") / "pattern_analyzer",
    ) -> Dict[str, Path]:
        """Serialise the opcode table into multiple documentation formats.

        Parameters
        ----------
        raw_entries:
            Optional mapping of opcode numbers to raw metadata.  When omitted
            the method behaves as if an empty mapping was supplied.
        output_dir:
            Directory where the documentation artefacts should be written.  The
            directory will be created if it does not already exist.
        """

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        table = self.generate_upcode_table(raw_entries)
        rows: List[Dict[str, Any]] = []
        for opcode, entry in sorted(table.items()):
            mnemonic = entry.get("mnemonic", "")
            frequency_value = entry.get("frequency", 0)
            try:
                frequency_int = int(frequency_value)
            except (TypeError, ValueError):
                frequency_int = 0
            if frequency_int < 0:
                frequency_int = 0
            rows.append(
                {
                    "opcode": f"0x{int(opcode) & 0x3F:02X}",
                    "mnemonic": str(mnemonic),
                    "frequency": frequency_int,
                }
            )

        json_path = output_path / "upcode_table.json"
        json_path.write_text(json.dumps(rows, indent=2, sort_keys=False))

        markdown_lines = [
            "| Opcode | Mnemonic | Frequency |",
            "| --- | --- | --- |",
        ]
        markdown_lines.extend(
            f"| {row['opcode']} | {row['mnemonic']} | {row['frequency']} |" for row in rows
        )
        md_path = output_path / "upcode_table.md"
        md_path.write_text("\n".join(markdown_lines) + "\n")

        csv_path = output_path / "upcode_table.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["opcode", "mnemonic", "frequency"])
            for row in rows:
                writer.writerow([row["opcode"], row["mnemonic"], row["frequency"]])

        html_rows = [
            "<table>",
            "  <thead>",
            "    <tr><th>Opcode</th><th>Mnemonic</th><th>Frequency</th></tr>",
            "  </thead>",
            "  <tbody>",
        ]
        for row in rows:
            html_rows.append(
                "    <tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    escape(row["opcode"]),
                    escape(row["mnemonic"]),
                    escape(str(row["frequency"])),
                )
            )
        html_rows.extend(["  </tbody>", "</table>"])
        html_path = output_path / "upcode_table.html"
        html_path.write_text("\n".join(html_rows) + "\n")

        return {
            "json": json_path,
            "md": md_path,
            "csv": csv_path,
            "html": html_path,
        }

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

    def optimise_ir(self, instructions: Iterable[IRInstruction]) -> List[IRInstruction]:
        """Run peephole optimisations and dead-code elimination on ``instructions``."""

        original = list(instructions)
        folded, report = self._fold_constants(original)
        folded = self._eliminate_bogus_loops(folded)
        folded = self._remove_nops(folded)
        pruned = self.prune_unreachable(folded)

        removed = {ins.index for ins in original} - {ins.index for ins in pruned}
        report.removed_blocks = removed

        renumbered = self._renumber(pruned)
        renumbered = self._peephole_cleanup(renumbered, report)
        renumbered = self._renumber(renumbered)

        cfg = self.build_cfg(renumbered)
        cfg = self.remove_dead_code(cfg)
        dfg = self.build_dfg(cfg.nodes.values())

        self.last_cfg = cfg
        self.last_dfg = dfg
        self.last_report = report

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
