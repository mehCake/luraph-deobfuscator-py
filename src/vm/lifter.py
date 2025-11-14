"""Heavyweight VM lifter that reconstructs structured IR from bytecode."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from src.lifter.lifter import LiftOutput, lift_program
from src.utils.luraph_vm import VMRebuildResult, rebuild_vm_bytecode

from .disassembler import Instruction
from .opcode_map import OpcodeMap

LOGGER = logging.getLogger(__name__)

SBX_BIAS = 131071
RK_THRESHOLD = 256

DEFAULT_IR_FORMAT = "structured"
SUPPORTED_IR_FORMATS = {"structured", "basic"}

# Common opcode hints mirrored from Lua 5.1 style dispatch tables.  These are
# not authoritative, but they significantly improve mnemonic guesses for
# Luraph v14.4.2 payloads when no explicit opcode map is available.
V1442_OPCODE_HINTS: Mapping[int, str] = {
    0x00: "MOVE",
    0x01: "LOADK",
    0x02: "LOADKX",
    0x03: "LOADBOOL",
    0x04: "LOADNIL",
    0x05: "GETUPVAL",
    0x06: "GETGLOBAL",
    0x07: "GETTABLE",
    0x08: "SETGLOBAL",
    0x09: "SETUPVAL",
    0x0A: "SETTABLE",
    0x0B: "NEWTABLE",
    0x0C: "SELF",
    0x0D: "ADD",
    0x0E: "SUB",
    0x0F: "MUL",
    0x10: "DIV",
    0x11: "MOD",
    0x12: "POW",
    0x13: "UNM",
    0x14: "NOT",
    0x15: "LEN",
    0x16: "CONCAT",
    0x17: "JMP",
    0x18: "EQ",
    0x19: "LT",
    0x1A: "LE",
    0x1B: "TEST",
    0x1C: "TESTSET",
    0x1D: "CALL",
    0x1E: "TAILCALL",
    0x1F: "RETURN",
    0x20: "FORLOOP",
    0x21: "FORPREP",
    0x22: "TFORLOOP",
    0x23: "SETLIST",
    0x24: "CLOSE",
    0x25: "CLOSURE",
    0x26: "VARARG",
}


def _encode_word(opcode: int, a: int, b: int, c: int) -> int:
    """Return the Lua 5.1 encoded instruction word for debugging helpers."""

    return (opcode & 0x3F) | ((a & 0xFF) << 6) | ((c & 0x1FF) << 14) | ((b & 0x1FF) << 23)


def _compute_bx(word: Optional[int]) -> Optional[int]:
    if word is None:
        return None
    return (word >> 14) & 0x3FFFF


def _compute_sbx(word: Optional[int]) -> Optional[int]:
    bx = _compute_bx(word)
    if bx is None:
        return None
    return bx - SBX_BIAS


@dataclass
class IROperand:
    """Representation of a single operand in the lifted IR."""

    field: str
    value: Optional[int]
    kind: str
    resolved: Any = None

    def as_dict(self) -> MutableMapping[str, Any]:
        payload: MutableMapping[str, Any] = {
            "field": self.field,
            "kind": self.kind,
            "value": self.value,
        }
        if self.resolved is not None:
            payload["resolved"] = self.resolved
        return payload


@dataclass
class IROp:
    """Lifted instruction entry with metadata."""

    mnemonic: str
    operands: Sequence[IROperand]
    index: int
    raw: Optional[int]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> MutableMapping[str, Any]:
        payload: MutableMapping[str, Any] = {
            "mnemonic": self.mnemonic,
            "operands": [operand.as_dict() for operand in self.operands],
            "index": self.index,
            "raw": self.raw,
        }
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass
class BasicBlock:
    """A straight-line block of instructions with explicit successors."""

    block_id: str
    start_index: int
    end_index: int
    ops: List[IROp] = field(default_factory=list)
    fallthrough: Optional[str] = None
    jump: Optional[str] = None
    raw_offsets: Sequence[int] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)
    metadata: MutableMapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> MutableMapping[str, Any]:
        payload: MutableMapping[str, Any] = {
            "id": self.block_id,
            "start_index": self.start_index,
            "end_index": self.end_index,
            "ops": [op.as_dict() for op in self.ops],
            "fallthrough": self.fallthrough,
            "jump": self.jump,
            "raw_offsets": list(self.raw_offsets),
            "successors": list(self.successors),
            "predecessors": list(self.predecessors),
        }
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass
class IRProgram:
    """Container for the lifted program with CFG metadata."""

    blocks: List[BasicBlock]
    metadata: MutableMapping[str, Any] = field(default_factory=dict)
    entry_block: Optional[str] = None

    def as_dict(self) -> MutableMapping[str, Any]:
        payload: MutableMapping[str, Any] = {
            "blocks": [block.as_dict() for block in self.blocks],
            "metadata": dict(self.metadata),
        }
        if self.entry_block is not None:
            payload["entry_block"] = self.entry_block
        return payload


@dataclass
class LiftResult:
    """Structured lifter output used by downstream tooling."""

    program: IRProgram
    metadata: Dict[str, Any]
    ir_entries: Sequence[Mapping[str, Any]]
    ir_format: str
    lua_source: str = ""
    raw_output: Optional[LiftOutput] = None
    verbose_mapping: Sequence[str] = field(default_factory=tuple)

    def as_dict(self) -> MutableMapping[str, Any]:
        payload: MutableMapping[str, Any] = {
            "metadata": dict(self.metadata),
            "ir_entries": [dict(entry) for entry in self.ir_entries],
            "program": self.program.as_dict(),
            "ir_format": self.ir_format,
        }
        if self.lua_source:
            payload["lua_source"] = self.lua_source
        if self.verbose_mapping:
            payload["verbose_mapping"] = list(self.verbose_mapping)
        return payload


class Lifter:
    """Entry point for lifting decoded VM bytecode into structured IR."""

    def __init__(
        self,
        opcode_map: Optional[OpcodeMap] = None,
        *,
        operand_kinds: Optional[Mapping[str, Mapping[str, str]]] = None,
        version_hint: Optional[str] = None,
        default_ir_format: str = DEFAULT_IR_FORMAT,
    ) -> None:
        self.opcode_map = opcode_map or OpcodeMap()
        self._operand_kind_overrides = operand_kinds or {}
        self.default_ir_format = default_ir_format if default_ir_format in SUPPORTED_IR_FORMATS else DEFAULT_IR_FORMAT
        self._apply_version_hints(version_hint)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lift(
        self,
        instructions: Sequence[Instruction],
        *,
        constants: Optional[Sequence[Any]] = None,
        prototypes: Optional[Sequence[Any]] = None,
        script_key: Optional[str | bytes] = None,
        vm_metadata: Optional[Mapping[str, Any]] = None,
        ir_format: Optional[str] = None,
        verbose: bool = False,
    ) -> LiftResult:
        """Lift a sequence of :class:`Instruction` objects into IR."""

        constants_list = list(constants or [])
        if not instructions:
            empty_program = IRProgram(
                blocks=[], metadata={"instruction_count": 0, "block_count": 0, "ir_format": ir_format or self.default_ir_format}
            )
            empty_output = None
            return LiftResult(
                program=empty_program,
                metadata={"instruction_count": 0, "block_count": 0, "ir_format": ir_format or self.default_ir_format},
                ir_entries=[],
                ir_format=ir_format or self.default_ir_format,
                raw_output=empty_output,
            )
        format_to_use = ir_format or self.default_ir_format
        if format_to_use not in SUPPORTED_IR_FORMATS:
            LOGGER.warning("Unsupported IR format %s, falling back to %s", format_to_use, self.default_ir_format)
            format_to_use = self.default_ir_format

        rows = [self._instruction_to_row(instr) for instr in instructions]
        opcode_mapping = self._opcode_mapping(rows)

        if format_to_use == "basic":
            program, entries = self._build_basic_ir(instructions, constants_list)
            metadata: Dict[str, Any] = {
                "instruction_count": len(instructions),
                "block_count": len(program.blocks),
                "ir_format": format_to_use,
            }
            verbose_lines = self._build_verbose_mapping(program)
            if verbose:
                for line in verbose_lines:
                    LOGGER.info("%s", line)
            return LiftResult(
                program=program,
                metadata=metadata,
                ir_entries=entries,
                ir_format=format_to_use,
                verbose_mapping=verbose_lines,
            )

        output = lift_program(
            rows,
            constants_list,
            opcode_mapping,
            prototypes=prototypes or [],
            script_key=script_key,
            vm_metadata=vm_metadata,
        )

        program = self._build_ir_program(instructions, output, constants_list)
        metadata = dict(output.metadata)
        metadata.setdefault("instruction_count", program.metadata.get("instruction_count"))
        metadata.setdefault("block_count", program.metadata.get("block_count"))
        metadata["ir_format"] = format_to_use
        verbose_lines = self._build_verbose_mapping(program)
        if verbose:
            for line in verbose_lines:
                LOGGER.info("%s", line)
        return LiftResult(
            program=program,
            lua_source=output.lua_source,
            metadata=metadata,
            ir_entries=output.ir_entries,
            ir_format=format_to_use,
            raw_output=output,
            verbose_mapping=verbose_lines,
        )

    def lift_unpacked(
        self,
        payload: Mapping[str, Any] | Sequence[Any],
        *,
        opcode_table: Optional[Mapping[str, Any]] = None,
        script_key: Optional[str | bytes] = None,
        vm_metadata: Optional[Mapping[str, Any]] = None,
        ir_format: Optional[str] = None,
        verbose: bool = False,
    ) -> LiftResult:
        """Lift a decoded ``unpackedData`` table from the bootstrapper."""

        vm_result = rebuild_vm_bytecode(payload, opcode_table)
        self._merge_opcode_hints(vm_result, opcode_table)
        instructions = self._instructions_from_vm_result(vm_result)
        return self.lift(
            instructions,
            constants=vm_result.constants,
            prototypes=getattr(vm_result, "micro_instructions", None),
            script_key=script_key,
            vm_metadata=vm_metadata,
            ir_format=ir_format,
            verbose=verbose,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _opcode_mapping(self, rows: Sequence[Mapping[str, Any]]) -> Dict[int, str]:
        mapping: Dict[int, str] = {}
        for opcode, mnemonic in self.opcode_map.iter_known():
            mapping[int(opcode)] = mnemonic
        for row in rows:
            opcode = row.get("opcode")
            mnemonic = row.get("mnemonic") or row.get("op")
            if isinstance(opcode, int) and isinstance(mnemonic, str):
                mapping.setdefault(opcode, mnemonic)
        return mapping

    def _apply_version_hints(self, version_hint: Optional[str]) -> None:
        if not version_hint:
            # Register a small set of defaults that are generally safe regardless
            # of version.  These mirror common Lua VM opcodes.
            for opcode, mnemonic in V1442_OPCODE_HINTS.items():
                self.opcode_map.register(opcode, mnemonic)
            return

        normalized = version_hint.strip().lower()
        if normalized in {"14.4.2", "v14.4.2", "luraph-14.4.2"}:
            for opcode, mnemonic in V1442_OPCODE_HINTS.items():
                self.opcode_map.register(opcode, mnemonic)
        else:
            # Fall back to the generic hints so other versions still benefit.
            for opcode, mnemonic in V1442_OPCODE_HINTS.items():
                self.opcode_map.register(opcode, mnemonic)

    def _merge_opcode_hints(
        self,
        vm_result: VMRebuildResult,
        opcode_table: Optional[Mapping[str, Any]],
    ) -> None:
        if opcode_table:
            for key, entry in opcode_table.items():
                try:
                    opcode = int(key)
                except Exception:
                    continue
                mnemonic: Optional[str]
                if isinstance(entry, Mapping):
                    mnemonic = entry.get("mnemonic") or entry.get("op") or entry.get("name")
                else:
                    mnemonic = str(entry)
                if mnemonic:
                    self.opcode_map.register(opcode, str(mnemonic))

        for item in vm_result.instructions:
            opcode = item.get("opcode") or item.get("opnum")
            mnemonic = item.get("mnemonic") or item.get("op")
            if isinstance(opcode, int) and isinstance(mnemonic, str):
                if mnemonic.upper().startswith("OP_"):
                    continue
                self.opcode_map.register(opcode, mnemonic)

    def _instruction_to_row(self, instr: Instruction) -> Dict[str, Any]:
        word = instr.raw
        bx = _compute_bx(word)
        sbx = _compute_sbx(word)
        mnemonic = self.opcode_map.get_mnemonic(instr.opcode)
        if mnemonic is None:
            mnemonic = f"OP_{instr.opcode:02X}"

        row: Dict[str, Any] = {
            "index": instr.index,
            "pc": instr.index,
            "opcode": instr.opcode,
            "opnum": instr.opcode,
            "mnemonic": mnemonic,
            "A": instr.a,
            "B": instr.b,
            "C": instr.c,
            "a": instr.a,
            "b": instr.b,
            "c": instr.c,
            "raw": [instr.raw, instr.a, instr.b, instr.c],
        }
        if bx is not None:
            row["Bx"] = bx
        if sbx is not None:
            row["sBx"] = sbx
            row["offset"] = sbx
        return row

    def _build_basic_ir(
        self, instructions: Sequence[Instruction], constants: Sequence[Any]
    ) -> Tuple[IRProgram, List[Mapping[str, Any]]]:
        if not instructions:
            empty_program = IRProgram(
                blocks=[], metadata={"instruction_count": 0, "block_count": 0, "ir_format": "basic"}
            )
            return empty_program, []

        entries: List[Mapping[str, Any]] = []
        block = BasicBlock(block_id="block_0", start_index=0, end_index=len(instructions) - 1)
        block.raw_offsets = [instr.index for instr in instructions]
        block.metadata["category"] = "linear"
        for instr in instructions:
            entry = {
                "opcode": instr.opcode,
                "mnemonic": self.opcode_map.get_mnemonic(instr.opcode) or f"OP_{instr.opcode:02X}",
                "a": instr.a,
                "b": instr.b,
                "c": instr.c,
            }
            sbx = _compute_sbx(instr.raw)
            operands = self._operands_for(entry, constants, instr, sbx)
            mnemonic = self._mnemonic(entry)
            category = self._categorize_basic(mnemonic)
            metadata: Dict[str, Any] = {"category": category}
            if sbx is not None:
                metadata["sbx"] = sbx
            block.ops.append(
                IROp(
                    mnemonic=mnemonic,
                    operands=operands,
                    index=instr.index,
                    raw=instr.raw,
                    metadata=metadata,
                )
            )
            entries.append(
                {
                    "index": instr.index,
                    "mnemonic": mnemonic,
                    "category": category,
                    "operands": [operand.as_dict() for operand in operands],
                    "raw": instr.raw,
                }
            )

        program = IRProgram(
            blocks=[block],
            metadata={
                "instruction_count": len(instructions),
                "block_count": 1,
                "ir_format": "basic",
            },
            entry_block=block.block_id,
        )
        return program, entries

    def _categorize_basic(self, mnemonic: str) -> str:
        op = mnemonic.upper()
        if op in {"LOADK", "LOADNIL", "MOVE", "LOADBOOL", "LOADKX"}:
            return "load"
        if op in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW"}:
            return "binop"
        if op in {"JMP", "FORLOOP", "FORPREP", "TFORLOOP"}:
            return "jump"
        if op in {"CALL", "TAILCALL"}:
            return "call"
        if op in {"RETURN"}:
            return "return"
        if op in {"EQ", "LT", "LE", "TEST", "TESTSET"}:
            return "compare"
        return "op"

    def _build_verbose_mapping(self, program: IRProgram) -> List[str]:
        lines: List[str] = []
        for block in program.blocks:
            for op in block.ops:
                lines.append(f"{op.index:04d} -> {block.block_id}:{op.mnemonic}")
        return lines

    def _instructions_from_vm_result(
        self, vm_result: VMRebuildResult
    ) -> List[Instruction]:
        bytecode = vm_result.bytecode
        words: List[int] = []
        step = 4
        for start in range(0, len(bytecode), step):
            chunk = bytecode[start : start + step]
            if len(chunk) < step:
                break
            words.append(int.from_bytes(chunk, "little"))

        instructions: List[Instruction] = []
        for index, item in enumerate(vm_result.instructions):
            opcode = item.get("opcode") or item.get("opnum") or 0
            a = item.get("A") if item.get("A") is not None else item.get("a")
            b = item.get("B") if item.get("B") is not None else item.get("b")
            c = item.get("C") if item.get("C") is not None else item.get("c")
            word = words[index] if index < len(words) else None
            instructions.append(
                Instruction(
                    index=index,
                    raw=word or _encode_word(int(opcode) & 0x3F, int(a or 0), int(b or 0), int(c or 0)),
                    opcode=int(opcode),
                    a=int(a or 0),
                    b=int(b or 0),
                    c=int(c or 0),
                )
            )
        return instructions

    def _build_ir_program(
        self,
        instructions: Sequence[Instruction],
        lift_output: LiftOutput,
        constants: Sequence[Any],
    ) -> IRProgram:
        ir_entries = list(lift_output.ir_entries)
        instruction_map = {instr.index: instr for instr in instructions}

        block_starts: set[int] = {0}
        control_info: Dict[int, Mapping[str, Any]] = {}
        total = len(ir_entries)

        for index, entry in enumerate(ir_entries):
            mnemonic = self._mnemonic(entry)
            instr = instruction_map.get(index)
            word = instr.raw if instr else None
            sbx = _compute_sbx(word)
            control = self._control_metadata(index, mnemonic, entry, sbx, total)
            if control:
                control_info[index] = control
                targets = [
                    control.get("target"),
                    control.get("true_target"),
                    control.get("false_target"),
                ]
                for target in targets:
                    if isinstance(target, int) and 0 <= target < total:
                        block_starts.add(target)
            if mnemonic in {"RETURN", "TAILCALL"} and index + 1 < total:
                block_starts.add(index + 1)
            if mnemonic == "JMP" and index + 1 < total:
                block_starts.add(index + 1)
            if mnemonic in {"FORLOOP", "TFORLOOP", "FORPREP", "TEST", "TESTSET", "LOADBOOL"}:
                if index + 1 < total:
                    block_starts.add(index + 1)
                if mnemonic in {"TEST", "TESTSET", "LOADBOOL"} and index + 2 < total:
                    block_starts.add(index + 2)

        ordered = sorted(idx for idx in block_starts if 0 <= idx < total)
        blocks: List[BasicBlock] = []
        index_to_block: Dict[int, str] = {}

        for block_id, start in enumerate(ordered):
            end = total - 1
            if block_id + 1 < len(ordered):
                end = ordered[block_id + 1] - 1
            end = max(start, min(end, total - 1))
            block_label = f"block_{block_id}"
            block = BasicBlock(block_id=block_label, start_index=start, end_index=end)
            block.raw_offsets = list(range(start, end + 1))
            blocks.append(block)
            for offset in range(start, end + 1):
                index_to_block[offset] = block.block_id

        for block in blocks:
            for index in range(block.start_index, block.end_index + 1):
                entry = ir_entries[index]
                instr = instruction_map.get(index)
                sbx = _compute_sbx(instr.raw) if instr else None
                operands = self._operands_for(entry, constants, instr, sbx)
                metadata: Dict[str, Any] = {}
                if control_info.get(index):
                    metadata["control"] = control_info[index]
                if sbx is not None:
                    metadata["sbx"] = sbx
                if entry.get("comment"):
                    metadata["comment"] = entry.get("comment")
                block.ops.append(
                    IROp(
                        mnemonic=self._mnemonic(entry),
                        operands=operands,
                        index=index,
                        raw=instr.raw if instr else None,
                        metadata=metadata,
                    )
                )

        self._link_blocks(blocks, control_info, index_to_block, total)

        metadata: Dict[str, Any] = {
            "instruction_count": total,
            "block_count": len(blocks),
        }
        metadata.update({key: value for key, value in lift_output.metadata.items() if key not in metadata})
        metadata.setdefault("ir_format", "structured")
        program = IRProgram(blocks=blocks, metadata=metadata)
        if blocks:
            program.entry_block = blocks[0].block_id
        return program

    def _link_blocks(
        self,
        blocks: Sequence[BasicBlock],
        control_info: Mapping[int, Mapping[str, Any]],
        index_to_block: Mapping[int, str],
        instruction_count: int,
    ) -> None:
        for block in blocks:
            last_index = block.end_index
            control = control_info.get(last_index, {})
            successors: List[str] = []

            def _map_target(target: Optional[int]) -> Optional[str]:
                if target is None:
                    return None
                return index_to_block.get(target)

            mnemonic = block.ops[-1].mnemonic if block.ops else ""
            if control.get("type") == "cond":
                true_block = _map_target(control.get("true_target"))
                false_block = _map_target(control.get("false_target"))
                if true_block:
                    block.fallthrough = true_block
                    successors.append(true_block)
                if false_block and false_block not in successors:
                    block.jump = false_block
                    successors.append(false_block)
            elif control.get("type") == "jump":
                jump_block = _map_target(control.get("target"))
                if jump_block:
                    block.jump = jump_block
                    successors.append(jump_block)
            elif control.get("type") == "loop":
                loop_block = _map_target(control.get("target"))
                if block.end_index + 1 < instruction_count:
                    fallthrough = _map_target(block.end_index + 1)
                    if fallthrough:
                        block.fallthrough = fallthrough
                        successors.append(fallthrough)
                if loop_block:
                    block.jump = loop_block
                    if loop_block not in successors:
                        successors.append(loop_block)
            elif mnemonic == "LOADBOOL" and control.get("type") == "skip":
                skip_block = _map_target(control.get("target"))
                if skip_block:
                    block.jump = skip_block
                    successors.append(skip_block)
            elif control.get("type") in {"return", "tailcall"}:
                successors = []
            else:
                next_index = block.end_index + 1
                if next_index < instruction_count:
                    successor = _map_target(next_index)
                    if successor:
                        block.fallthrough = successor
                        successors.append(successor)

            block.successors = successors
            block.metadata.setdefault("mnemonic", mnemonic)
            if control:
                block.metadata.setdefault("control", control)

        predecessor_map: Dict[str, List[str]] = {block.block_id: [] for block in blocks}
        for block in blocks:
            for successor in block.successors:
                predecessor_map.setdefault(successor, []).append(block.block_id)
        for block in blocks:
            block.predecessors = predecessor_map.get(block.block_id, [])
            if block.predecessors:
                block.metadata.setdefault("predecessor_count", len(block.predecessors))

    def _control_metadata(
        self,
        index: int,
        mnemonic: str,
        entry: Mapping[str, Any],
        sbx: Optional[int],
        total: int,
    ) -> Optional[Dict[str, Any]]:
        if mnemonic == "JMP":
            target = index + 1 + (sbx or 0)
            return {"type": "jump", "target": target if 0 <= target < total else None}
        if mnemonic in {"FORLOOP", "TFORLOOP"}:
            target = index + 1 + (sbx or 0)
            return {"type": "loop", "target": target if 0 <= target < total else None}
        if mnemonic == "FORPREP":
            target = index + 1 + (sbx or 0)
            return {"type": "jump", "mode": "forprep", "target": target if 0 <= target < total else None}
        if mnemonic in {"TEST", "TESTSET"}:
            true_target = index + 1
            false_target = index + 2
            return {
                "type": "cond",
                "guard_register": entry.get("a") or entry.get("A"),
                "true_target": true_target if true_target < total else None,
                "false_target": false_target if false_target < total else None,
            }
        if mnemonic == "LOADBOOL" and int(entry.get("c") or entry.get("C") or 0):
            skip = index + 2
            return {"type": "skip", "target": skip if skip < total else None}
        if mnemonic in {"RETURN", "TAILCALL"}:
            return {"type": "return"}
        return None

    def _mnemonic(self, entry: Mapping[str, Any]) -> str:
        mnemonic = entry.get("op") or entry.get("mnemonic")
        if not isinstance(mnemonic, str) or not mnemonic:
            opcode = entry.get("opcode") or entry.get("opnum")
            if isinstance(opcode, int):
                mnemonic = f"OP_{opcode:02X}"
            else:
                mnemonic = "OP_UNKNOWN"
        return mnemonic.upper()

    def _operands_for(
        self,
        entry: Mapping[str, Any],
        constants: Sequence[Any],
        instr: Optional[Instruction],
        sbx: Optional[int],
    ) -> List[IROperand]:
        mnemonic = self._mnemonic(entry)
        operands: List[IROperand] = []
        operand_values: List[Tuple[str, Optional[int]]] = [
            ("a", self._extract_operand(entry, "a")),
            ("b", self._extract_operand(entry, "b")),
            ("c", self._extract_operand(entry, "c")),
        ]

        for field, value in operand_values:
            kind = self._classify_operand(mnemonic, field, value, instr, sbx)
            resolved = self._resolve_operand(kind, value, constants)
            operands.append(IROperand(field=field, value=value, kind=kind, resolved=resolved))
        return operands

    def _extract_operand(self, entry: Mapping[str, Any], field: str) -> Optional[int]:
        value = entry.get(field)
        if value is None:
            value = entry.get(field.upper())
        if isinstance(value, int):
            return value
        try:
            return int(value)
        except Exception:
            return None

    def _classify_operand(
        self,
        mnemonic: str,
        field: str,
        value: Optional[int],
        instr: Optional[Instruction],
        sbx: Optional[int],
    ) -> str:
        overrides = self._operand_kind_overrides.get(mnemonic.upper())
        if overrides and field in overrides:
            return overrides[field]

        if field == "a":
            return "reg"

        if mnemonic == "JMP" and field in {"b", "c"}:
            return "offset"

        if mnemonic in {"FORLOOP", "FORPREP", "TFORLOOP"} and field in {"b", "c"}:
            return "offset"

        if mnemonic in {"TEST", "TESTSET"}:
            if field == "b":
                return "reg"
            if field == "c":
                return "immediate"

        if mnemonic == "LOADBOOL" and field == "b":
            return "boolean"

        if mnemonic == "LOADBOOL" and field == "c":
            return "skipflag"

        if mnemonic == "RETURN" and field == "b":
            return "count"

        if mnemonic == "CALL" and field in {"b", "c"}:
            return "count"

        if mnemonic == "CLOSURE" and field == "b":
            return "proto"

        if mnemonic in {"LOADK", "GETGLOBAL", "SETGLOBAL"}:
            if field == "b":
                if instr is not None:
                    bx = _compute_bx(instr.raw)
                    if bx is not None:
                        return "const"
                return "const"

        if value is not None and value >= RK_THRESHOLD:
            return "const"

        return "reg"

    def _resolve_operand(
        self, kind: str, value: Optional[int], constants: Sequence[Any]
    ) -> Any:
        if value is None:
            return None
        if kind == "const":
            index = value
            if value >= RK_THRESHOLD:
                index = value - RK_THRESHOLD
            if 0 <= index < len(constants):
                return constants[index]
            return None
        return None


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _result_summary(result: LiftResult) -> Dict[str, Any]:
    program = result.program
    return {
        "instructions": program.metadata.get("instruction_count"),
        "blocks": program.metadata.get("block_count"),
        "entry_block": program.entry_block,
        "opcode_coverage": result.metadata.get("opcode_coverage"),
        "ir_format": result.ir_format,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lift decoded Luraph VM bytecode into IR")
    parser.add_argument("unpacked", type=Path, help="Path to unpacked JSON payload")
    parser.add_argument(
        "--opcode-map",
        dest="opcode_map",
        type=Path,
        help="Optional opcode map JSON providing mnemonic hints",
    )
    parser.add_argument(
        "--output",
        dest="output",
        type=Path,
        help="Write the full lift result JSON to this file",
    )
    parser.add_argument(
        "--candidate",
        dest="candidate",
        help="Name of the opcode-map candidate (controls default output path)",
    )
    parser.add_argument(
        "--script-key",
        dest="script_key",
        help="Script key used for decoding (not stored, only forwarded)",
    )
    parser.add_argument(
        "--version-hint",
        dest="version_hint",
        help="Optional Luraph version hint (e.g. v14.4.2)",
    )
    parser.add_argument(
        "--ir-format",
        dest="ir_format",
        choices=sorted(SUPPORTED_IR_FORMATS),
        default=DEFAULT_IR_FORMAT,
        help="IR format to emit (structured or basic)",
    )
    parser.add_argument(
        "--summary",
        dest="summary",
        action="store_true",
        help="Print a short human-readable summary",
    )
    parser.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Print raw-offset to IR mapping lines",
    )
    args = parser.parse_args(argv)

    payload = _load_json(args.unpacked)
    opcode_table = _load_json(args.opcode_map) if args.opcode_map else None

    lifter = Lifter(version_hint=args.version_hint)
    result = lifter.lift_unpacked(
        payload,
        opcode_table=opcode_table,
        script_key=args.script_key,
        ir_format=args.ir_format,
        verbose=args.verbose,
    )

    output_path = args.output
    if output_path is None and args.candidate:
        safe_candidate = args.candidate.replace("/", "_")
        output_path = Path("out") / "ir" / f"{safe_candidate}.json"

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result.as_dict(), indent=2) + "\n", encoding="utf-8")
        LOGGER.info("Lift result written to %s", output_path)

    if args.summary or not args.output:
        summary = _result_summary(result)
        print(json.dumps(summary, indent=2))

    if args.verbose and result.verbose_mapping:
        for line in result.verbose_mapping:
            print(line)

    return 0


__all__ = [
    "BasicBlock",
    "IRProgram",
    "IROp",
    "IROperand",
    "LiftResult",
    "Lifter",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
