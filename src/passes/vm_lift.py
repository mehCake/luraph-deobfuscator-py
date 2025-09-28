"""VM bytecode lifting helpers.

The project originally shipped a placeholder module without the ``VMLifter``
class that the tests rely on.  This implementation provides a minimal yet
practical lifter capable of translating decoded initv4 bytecode into the IR
structures defined in :mod:`src.utils_pkg.ir`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, TYPE_CHECKING

from ..utils_pkg.ir import IRBasicBlock, IRInstruction, IRModule
from ..versions import OpSpec

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..pipeline import Context


@dataclass
class VMInstruction:
    opcode: int
    operands: List[int]
    pc: int
    mnemonic: str


@dataclass
class VMFunction:
    instructions: List[VMInstruction] = field(default_factory=list)


@dataclass(frozen=True)
class _DecodedInstruction:
    pc: int
    opcode: int
    operands: Tuple[int, ...]
    spec: Optional[OpSpec]


def _friendly_opcode_name(spec: Optional[OpSpec]) -> str:
    if spec is None:
        return "UNKNOWN_OP"
    name = spec.mnemonic.upper()
    overrides = {
        "LOADK": "LoadK",
        "LOADKX": "LoadKx",
        "LOADBOOL": "LoadBool",
        "LOADNIL": "LoadNil",
        "JMP": "Jump",
        "RETURN": "Return",
        "CALL": "Call",
        "TAILCALL": "TailCall",
        "CLOSURE": "Closure",
    }
    if name in overrides:
        return overrides[name]

    parts = name.split("_")
    result: List[str] = []
    for part in parts:
        if not part:
            continue
        if len(part) == 1:
            result.append(part.upper())
        elif part.isupper():
            result.append(part[:-1].capitalize() + part[-1])
        else:
            result.append(part.capitalize())
    return "".join(result) if result else name.title()


class VMLiftError(Exception):
    """Raised when bytecode cannot be converted into IR."""


class VMLifter:
    """Translate decoded VM bytecode into :class:`IRModule` objects."""

    instr_size: int = 4

    def lift(
        self,
        bytecode: bytes,
        opcode_table: Mapping[int, OpSpec],
        consts: Optional[Sequence[object]] = None,
    ) -> IRModule:
        const_pool = list(consts) if consts is not None else []
        decoded = list(self._decode_stream(bytecode, opcode_table))
        if not decoded:
            raise VMLiftError("no bytecode to lift")

        block_map, order, register_types, warnings = self._build_blocks(decoded, const_pool)
        entry_label = order[0]
        module = IRModule(
            blocks=block_map,
            order=order,
            entry=entry_label,
            register_types=register_types,
            constants=const_pool,
            warnings=warnings,
        )
        module.bytecode_size = len(bytecode)

        for label in module.order:
            block = module.blocks[label]
            module.instructions.extend(block.instructions)

        return module

    # ------------------------------------------------------------------
    def _decode_stream(
        self, bytecode: bytes, opcode_table: Mapping[int, OpSpec]
    ) -> Iterable[_DecodedInstruction]:
        size = self.instr_size
        if len(bytecode) % size:
            LOG.warning(
                "Bytecode length %%d is not a multiple of instruction size %%d", len(bytecode), size
            )
        for pc in range(0, len(bytecode), size):
            chunk = bytecode[pc : pc + size]
            if len(chunk) < size:
                break
            opcode = chunk[0]
            operands = tuple(chunk[1:])
            spec = opcode_table.get(opcode)
            yield _DecodedInstruction(pc, opcode, operands, spec)

    # ------------------------------------------------------------------
    def _build_blocks(
        self, decoded: List[_DecodedInstruction], const_pool: Sequence[object]
    ) -> Tuple[Dict[str, IRBasicBlock], List[str], Dict[int, str], List[str]]:
        block_starts = {decoded[0].pc}
        last_pc = decoded[-1].pc

        for inst in decoded:
            next_pc = inst.pc + self.instr_size
            mnemonic = inst.spec.mnemonic.upper() if inst.spec else ""
            if mnemonic == "JMP":
                offset = self._signed_byte(inst.operands[0] if inst.operands else 0)
                target_pc = next_pc + offset * self.instr_size
                block_starts.add(target_pc)
                block_starts.add(next_pc)
            elif mnemonic == "RETURN":
                block_starts.add(next_pc)

        block_starts = {pc for pc in block_starts if 0 <= pc <= last_pc}
        ordered_pcs = sorted(block_starts)
        label_for_pc: Dict[int, str] = {}
        blocks: Dict[str, IRBasicBlock] = {}
        for index, pc in enumerate(ordered_pcs):
            label = f"block_{index}"
            blocks[label] = IRBasicBlock(label=label, start_pc=pc)
            label_for_pc[pc] = label

        register_types: Dict[int, str] = {}
        warnings: List[str] = []
        successors: MutableMapping[str, List[str]] = {}

        for inst in decoded:
            label = self._label_for_pc(inst.pc, ordered_pcs, label_for_pc)
            block = blocks[label]
            ir_inst, reg_type, warning = self._translate(inst, const_pool, label_for_pc)
            block.instructions.append(ir_inst)
            if reg_type is not None:
                register, kind = reg_type
                register_types.setdefault(register, kind)
            if warning:
                warnings.append(warning)

            next_pc = inst.pc + self.instr_size
            next_label = label_for_pc.get(next_pc)
            mnemonic = inst.spec.mnemonic.upper() if inst.spec else ""
            if mnemonic == "JMP":
                offset = self._signed_byte(inst.operands[0] if inst.operands else 0)
                target_pc = next_pc + offset * self.instr_size
                target_label = label_for_pc.get(target_pc)
                if target_label:
                    successors.setdefault(label, []).append(target_label)
            elif mnemonic == "RETURN":
                continue
            elif next_label:
                successors.setdefault(label, []).append(next_label)

        for label, succs in successors.items():
            unique: List[str] = []
            for entry in succs:
                if entry not in unique:
                    unique.append(entry)
            blocks[label].successors = unique

        order = [label_for_pc[pc] for pc in ordered_pcs]
        return blocks, order, register_types, warnings

    # ------------------------------------------------------------------
    def _label_for_pc(
        self, pc: int, ordered_pcs: Sequence[int], mapping: Mapping[int, str]
    ) -> str:
        if pc in mapping:
            return mapping[pc]
        previous = max(value for value in ordered_pcs if value <= pc)
        return mapping[previous]

    # ------------------------------------------------------------------
    def _translate(
        self,
        inst: _DecodedInstruction,
        const_pool: Sequence[object],
        pc_to_label: Mapping[int, str],
    ) -> Tuple[IRInstruction, Optional[Tuple[int, str]], Optional[str]]:
        spec = inst.spec
        name = _friendly_opcode_name(spec)
        args: Dict[str, object] = {"operands": list(inst.operands)}
        dest: Optional[int] = None
        sources: List[int] = []
        register_type: Optional[Tuple[int, str]] = None
        warning: Optional[str] = None

        if spec is None:
            warning = f"Unknown opcode 0x{inst.opcode:02X} at pc 0x{inst.pc:04X}"
            args["warning"] = warning
        else:
            mnemonic = spec.mnemonic.upper()
            if mnemonic == "LOADK":
                dest = inst.operands[0] if inst.operands else 0
                const_index = inst.operands[1] if len(inst.operands) > 1 else 0
                args.update({"register": dest, "const_index": const_index})
                if 0 <= const_index < len(const_pool):
                    const_value = const_pool[const_index]
                    args["const_value"] = const_value
                    if isinstance(const_value, str):
                        register_type = (dest, "string")
                    elif isinstance(const_value, (int, float)):
                        register_type = (dest, "number")
            elif mnemonic == "RETURN":
                args["register"] = inst.operands[0] if inst.operands else 0
            elif mnemonic == "JMP":
                offset = self._signed_byte(inst.operands[0] if inst.operands else 0)
                target_pc = inst.pc + self.instr_size + offset * self.instr_size
                target_label = pc_to_label.get(target_pc)
                if target_label:
                    args["target"] = target_label
            elif mnemonic == "CONCAT":
                dest = inst.operands[0] if inst.operands else 0
                op_a = inst.operands[1] if len(inst.operands) > 1 else 0
                op_b = inst.operands[2] if len(inst.operands) > 2 else 0
                name = "BinOp"
                args.update({"op": "CONCAT", "dest": dest})
                sources = [op_a, op_b]
                register_type = (dest, "string")
            elif mnemonic in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW"}:
                dest = inst.operands[0] if inst.operands else 0
                name = "BinOp"
                args.update({"op": mnemonic, "dest": dest})
                sources = list(inst.operands[1:3])

        ir_inst = IRInstruction(pc=inst.pc, opcode=name, args=args, dest=dest, sources=sources)
        return ir_inst, register_type, warning

    # ------------------------------------------------------------------
    @staticmethod
    def _signed_byte(value: int) -> int:
        return value - 0x100 if value >= 0x80 else value


def lift_entry(decoded_bytes: bytes, bootstrapper_metadata: Mapping[str, object]) -> IRModule:
    opcode_map = bootstrapper_metadata.get("opcode_map") or bootstrapper_metadata.get("opcode_dispatch")
    if not isinstance(opcode_map, Mapping):
        raise VMLiftError("Missing opcode map in bootstrap metadata")

    specs = {int(key, 0) if isinstance(key, str) else int(key): OpSpec(str(value), ()) for key, value in opcode_map.items()}
    return VMLifter().lift(decoded_bytes, specs)


def _flatten_bytecode(payload: object) -> bytes:
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, list):
        if all(isinstance(entry, int) for entry in payload):
            return bytes(entry & 0xFF for entry in payload)
        if all(isinstance(entry, (bytes, bytearray)) for entry in payload):
            return b"".join(bytes(entry) for entry in payload)
        flattened: List[int] = []
        for chunk in payload:
            if isinstance(chunk, list):
                for value in chunk:
                    if isinstance(value, int):
                        flattened.append(value & 0xFF)
        if flattened:
            return bytes(flattened)
    return b""


def _opcode_specs(mapping: Mapping[object, object] | None) -> Dict[int, OpSpec]:
    specs: Dict[int, OpSpec] = {}
    if not isinstance(mapping, Mapping):
        return specs
    for key, value in mapping.items():
        try:
            opcode = int(key, 0) if isinstance(key, str) else int(key)
        except (TypeError, ValueError):
            continue
        specs[opcode] = OpSpec(str(value), ())
    return specs


def run(ctx: "Context") -> Dict[str, object]:
    """Lift decoded VM bytecode into an :class:`IRModule`."""

    vm_ir = getattr(ctx, "vm_ir", None)
    bytecode: bytes = b""
    const_pool: Sequence[object] = ctx.vm.const_pool or []
    opcode_map: Mapping[object, object] | None = None

    if vm_ir is not None:
        bytecode = _flatten_bytecode(vm_ir.bytecode)
        if vm_ir.constants:
            const_pool = vm_ir.constants
        opcode_map = vm_ir.opcode_map
    elif ctx.vm.bytecode:
        bytecode = _flatten_bytecode(ctx.vm.bytecode)

    if not bytecode:
        ctx.ir_module = None
        return {"skipped": True}

    if not const_pool and ctx.vm.const_pool:
        const_pool = ctx.vm.const_pool

    if not opcode_map:
        meta = getattr(ctx, "bootstrapper_metadata", {})
        if isinstance(meta, Mapping):
            opcode_map = meta.get("opcode_map") or meta.get("opcode_dispatch")

    specs = _opcode_specs(opcode_map)
    lifter = VMLifter()
    try:
        module = lifter.lift(bytecode, specs, const_pool)
    except Exception as exc:
        LOG.exception("vm lift failed: %s", exc)
        ctx.ir_module = None
        return {"error": str(exc), "skipped": True}

    ctx.ir_module = module
    metadata: Dict[str, object] = {
        "instructions": module.instruction_count,
        "blocks": module.block_count,
        "bytecode_size": module.bytecode_size,
    }
    if module.warnings:
        metadata["warnings"] = list(module.warnings)
    unknown = sum(1 for inst in module.instructions if inst.opcode == "UNKNOWN_OP")
    metadata["unknown_opcodes"] = unknown
    return metadata


__all__ = ["VMLifter", "VMLiftError", "lift_entry", "VMInstruction", "VMFunction", "run"]
