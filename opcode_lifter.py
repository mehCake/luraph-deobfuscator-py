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

from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional

from src.ir import VMFunction, VMInstruction


logger = logging.getLogger(__name__)


@dataclass
class InstructionSignature:
    """Describe operand semantics for a canonical opcode."""

    fields: List[str]
    modes: Mapping[str, str]


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

    # ------------------------------------------------------------------
    def lift_program(self, payload: Mapping[str, Any], version: Optional[str] = None) -> VMFunction:
        """Return a :class:`VMFunction` built from ``payload``."""

        constants = list(payload.get("constants", []))
        raw_instructions: Iterable[Any] = payload.get("bytecode") or payload.get("code") or []
        prototypes = payload.get("prototypes") or []

        lifted_instructions: List[VMInstruction] = []
        register_max = -1
        upvalue_max = -1

        for raw in raw_instructions:
            instr = self._lift_instruction(raw, constants, version)
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
                lifted_prototypes.append(self.lift_program(proto, version))

        return VMFunction(
            constants=constants,
            instructions=lifted_instructions,
            prototypes=lifted_prototypes,
            num_params=int(payload.get("num_params", 0) or 0),
            is_vararg=bool(payload.get("is_vararg")),
            register_count=max(register_max + 1, int(payload.get("max_register", 0) or 0)),
            upvalue_count=max(upvalue_max + 1, int(payload.get("upvalue_count", 0) or 0)),
        )

    # ------------------------------------------------------------------
    def _lift_instruction(
        self,
        raw: Any,
        constants: List[Any],
        version: Optional[str],
    ) -> VMInstruction:
        opcode_token, operands = self._extract_opcode(raw)
        opcode = self._normalise_opcode(opcode_token, version)
        data = self._normalise_operands(opcode, operands)
        signature = INSTRUCTION_SIGNATURES.get(opcode)

        aux: Dict[str, Any] = {}
        if signature:
            for field in signature.fields:
                mode = signature.modes.get(field)
                if mode and field in data:
                    aux[f"{field}_mode"] = mode
                    if mode == "const":
                        index = data[field]
                        aux[f"{field}_index"] = index
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
        )

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

    def _normalise_opcode(self, token: Any, version: Optional[str]) -> str:
        if isinstance(token, str):
            candidate = token.upper()
            table = self._opcode_tables.get(version or "", {})
            if candidate in table:
                return table[candidate]
            if candidate in INSTRUCTION_SIGNATURES:
                return candidate
            try:
                numeric = int(candidate, 0)
            except Exception:
                return candidate
            candidate = f"0X{numeric:X}"
            if candidate in table:
                return table[candidate]
            return f"0X{numeric:X}"
        if isinstance(token, int):
            candidate = f"0X{token:X}"
            table = self._opcode_tables.get(version or "", {})
            return table.get(candidate, candidate)
        return str(token).upper()

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


__all__ = ["OpcodeLifter"]
