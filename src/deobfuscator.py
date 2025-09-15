from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from lph_handler import extract_vm_ir
from version_detector import VersionDetector, VersionInfo

from opcode_lifter import OpcodeLifter
from lua_vm_simulator import LuaVMSimulator
from variable_renamer import VariableRenamer

from . import utils, versions
from .passes import Devirtualizer
from .vm import LuraphVM
from .exceptions import VMEmulationError

logger = logging.getLogger(__name__)


@dataclass
class VMIR:
    """Lightweight representation of a VM program."""

    constants: list[Any]
    bytecode: list[list[Any]]
    version: str | None = None
    prototypes: list[Any] | None = None


@dataclass
class DeobResult:
    """Result of a pipeline stage."""

    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class LuaDeobfuscator:
    """Coordinate the individual stages of the deobfuscation pipeline."""

    def __init__(self) -> None:
        self.logger = logger
        self._version_detector = VersionDetector()
        self._opcode_lifter = OpcodeLifter()
        self._formatter = utils.LuaFormatter()

    # --- Pipeline stages -------------------------------------------------
    def detect_version(self, text: str) -> VersionInfo:
        """Return heuristically detected Luraph version information."""

        return self._version_detector.detect_version(text)

    def preprocess(self, text: str) -> str:
        """Normalise line endings and trim trailing whitespace."""

        normalised = text.replace("\r\n", "\n").replace("\r", "\n")
        return "\n".join(line.rstrip() for line in normalised.splitlines())

    def decode_payload(self, text: str) -> DeobResult:
        """Decode known payload formats and return a :class:`DeobResult`."""

        metadata: Dict[str, Any] = {}

        embedded = utils.extract_embedded_json(text)
        payload_dict = extract_vm_ir(text)
        if payload_dict is None and embedded:
            metadata["embedded_json"] = True
            text = embedded
            payload_dict = extract_vm_ir(text)
        elif embedded:
            metadata["embedded_json"] = True

        version = self.detect_version(text)
        metadata["version"] = version
        if version.features:
            metadata["version_features"] = sorted(version.features)

        handler: Optional[Any] = None
        if not version.is_unknown:
            try:
                handler = versions.get_handler(version.name)
                metadata["handler"] = version.name
            except KeyError:
                handler = None

        constant_rendered: Optional[str] = None
        vm_ir = None
        if payload_dict:
            script_text = payload_dict.get("script")
            if isinstance(script_text, str) and script_text.strip():
                cleaned_script = utils.strip_non_printable(script_text)
                metadata["script_payload"] = True
                return DeobResult(cleaned_script, metadata)
            vm_ir = self._vm_ir_from_mapping(payload_dict)
            if vm_ir is None:
                constants = payload_dict.get("constants")
                if isinstance(constants, list) and constants:
                    rendered = "".join(str(c) for c in constants if isinstance(c, (str, int, float)))
                    if rendered and utils._is_printable(rendered) and len(rendered) <= 512:
                        constant_rendered = rendered
                        metadata["constant_payload"] = True
        if vm_ir is None:
            vm_ir = self._try_parse_vm(text)
        if vm_ir is not None:
            vm_ir.version = version.name if not version.is_unknown else None
            metadata["vm_ir"] = vm_ir
            vm_payload = {"constants": vm_ir.constants, "bytecode": vm_ir.bytecode}
            if vm_ir.prototypes:
                metadata["prototype_count"] = len(vm_ir.prototypes)
            if vm_ir.bytecode:
                vm_output = utils.decode_virtual_machine(vm_payload, handler=handler)
                if vm_output:
                    return DeobResult(vm_output, metadata)
            return DeobResult(text, metadata)
        if constant_rendered is not None:
            return DeobResult(constant_rendered, metadata)

        for decoder in (utils.decode_json_format, utils.decode_superflow):
            decoded = decoder(text)
            if decoded:
                metadata["decoder"] = decoder.__name__
                text = decoded
                break

        text = utils.decode_simple_obfuscations(text)
        return DeobResult(text, metadata)

    def devirtualize(self, vm_ir: VMIR) -> DeobResult:
        """Run the VM program and emit pseudo Lua code when possible."""

        metadata: Dict[str, Any] = {}

        canonical: Optional[Any] = None
        if vm_ir.bytecode and all(isinstance(ins, dict) for ins in vm_ir.bytecode):
            try:
                canonical = self._opcode_lifter.lift_program(
                    {
                        "constants": vm_ir.constants,
                        "bytecode": vm_ir.bytecode,
                        "prototypes": vm_ir.prototypes or [],
                    },
                    version=vm_ir.version,
                )
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.debug("Opcode lifting failed: %s", exc)

        if canonical and canonical.instructions:
            simulator = LuaVMSimulator()
            try:
                result = simulator.run(canonical)
            except VMEmulationError:  # pragma: no cover - fallback
                result = None
            if simulator.trace_log:
                metadata["vm_trace"] = simulator.trace_log
            if isinstance(result, (str, int, float)):
                return DeobResult(str(result), {**metadata, "vm_result": result})
            pseudo = Devirtualizer(canonical).render()
            if pseudo:
                metadata["devirtualized"] = True
                return DeobResult(pseudo, metadata)

        vm = LuraphVM(constants=vm_ir.constants, bytecode=vm_ir.bytecode)
        if vm_ir.version:
            try:
                handler = versions.get_handler(vm_ir.version)
                handler.process(vm)
            except KeyError:
                pass

        result = vm.run()
        metadata.setdefault("vm_result", result)
        if isinstance(result, (str, int, float)):
            if isinstance(result, str):
                decrypted = utils.decrypt_lph_string(result)
                if decrypted != result and utils._is_printable(decrypted):
                    metadata["vm_result_decrypted"] = True
                    return DeobResult(decrypted, metadata)
            return DeobResult(str(result), metadata)
        pseudo = Devirtualizer(vm).render()
        if pseudo:
            return DeobResult(pseudo, metadata)
        return DeobResult("", metadata)

    def cleanup(self, lua_src: str) -> str:
        """Apply lightweight decoding passes to ``lua_src``."""

        cleaned = utils.decode_simple_obfuscations(lua_src)
        return utils.strip_non_printable(cleaned)

    def render(self, lua_src: str) -> str:
        """Pretty print Lua code for readability."""

        renamer = VariableRenamer()
        renamed = renamer.rename_variables(lua_src)
        return self._formatter.format_source(renamed)

    # --- Public convenience API -----------------------------------------
    def deobfuscate_content(self, content: str) -> str:
        """Run the full pipeline on ``content`` and return decoded Lua."""

        processed = self.preprocess(content)
        result = self.decode_payload(processed)
        vm_ir = result.metadata.get("vm_ir")
        if isinstance(vm_ir, VMIR):
            vm_result = self.devirtualize(vm_ir)
            text = vm_result.text or result.text
        else:
            text = result.text
        cleaned = self.cleanup(text)
        return self.render(cleaned)

    def deobfuscate_file(self, path: str) -> str:
        """Load ``path`` and return the deobfuscated content."""

        content = utils.safe_read_file(path)
        if content is None:
            raise FileNotFoundError(path)
        return self.deobfuscate_content(content)

    # --- Internal helpers ------------------------------------------------
    def _vm_ir_from_mapping(self, payload: Optional[Dict[str, Any]]) -> Optional[VMIR]:
        if not payload:
            return None
        constants = payload.get("constants")
        bytecode = payload.get("bytecode") or payload.get("code")
        prototypes = payload.get("prototypes")
        if not isinstance(constants, list) or not isinstance(bytecode, list) or not bytecode:
            return None
        if not all(isinstance(instr, list) and instr for instr in bytecode):
            return None
        proto_list = list(prototypes) if isinstance(prototypes, list) else None
        return VMIR(constants=list(constants), bytecode=[list(instr) for instr in bytecode], prototypes=proto_list)

    def _try_parse_vm(self, text: str) -> Optional[VMIR]:
        try:
            data = json.loads(text)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        return self._vm_ir_from_mapping(data)


__all__ = ["LuaDeobfuscator", "VersionInfo", "DeobResult", "VMIR"]
