from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, Optional, Tuple

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


_VM_SCAFFOLD_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"vm_dispatch", re.IGNORECASE),
    re.compile(r"vm_stack", re.IGNORECASE),
    re.compile(r"vm_state", re.IGNORECASE),
    re.compile(r"LPH_ENCFUNC", re.IGNORECASE),
    re.compile(r"superflow_bytecode", re.IGNORECASE),
    re.compile(r"bytecode\s*=", re.IGNORECASE),
    re.compile(r"opaque[_\s-]?predicate", re.IGNORECASE),
    re.compile(r"\[\[[\"'][0-9A-Fa-f]{2}", re.IGNORECASE),
)


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

    def __init__(self, *, vm_trace: bool = False) -> None:
        self.logger = logger
        self._version_detector = VersionDetector()
        self._all_features = self._version_detector.all_features
        self._opcode_lifter = OpcodeLifter()
        self._formatter = utils.LuaFormatter()
        self._vm_max_steps = 100_000
        self._vm_timeout = 5.0
        self._vm_trace = vm_trace

    # --- Pipeline stages -------------------------------------------------
    def detect_version(self, text: str) -> VersionInfo:
        """Return heuristically detected Luraph version information."""

        return self._version_detector.detect_version(text)

    def preprocess(self, text: str) -> str:
        """Normalise line endings and trim trailing whitespace."""

        normalised = text.replace("\r\n", "\n").replace("\r", "\n")
        return "\n".join(line.rstrip() for line in normalised.splitlines())

    def decode_payload(
        self,
        text: str,
        *,
        version: VersionInfo,
        features: FrozenSet[str] | None = None,
    ) -> DeobResult:
        """Decode known payload formats and return a :class:`DeobResult`."""

        metadata: Dict[str, Any] = {"version": version}
        if version.features:
            metadata["version_features"] = sorted(version.features)

        active_features = self._normalise_features(features)
        if active_features is not None:
            metadata["active_features"] = sorted(active_features)

        def feature_enabled(flag: str) -> bool:
            return active_features is None or flag in active_features

        handler: Optional[Any] = None
        if not version.is_unknown:
            try:
                handler = versions.get_handler(version.name)
                metadata["handler"] = version.name
            except KeyError:
                handler = None

        payload_dict: Optional[Dict[str, Any]] = None
        embedded: Optional[str] = None
        if feature_enabled("container"):
            embedded = utils.extract_embedded_json(text)
        if feature_enabled("loader") or feature_enabled("container"):
            payload_dict = extract_vm_ir(text)
        if payload_dict is None and embedded:
            metadata["embedded_json"] = True
            text = embedded
            payload_dict = extract_vm_ir(text) if (feature_enabled("loader") or feature_enabled("container")) else None
        elif embedded:
            metadata["embedded_json"] = True

        if payload_dict is None and self._looks_like_json(text):
            payload_dict = extract_vm_ir(text)

        constant_rendered: Optional[str] = None
        vm_ir: Optional[VMIR] = None
        if payload_dict:
            script_text = payload_dict.get("script")
            if isinstance(script_text, str) and script_text.strip():
                cleaned_script = utils.strip_non_printable(script_text)
                metadata["script_payload"] = True
                return DeobResult(cleaned_script, metadata)
            vm_ir = self._vm_ir_from_mapping(payload_dict)
            if vm_ir is None and feature_enabled("constants"):
                constants = payload_dict.get("constants")
                if isinstance(constants, list) and constants:
                    rendered = "".join(
                        str(c) for c in constants if isinstance(c, (str, int, float))
                    )
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
            if vm_ir.bytecode and feature_enabled("loader"):
                vm_output = utils.decode_virtual_machine(vm_payload, handler=handler)
                if vm_output:
                    return DeobResult(vm_output, metadata)
            return DeobResult(text, metadata)
        if constant_rendered is not None:
            return DeobResult(constant_rendered, metadata)

        for decoder in (utils.decode_json_format, utils.decode_superflow):
            if decoder is utils.decode_json_format and not feature_enabled("container"):
                continue
            decoded = decoder(text)
            if decoded:
                metadata["decoder"] = decoder.__name__
                text = decoded
                break

        text = utils.decode_simple_obfuscations(text)
        return DeobResult(text, metadata)

    def devirtualize(
        self,
        vm_ir: VMIR,
        *,
        version: VersionInfo | None = None,
        features: FrozenSet[str] | None = None,
    ) -> DeobResult:
        """Run the VM program and emit pseudo Lua code when possible."""

        metadata: Dict[str, Any] = {}
        if version is not None:
            metadata["version"] = version
        if features is not None:
            metadata["active_features"] = sorted(features)

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
            simulator = LuaVMSimulator(trace=self._vm_trace)
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

        vm = LuraphVM(
            constants=vm_ir.constants,
            bytecode=vm_ir.bytecode,
            max_steps=self._vm_max_steps,
            timeout=self._vm_timeout,
        )
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
    def deobfuscate_content(
        self,
        content: str,
        *,
        max_iterations: int = 1,
        version_override: str | None = None,
    ) -> str:
        """Run the full pipeline on ``content`` and return decoded Lua."""

        iterations = max(1, max_iterations)
        current = content
        for _ in range(iterations):
            processed = self.preprocess(current)
            version = self._resolve_version(processed, version_override)
            output = self._run_strategies(processed, version)
            if output == current:
                return output
            current = output
        return current

    def deobfuscate_file(
        self,
        path: str,
        *,
        max_iterations: int = 1,
        version_override: str | None = None,
    ) -> str:
        """Load ``path`` and return the deobfuscated content."""

        content = utils.safe_read_file(path)
        if content is None:
            raise FileNotFoundError(path)
        return self.deobfuscate_content(
            content,
            max_iterations=max_iterations,
            version_override=version_override,
        )

    # --- Internal helpers ------------------------------------------------
    def _resolve_version(self, text: str, override: str | None) -> VersionInfo:
        if override:
            info = self._version_detector.info_for_name(override)
            features = info.features or self._all_features
            confidence = info.confidence or 1.0
            return VersionInfo(
                name=info.name,
                major=info.major,
                minor=info.minor,
                features=features,
                confidence=confidence,
                matched_categories=info.matched_categories,
            )
        return self.detect_version(text)

    def _run_strategies(self, processed: str, version: VersionInfo) -> str:
        best_output = processed
        best_score = self._score_output(best_output)
        for name, features in self._strategy_feature_sets(version):
            try:
                output, _ = self._run_strategy(
                    processed,
                    version,
                    features,
                    strategy=name,
                )
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.debug("strategy %s failed: %s", name, exc)
                continue
            if self._output_is_clean(output):
                self.logger.debug("strategy %s produced clean output", name)
                return output
            score = self._score_output(output)
            if score < best_score:
                best_output = output
                best_score = score
        return best_output

    def _run_strategy(
        self,
        processed: str,
        version: VersionInfo,
        features: FrozenSet[str],
        *,
        strategy: str,
    ) -> Tuple[str, Dict[str, Any]]:
        self.logger.debug(
            "running strategy %s with features=%s",
            strategy,
            ",".join(sorted(features)) if features else "",
        )
        decode_result = self.decode_payload(
            processed,
            version=version,
            features=features,
        )
        stage_output = decode_result.text
        metadata: Dict[str, Any] = {"decode": decode_result.metadata}
        vm_ir = decode_result.metadata.get("vm_ir")
        if isinstance(vm_ir, VMIR):
            vm_result = self.devirtualize(
                vm_ir,
                version=version,
                features=features,
            )
            metadata["devirtualize"] = vm_result.metadata
            stage_output = vm_result.text or stage_output
        cleaned = self.cleanup(stage_output)
        rendered = self.render(cleaned)
        metadata["render_length"] = len(rendered)
        return rendered, metadata

    def _strategy_feature_sets(self, version: VersionInfo) -> Iterable[Tuple[str, FrozenSet[str]]]:
        base = frozenset(version.features) or self._all_features
        strategies: list[Tuple[str, FrozenSet[str]]] = [("detected", base)]
        if base:
            for feature in sorted(base):
                reduced = base - {feature}
                strategies.append((f"without_{feature}", reduced))
        if base != self._all_features:
            strategies.append(("aggressive", self._all_features))
        strategies.append(("minimal", frozenset()))

        seen: set[FrozenSet[str]] = set()
        ordered: list[Tuple[str, FrozenSet[str]]] = []
        for name, feats in strategies:
            if feats not in seen:
                ordered.append((name, feats))
                seen.add(feats)
        return ordered

    def _normalise_features(self, features: FrozenSet[str] | None) -> FrozenSet[str] | None:
        if features is None:
            return None
        return frozenset(features)

    def _score_output(self, text: str) -> Tuple[int, int]:
        penalty = sum(1 for pattern in _VM_SCAFFOLD_PATTERNS if pattern.search(text))
        return penalty, len(text)

    def _output_is_clean(self, text: str) -> bool:
        return bool(text.strip()) and all(
            not pattern.search(text) for pattern in _VM_SCAFFOLD_PATTERNS
        )

    def _looks_like_json(self, text: str) -> bool:
        snippet = text.strip()
        if not snippet:
            return False
        return (snippet[0], snippet[-1]) in {("{", "}"), ("[", "]")}

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
