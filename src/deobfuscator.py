from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, Optional, Tuple

from lph_handler import extract_vm_ir
from version_detector import VersionDetector, VersionInfo

from opcode_lifter import OpcodeLifter
from lua_vm_simulator import LuaVMSimulator
from variable_renamer import VariableRenamer

from . import utils, versions
from .versions import VersionHandler, PayloadInfo
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

    def __init__(
        self,
        *,
        vm_trace: bool = False,
        script_key: str | None = None,
        bootstrapper: str | os.PathLike[str] | Path | None = None,
    ) -> None:
        self.logger = logger
        self._version_detector = VersionDetector()
        self._all_features = self._version_detector.all_features
        self._opcode_lifter = OpcodeLifter()
        self._formatter = utils.LuaFormatter()
        self._vm_max_steps = 100_000
        self._vm_timeout = 5.0
        self._vm_trace = vm_trace
        self._script_key = script_key.strip() if script_key else None
        self._bootstrapper_path = self._normalise_bootstrapper(bootstrapper)

    # --- Pipeline stages -------------------------------------------------
    def detect_version(
        self,
        text: str,
        *,
        from_json: bool | None = None,
    ) -> VersionInfo:
        """Return heuristically detected Luraph version information."""

        flag = self._looks_like_json(text) if from_json is None else from_json
        return self._version_detector.detect_version(text, from_json=flag)

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
        script_key: str | None = None,
        bootstrapper: str | os.PathLike[str] | Path | None = None,
    ) -> DeobResult:
        """Decode known payload formats and return a :class:`DeobResult`."""

        metadata: Dict[str, Any] = {"version": version}
        if version.features:
            metadata["version_features"] = sorted(version.features)

        active_features = self._normalise_features(features)
        if active_features is not None:
            metadata["active_features"] = sorted(active_features)

        override_token = "_script_key_override"
        provided_key = (script_key or "").strip()
        if provided_key:
            self._script_key = provided_key
            metadata["script_key_override"] = True
        override_key = (self._script_key or "").strip()

        bootstrapper_path = self._normalise_bootstrapper(bootstrapper)
        if bootstrapper_path is not None:
            self._bootstrapper_path = bootstrapper_path
        if self._bootstrapper_path is not None:
            metadata["bootstrapper_path"] = str(self._bootstrapper_path)

        def feature_enabled(flag: str) -> bool:
            return active_features is None or flag in active_features

        handler: Optional[Any] = None
        handler_instance: VersionHandler | None = None
        payload_info: PayloadInfo | None = None
        if not version.is_unknown:
            try:
                handler = versions.get_handler(version.name)
                metadata["handler"] = version.name
            except KeyError:
                handler = None
        if isinstance(handler, VersionHandler):
            handler_instance = handler
            if self._bootstrapper_path is not None:
                setter = getattr(handler_instance, "set_bootstrapper", None)
                if callable(setter):
                    try:
                        bootstrap_meta = setter(self._bootstrapper_path)
                    except Exception as exc:  # pragma: no cover - best effort
                        metadata["bootstrapper_error"] = str(exc)
                    else:
                        if isinstance(bootstrap_meta, dict) and bootstrap_meta:
                            metadata.setdefault("bootstrapper", bootstrap_meta)

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

        if payload_dict is None and handler_instance is not None:
            payload_info = handler_instance.locate_payload(text)
            if payload_info is not None:
                metadata["handler_payload_offset"] = payload_info.start
                data_candidate = payload_info.data
                if data_candidate is None:
                    try:
                        data_candidate = json.loads(payload_info.text)
                    except json.JSONDecodeError as exc:
                        metadata["handler_payload_error"] = str(exc)

                if override_key:
                    payload_info.metadata[override_token] = override_key
                raw_bytes: bytes | None = None
                try:
                    raw_bytes = handler_instance.extract_bytecode(payload_info)
                except Exception as exc:  # pragma: no cover - best effort
                    message = str(exc)
                    metadata["handler_bytecode_error"] = message
                    payload_meta = payload_info.metadata or {}
                    literal_key = bool(payload_meta.get("script_key"))
                    env_key = os.environ.get("LURAPH_SCRIPT_KEY", "")
                    if (
                        version.name == "v14.4.1"
                        and not override_key
                        and not literal_key
                        and not env_key
                    ):
                        self.logger.error(
                            "script key required to decode %s payload: %s",
                            version.name,
                            message,
                        )
                else:
                    metadata["handler_bytecode_bytes"] = len(raw_bytes)
                    metadata["handler_vm_bytecode"] = raw_bytes
                    if payload_dict is None:
                        decoded_text = raw_bytes.decode("utf-8", errors="ignore")
                        cleaned_text = utils.strip_non_printable(decoded_text)
                        mapping: Any = None
                        if cleaned_text:
                            stripped = cleaned_text.lstrip()
                            if stripped.startswith("{") or stripped.startswith("["):
                                try:
                                    mapping = json.loads(cleaned_text)
                                except json.JSONDecodeError:
                                    mapping = None
                            if mapping is None:
                                mapping = extract_vm_ir(cleaned_text)
                        if isinstance(mapping, dict):
                            payload_dict = mapping
                            payload_info.data = mapping
                            metadata["handler_decoded_json"] = True
                        elif isinstance(mapping, list):
                            converted = extract_vm_ir(json.dumps(mapping))
                            if isinstance(converted, dict):
                                payload_dict = converted
                                payload_info.data = converted
                                metadata["handler_decoded_json"] = True
                finally:
                    if override_key:
                        payload_info.metadata.pop(override_token, None)

                cleaned_meta = dict(payload_info.metadata)
                cleaned_meta.pop(override_token, None)
                if cleaned_meta:
                    metadata["handler_payload_meta"] = cleaned_meta

                if data_candidate is not None:
                    payload_dict = data_candidate
                elif payload_info.data is not None:
                    payload_dict = payload_info.data

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
            if handler_instance is not None:
                const_decoder = handler_instance.const_decoder()
                if const_decoder is not None:
                    vm_ir.constants = versions.decode_constant_pool(
                        const_decoder, vm_ir.constants
                    )
                    metadata["handler_constants_decoded"] = True
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

    # ------------------------------------------------------------------
    @staticmethod
    def _normalise_bootstrapper(
        path: str | os.PathLike[str] | Path | None,
    ) -> Path | None:
        if path is None:
            return None
        if isinstance(path, Path):
            candidate = path
        else:
            text = os.fspath(path)
            if not text:
                return None
            candidate = Path(text)
        try:
            return candidate.expanduser().resolve()
        except OSError:
            return candidate.expanduser()

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
            version = self._resolve_version(
                processed,
                version_override,
                from_json=self._looks_like_json(current),
            )
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
    def _resolve_version(
        self,
        text: str,
        override: str | None,
        *,
        from_json: bool | None = None,
    ) -> VersionInfo:
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
        return self.detect_version(text, from_json=from_json)

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
