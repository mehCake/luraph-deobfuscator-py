from __future__ import annotations

import json
import logging
import os
import re
from types import SimpleNamespace
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from lph_handler import extract_vm_ir
from version_detector import VersionDetector, VersionInfo

from opcode_lifter import OpcodeLifter
from lua_vm_simulator import LuaVMSimulator
from variable_renamer import VariableRenamer

from . import utils, versions
from .versions import VersionHandler, PayloadInfo, decode_constant_pool, OpSpec
from .versions.luraph_v14_4_1 import looks_like_vm_bytecode
from .passes import Devirtualizer
from .passes.vm_lift import VMLifter
from .passes.vm_devirtualize import IRDevirtualizer
from .utils_pkg import ast as lua_ast
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
    opcode_map: Dict[int, Any] | None = None


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
        self._lua_validator = utils.LuaSyntaxValidator()
        self._vm_max_steps = 100_000
        self._vm_timeout = 5.0
        self._vm_trace = vm_trace
        self._script_key = script_key.strip() if script_key else None
        self._bootstrapper_path = self._normalise_bootstrapper(bootstrapper)
        self._last_render_validation: Dict[str, Any] = {}
        self._last_handler: VersionHandler | None = None

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
        force: bool | None = None,
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

        force_flag = bool(force)

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

        self._last_handler = handler_instance

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
                chunk_meta_updates: Dict[str, Any] = {}
                chunk_parts: list[bytes] = []
                try:
                    raw_bytes = handler_instance.extract_bytecode(payload_info)
                except Exception as exc:  # pragma: no cover - best effort
                    message = str(exc)
                    metadata["handler_bytecode_error"] = message
                    payload_info_meta = payload_info.metadata or {}
                    literal_key = bool(payload_info_meta.get("script_key"))
                    env_key = os.environ.get("LURAPH_SCRIPT_KEY", "")
                    if (
                        version.name in {"luraph_v14_4_initv4", "v14.4.1"}
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
                        mapping, _, mapping_meta = self._decode_payload_mapping(raw_bytes)
                        if mapping is not None:
                            payload_dict = mapping
                            payload_info.data = mapping
                        for key, value in mapping_meta.items():
                            if key not in metadata or not metadata.get(key):
                                metadata[key] = value

                    if version.name in {"luraph_v14_4_initv4", "v14.4.1"}:
                        chunk_key: str | None = override_key or payload_info.metadata.get("script_key")
                        if not chunk_key:
                            chunk_key = os.environ.get("LURAPH_SCRIPT_KEY", "") or None
                        if chunk_key:
                            (
                                chunk_parts,
                                chunk_meta_updates,
                                chunk_analysis,
                            ) = self._decode_initv4_chunks(
                                text,
                                script_key=chunk_key,
                                handler=handler_instance,
                                version=version,
                                force=force_flag,
                            )
                            if chunk_parts:
                                combined_bytes = b"".join(chunk_parts)
                                if combined_bytes:
                                    existing_vm = metadata.get("handler_vm_bytecode")
                                    if not existing_vm:
                                        metadata["handler_vm_bytecode"] = combined_bytes
                                        metadata["handler_bytecode_bytes"] = len(combined_bytes)
                                    elif isinstance(existing_vm, (bytes, bytearray)) and len(combined_bytes) > len(existing_vm):
                                        metadata.setdefault("handler_chunk_combined_bytes", len(combined_bytes))
                                    if payload_dict is None:
                                        mapping, _, mapping_meta = self._decode_payload_mapping(combined_bytes)
                                        if mapping is not None:
                                            payload_dict = mapping
                                            payload_info.data = mapping
                                        for key, value in mapping_meta.items():
                                            if key not in metadata or not metadata.get(key):
                                                metadata[key] = value
                                if chunk_analysis:
                                    sources = chunk_analysis.get("sources")
                                    if sources:
                                        metadata.setdefault(
                                            "handler_chunk_sources",
                                            list(sources),
                                        )
                                    rename_counts = chunk_analysis.get("rename_counts")
                                    if rename_counts and "handler_chunk_rename_counts" not in metadata:
                                        metadata["handler_chunk_rename_counts"] = list(rename_counts)
                                    cleaned_flags = chunk_analysis.get("cleaned_chunks")
                                    if cleaned_flags and "handler_chunk_cleaned" not in metadata:
                                        metadata["handler_chunk_cleaned"] = list(cleaned_flags)
                                    combined_source = chunk_analysis.get("final_source")
                                    placeholder_only = bool(
                                        chunk_analysis.get("placeholders_only")
                                    )
                                    if combined_source:
                                        metadata.setdefault(
                                            "handler_chunk_combined_source",
                                            combined_source,
                                        )
                                        if placeholder_only:
                                            metadata.setdefault(
                                                "handler_placeholder_source",
                                                combined_source,
                                            )
                                        if (
                                            not placeholder_only
                                            and (
                                                payload_dict is None
                                                or (
                                                    isinstance(sources, list)
                                                    and len(
                                                        [
                                                            src
                                                            for src in sources
                                                            if src.strip()
                                                        ]
                                                    )
                                                    > 1
                                                )
                                            )
                                        ):
                                            payload_dict = {"script": combined_source}
                                            metadata["script_payload"] = True
                                            if payload_info is not None:
                                                payload_info.data = {"script": combined_source}
                finally:
                    if override_key:
                        payload_info.metadata.pop(override_token, None)

                cleaned_meta = dict(payload_info.metadata)
                cleaned_meta.pop(override_token, None)
                cleaned_meta.pop("_chunks", None)
                chunk_count = cleaned_meta.get("chunk_count")
                if isinstance(chunk_count, int) and chunk_count > 0:
                    metadata["handler_payload_chunks"] = chunk_count
                chunk_bytes = cleaned_meta.get("chunk_decoded_bytes")
                if isinstance(chunk_bytes, list):
                    metadata["handler_chunk_decoded_bytes"] = list(chunk_bytes)
                success_value = cleaned_meta.get("chunk_success_count")
                if isinstance(success_value, int) and success_value >= 0:
                    metadata["handler_chunk_success_count"] = success_value
                if cleaned_meta:
                    metadata["handler_payload_meta"] = cleaned_meta

                if chunk_meta_updates:
                    if (
                        isinstance(chunk_meta_updates.get("chunk_count"), int)
                        and chunk_meta_updates["chunk_count"] > 0
                        and "handler_payload_chunks" not in metadata
                    ):
                        metadata["handler_payload_chunks"] = chunk_meta_updates["chunk_count"]
                    if (
                        isinstance(chunk_meta_updates.get("chunk_decoded_bytes"), list)
                        and "handler_chunk_decoded_bytes" not in metadata
                    ):
                        metadata["handler_chunk_decoded_bytes"] = list(
                            chunk_meta_updates["chunk_decoded_bytes"]
                        )
                    success_value = chunk_meta_updates.get("chunk_success_count")
                    if (
                        isinstance(success_value, int)
                        and success_value >= 0
                        and "handler_chunk_success_count" not in metadata
                    ):
                        metadata["handler_chunk_success_count"] = success_value
                    encoded_lengths = chunk_meta_updates.get("chunk_encoded_lengths")
                    if isinstance(encoded_lengths, list) and encoded_lengths:
                        metadata.setdefault("handler_chunk_encoded_lengths", list(encoded_lengths))
                    errors = chunk_meta_updates.get("chunk_errors")
                    if isinstance(errors, list) and errors:
                        metadata.setdefault("handler_chunk_errors", list(errors))
                    suspicious_flags = chunk_meta_updates.get("chunk_suspicious_flags")
                    if (
                        isinstance(suspicious_flags, list)
                        and "handler_chunk_suspicious" not in metadata
                    ):
                        metadata["handler_chunk_suspicious"] = [
                            bool(flag) for flag in suspicious_flags
                        ]
                    warning_entries = chunk_meta_updates.get("warnings")
                    if isinstance(warning_entries, list) and warning_entries:
                        bucket = metadata.setdefault("warnings", [])
                        bucket.extend(str(entry) for entry in warning_entries if entry)
                    if chunk_meta_updates.get("vm_lift_skipped"):
                        metadata["handler_vm_lift_skipped"] = True
                    if chunk_meta_updates.get("vm_lift_forced"):
                        metadata["handler_vm_lift_forced"] = True
                    existing_payload_meta_obj = metadata.get("handler_payload_meta")
                    if isinstance(existing_payload_meta_obj, dict):
                        existing_payload_meta: Dict[str, Any] = existing_payload_meta_obj
                        for key in (
                            "chunk_count",
                            "chunk_decoded_bytes",
                            "chunk_encoded_lengths",
                            "chunk_success_count",
                        ):
                            value = chunk_meta_updates.get(key)
                            if value is not None and key not in existing_payload_meta:
                                existing_payload_meta[key] = value
                        for extra in (
                            "chunk_suspicious_flags",
                            "warnings",
                            "vm_lift_skipped",
                            "vm_lift_forced",
                        ):
                            if extra in chunk_meta_updates and extra not in existing_payload_meta:
                                existing_payload_meta[extra] = chunk_meta_updates[extra]
                    elif any(
                        key in chunk_meta_updates
                        for key in (
                            "chunk_count",
                            "chunk_decoded_bytes",
                            "chunk_encoded_lengths",
                            "chunk_success_count",
                        )
                    ):
                        metadata["handler_payload_meta"] = {
                            key: chunk_meta_updates[key]
                            for key in (
                                "chunk_count",
                                "chunk_decoded_bytes",
                                "chunk_encoded_lengths",
                                "chunk_success_count",
                            )
                            if key in chunk_meta_updates
                        }
                        for extra in (
                            "chunk_suspicious_flags",
                            "warnings",
                            "vm_lift_skipped",
                            "vm_lift_forced",
                        ):
                            if extra in chunk_meta_updates:
                                metadata["handler_payload_meta"][extra] = chunk_meta_updates[extra]

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
                payload: Dict[str, Any] = {
                    "constants": vm_ir.constants,
                    "bytecode": vm_ir.bytecode,
                    "prototypes": vm_ir.prototypes or [],
                }
                if vm_ir.opcode_map:
                    payload["opcode_map"] = vm_ir.opcode_map
                canonical = self._opcode_lifter.lift_program(
                    payload,
                    version=vm_ir.version,
                    opcode_map=vm_ir.opcode_map,
                )
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.debug("Opcode lifting failed: %s", exc)

        if canonical and canonical.instructions:
            simulator = LuaVMSimulator(trace=self._vm_trace)
            try:
                result = simulator.run(canonical)
            except VMEmulationError:  # pragma: no cover - fallback
                result = None
            analysis = getattr(simulator, "analysis", {})
            if simulator.trace_log:
                metadata["vm_trace"] = simulator.trace_log
            if analysis.get("dummy_loops"):
                metadata["vm_dummy_loops"] = analysis["dummy_loops"]
            if analysis.get("anti_debug_checks"):
                metadata["vm_anti_debug"] = analysis["anti_debug_checks"]
            if analysis.get("halt_reason"):
                metadata["vm_halt_reason"] = analysis["halt_reason"]
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
        formatted = self._formatter.format_source(renamed)
        self._last_render_validation = {}
        try:
            validation = self._lua_validator.check(formatted)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug("lua syntax validation error: %s", exc)
            validation = {"available": False, "error": str(exc)}
        self._last_render_validation = validation
        if validation.get("available") and validation.get("valid") is False:
            error = validation.get("error", "unknown syntax error")
            self.logger.warning("rendered Lua failed syntax validation: %s", error)
        return formatted

    @property
    def last_render_validation(self) -> Dict[str, Any]:
        return dict(self._last_render_validation)

    @property
    def last_handler(self) -> VersionHandler | None:
        """Return the most recently used version handler instance."""

        return self._last_handler

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

    def _decode_payload_mapping(
        self, raw_bytes: bytes
    ) -> Tuple[Optional[Dict[str, Any]], str, Dict[str, Any]]:
        """Return a mapping derived from ``raw_bytes`` when possible."""

        metadata: Dict[str, Any] = {}
        if not raw_bytes:
            return None, "", metadata

        try:
            decoded_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None, "", metadata

        cleaned_text = utils.strip_non_printable(decoded_text)
        if not cleaned_text:
            return None, "", metadata

        mapping: Any = None
        stripped = cleaned_text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                mapping = json.loads(cleaned_text)
            except json.JSONDecodeError:
                mapping = None
            else:
                metadata["handler_decoded_json"] = True

        if isinstance(mapping, list):
            converted = extract_vm_ir(json.dumps(mapping))
            if isinstance(converted, dict):
                mapping = converted

        if isinstance(mapping, dict):
            if isinstance(mapping.get("script"), str):
                metadata.setdefault("script_payload", True)
            return mapping, cleaned_text, metadata

        return None, cleaned_text, metadata

    def _decode_initv4_chunks(
        self,
        source: str,
        *,
        script_key: str,
        handler: VersionHandler | None = None,
        version: VersionInfo | None = None,
        force: bool = False,
    ) -> Tuple[list[bytes], Dict[str, Any], Dict[str, Any]]:
        """Decode every initv4 payload chunk discovered in ``source``."""

        if not script_key:
            return [], {}, {}

        try:
            from .versions.initv4 import InitV4Decoder
        except Exception:  # pragma: no cover - optional dependency
            return [], {}, {}

        ctx = SimpleNamespace(
            script_key=script_key,
            bootstrapper_path=self._bootstrapper_path,
        )
        try:
            decoder = InitV4Decoder(ctx)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug("initv4 decoder setup failed: %s", exc)
            return [], {}, {}

        try:
            payloads = decoder.locate_payload(source)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug("initv4 chunk discovery failed: %s", exc)
            return [], {}, {}

        try:
            decoder_opcode_table = decoder.opcode_table()
        except Exception:  # pragma: no cover - best effort
            decoder_opcode_table = {}
        opcode_table_trusted = decoder.has_custom_opcodes()
        opcode_table_source = "bootstrapper" if opcode_table_trusted else "default"

        decoded_parts: list[bytes] = []
        decoded_lengths: list[int] = []
        encoded_lengths: list[int] = []
        errors: list[Dict[str, Any]] = []
        chunk_sources: list[str] = []
        rename_counts: list[int] = []
        cleaned_flags: list[bool] = []
        chunk_details: list[Dict[str, Any]] = []
        chunk_suspicious_flags: list[bool] = []
        chunk_warnings: list[str] = []
        any_lift_skipped = False
        any_lift_forced = False

        opcode_table: Dict[int, Any] = {}
        if handler is not None:
            try:
                opcode_table = handler.opcode_table()
            except Exception:  # pragma: no cover - best effort
                opcode_table = {}
        if decoder_opcode_table:
            merged_table: Dict[int, OpSpec] = {}
            name_lookup: Dict[str, OpSpec] = {}
            for key, spec in opcode_table.items():
                if isinstance(spec, OpSpec):
                    try:
                        merged_table[int(key)] = spec
                    except Exception:
                        continue
                    name_lookup[spec.mnemonic.upper()] = spec
            for raw_opcode, name in decoder_opcode_table.items():
                try:
                    if isinstance(raw_opcode, str):
                        opcode_int = int(raw_opcode, 0)
                    else:
                        opcode_int = int(raw_opcode)
                except (TypeError, ValueError):
                    continue
                canonical = str(name).upper()
                spec = name_lookup.get(canonical)
                if spec is None:
                    spec = OpSpec(canonical, ())
                    name_lookup[canonical] = spec
                merged_table[opcode_int] = spec
            if merged_table:
                opcode_table = merged_table
        const_decoder = handler.const_decoder() if handler is not None else None

        discovered_chunks = 0

        for index, blob in enumerate(payloads):
            if not isinstance(blob, str):
                continue
            discovered_chunks += 1
            cleaned = blob.strip()
            if cleaned.startswith('"') and cleaned.endswith('"'):
                encoded_lengths.append(max(len(cleaned) - 2, 0))
            else:
                encoded_lengths.append(len(cleaned))

            decoded_length = 0
            cleaned_flag = False
            rename_count = 0
            renamed_chunk = ""
            chunk_source: str | None = None

            try:
                chunk_bytes = decoder.extract_bytecode(blob)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append({"chunk_index": index, "error": str(exc)})
                continue

            decoded_length = len(chunk_bytes)
            decoded_parts.append(chunk_bytes)

            opcode_probe: Optional[Mapping[int, object]]
            opcode_probe = opcode_table if opcode_table else None
            is_vm_like = looks_like_vm_bytecode(chunk_bytes, opcode_probe)
            suspicious_chunk = not is_vm_like
            chunk_suspicious_flags.append(suspicious_chunk)

            allow_vm_lift = True
            vm_lift_attempted = False
            chunk_detail: Dict[str, Any] = {
                "index": index,
                "decoded_bytes": decoded_length,
            }

            if suspicious_chunk:
                message = (
                    f"Chunk {index + 1} does not resemble VM bytecode "
                    f"({decoded_length} bytes)."
                )
                if force:
                    any_lift_forced = True
                    chunk_detail["vm_lift_forced"] = True
                    warning_text = f"{message} Proceeding due to --force."
                    chunk_warnings.append(warning_text)
                    self.logger.warning(warning_text)
                else:
                    allow_vm_lift = False
                    any_lift_skipped = True
                    chunk_detail["vm_lift_skipped"] = True
                    warning_text = (
                        f"{message} Skipping VM lifter; rerun with --force to override."
                    )
                    chunk_warnings.append(warning_text)
                    self.logger.warning(warning_text)

            chunk_detail["suspicious"] = suspicious_chunk

            mapping, _, _ = self._decode_payload_mapping(chunk_bytes)
            if isinstance(mapping, dict):
                if decoder_opcode_table:
                    mapping.setdefault("opcode_map", dict(decoder_opcode_table))
                script_text = mapping.get("script")
                if isinstance(script_text, str) and script_text.strip():
                    chunk_source = utils.strip_non_printable(script_text)
                else:
                    byte_values = mapping.get("bytecode") or mapping.get("code")
                    if (
                        handler is not None
                        and isinstance(byte_values, list)
                        and byte_values
                        and all(
                            isinstance(value, int) and 0 <= value <= 255
                            for value in byte_values
                        )
                        and allow_vm_lift
                    ):
                        consts = list(mapping.get("constants", []))
                        if const_decoder is not None:
                            try:
                                consts = decode_constant_pool(const_decoder, consts)
                            except Exception:  # pragma: no cover - defensive
                                consts = list(mapping.get("constants", []))
                        lifter = VMLifter()
                        try:
                            module = lifter.lift(
                                bytes(byte_values),
                                opcode_table,
                                consts,
                                endianness=(
                                    mapping.get("endianness")
                                    or mapping.get("endian")
                                ),
                            )
                        except Exception as exc:  # pragma: no cover - defensive
                            errors.append(
                                {
                                    "chunk_index": index,
                                    "error": str(exc),
                                }
                            )
                        else:
                            vm_lift_attempted = True
                            devirt = IRDevirtualizer(module, consts)
                            chunk_ast, _ = devirt.lower()
                            chunk_source = lua_ast.to_source(chunk_ast)
                    elif (
                        handler is not None
                        and isinstance(byte_values, list)
                        and byte_values
                        and not allow_vm_lift
                    ):
                        chunk_detail["vm_lift_skipped"] = True

            if chunk_source:
                cleaned_source = self.cleanup(chunk_source)
                cleaned_flag = cleaned_source != chunk_source
                renamer = VariableRenamer()
                renamed_chunk = renamer.rename_variables(cleaned_source)
                stats = getattr(renamer, "last_stats", {})
                if isinstance(stats, dict):
                    count_value = stats.get("replacements")
                    if isinstance(count_value, int):
                        rename_count = max(count_value, 0)
            else:
                try:
                    decoded_text = chunk_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    decoded_text = ""
                if decoded_text:
                    stripped = utils.strip_non_printable(decoded_text)
                    if stripped and any(
                        token in stripped for token in ("function", "local ", "return", "init_fn")
                    ):
                        chunk_source = stripped
                        cleaned_source = chunk_source
                        cleaned_flag = False
                        renamed_chunk = chunk_source

            chunk_detail["vm_lift_attempted"] = vm_lift_attempted
            chunk_details.append(chunk_detail)

            decoded_lengths.append(decoded_length)
            cleaned_flags.append(cleaned_flag)
            rename_counts.append(rename_count)
            emitted = renamed_chunk or chunk_source or ""
            if not emitted.strip():
                placeholder = (
                    f"--[[ undecoded initv4 chunk {index + 1} ({decoded_length} bytes) ]]"
                )
                chunk_detail["placeholder"] = placeholder
                chunk_sources.append(placeholder)
            else:
                chunk_sources.append(emitted)

        meta: Dict[str, Any] = {}
        if discovered_chunks:
            meta["chunk_count"] = discovered_chunks
        if decoded_parts:
            meta["chunk_success_count"] = len(decoded_parts)
        if decoded_lengths:
            meta["chunk_decoded_bytes"] = decoded_lengths
        if encoded_lengths:
            meta["chunk_encoded_lengths"] = encoded_lengths
        if errors:
            meta["chunk_errors"] = errors
        if chunk_details:
            meta["chunk_meta"] = chunk_details
        if chunk_suspicious_flags:
            meta["chunk_suspicious_flags"] = chunk_suspicious_flags
        if chunk_warnings:
            meta.setdefault("warnings", []).extend(chunk_warnings)
        if any_lift_skipped:
            meta["vm_lift_skipped"] = True
        if any_lift_forced:
            meta["vm_lift_forced"] = True
        if decoder_opcode_table:
            meta.setdefault("opcode_table_entries", len(decoder_opcode_table))
        meta.setdefault(
            "opcode_table_source",
            opcode_table_source,
        )
        meta.setdefault("opcode_table_trusted", bool(opcode_table_trusted))

        merged_source = ""
        placeholder_only = False
        combined_script = ""
        if decoded_parts:
            combined_bytes = b"".join(decoded_parts)
            mapping, _, _ = self._decode_payload_mapping(combined_bytes)
            if isinstance(mapping, dict):
                script_text = mapping.get("script")
                if isinstance(script_text, str) and script_text.strip():
                    combined_script = utils.strip_non_printable(script_text)

        if combined_script:
            merged_source = combined_script
        else:
            actual_sources = [
                text.strip()
                for text, detail in zip(chunk_sources, chunk_details)
                if text.strip() and not detail.get("placeholder")
            ]
            if actual_sources:
                merged_source = "\n\n".join(actual_sources)
            else:
                placeholder_texts = [text.strip() for text in chunk_sources if text.strip()]
                if placeholder_texts:
                    placeholder_only = True
                    merged_source = "\n\n".join(placeholder_texts)

        analysis: Dict[str, Any] = {}
        if chunk_sources:
            analysis["sources"] = chunk_sources
        if merged_source:
            analysis["final_source"] = merged_source
        if placeholder_only:
            analysis["placeholders_only"] = True
        if rename_counts and any(rename_counts):
            analysis["rename_counts"] = rename_counts
        if cleaned_flags and any(cleaned_flags):
            analysis["cleaned_chunks"] = cleaned_flags

        return decoded_parts, meta, analysis

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
        opcode_map = payload.get("opcode_map")
        prepared_map: Dict[int, Any] | None = None
        if isinstance(opcode_map, Mapping) and opcode_map:
            prepared_map = {}
            for raw_opcode, name in opcode_map.items():
                try:
                    if isinstance(raw_opcode, str):
                        opcode_int = int(raw_opcode, 0)
                    else:
                        opcode_int = int(raw_opcode)
                except (TypeError, ValueError):
                    continue
                prepared_map[opcode_int] = name
        return VMIR(
            constants=list(constants),
            bytecode=[list(instr) for instr in bytecode],
            prototypes=proto_list,
            opcode_map=prepared_map,
        )

    def _try_parse_vm(self, text: str) -> Optional[VMIR]:
        try:
            data = json.loads(text)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        return self._vm_ir_from_mapping(data)


__all__ = ["LuaDeobfuscator", "VersionInfo", "DeobResult", "VMIR"]
