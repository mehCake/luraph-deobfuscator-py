"""Run manifest generation utilities for pipeline executions.

The manifest summarises the key artefacts produced during a detection run
without persisting any sensitive material such as session keys.  Entries are
versioned so future schema adjustments can be migrated transparently.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence

from .uid_generator import generate_run_id, reserve_artifact_path

LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"

__all__ = [
    "RunManifest",
    "RunManifestError",
    "build_run_manifest",
    "write_run_manifest",
    "load_run_manifest",
]


class RunManifestError(RuntimeError):
    """Raised when manifest data fails validation."""


def _contains_key_field(payload: Any) -> bool:
    """Return ``True`` if the payload contains a mapping entry named ``key``."""

    if isinstance(payload, MutableMapping):
        for key, value in payload.items():
            if str(key).lower() == "key" or _contains_key_field(value):
                return True
        return False
    if isinstance(payload, Mapping):  # pragma: no cover - defensive branch
        if any(str(key).lower() == "key" for key in payload.keys()):
            return True
        return any(_contains_key_field(value) for value in payload.values())
    if isinstance(payload, (list, tuple)):
        return any(_contains_key_field(item) for item in payload)
    return False


def _ensure_no_key_fields(data: Mapping[str, Any]) -> None:
    if _contains_key_field(data):
        raise RunManifestError("manifest data contains forbidden key fields")


def _normalise_path(path: Optional[Path | str]) -> Optional[str]:
    if path is None:
        return None
    return str(path)


def _normalise_paths(paths: Mapping[str, Path | str | None]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name, value in paths.items():
        path_str = _normalise_path(value)
        if path_str:
            result[name] = path_str
    return result


def _top_pipeline_summary(pipelines: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    if not pipelines:
        return {}
    top = pipelines[0]
    if not isinstance(top, Mapping):
        return {}
    summary: Dict[str, Any] = {}
    sequence = top.get("sequence") or top.get("pipeline")
    if isinstance(sequence, Iterable) and not isinstance(sequence, (str, bytes)):
        summary["sequence"] = [str(step) for step in sequence]
    for key in ("confidence", "overall", "score"):
        value = top.get(key)
        if isinstance(value, (int, float)):
            summary["overall_confidence"] = float(value)
            break
    hypothesis = top.get("hypothesis_score")
    if isinstance(hypothesis, Mapping):
        components = hypothesis.get("components") or {}
        if isinstance(components, Mapping):
            summary["components"] = {
                str(name): float(value)
                for name, value in components.items()
                if isinstance(value, (int, float))
            }
        overall = hypothesis.get("overall")
        if isinstance(overall, (int, float)):
            summary["overall_confidence"] = float(overall)
    version_hint = top.get("version_hint")
    if isinstance(version_hint, str) and version_hint.strip():
        summary["version_hint"] = version_hint.strip()
    return summary


def _candidate_map_preview(mapping: Mapping[str, Any]) -> Sequence[str]:
    raw_mapping = mapping.get("mapping")
    if not isinstance(raw_mapping, Mapping):
        return []
    preview: list[str] = []
    for opcode, mnemonic in list(raw_mapping.items())[:5]:
        preview.append(f"{opcode}->{mnemonic}")
    return preview


def _candidate_map_summaries(
    candidates: Sequence[Mapping[str, Any]],
    candidate_files: Sequence[str],
) -> list[Dict[str, Any]]:
    summaries: list[Dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            continue
        entry: Dict[str, Any] = {}
        if index < len(candidate_files):
            entry["path"] = candidate_files[index]
        confidence = candidate.get("confidence")
        if isinstance(confidence, (int, float)):
            entry["confidence"] = float(confidence)
        entry["preview"] = list(_candidate_map_preview(candidate))
        mapping_obj = candidate.get("mapping")
        if isinstance(mapping_obj, Mapping):
            entry["total_entries"] = len(mapping_obj)
        version_hint = candidate.get("version_hint")
        if isinstance(version_hint, str) and version_hint.strip():
            entry["version_hint"] = version_hint.strip()
        summaries.append(entry)
    return summaries


def _mapping_summary(mapping_report: Mapping[str, Any]) -> Dict[str, Any]:
    tables = mapping_report.get("tables")
    summary: Dict[str, Any] = {"table_count": 0}
    if not isinstance(tables, Sequence):
        return summary
    summary["table_count"] = len(tables)
    top_tables: list[Dict[str, Any]] = []
    for table in list(tables)[:3]:
        if not isinstance(table, Mapping):
            continue
        item: Dict[str, Any] = {
            "name": str(table.get("name", "unknown")),
        }
        confidence = table.get("confidence")
        if isinstance(confidence, (int, float)):
            item["confidence"] = float(confidence)
        samples = table.get("samples")
        if isinstance(samples, int):
            item["samples"] = samples
        permutation_score = table.get("permutation_score")
        if isinstance(permutation_score, (int, float)):
            item["permutation_score"] = float(permutation_score)
        version_hint = table.get("version_hint")
        if isinstance(version_hint, str) and version_hint.strip():
            item["version_hint"] = version_hint.strip()
        top_tables.append(item)
    if top_tables:
        summary["top_tables"] = top_tables
    return summary


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0.0


def _migrate_manifest_data(raw: Mapping[str, Any]) -> Dict[str, Any]:
    version = str(raw.get("schema_version") or raw.get("version") or SCHEMA_VERSION)
    run_id = str(raw.get("run_id") or raw.get("id") or "unknown")
    created_at = str(raw.get("created_at") or raw.get("timestamp") or "")

    pipeline_section: Mapping[str, Any]
    if "pipeline" in raw and isinstance(raw.get("pipeline"), Mapping):
        pipeline_section = raw["pipeline"]  # type: ignore[index]
    else:
        pipeline_section = {
            "steps": raw.get("pipeline_steps") or raw.get("pipeline") or [],
            "confidence": raw.get("pipeline_confidence", 0.0),
            "hints": raw.get("pipeline_hints", []),
        }

    steps = pipeline_section.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        steps = []
    hints = pipeline_section.get("hints")
    if not isinstance(hints, Sequence) or isinstance(hints, (str, bytes)):
        hints = []
    confidence = pipeline_section.get("confidence")
    components = pipeline_section.get("components")
    if not isinstance(components, Mapping):
        components = {}

    artefacts = raw.get("artefacts") or raw.get("artifacts") or {}
    if not isinstance(artefacts, Mapping):
        artefacts = {}

    candidates = raw.get("candidate_maps") or raw.get("candidates") or []
    if not isinstance(candidates, Sequence):
        candidates = []

    notes = raw.get("notes")
    if not isinstance(notes, Sequence) or isinstance(notes, (str, bytes)):
        notes = []

    mapping_summary = raw.get("mapping_summary")
    if not isinstance(mapping_summary, Mapping):
        mapping_summary = {}

    scoring = raw.get("scoring")
    if not isinstance(scoring, Mapping):
        scoring = {}

    version_hint = raw.get("version_hint")
    if not isinstance(version_hint, str):
        version_hint = None

    return {
        "schema_version": version,
        "run_id": run_id,
        "created_at": created_at,
        "pipeline_steps": [str(step) for step in steps],
        "pipeline_confidence": _safe_float(confidence),
        "pipeline_hints": [str(hint) for hint in hints],
        "pipeline_components": {
            str(name): _safe_float(value) for name, value in components.items()
        },
        "artefacts": _normalise_paths({str(k): v for k, v in artefacts.items()}),
        "candidate_maps": list(candidates),
        "notes": [str(note) for note in notes],
        "mapping_summary": dict(mapping_summary),
        "scoring": {str(k): _safe_float(v) for k, v in scoring.items()},
        "version_hint": version_hint,
    }


@dataclass(slots=True)
class RunManifest:
    run_id: str
    created_at: str
    target: str
    pipeline_steps: list[str]
    pipeline_confidence: float
    pipeline_hints: list[str] = field(default_factory=list)
    pipeline_components: Dict[str, float] = field(default_factory=dict)
    artefacts: Dict[str, str] = field(default_factory=dict)
    candidate_maps: list[Dict[str, Any]] = field(default_factory=list)
    mapping_summary: Dict[str, Any] = field(default_factory=dict)
    scoring: Dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    version_hint: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "target": self.target,
            "pipeline_steps": list(self.pipeline_steps),
            "pipeline_confidence": self.pipeline_confidence,
            "pipeline_hints": list(self.pipeline_hints),
            "pipeline_components": dict(self.pipeline_components),
            "artefacts": dict(self.artefacts),
            "candidate_maps": list(self.candidate_maps),
            "mapping_summary": dict(self.mapping_summary),
            "scoring": dict(self.scoring),
            "notes": list(self.notes),
        }
        if self.version_hint:
            payload["version_hint"] = self.version_hint
        return payload

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "RunManifest":
        migrated = _migrate_manifest_data(raw)
        return cls(
            run_id=str(migrated.get("run_id")),
            created_at=str(migrated.get("created_at")),
            target=str(raw.get("target", migrated.get("target", "unknown"))),
            pipeline_steps=list(migrated.get("pipeline_steps", [])),
            pipeline_confidence=_safe_float(migrated.get("pipeline_confidence")),
            pipeline_hints=list(migrated.get("pipeline_hints", [])),
            pipeline_components=dict(migrated.get("pipeline_components", {})),
            artefacts=dict(migrated.get("artefacts", {})),
            candidate_maps=list(migrated.get("candidate_maps", [])),
            mapping_summary=dict(migrated.get("mapping_summary", {})),
            scoring=dict(migrated.get("scoring", {})),
            notes=list(migrated.get("notes", [])),
            version_hint=migrated.get("version_hint"),
            schema_version=str(migrated.get("schema_version", SCHEMA_VERSION)),
        )


def build_run_manifest(
    *,
    target: str,
    pipeline_report: Mapping[str, Any],
    mapping_report: Mapping[str, Any],
    artefact_paths: Mapping[str, Path | str | None],
    candidate_maps: Sequence[Mapping[str, Any]],
    candidate_map_files: Sequence[Path | str],
    parity_summary: Optional[Mapping[str, Any]] = None,
    version_hint: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> RunManifest:
    """Create a manifest summary for a completed detection run."""

    ts = timestamp or datetime.utcnow()
    timestamp_token = ts.strftime("%Y%m%d-%H%M%S")
    target_name = Path(str(target)).stem or Path(str(target)).name
    run_id = generate_run_id(components=[timestamp_token, target_name])
    created_at = ts.isoformat(timespec="seconds")

    pipeline_steps = [str(step) for step in pipeline_report.get("pipeline", [])]
    pipeline_confidence = _safe_float(pipeline_report.get("pipeline_confidence"))
    pipeline_hints = [
        str(hint)
        for hint in pipeline_report.get("pipeline_hints", [])
        if isinstance(hint, (str, int, float))
    ]

    pipelines = pipeline_report.get("pipelines")
    if isinstance(pipelines, Sequence):
        components = _top_pipeline_summary(pipelines)
    else:
        components = {}

    artefacts = _normalise_paths(artefact_paths)
    candidate_files = [_normalise_path(path) or "" for path in candidate_map_files]
    candidate_summaries = _candidate_map_summaries(candidate_maps, candidate_files)

    mapping_summary = _mapping_summary(mapping_report)

    scoring: Dict[str, float] = {
        "pipeline_confidence": pipeline_confidence,
    }
    if components.get("overall_confidence") is not None:
        scoring["top_pipeline"] = _safe_float(components["overall_confidence"])
    if isinstance(parity_summary, Mapping):
        match = parity_summary.get("matching_prefix")
        if isinstance(match, int):
            scoring["parity_match_bytes"] = float(match)
        success = parity_summary.get("success")
        if isinstance(success, bool):
            scoring["parity_success"] = 1.0 if success else 0.0

    version_hint = (
        str(version_hint)
        if isinstance(version_hint, str)
        else components.get("version_hint")
    )
    if isinstance(version_hint, str) and not version_hint.strip():
        version_hint = None

    manifest = RunManifest(
        run_id=run_id,
        created_at=created_at,
        target=str(target),
        pipeline_steps=pipeline_steps,
        pipeline_confidence=pipeline_confidence,
        pipeline_hints=pipeline_hints,
        pipeline_components={
            key: value
            for key, value in components.get("components", {}).items()
            if isinstance(value, (int, float))
        },
        artefacts=artefacts,
        candidate_maps=candidate_summaries,
        mapping_summary=mapping_summary,
        scoring=scoring,
        notes=["Manifest generated automatically"],
        version_hint=version_hint,
    )

    data = manifest.to_dict()
    _ensure_no_key_fields(data)
    return manifest


def write_run_manifest(*, runs_dir: Path, manifest: RunManifest) -> Path:
    """Persist ``manifest`` into ``runs_dir`` and return the written path."""

    data = manifest.to_dict()
    _ensure_no_key_fields(data)
    path, should_write = reserve_artifact_path(
        runs_dir,
        run_id=manifest.run_id,
        prefix="run",
        suffix=".manifest.json",
    )

    if not should_write:
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:  # pragma: no cover - race condition safeguard
            should_write = True
        else:
            if existing != data:
                LOGGER.warning(
                    "Manifest %s already exists; keeping original contents", path
                )
            else:
                LOGGER.info("Manifest %s already exists and matches", path)
            return path

    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Wrote run manifest %s", path)
    return path


def load_run_manifest(path: Path) -> RunManifest:
    """Load a previously generated manifest file."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):  # pragma: no cover - defensive
        raise RunManifestError("manifest payload is not a mapping")
    return RunManifest.from_dict(payload)
