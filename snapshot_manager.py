"""Snapshot manager for long-running search workflows.

The manager persists search metadata to disk so automated pipelines can pause
and resume expensive decoding passes.  Snapshots intentionally avoid storing
secret material such as raw keys; only hashed tokens and high-level metadata is
recorded.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


class SnapshotManager:
    """Persist and restore search snapshot metadata."""

    VERSION = 1

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._state: Dict[str, Any] = self._empty_state()
        self._attempted_keys: set[Tuple[str, str, str]] = set()
        if self.path and self.path.exists():
            try:
                self.load()
            except Exception:
                # Corrupted or incompatible snapshots are ignored so callers can
                # resume with a clean state.
                self.reset()

    def _empty_state(self) -> Dict[str, Any]:
        return {
            "version": self.VERSION,
            "metadata": {},
            "prga_attempts": [],
            "candidates": [],
            "opcode_mappings": {},
        }

    def reset(self) -> None:
        """Reset the in-memory snapshot state without touching disk."""

        with self._lock:
            self._state = self._empty_state()
            self._attempted_keys.clear()

    def load(self) -> None:
        """Load snapshot data from :attr:`path` if available."""

        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self.reset()
            return
        if data.get("version") != self.VERSION:
            self.reset()
            return
        with self._lock:
            self._state = {
                "version": self.VERSION,
                "metadata": data.get("metadata", {}),
                "prga_attempts": list(data.get("prga_attempts", [])),
                "candidates": list(data.get("candidates", [])),
                "opcode_mappings": data.get("opcode_mappings", {}),
            }
            self._attempted_keys = {
                (
                    entry.get("fragment_sha", ""),
                    entry.get("transform_sha", ""),
                    entry.get("key_sha", ""),
                )
                for entry in self._state["prga_attempts"]
                if entry.get("fragment_sha") and entry.get("transform_sha") and entry.get("key_sha")
            }

    def update_metadata(self, **fields: Any) -> None:
        """Merge ``fields`` into the snapshot metadata block."""

        with self._lock:
            metadata = dict(self._state.get("metadata", {}))
            metadata.update({key: self._clean(value) for key, value in fields.items()})
            metadata.setdefault("updated_at", time.time())
            self._state["metadata"] = metadata

    def has_attempted(self, fragment_sha: str, transform_sha: str, key_sha: str) -> bool:
        """Return ``True`` if the PRGA combination has already been recorded."""

        with self._lock:
            return (fragment_sha, transform_sha, key_sha) in self._attempted_keys

    def record_prga_attempt(
        self,
        *,
        fragment_sha: str,
        transform_sha: str,
        key_sha: str,
        key_token: str,
        method: str,
        source_label: str,
        status: str,
        candidate_sha: Optional[str],
        saved_path: Optional[str],
        metadata: Optional[Mapping[str, Any]] = None,
        diff_notes: Optional[Sequence[str]] = None,
        emulator_status: Optional[str] = None,
    ) -> None:
        """Record a PRGA attempt outcome."""

        entry = {
            "fragment_sha": fragment_sha,
            "transform_sha": transform_sha,
            "key_sha": key_sha,
            "key_token": key_token,
            "method": method,
            "source": source_label,
            "status": status,
            "candidate_sha": candidate_sha,
            "saved_path": saved_path,
            "metadata": self._clean(metadata or {}),
            "diff_notes": list(diff_notes or ()),
            "emulator_status": emulator_status,
            "timestamp": time.time(),
        }
        key_tuple = (fragment_sha, transform_sha, key_sha)
        with self._lock:
            attempts: list = self._state.setdefault("prga_attempts", [])
            replaced = False
            for index, existing in enumerate(attempts):
                existing_key = (
                    existing.get("fragment_sha"),
                    existing.get("transform_sha"),
                    existing.get("key_sha"),
                )
                if existing_key == key_tuple:
                    attempts[index] = entry
                    replaced = True
                    break
            if not replaced:
                attempts.append(entry)
            self._attempted_keys.add(key_tuple)

    def record_candidate(
        self,
        *,
        path: str,
        sha256: str,
        method: str,
        key_token: str,
        source_label: str,
        metadata: Optional[Mapping[str, Any]] = None,
        diff_notes: Optional[Sequence[str]] = None,
        emulator_status: Optional[str] = None,
    ) -> None:
        """Record a persisted candidate for resume workflows."""

        entry = {
            "path": path,
            "sha256": sha256,
            "method": method,
            "key_token": key_token,
            "source": source_label,
            "metadata": self._clean(metadata or {}),
            "diff_notes": list(diff_notes or ()),
            "emulator_status": emulator_status,
            "timestamp": time.time(),
        }
        with self._lock:
            candidates: list = self._state.setdefault("candidates", [])
            for index, existing in enumerate(candidates):
                if existing.get("sha256") == sha256 and existing.get("path") == path:
                    candidates[index] = entry
                    break
            else:
                candidates.append(entry)

    def record_opcode_mappings(self, mapping: Mapping[str, Any]) -> None:
        """Persist opcode mapping data for resume flows."""

        with self._lock:
            self._state["opcode_mappings"] = self._clean(mapping)
            self._state["metadata"].setdefault("updated_at", time.time())

    def saved_candidate_count(self) -> int:
        """Return the number of recorded candidates."""

        with self._lock:
            return len(self._state.get("candidates", []))

    def save(self) -> None:
        """Write the current snapshot state to disk."""

        if not self.path:
            return
        with self._lock:
            payload = self._clean(self._state)
            payload["version"] = self.VERSION
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp_path.replace(self.path)

    def _clean(self, value: Any) -> Any:
        """Recursively convert *value* into JSON-serialisable primitives."""

        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, bytes):
            return value.decode("utf-8", "ignore")
        if isinstance(value, Mapping):
            return {str(key): self._clean(sub_value) for key, sub_value in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._clean(item) for item in value]
        return str(value)

    def iter_attempt_keys(self) -> Iterable[Tuple[str, str, str]]:
        """Yield attempted PRGA identifiers (mainly for tests)."""

        with self._lock:
            return set(self._attempted_keys)
