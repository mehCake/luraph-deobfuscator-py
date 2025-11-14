"""Sandboxed snapshot capture for bootstrap analysis.

This module executes short Lua snippets inside a restricted runtime and records
structured snapshots of reconstructed tables (such as constant pools).  The
snapshots are serialised to JSON for offline inspection while carefully
scrubbing any fields named ``key`` so that session keys are never written to
disk.  When multiple snapshots are captured, diff artefacts are generated to
highlight changes between states.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

try:  # pragma: no cover - optional dependency
    from lupa import LuaError, LuaRuntime
except Exception:  # pragma: no cover - fallback shim bundled with the repo
    from .. import lupa as _fallback_lupa

    LuaRuntime = getattr(_fallback_lupa, "LuaRuntime", None)  # type: ignore[assignment]
    LuaError = getattr(_fallback_lupa, "LuaError", RuntimeError)  # type: ignore[assignment]
else:  # pragma: no cover - executed only when real lupa available
    _fallback_lupa = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)

__all__ = [
    "Snapshot",
    "SnapshotDiff",
    "SnapshotRun",
    "SnapshotterError",
    "capture_bootstrap_snapshots",
    "diff_snapshots",
    "write_snapshot_run",
    "build_arg_parser",
    "main",
]


class SnapshotterError(RuntimeError):
    """Raised when the snapshotter is unable to execute the sandboxed snippet."""


@dataclass
class Snapshot:
    """Represents a captured snapshot from a sandbox run."""

    label: str
    index: int
    created_at: datetime
    payload: Any


@dataclass
class SnapshotDiff:
    """Describes differences between two snapshots."""

    base_label: str
    current_label: str
    added: Dict[str, Any] = field(default_factory=dict)
    removed: Dict[str, Any] = field(default_factory=dict)
    changed: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class SnapshotRun:
    """Aggregated information for a snapshot capture session."""

    run_name: str
    snapshots: List[Snapshot]
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


def _get_globals(runtime: LuaRuntime) -> MutableMapping[str, Any]:
    if hasattr(runtime, "globals"):
        return runtime.globals()  # type: ignore[return-value]
    if hasattr(runtime, "_globals"):
        return getattr(runtime, "_globals")  # pragma: no cover - fallback shim
    raise SnapshotterError("Lua runtime does not expose globals table")


def _new_table(runtime: LuaRuntime) -> Any:
    if hasattr(runtime, "table_from"):
        return runtime.table_from({})  # type: ignore[call-arg]
    if hasattr(runtime, "table"):
        return runtime.table()
    if _fallback_lupa is not None:
        table_cls = getattr(_fallback_lupa, "LuaTable", None)
        if table_cls is not None:
            return table_cls([])  # type: ignore[call-arg]
    return {}


def _convert_python_to_lua(runtime: LuaRuntime, value: Any) -> Any:
    if isinstance(value, Mapping):
        table = _new_table(runtime)
        for key, item in value.items():
            table[key] = _convert_python_to_lua(runtime, item)
        return table
    if isinstance(value, (list, tuple)):
        table = _new_table(runtime)
        for index, item in enumerate(value, start=1):
            table[index] = _convert_python_to_lua(runtime, item)
        return table
    return value


def _is_lua_table(value: Any) -> bool:
    if _fallback_lupa is not None:
        table_cls = getattr(_fallback_lupa, "LuaTable", None)
        if table_cls is not None and isinstance(value, table_cls):  # type: ignore[arg-type]
            return True
    return hasattr(value, "keys") and hasattr(value, "__getitem__")


def _convert_lua_table_to_python(value: Any) -> Any:
    if not _is_lua_table(value):
        return value
    sequential: List[Any] = []
    index = 1
    while True:
        try:
            item = value[index]
        except Exception:  # pragma: no cover - defensive for fallback shim
            item = None
        if item is None:
            break
        sequential.append(_convert_lua_table_to_python(item))
        index += 1
    mapping: Dict[str, Any] = {}
    try:
        keys = list(value.keys())  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - fallback shim uses generator
        keys = []
        try:
            iterator = value.keys()  # type: ignore[attr-defined]
            for key in iterator:
                keys.append(key)
        except Exception:
            keys = []
    for key in keys:
        if isinstance(key, int) and 1 <= key <= len(sequential):
            continue
        mapping[str(_convert_lua_table_to_python(key))] = _convert_lua_table_to_python(value[key])
    if mapping:
        if sequential:
            mapping.setdefault("__array__", sequential)
        return mapping
    return sequential


def _strip_key_fields(value: Any) -> Any:
    if isinstance(value, MutableMapping):
        return {
            k: _strip_key_fields(v)
            for k, v in value.items()
            if str(k).lower() != "key"
        }
    if isinstance(value, Mapping):  # pragma: no cover - defensive branch
        return {
            k: _strip_key_fields(v)
            for k, v in value.items()
            if str(k).lower() != "key"
        }
    if isinstance(value, list):
        return [_strip_key_fields(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_strip_key_fields(item) for item in value)
    return value


def _normalise_value(value: Any) -> Any:
    if _is_lua_table(value):
        converted = _convert_lua_table_to_python(value)
    else:
        converted = value
    return _strip_key_fields(converted)


def _install_sandbox(runtime: LuaRuntime) -> None:
    globals_table = _get_globals(runtime)
    forbidden_names = {
        "io": {"open": "io.open", "popen": "io.popen"},
        "os": {
            "execute": "os.execute",
            "remove": "os.remove",
            "rename": "os.rename",
            "tmpname": "os.tmpname",
            "getenv": "os.getenv",
        },
        "package": {
            "loadlib": "package.loadlib",
            "searchpath": "package.searchpath",
        },
    }
    for namespace, mapping in forbidden_names.items():
        globals_table[namespace] = {name: _make_forbidden(alias) for name, alias in mapping.items()}
    globals_table["require"] = _make_forbidden("require")


def _make_forbidden(name: str):
    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise SnapshotterError(
            f"sandboxed Lua attempted to access forbidden primitive '{name}'"
        )

    return _forbidden


def _flatten_payload(value: Any, prefix: str = "", *, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if result is None:
        result = {}
    if isinstance(value, Mapping):
        for key, item in value.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            _flatten_payload(item, new_prefix, result=result)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            new_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            _flatten_payload(item, new_prefix, result=result)
    else:
        result[prefix or "value"] = value
    return result


def diff_snapshots(base: Snapshot, current: Snapshot) -> SnapshotDiff:
    base_flat = _flatten_payload(base.payload)
    current_flat = _flatten_payload(current.payload)

    added = {path: value for path, value in current_flat.items() if path not in base_flat}
    removed = {path: value for path, value in base_flat.items() if path not in current_flat}
    changed: Dict[str, Dict[str, Any]] = {}
    for path, old_value in base_flat.items():
        if path in current_flat and current_flat[path] != old_value:
            changed[path] = {"base": old_value, "current": current_flat[path]}

    return SnapshotDiff(
        base_label=base.label,
        current_label=current.label,
        added=added,
        removed=removed,
        changed=changed,
    )


def _unique_snapshot_dir(destination: Path, run_name: str, *, timestamp: Optional[datetime]) -> Path:
    base = destination / "snapshots"
    stamp = (timestamp or datetime.utcnow()).strftime("%Y%m%d-%H%M%S")
    run_dir = base / f"{run_name}-{stamp}"
    counter = 2
    while run_dir.exists():
        run_dir = base / f"{run_name}-{stamp}-{counter}"
        counter += 1
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_snapshot_run(
    run: SnapshotRun,
    *,
    destination: Path,
    timestamp: Optional[datetime] = None,
) -> Path:
    """Serialise snapshot information to ``destination`` and return the directory."""

    run_dir = _unique_snapshot_dir(destination, run.run_name, timestamp=timestamp)

    manifest = {
        "run_name": run.run_name,
        "created_at": run.created_at.isoformat() + "Z",
        "snapshot_count": len(run.snapshots),
        "snapshots": [],
    }

    for snapshot in run.snapshots:
        payload = {
            "label": snapshot.label,
            "index": snapshot.index,
            "created_at": snapshot.created_at.isoformat() + "Z",
            "payload": snapshot.payload,
        }
        filename = f"snapshot_{snapshot.index:03d}.json"
        (run_dir / filename).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        manifest["snapshots"].append(filename)

    for previous, current in zip(run.snapshots, run.snapshots[1:]):
        diff = diff_snapshots(previous, current)
        diff_payload = {
            "base_label": diff.base_label,
            "current_label": diff.current_label,
            "added": diff.added,
            "removed": diff.removed,
            "changed": diff.changed,
        }
        diff_name = f"diff_{previous.index:03d}_{current.index:03d}.json"
        (run_dir / diff_name).write_text(json.dumps(diff_payload, indent=2) + "\n", encoding="utf-8")

    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Snapshots written to %s", run_dir)
    return run_dir


def _build_runtime(*, unpack: bool = True) -> LuaRuntime:
    if LuaRuntime is None:
        raise SnapshotterError("lupa is not available; cannot execute Lua snippets")
    return LuaRuntime(unpack_returned_tuples=unpack)  # type: ignore[call-arg]


def capture_bootstrap_snapshots(
    *,
    snippet: Optional[str] = None,
    path: Optional[Path] = None,
    run_name: str,
    requested_globals: Optional[Sequence[str]] = None,
    lua_args: Optional[Mapping[str, Any]] = None,
    max_instructions: int = 50_000,
) -> SnapshotRun:
    """Execute ``snippet`` in a sandbox and capture emitted snapshots."""

    if snippet is None and path is None:
        raise SnapshotterError("either snippet or path must be provided")
    if snippet is None and path is not None:
        snippet = Path(path).read_text(encoding="utf-8")

    runtime = _build_runtime()
    _install_sandbox(runtime)
    globals_table = _get_globals(runtime)

    snapshots: List[Snapshot] = []

    def snapshot_emit(label: Any, value: Any) -> None:
        sanitized = _normalise_value(value)
        snapshots.append(
            Snapshot(
                label=str(label),
                index=len(snapshots),
                created_at=datetime.utcnow(),
                payload=sanitized,
            )
        )

    globals_table["snapshot_emit"] = snapshot_emit

    if lua_args:
        for key, value in lua_args.items():
            globals_table[str(key)] = _convert_python_to_lua(runtime, value)

    if requested_globals is None:
        requested_globals = []

    instruction_counter = {"count": 0}

    def hook(*_args: Any) -> None:  # pragma: no cover - requires real lupa
        instruction_counter["count"] += 1
        if instruction_counter["count"] > max_instructions:
            raise SnapshotterError("instruction limit exceeded during snapshot capture")

    if hasattr(runtime, "set_debug_hook"):
        try:
            runtime.set_debug_hook(hook, instruction_count=100)
        except Exception:  # pragma: no cover - fallback runtimes may not support hooks
            LOGGER.debug("debug hook not supported; proceeding without instruction guard")

    try:
        runtime.execute(snippet)
    except LuaError as exc:  # pragma: no cover - depends on runtime behaviour
        raise SnapshotterError(f"failed to execute sandboxed snippet: {exc}") from exc

    for name in requested_globals:
        value = globals_table.get(name)
        if value is None:
            LOGGER.debug("Requested global '%s' was not present after execution", name)
            continue
        snapshots.append(
            Snapshot(
                label=f"global:{name}",
                index=len(snapshots),
                created_at=datetime.utcnow(),
                payload=_normalise_value(value),
            )
        )

    metadata = {
        "requested_globals": list(requested_globals),
        "snapshot_count": len(snapshots),
    }
    return SnapshotRun(run_name=run_name, snapshots=snapshots, metadata=metadata)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture bootstrap memory snapshots")
    parser.add_argument("--snippet", help="Lua snippet to execute")
    parser.add_argument("--file", type=Path, help="Lua source file to execute")
    parser.add_argument("--run-name", required=True, help="Identifier for the snapshot run")
    parser.add_argument("--output", type=Path, default=Path("out"), help="Output directory")
    parser.add_argument(
        "--request-global",
        action="append",
        default=[],
        dest="requested_globals",
        help="Capture a global table after execution",
    )
    parser.add_argument(
        "--max-instructions",
        type=int,
        default=50_000,
        help="Maximum Lua instructions to execute inside the sandbox",
    )
    parser.add_argument(
        "--diff-only",
        action="store_true",
        help="Only recompute diffs for an existing snapshot directory",
    )
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        help="Existing snapshot directory when using --diff-only",
    )
    return parser


def _recompute_diffs(snapshot_dir: Path) -> None:
    snapshot_files = sorted(snapshot_dir.glob("snapshot_*.json"))
    snapshots: List[Snapshot] = []
    for index, file in enumerate(snapshot_files):
        payload = json.loads(file.read_text(encoding="utf-8"))
        snapshots.append(
            Snapshot(
                label=payload.get("label", file.stem),
                index=index,
                created_at=datetime.utcnow(),
                payload=payload.get("payload"),
            )
        )
    for previous, current in zip(snapshots, snapshots[1:]):
        diff = diff_snapshots(previous, current)
        diff_payload = {
            "base_label": diff.base_label,
            "current_label": diff.current_label,
            "added": diff.added,
            "removed": diff.removed,
            "changed": diff.changed,
        }
        diff_name = f"diff_{previous.index:03d}_{current.index:03d}.json"
        (snapshot_dir / diff_name).write_text(json.dumps(diff_payload, indent=2) + "\n", encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.diff_only:
        if not args.snapshot_dir:
            raise SnapshotterError("--snapshot-dir is required when using --diff-only")
        _recompute_diffs(args.snapshot_dir)
        LOGGER.info("Recomputed diffs in %s", args.snapshot_dir)
        return 0

    if not args.snippet and not args.file:
        raise SnapshotterError("either --snippet or --file must be provided")

    snippet_text = args.snippet
    if snippet_text is None and args.file:
        snippet_text = args.file.read_text(encoding="utf-8")

    run = capture_bootstrap_snapshots(
        snippet=snippet_text,
        run_name=args.run_name,
        requested_globals=args.requested_globals,
        max_instructions=args.max_instructions,
    )
    write_snapshot_run(run, destination=args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
