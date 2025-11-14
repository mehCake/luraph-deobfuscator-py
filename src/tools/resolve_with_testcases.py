"""Sandboxed testcase runner for opcode behaviour exploration.

This helper executes user-supplied Lua snippets or bootstrap payloads in a
constrained runtime so that analysts can observe how particular opcode handlers
behave on carefully crafted inputs.  The goal is to aid manual investigations
while keeping strict guarantees around key-handling: the tool never persists
session keys, refuses to fetch remote resources, and requires an explicit
confirmation step before executing arbitrary code.

Each testcase definition is intentionally lightweight – analysts provide a
short Lua snippet (inline or as a local file), optionally specify a bootstrap
chunk executed before every testcase, and choose an entrypoint function plus
arguments.  The runner captures return values, logged output, and runtime
metadata, writing the results to JSON for later inspection.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence


try:  # pragma: no cover - optional dependency
    from lupa import LuaError, LuaRuntime
except Exception:  # pragma: no cover - fallback shim bundled with the repo
    from .. import lupa as _fallback_lupa

    LuaRuntime = getattr(_fallback_lupa, "LuaRuntime", None)  # type: ignore[assignment]
    LuaError = getattr(_fallback_lupa, "LuaError", RuntimeError)  # type: ignore[assignment]
    LuaTable = getattr(_fallback_lupa, "LuaTable", None)
else:  # pragma: no cover - executed when lupa available
    LuaTable = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)


class ResolveWithTestcasesError(RuntimeError):
    """Raised when testcase execution fails or the definition is invalid."""


@dataclass
class TestcaseDefinition:
    """Structured testcase metadata parsed from a JSON definition file."""

    name: str
    lua_source: Optional[str] = None
    lua_path: Optional[Path] = None
    entrypoint: Optional[str] = None
    args: Sequence[Any] = field(default_factory=list)
    expect_error: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestcaseObservation:
    """Result data captured after executing a testcase."""

    name: str
    success: bool
    duration_seconds: float
    returns: List[Any]
    error: Optional[str] = None
    logs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResolveSummary:
    """Collection of observations emitted by a testcase run."""

    bootstrap: Optional[str]
    observations: List[TestcaseObservation]
    started_at: float
    completed_at: float

    @property
    def elapsed_seconds(self) -> float:
        return self.completed_at - self.started_at


FORBIDDEN_SCHEMES = ("http://", "https://", "ftp://", "ftps://")


def _ensure_runtime() -> LuaRuntime:
    if LuaRuntime is None:  # pragma: no cover - triggered when lupa missing
        raise ResolveWithTestcasesError("Lua runtime is unavailable – install 'lupa' to run testcases")
    return LuaRuntime(unpack_returned_tuples=True)


def _get_globals(runtime: LuaRuntime) -> MutableMapping[str, Any]:
    if hasattr(runtime, "globals"):
        return runtime.globals()  # type: ignore[return-value]
    if hasattr(runtime, "_globals"):
        return getattr(runtime, "_globals")  # pragma: no cover - fallback shim
    raise ResolveWithTestcasesError("Lua runtime does not expose globals table")


def _make_forbidden(name: str):
    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise ResolveWithTestcasesError(
            f"sandboxed Lua attempted to access forbidden primitive '{name}'"
        )

    return _forbidden


def _install_sandbox(runtime: LuaRuntime, *, log_sink: Optional[List[str]] = None) -> None:
    globals_table = _get_globals(runtime)
    globals_table["io"] = {"open": _make_forbidden("io.open"), "popen": _make_forbidden("io.popen")}
    globals_table["os"] = {
        "execute": _make_forbidden("os.execute"),
        "remove": _make_forbidden("os.remove"),
        "rename": _make_forbidden("os.rename"),
        "tmpname": _make_forbidden("os.tmpname"),
    }
    globals_table["require"] = _make_forbidden("require")
    globals_table["loadfile"] = _make_forbidden("loadfile")
    globals_table["dofile"] = _make_forbidden("dofile")
    if log_sink is not None:
        def _log_function(*items: object) -> None:
            message = " ".join(str(item) for item in items)
            log_sink.append(message)

        globals_table["print"] = _log_function


def _is_lua_table(value: Any) -> bool:
    if LuaTable is not None and isinstance(value, LuaTable):  # type: ignore[arg-type]
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
        except Exception:
            item = None
        if item is None:
            break
        sequential.append(_convert_lua_table_to_python(item))
        index += 1
    mapping: Dict[str, Any] = {}
    try:
        keys = list(value.keys())  # type: ignore[attr-defined]
    except Exception:
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


def _convert_sequence(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [
            _convert_lua_table_to_python(item) if _is_lua_table(item) else item
            for item in value
        ]
    if _is_lua_table(value):
        converted = _convert_lua_table_to_python(value)
        if isinstance(converted, list):
            return converted
        return [converted]
    return [value]


def _validate_local_reference(value: Optional[str]) -> None:
    if not value:
        return
    lowered = value.strip().lower()
    if any(lowered.startswith(scheme) for scheme in FORBIDDEN_SCHEMES):
        raise ResolveWithTestcasesError(
            f"remote references are not allowed in testcases: '{value}'"
        )


def _load_lua_source(testcase: TestcaseDefinition, base_dir: Path) -> str:
    if testcase.lua_source:
        return testcase.lua_source
    if testcase.lua_path is None:
        raise ResolveWithTestcasesError(
            f"testcase '{testcase.name}' must provide either 'lua_source' or 'lua_path'"
        )
    _validate_local_reference(str(testcase.lua_path))
    file_path = testcase.lua_path
    if not file_path.is_absolute():
        file_path = base_dir / file_path
    if not file_path.exists():
        raise ResolveWithTestcasesError(
            f"testcase '{testcase.name}' references missing Lua file: {file_path}"
        )
    return file_path.read_text(encoding="utf-8")


def _convert_args(args: Sequence[Any]) -> Sequence[Any]:
    converted: List[Any] = []
    for arg in args:
        if isinstance(arg, Mapping):
            converted.append({k: v for k, v in arg.items()})
        else:
            converted.append(arg)
    return converted


def execute_testcase(
    testcase: TestcaseDefinition,
    *,
    bootstrap: Optional[str] = None,
    base_dir: Optional[Path] = None,
) -> TestcaseObservation:
    """Execute a single testcase and return observation data."""

    runtime = _ensure_runtime()
    logs: List[str] = []
    _install_sandbox(runtime, log_sink=logs)
    base_dir = base_dir or Path.cwd()

    if bootstrap:
        LOGGER.debug("Executing shared bootstrap chunk for testcase '%s'", testcase.name)
        try:
            runtime.execute(bootstrap)
        except LuaError as exc:
            raise ResolveWithTestcasesError(
                f"bootstrap failed for testcase '{testcase.name}': {exc}"
            ) from exc

    source = _load_lua_source(testcase, base_dir)
    LOGGER.debug("Running Lua snippet for testcase '%s'", testcase.name)
    start = time.time()
    error: Optional[str] = None
    success = False
    returns: List[Any] = []
    try:
        runtime.execute(source)
        if testcase.entrypoint:
            try:
                entry_func = runtime.eval(testcase.entrypoint)
            except LuaError as exc:  # pragma: no cover - defensive fallback
                raise ResolveWithTestcasesError(
                    f"entrypoint '{testcase.entrypoint}' not defined for testcase '{testcase.name}'"
                ) from exc
            converted_args = _convert_args(testcase.args)
            LOGGER.debug(
                "Invoking entrypoint '%s' with args=%s", testcase.entrypoint, converted_args
            )
            result = entry_func(*converted_args)
            returns = _convert_sequence(result)
        success = True
    except LuaError as exc:
        error = str(exc)
        success = False
    duration = time.time() - start
    if testcase.expect_error and success:
        success = False
        error = error or "expected testcase to raise an error"
    elif not testcase.expect_error and not success:
        LOGGER.warning("Testcase '%s' failed: %s", testcase.name, error)
    observation = TestcaseObservation(
        name=testcase.name,
        success=success,
        duration_seconds=duration,
        returns=returns,
        error=error,
        logs=logs,
        metadata=dict(testcase.metadata),
    )
    return observation


def load_testcases(path: Path) -> tuple[List[TestcaseDefinition], Optional[str]]:
    """Load testcase definitions and optional bootstrap from a JSON file."""

    if not path.exists():
        raise ResolveWithTestcasesError(f"testcase file not found: {path}")
    _validate_local_reference(str(path))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ResolveWithTestcasesError(f"failed to parse testcases JSON: {exc}") from exc

    bootstrap_source: Optional[str] = None
    items = payload
    if isinstance(payload, Mapping):
        items = payload.get("testcases", [])
        bootstrap_value = payload.get("bootstrap")
        if isinstance(bootstrap_value, str):
            bootstrap_source = bootstrap_value
        elif isinstance(bootstrap_value, Mapping) and "path" in bootstrap_value:
            bootstrap_path = Path(str(bootstrap_value["path"]))
            _validate_local_reference(str(bootstrap_path))
            if not bootstrap_path.is_absolute():
                bootstrap_path = path.parent / bootstrap_path
            if not bootstrap_path.exists():
                raise ResolveWithTestcasesError(
                    f"bootstrap snippet not found: {bootstrap_path}"
                )
            bootstrap_source = bootstrap_path.read_text(encoding="utf-8")

    if not isinstance(items, Iterable):
        raise ResolveWithTestcasesError("testcases definition must be an array or mapping")

    definitions: List[TestcaseDefinition] = []
    for raw in items:
        if not isinstance(raw, Mapping):
            raise ResolveWithTestcasesError("each testcase definition must be an object")
        name = str(raw.get("name") or f"testcase-{len(definitions)}")
        lua_source = raw.get("lua_source")
        lua_path = raw.get("lua_path")
        entrypoint = raw.get("entrypoint")
        raw_args = raw.get("args", [])
        expect_error = bool(raw.get("expect_error", False))
        metadata = {
            key: value
            for key, value in raw.items()
            if key
            not in {"name", "lua_source", "lua_path", "entrypoint", "args", "expect_error"}
        }
        definition = TestcaseDefinition(
            name=name,
            lua_source=str(lua_source) if lua_source is not None else None,
            lua_path=Path(str(lua_path)) if lua_path else None,
            entrypoint=str(entrypoint) if entrypoint else None,
            args=list(raw_args)
            if isinstance(raw_args, Sequence) and not isinstance(raw_args, (str, bytes))
            else [raw_args],
            expect_error=expect_error,
            metadata=metadata,
        )
        if lua_path is not None:
            if not isinstance(lua_path, str):
                raise ResolveWithTestcasesError(
                    f"testcase '{name}' expected 'lua_path' to be a string"
                )
            _validate_local_reference(lua_path)
        definitions.append(definition)

    return definitions, bootstrap_source


def resolve_with_testcases(
    testcases: Sequence[TestcaseDefinition],
    *,
    bootstrap_source: Optional[str] = None,
    base_dir: Optional[Path] = None,
) -> ResolveSummary:
    """Execute the provided testcases and collect observations."""

    base_dir = base_dir or Path.cwd()
    started_at = time.time()
    observations: List[TestcaseObservation] = []
    for testcase in testcases:
        LOGGER.info("Executing testcase '%s'", testcase.name)
        observation = execute_testcase(
            testcase,
            bootstrap=bootstrap_source,
            base_dir=base_dir,
        )
        observations.append(observation)
    completed_at = time.time()
    return ResolveSummary(
        bootstrap=bootstrap_source,
        observations=observations,
        started_at=started_at,
        completed_at=completed_at,
    )


def write_summary(summary: ResolveSummary, path: Path) -> None:
    """Serialise the summary to JSON for downstream tooling."""

    payload = {
        "bootstrap_present": summary.bootstrap is not None,
        "started_at": summary.started_at,
        "completed_at": summary.completed_at,
        "elapsed_seconds": summary.elapsed_seconds,
        "observations": [
            {
                "name": obs.name,
                "success": obs.success,
                "duration_seconds": obs.duration_seconds,
                "returns": obs.returns,
                "error": obs.error,
                "logs": obs.logs,
                "metadata": obs.metadata,
            }
            for obs in summary.observations
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _confirm_execution(testcases: Sequence[TestcaseDefinition], *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print("About to execute the following testcases in a sandbox:")
    for case in testcases:
        location = case.lua_path or "inline source"
        print(f"  - {case.name} (source: {location})")
    answer = input("Proceed? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("testcase_file", type=Path, help="Path to a JSON file describing testcases")
    parser.add_argument(
        "--bootstrap",
        type=Path,
        help="Optional Lua snippet executed before each testcase (local file only)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out/testcases/observations.json"),
        help="Path to write the testcase observation JSON report",
    )
    parser.add_argument(
        "--assume-yes",
        action="store_true",
        help="Skip the interactive confirmation prompt",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Configure logging verbosity",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level))

    try:
        testcases, bootstrap_from_file = load_testcases(args.testcase_file)
    except ResolveWithTestcasesError as exc:
        LOGGER.error("%s", exc)
        return 1

    if not testcases:
        LOGGER.warning("No testcases supplied – nothing to do")
        return 0

    if not _confirm_execution(testcases, assume_yes=args.assume_yes):
        LOGGER.info("User declined to execute testcases")
        return 0

    bootstrap_source: Optional[str] = bootstrap_from_file
    if args.bootstrap:
        _validate_local_reference(str(args.bootstrap))
        bootstrap_path = args.bootstrap if args.bootstrap.is_absolute() else args.bootstrap.resolve()
        if not bootstrap_path.exists():
            LOGGER.error("Bootstrap snippet not found: %s", bootstrap_path)
            return 1
        bootstrap_source = bootstrap_path.read_text(encoding="utf-8")

    try:
        summary = resolve_with_testcases(
            testcases,
            bootstrap_source=bootstrap_source,
            base_dir=args.testcase_file.parent,
        )
    except ResolveWithTestcasesError as exc:
        LOGGER.error("%s", exc)
        return 1

    write_summary(summary, args.output)
    LOGGER.info("Wrote testcase observations to %s", args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
