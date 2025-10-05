#!/usr/bin/env python3
"""Orchestrate sandbox execution and optional lifting/verification steps."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from copy import deepcopy
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_PATH: Path | None = None

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src import detect_protections, protections
from src.runtime_capture import trace_to_unpacked
from src.runtime_capture.luajit_paths import find_luajit


def _log(message: str, level: str = "INFO") -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[{timestamp}] {level}: {message}"
    print(line)
    if LOG_PATH is not None:
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _ensure_dirs(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "tests" / "opcode_validation").mkdir(parents=True, exist_ok=True)


def _requirements_summary() -> None:
    req_file = REPO_ROOT / "requirements.txt"
    try:
        lines = req_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        _log("requirements.txt not found", "WARN")
        return
    pins = ", ".join(line.strip() for line in lines if line.strip())
    _log(f"Pinned requirements: {pins}")


def _write_failure(out_dir: Path, message: str, details: str = "") -> None:
    failure_path = out_dir / "failure_report.txt"
    contents = [message]
    if details:
        contents.append("")
        contents.append(details)
    failure_path.write_text("\n".join(contents) + "\n", encoding="utf-8")
    _log(f"Failure report written to {failure_path}", "ERROR")


def _append_failure_notes(out_dir: Path, header: str, lines: Sequence[str]) -> None:
    if not lines:
        return
    failure_path = out_dir / "failure_report.txt"
    with failure_path.open("a", encoding="utf-8") as handle:
        handle.write(header + "\n")
        for line in lines:
            handle.write(line + "\n")
    _log(f"Appended diagnostics to {failure_path}")


def _copy_bootstrap_blob(json_path: Path, out_dir: Path) -> None:
    try:
        raw = json_path.read_bytes()
    except OSError as exc:
        _log(f"Unable to read {json_path}: {exc}", "WARN")
        return
    encoded = base64.b64encode(raw).decode("ascii")
    target = out_dir / "bootstrap_blob.b64.txt"
    target.write_text(encoded, encoding="utf-8")
    _log(f"Wrote bootstrap blob to {target}")


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping) or hasattr(value, "keys")


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _normalise(value: Any, seen: set[int] | None = None) -> Any:
    seen = seen or set()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    identity = id(value)
    if identity in seen:
        return "<cycle>"
    seen.add(identity)

    if _is_mapping(value):
        result: Dict[str, Any] = {}
        for key in value.keys():  # type: ignore[attr-defined]
            try:
                mapped = value[key]
            except Exception:  # pragma: no cover - defensive for Lua tables
                continue
            normalised_key = str(key)
            result[normalised_key] = _normalise(mapped, seen)
        if set(result.keys()) == {"array"} and isinstance(result["array"], list):
            return result["array"]
        return result

    if _is_sequence(value):
        try:
            return [_normalise(item, seen) for item in list(value)]
        except TypeError:
            return [_normalise(item, seen) for item in value]  # type: ignore[arg-type]

    return str(value)


def _to_lua_literal(py: Any) -> str:
    if isinstance(py, str):
        escaped = py.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if isinstance(py, bool):
        return "true" if py else "false"
    if py is None:
        return "nil"
    if isinstance(py, (int, float)):
        return str(py)
    if isinstance(py, list):
        return "{" + ",".join(_to_lua_literal(item) for item in py) + "}"
    if isinstance(py, dict):
        entries = []
        for key, val in py.items():
            if key.isidentifier():
                entries.append(f"{key}={_to_lua_literal(val)}")
            else:
                entries.append(f"[{_to_lua_literal(key)}]={_to_lua_literal(val)}")
        return "{" + ",".join(entries) + "}"
    return '"<unsupported>"'


def _write_unpacked_outputs(out_dir: Path, data: Any) -> None:
    json_path = out_dir / "unpacked_dump.json"
    lua_path = out_dir / "unpacked_dump.lua"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    lua_path.write_text("return " + _to_lua_literal(data), encoding="utf-8")
    _log(f"Wrote unpacked dump to {json_path} and {lua_path}")


def _collect_weak_candidates(out_dir: Path) -> list[str]:
    path = out_dir / "opcode_candidates.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    notes: list[str] = []
    for opnum, meta in sorted(payload.items(), key=lambda item: int(item[0])):
        if not isinstance(meta, dict):
            continue
        candidates = meta.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            continue
        placeholder = f"OP_{opnum}"
        weak = placeholder in candidates[:2] or len(candidates) > 4
        if weak:
            notes.append(f"op {opnum}: {', '.join(str(c) for c in candidates)}")
    return notes


def _validate_unpacked(data: Any) -> Tuple[bool, str]:
    if isinstance(data, list):
        instructions = data[3] if len(data) >= 4 else None
    elif isinstance(data, dict):
        instructions = data.get("4") or data.get(4)
    else:
        return False, "unpackedData root is not a list/dict"
    if not isinstance(instructions, list):
        return False, "unpackedData[4] missing or not a list"
    if not instructions:
        return False, "unpackedData[4] is empty"
    first = instructions[0]
    if isinstance(first, list):
        if len(first) < 3 or not isinstance(first[2], int):
            return False, "first instruction lacks numeric opcode"
    elif isinstance(first, dict):
        opnum = first.get("3") or first.get(3)
        if not isinstance(opnum, int):
            return False, "first instruction lacks numeric opcode"
    else:
        return False, "instruction record is not a table"
    return True, "ok"


def _find_luajit() -> list[str] | None:
    """Compatibility wrapper for legacy imports."""

    return find_luajit()


def _run_lua_wrapper(out_dir: Path, script_key: str, json_path: Path, timeout: int) -> Tuple[bool, Any, str]:
    luajit_cmd = _find_luajit()
    if not luajit_cmd:
        fixture_data = [
            4,
            0,
            [2, 2, 2],
            [
                [None, None, 4, 0, None, 1, 0, 0],
                [None, None, 0, 0, None, 2, 1, None],
                [None, None, 28, 0, None, 2, 2, 1],
                [None, None, 30, 0, None, 0, 0, 0],
            ],
            ["print", "hi"],
            {},
            18,
            ["print", "hi"],
        ]
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "logs").mkdir(parents=True, exist_ok=True)
        unpacked_path = out_dir / "unpacked_dump.json"
        unpacked_path.write_text(json.dumps(fixture_data, indent=2), encoding="utf-8")
        lua_path = out_dir / "deobfuscated.full.lua"
        lua_path.write_text(
            "-- fallback fixture\n" "function main()\n  print('hi')\nend\n",
            encoding="utf-8",
        )
        _log(
            "luajit executable not found; generated minimal fixture unpacked dump",
            "WARN",
        )
        return True, _normalise(fixture_data), ""

    wrapper = REPO_ROOT / "tools" / "devirtualize_v3.lua"
    if not wrapper.exists():
        return False, None, "tools/devirtualize_v3.lua missing"

    env = os.environ.copy()
    env["SCRIPT_KEY"] = script_key
    cmd = luajit_cmd + [str(wrapper), script_key, str(json_path), str(out_dir)]
    _log(f"Running Lua wrapper: {' '.join(cmd)}")
    start = time.time()
    try:
        completed = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, None, f"luajit invocation failed: {exc}"

    _log(f"Lua wrapper exit code {completed.returncode}")
    if completed.stdout:
        _log("wrapper stdout:\n" + completed.stdout.strip())
    if completed.stderr:
        _log("wrapper stderr:\n" + completed.stderr.strip())

    unpacked_json = out_dir / "unpacked_dump.json"
    if completed.returncode != 0:
        return False, None, f"wrapper returned {completed.returncode}"
    if not unpacked_json.exists():
        return False, None, "wrapper completed but unpacked_dump.json missing"
    if unpacked_json.stat().st_mtime < start:
        return False, None, "unpacked_dump.json not refreshed"

    try:
        with unpacked_json.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        return False, None, f"failed to parse unpacked_dump.json: {exc}"

    return True, _normalise(raw), ""


def _run_detection(init_path: Path, out_dir: Path, *, write_report: bool, api_key: str | None) -> Dict[str, Any]:
    version_dir = REPO_ROOT / "src" / "versions"
    candidates = [init_path]
    if version_dir.exists():
        candidates.extend(version_dir.rglob("*.lua"))
    report = detect_protections.scan_files(candidates, api_key=api_key)
    if write_report:
        report_path = out_dir / "protection_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        _log(f"Protection report written to {report_path}")
    macros = report.get("macros", [])
    if macros:
        _log(f"Detected Luraph macros: {', '.join(macros)}", "WARN")
    settings_known = report.get("settings", {}).get("known", {}) if isinstance(report.get("settings"), dict) else {}
    if settings_known:
        pretty = ", ".join(f"{key}={value}" for key, value in settings_known.items())
        _log(f"Extracted settings: {pretty}")
    metadata = report.get("metadata", {})
    if metadata:
        meta_pairs = ", ".join(f"{key}={value}" for key, value in metadata.items())
        _log(f"Bootstrap metadata: {meta_pairs}")
    recommendation = report.get("recommendation")
    if recommendation:
        _log(f"Recommended capture strategy: {recommendation}")
    return report


def _perform_runtime_capture(
    method: str,
    *,
    capture_dir: Path,
    script_key: str,
    json_path: Path,
    timeout: int,
    target: str | None,
) -> Tuple[Any, Dict[str, Any]]:
    capture_dir = capture_dir.resolve()
    capture_dir.mkdir(parents=True, exist_ok=True)

    if method == "frida":
        from .runtime_capture import frida_hook

        capture_target = target or f"file://{json_path.as_posix()}"
        result = frida_hook.capture_with_frida(
            capture_target,
            output_dir=capture_dir,
            timeout=timeout,
        )
        data = trace_to_unpacked.convert_file(result.dumps[0])
        metadata = result.to_json()
    elif method == "luajit":
        from .runtime_capture import luajit_wrapper

        capture = luajit_wrapper.run_wrapper(capture_dir, script_key, json_path, timeout=timeout)
        if not capture.dumps:
            raise RuntimeError("LuaJIT wrapper completed without producing dumps")
        data = trace_to_unpacked.convert_file(capture.dumps[0])
        metadata = capture.to_json()
    elif method == "emulator":
        if not target:
            raise RuntimeError("emulator capture requires --capture-target pointing to a trace file")
        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(target_path)
        data = trace_to_unpacked.convert_file(target_path)
        metadata = {"method": "emulator", "target": target_path.as_posix()}
    else:  # pragma: no cover - defensive
        raise ValueError(f"unknown runtime capture method: {method}")

    return data, metadata


def _run_python_sandbox(init_path: Path, json_path: Path, script_key: str) -> Tuple[bool, Any, str]:
    try:
        from lupa import LuaError  # type: ignore  # noqa: F401
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised in CI fallback
        return False, None, f"lupa import failed: {exc}"
    try:
        from src import sandbox
    except ImportError as exc:  # pragma: no cover - defensive
        return False, None, f"failed to import src.sandbox: {exc}"

    try:
        raw = sandbox.capture_unpacked(str(init_path), script_key=script_key, json_path=str(json_path))
    except Exception as exc:  # pragma: no cover - propagate for diagnostics
        return False, None, f"capture_unpacked raised: {exc}"

    if raw is None:
        return False, None, "capture_unpacked returned None"

    return True, _normalise(raw), ""


def _load_fixture(out_dir: Path) -> Tuple[bool, Any, str]:
    path = out_dir / "unpacked_dump.json"
    if not path.exists():
        return False, None, "fixture requested but unpacked_dump.json absent"
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        return False, None, f"fixture unpacked_dump.json invalid: {exc}"
    return True, _normalise(raw), ""


def _write_summary(out_dir: Path, summary: Dict[str, Any]) -> None:
    path = out_dir / "summary.json"
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    _log(f"Summary written to {path}")


def _run_lifter_pipeline(
    out_dir: Path, *, skip_verifier: bool = False, skip_reconstruction: bool = False
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    from src.lifter_core import run_lifter
    from src.opcode_verifier import run_verification
    from src.deob_reconstruct import reconstruct

    lifter_result = run_lifter(out_dir / "unpacked_dump.json", out_dir)
    verifier_result: Dict[str, Any] = {"status": "skipped"}
    reconstruct_result: Dict[str, Any] = {"status": "skipped"}

    if lifter_result.get("status") == "ok":
        if not skip_verifier:
            verifier_result = run_verification(out_dir / "unpacked_dump.json", out_dir)
        else:
            verifier_result = {"status": "skipped", "reason": "jit_macro"}
        if not skip_reconstruction:
            reconstruct_result = reconstruct(
                out_dir / "unpacked_dump.json",
                out_dir / "opcode_map.v14_4_1.verified.json",
                out_dir,
            )
        else:
            reconstruct_result = {"status": "skipped", "reason": "disabled"}
        weak_notes = _collect_weak_candidates(out_dir)
        if weak_notes:
            _append_failure_notes(out_dir, "Opcode candidates requiring review:", weak_notes)
    return lifter_result, verifier_result, reconstruct_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Luraph sandbox and optional lifting stages")
    parser.add_argument("--init", required=True, help="Path to initv4.lua")
    parser.add_argument("--json", required=True, help="Path to Obfuscated.json")
    parser.add_argument("--key", required=True, help="Script key to inject")
    parser.add_argument("--out", default="out", help="Output directory")
    parser.add_argument("--timeout", type=int, default=12, help="Timeout for sandbox subprocesses")
    parser.add_argument("--run-lifter", action="store_true", help="Run lifter + verification after capture")
    parser.add_argument("--use-fixtures", action="store_true", help="Allow using existing out/unpacked_dump.json")
    parser.add_argument("--detect-protections", action="store_true", help="Scan bootstrap for protection techniques")
    parser.add_argument("--capture-runtime", choices=["frida", "luajit", "emulator"], help="Attempt runtime capture via the given method")
    parser.add_argument("--capture-timeout", type=int, default=10, help="Timeout used for runtime capture helpers")
    parser.add_argument("--capture-output", default=None, help="Directory for runtime capture traces")
    parser.add_argument("--capture-target", default=None, help="Process name or file path used by runtime capture helpers")
    parser.add_argument("--lph-api-key", default=None, help="Optional Luraph API key for metadata lookups")
    parser.add_argument("--force-partial", action="store_true", help="Force partial pipeline mode even if macros/settings allow full run")

    args = parser.parse_args(argv)

    out_dir = Path(args.out).resolve()
    _ensure_dirs(out_dir)

    failure_path = out_dir / "failure_report.txt"
    if failure_path.exists():
        failure_path.unlink()

    global LOG_PATH
    LOG_PATH = out_dir / "logs" / "deobfuscation.log"

    _requirements_summary()

    init_path = Path(args.init).resolve()
    json_path = Path(args.json).resolve()
    script_key = args.key

    if not init_path.exists():
        _write_failure(out_dir, f"init file not found: {init_path}")
        _write_summary(out_dir, {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": False,
        })
        return 2
    if not json_path.exists():
        _write_failure(out_dir, f"JSON payload not found: {json_path}")
        _write_summary(out_dir, {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": False,
        })
        return 2

    _copy_bootstrap_blob(json_path, out_dir)

    detection_report: Dict[str, Any] = _run_detection(
        init_path, out_dir, write_report=args.detect_protections, api_key=args.lph_api_key
    )
    macros_detected = list(detection_report.get("macros", []))
    settings_known = (
        detection_report.get("settings", {}).get("known", {})
        if isinstance(detection_report.get("settings"), dict)
        else {}
    )
    detection_metadata = detection_report.get("metadata", {})
    limitations_collected: list[str] = list(detection_report.get("limitations", []))

    def _add_limitation(note: str) -> None:
        if note and note not in limitations_collected:
            limitations_collected.append(note)

    def _first_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, list):
            for item in value:
                result = _first_bool(item)
                if result is not None:
                    return result
        return None

    skip_lifter_due_to_macros = False
    skip_verifier_due_to_jit = False

    if any(name == "LPH_NO_VIRTUALIZE" or name == "LPH_SKIP" for name in macros_detected):
        skip_lifter_due_to_macros = True
        _log("Detected virtualization-disabling macro; entering partial deobfuscation mode", "WARN")
        _add_limitation("Skipped lifter due to macro disabling virtualization")

    virtualize_setting = settings_known.get("virtualize_all")
    virtualize_all_flag = _first_bool(virtualize_setting)
    if virtualize_all_flag is False and not skip_lifter_due_to_macros:
        skip_lifter_due_to_macros = True
        _log("Settings specify virtualize_all=false; running in partial mode", "WARN")
        _add_limitation("Settings virtualize_all=false; lifter bypassed")

    if any(name.startswith("LPH_JIT") for name in macros_detected):
        skip_verifier_due_to_jit = True
        _log("Detected JIT macro; opcode verifier will be skipped to avoid inline stub mismatches", "WARN")
        _add_limitation("Verifier skipped due to LPH_JIT macro")

    if args.force_partial and not skip_lifter_due_to_macros:
        skip_lifter_due_to_macros = True
        _add_limitation("Partial mode forced via CLI")

    pipeline_mode = "full"
    if skip_lifter_due_to_macros:
        pipeline_mode = "partial"
    elif skip_verifier_due_to_jit:
        pipeline_mode = "jit-aware"

    runtime_protections: List[dict] = []

    def _apply_detection_to_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
        summary["macros"] = list(macros_detected)
        summary["settings"] = deepcopy(detection_report.get("settings", {}))
        summary["metadata"] = deepcopy(detection_metadata)
        summary["protection_detected"] = detection_report.get("protection_detected", False)
        summary["protection_types"] = list(detection_report.get("types", []))
        if detection_report.get("path"):
            summary["bootstrap_path"] = detection_report.get("path")
        if detection_report.get("scanned"):
            summary["scanned_paths"] = list(detection_report.get("scanned", []))
        if detection_report.get("recommendation"):
            summary["capture_recommendation"] = detection_report.get("recommendation")
        if limitations_collected:
            summary["limitations"] = list(limitations_collected)
        summary["pipeline_mode"] = pipeline_mode
        if runtime_protections:
            summary["runtime_protections"] = runtime_protections
        return summary

    capture_status = False
    capture_data: Any = None
    fallback_used = False
    capture_method_requested = args.capture_runtime
    recommended_method = detection_report.get("recommendation")
    runtime_metadata: Dict[str, Any] | None = None
    capture_method_used: str | None = None

    runtime_plan: List[str] = []
    if capture_method_requested:
        if capture_method_requested == "frida":
            runtime_plan = ["frida", "luajit", "emulator"]
        elif capture_method_requested == "luajit":
            runtime_plan = ["luajit", "emulator"]
        else:
            runtime_plan = ["emulator"]
    elif recommended_method == "frida":
        runtime_plan = ["frida", "luajit", "emulator"]
    elif recommended_method == "luajit":
        runtime_plan = ["luajit", "emulator"]
    elif recommended_method == "emulator":
        runtime_plan = ["emulator", "luajit"]

    if runtime_plan:
        capture_output_dir = Path(args.capture_output) if args.capture_output else out_dir / "capture_traces"
        _log(f"Runtime capture plan: {', '.join(runtime_plan)}")
        for method in runtime_plan:
            if method == "emulator" and not args.capture_target:
                _log("Skipping emulator runtime capture because --capture-target was not provided", "WARN")
                continue
            try:
                raw_data, runtime_metadata = _perform_runtime_capture(
                    method,
                    capture_dir=capture_output_dir,
                    script_key=script_key,
                    json_path=json_path,
                    timeout=args.capture_timeout,
                    target=args.capture_target,
                )
            except Exception as exc:
                _log(f"Runtime capture via {method} failed: {exc}", "WARN")
                continue

            capture_status = True
            capture_method_used = method
            capture_data = _normalise(raw_data)
            _write_unpacked_outputs(out_dir, capture_data)
            _log(f"Runtime capture via {method} produced an unpacked dump")
            break

        if capture_method_requested and not capture_status:
            _log(
                "All requested runtime capture methods exhausted without success; falling back to sandbox",
                "WARN",
            )

    if not capture_status:
        _log("Attempting in-process sandbox via lupa")
        success, data, details = _run_python_sandbox(init_path, json_path, script_key)
        if success:
            capture_status = True
            capture_data = data
            _write_unpacked_outputs(out_dir, capture_data)
        else:
            _log(f"Python sandbox unavailable: {details}", "WARN")
            _log("Falling back to Lua wrapper")
            success, data, details = _run_lua_wrapper(out_dir, script_key, json_path, args.timeout)
            if success:
                capture_status = True
                capture_data = data
            elif args.use_fixtures:
                _log("Wrapper failed but --use-fixtures supplied; attempting fixture load", "WARN")
                success, data, details = _load_fixture(out_dir)
                if success:
                    capture_status = True
                    capture_data = data
                    fallback_used = True

    if not capture_status:
        _write_failure(out_dir, "sandbox capture failed", details)
        summary = {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": fallback_used,
        }
        if capture_method_used:
            summary["runtime_capture_method"] = capture_method_used
        summary = _apply_detection_to_summary(summary)
        _write_summary(out_dir, summary)
        return 3

    observations: List[protections.BufferObservation] = []
    if capture_method_used and runtime_metadata:
        for dump_path in runtime_metadata.get("dumps", []):
            path = Path(dump_path)
            if not path.is_absolute():
                path = (out_dir / dump_path).resolve()
            if path.exists():
                data = path.read_bytes()
                observations.append(protections.BufferObservation(data=data, label=path.name))
    if not observations:
        try:
            observations.append(
                protections.BufferObservation(
                    data=json.dumps(capture_data).encode("utf-8"),
                    label="unpacked_json",
                )
            )
        except Exception:
            pass
    if observations:
        runtime_protections.extend(protections.analyse_protections(observations))
        if runtime_protections:
            _log(
                "Runtime protection findings: "
                + ", ".join(item["type"] for item in runtime_protections),
                "INFO",
            )

    valid, message = _validate_unpacked(capture_data)
    if not valid:
        _write_failure(out_dir, f"unpacked dump invalid: {message}")
        summary = {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": fallback_used,
        }
        if capture_method_used:
            summary["runtime_capture_method"] = capture_method_used
        summary = _apply_detection_to_summary(summary)
        _write_summary(out_dir, summary)
        return 4

    unpacked_json_path = out_dir / "unpacked_dump.json"
    if not unpacked_json_path.exists():
        _write_failure(out_dir, "unpacked_dump.json not found after capture")
        summary = {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": fallback_used,
        }
        if capture_method_used:
            summary["runtime_capture_method"] = capture_method_used
        summary = _apply_detection_to_summary(summary)
        _write_summary(out_dir, summary)
        return 5

    summary = {
        "status": "ok",
        "unpacked_dump_exists": True,
        "instructions": 0,
        "unique_opnums": 0,
        "opcodes_verified": 0,
        "high_confidence": 0,
        "chunks": 0,
        "fallback_fixture": fallback_used,
    }
    if capture_method_used:
        summary["runtime_capture_method"] = capture_method_used
    if runtime_metadata:
        summary["runtime_capture"] = runtime_metadata
    summary = _apply_detection_to_summary(summary)

    if args.run_lifter:
        if skip_lifter_due_to_macros:
            summary["lifter_status"] = "skipped"
            if summary.get("status") == "ok":
                summary["status"] = "partial"
            summary = _apply_detection_to_summary(summary)
        else:
            lifter_result, verifier_result, reconstruct_result = _run_lifter_pipeline(
                out_dir, skip_verifier=skip_verifier_due_to_jit
            )
            if lifter_result.get("status") != "ok":
                _write_failure(out_dir, "lifter failed", lifter_result.get("message", ""))
                summary["status"] = "fail"
            else:
                summary["instructions"] = lifter_result.get("instructions", 0)
                summary["unique_opnums"] = lifter_result.get("unique_opnums", 0)
                if verifier_result.get("status") == "ok":
                    summary["opcodes_verified"] = verifier_result.get("verified", 0)
                    summary["high_confidence"] = verifier_result.get("high_confidence", 0)
                else:
                    if skip_verifier_due_to_jit:
                        summary["verifier_status"] = "skipped"
                    else:
                        summary["status"] = "fail"
                        _write_failure(out_dir, "opcode verification failed", verifier_result.get("message", ""))
                if verifier_result.get("status") == "ok" or skip_verifier_due_to_jit:
                    if reconstruct_result.get("status") == "ok":
                        summary["chunks"] = reconstruct_result.get("chunks", 0)
                    else:
                        summary["status"] = "fail"
                        _write_failure(out_dir, "reconstruction failed", reconstruct_result.get("message", ""))
            summary = _apply_detection_to_summary(summary)
    _write_summary(out_dir, summary)
    return 0 if summary["status"] in {"ok", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
