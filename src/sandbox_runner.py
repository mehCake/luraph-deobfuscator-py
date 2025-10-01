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
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Dict, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_PATH: Path | None = None

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


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
    candidates = [REPO_ROOT / "bin" / "luajit.exe", shutil.which("luajit"), REPO_ROOT / "bin" / "luajit"]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists():
            return [str(path)]
    return None


def _run_lua_wrapper(out_dir: Path, script_key: str, json_path: Path, timeout: int) -> Tuple[bool, Any, str]:
    luajit_cmd = _find_luajit()
    if not luajit_cmd:
        return False, None, "luajit executable not found"

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


def _run_lifter_pipeline(out_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    from src.lifter_core import run_lifter
    from src.opcode_verifier import run_verification
    from src.deob_reconstruct import reconstruct

    lifter_result = run_lifter(out_dir / "unpacked_dump.json", out_dir)
    verifier_result: Dict[str, Any] = {"status": "skipped"}
    reconstruct_result: Dict[str, Any] = {"status": "skipped"}

    if lifter_result.get("status") == "ok":
        verifier_result = run_verification(out_dir / "unpacked_dump.json", out_dir)
        reconstruct_result = reconstruct(
            out_dir / "unpacked_dump.json",
            out_dir / "opcode_map.v14_4_1.verified.json",
            out_dir,
        )
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

    capture_status = False
    capture_data: Any = None
    fallback_used = False

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
        else:
            if args.use_fixtures:
                _log("Wrapper failed but --use-fixtures supplied; attempting fixture load", "WARN")
                success, data, details = _load_fixture(out_dir)
                if success:
                    capture_status = True
                    capture_data = data
                    fallback_used = True
            if not capture_status:
                _write_failure(out_dir, "sandbox capture failed", details)
                _write_summary(out_dir, {
                    "status": "fail",
                    "unpacked_dump_exists": False,
                    "instructions": 0,
                    "unique_opnums": 0,
                    "opcodes_verified": 0,
                    "high_confidence": 0,
                    "chunks": 0,
                    "fallback_fixture": fallback_used,
                })
                return 3

    valid, message = _validate_unpacked(capture_data)
    if not valid:
        _write_failure(out_dir, f"unpacked dump invalid: {message}")
        _write_summary(out_dir, {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": fallback_used,
        })
        return 4

    unpacked_json_path = out_dir / "unpacked_dump.json"
    if not unpacked_json_path.exists():
        _write_failure(out_dir, "unpacked_dump.json not found after capture")
        _write_summary(out_dir, {
            "status": "fail",
            "unpacked_dump_exists": False,
            "instructions": 0,
            "unique_opnums": 0,
            "opcodes_verified": 0,
            "high_confidence": 0,
            "chunks": 0,
            "fallback_fixture": fallback_used,
        })
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

    if args.run_lifter:
        lifter_result, verifier_result, reconstruct_result = _run_lifter_pipeline(out_dir)
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
                summary["status"] = "fail"
                _write_failure(out_dir, "opcode verification failed", verifier_result.get("message", ""))
            if reconstruct_result.get("status") == "ok":
                summary["chunks"] = reconstruct_result.get("chunks", 0)
            else:
                summary["status"] = "fail"
                _write_failure(out_dir, "reconstruction failed", reconstruct_result.get("message", ""))
    _write_summary(out_dir, summary)
    return 0 if summary["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
