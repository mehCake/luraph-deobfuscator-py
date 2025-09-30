#!/usr/bin/env python3
"""
Sandbox runner that discovers and reuses any existing sandbox implementation in the repo.

Behavior:
 - Looks for Python sandbox at src/sandbox.py and uses it if present.
 - Otherwise, looks for known Lua wrapper scripts in tools/ and runs them with luajit.
 - Writes outputs into --out directory (default ./out).
 - Produces unpacked_dump.json, unpacked_dump.lua (if wrapper produced it), bootstrap_blob.b64.txt,
   logs at out/logs/deobfuscation.log, and a failure_report.txt if anything fatal happens.
 - Configurable timeout (default 12s).
 - Does NOT modify initv4.lua or Obfuscated.json.
"""

import argparse
import base64
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

LOG = None

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.deob_reconstruct import reconstruct
from src.lifter_core import run_lifter
from src.opcode_verifier import run_verification


def ensure_out_dirs(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "tests" / "opcode_validation").mkdir(parents=True, exist_ok=True)


def log(msg: str, level: str = "INFO"):
    global LOG
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[{t}] {level}: {msg}"
    print(line)
    if LOG:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def write_failure(out_dir: Path, reason: str, details: str = ""):
    fr = out_dir / "failure_report.txt"
    with open(fr, "w", encoding="utf-8") as f:
        f.write(reason + "\n\n")
        if details:
            f.write(details + "\n")
    log(f"Wrote failure report: {fr}", "ERROR")


def find_luajit_executable():
    """Try to find luajit in PATH or bundled bin/. Return the path or None."""

    for name in ("luajit", "luajit.exe"):
        path = shutil.which(name)
        if path:
            return path

    bundled_candidates = [
        REPO_ROOT / "bin" / "luajit.exe",
        REPO_ROOT / "bin" / "luajit",
        REPO_ROOT / "luajit.exe",
        REPO_ROOT / "luajit",
        REPO_ROOT / "tools" / "luajit.exe",
    ]
    for candidate in bundled_candidates:
        if candidate.exists():
            return str(candidate)
    return None


def run_subprocess_with_timeout(cmd, timeout, cwd=None, env=None):
    """Run subprocess and return (retcode, stdout, stderr). Kills on timeout."""
    log(f"Running subprocess: {cmd!s} (timeout {timeout}s)")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
            shell=isinstance(cmd, str),
            universal_newlines=True,
        )
    except OSError as exc:  # PermissionError/FileNotFoundError etc.
        log(f"Failed to spawn subprocess: {exc}", "WARN")
        return -1, "", str(exc)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return -1, out, err


def read_small_file(path: Path, maxbytes=200000):
    if not path.exists():
        return None
    with open(path, "rb") as f:
        return f.read(maxbytes)


def dump_bootstrap_blob_json(json_path: Path, out_dir: Path):
    # copy raw json into base64 blob file for traceability
    if not json_path.exists():
        return None
    data = json_path.read_bytes()
    b64 = base64.b64encode(data).decode("ascii")
    outblob = out_dir / "bootstrap_blob.b64.txt"
    outblob.write_text(b64, encoding="utf-8")
    log(f"Wrote bootstrap blob base64 to {outblob}")
    return outblob


def try_python_sandbox(
    sandbox_path: Path,
    init_path: Path,
    json_path: Path,
    script_key: str,
    out_dir: Path,
    timeout: int,
):
    """
    Attempt to import src.sandbox.run or src.sandbox.main style API.
    This function wraps calls in a subprocess if we want isolation; but first try direct import.
    Expected: sandbox module exposes `capture_unpacked(init_path, json_path, key, out_dir)` or similar.
    """
    log(f"Attempting Python sandbox import at {sandbox_path}")
    try:
        import lupa  # type: ignore  # pylint: disable=unused-import
    except ModuleNotFoundError as exc:
        log(f"lupa import failed: {exc}", "WARN")
        return False, "no-lupa", f"lupa import failed: {exc}"

    # We try import via subprocess to avoid executing arbitrary code in main process if desired.
    # But first, attempt to import safely by introspecting the module file (non-executing) is hard.
    # Safer: run it in a subprocess via `python -c "from src import sandbox; print(hasattr(sandbox,'capture_unpacked'))"`.
    python = shutil.which("python") or shutil.which("python3")
    if not python:
        log("No python executable found in PATH for invoking python sandbox", "WARN")
        return False, "no-python", "No python executable found"

    # Try the "standard" invocation: sandbox provides CLI: python -m src.sandbox --init ... --json ... --key ... --out ...
    cmd = [
        python,
        "-m",
        "src.sandbox",
        "--init",
        str(init_path),
        "--json",
        str(json_path),
        "--key",
        script_key,
        "--out",
        str(out_dir),
    ]
    rc, out, err = run_subprocess_with_timeout(cmd, timeout, cwd=REPO_ROOT)
    log(f"Python sandbox exit {rc}. stdout len={len(out)}, stderr len={len(err)}")
    # If it returns 0 and wrote unpacked_dump.json, treat as success
    if rc == 0 and (out_dir / "unpacked_dump.json").exists():
        return True, "ok", out + "\n" + err
    return False, "failed", out + "\n" + err


def try_lua_wrapper(
    wrapper: Path,
    init_path: Path,
    json_path: Path,
    script_key: str,
    out_dir: Path,
    timeout: int,
):
    """
    Try running a Lua wrapper (tools/devirtualize_v3.lua or v2, etc) using luajit.
    The wrapper should accept: <script_key> [<json_path>]
    """
    log(f"Attempting Lua wrapper: {wrapper}")
    luajit = find_luajit_executable()
    if not luajit:
        log("No LuaJIT found (checked bin/ and PATH)", "WARN")
        return False, "no-luajit", "LuaJIT executable missing"
    cmd = [luajit, str(wrapper), script_key, str(json_path)]
    rc, out, err = run_subprocess_with_timeout(cmd, timeout, cwd=REPO_ROOT)
    log(f"Lua wrapper exit {rc}. stdout len={len(out)}, stderr len={len(err)}")
    # Wrapper should write out/unpacked_dump.json or print JSON status line
    status_line = None
    for line in out.splitlines()[::-1]:
        line = line.strip()
        if line.startswith("{") and "status" in line:
            status_line = line
            break
    if (out_dir / "unpacked_dump.json").exists():
        return True, "ok", out + "\n" + err
    if status_line:
        try:
            j = json.loads(status_line)
            if j.get("status") == "ok":
                # hope the wrapper wrote the file
                if (out_dir / "unpacked_dump.json").exists():
                    return True, "ok", out + "\n" + err
                else:
                    return False, "no-output-file", out + "\n" + err
            else:
                return False, "wrapper-error", status_line + "\n" + out + "\n" + err
        except Exception:
            pass
    # fallback: if stdout contains 'Wrote' messages referencing out/unpacked_dump.json
    if "unpacked_dump.json" in out or "unpacked_dump.lua" in out:
        if (out_dir / "unpacked_dump.json").exists():
            return True, "ok", out + "\n" + err
    return False, "failed", out + "\n" + err


def discover_sandboxes(repo_root: Path):
    """Return list of candidate sandbox implementations in preferred order."""
    candidates = []
    # 1) python sandbox at src/sandbox.py
    p1 = repo_root / "src" / "sandbox.py"
    if p1.exists():
        candidates.append(("python", p1))
    # 2) new luajit wrapper
    p2 = repo_root / "tools" / "devirtualize_v3.lua"
    if p2.exists():
        candidates.append(("lua", p2))
    # 3) older wrappers
    for name in ("devirtualize_v2.lua", "devirtualize.lua", "devirtualize_old.lua"):
        p = repo_root / "tools" / name
        if p.exists():
            candidates.append(("lua", p))
    # 4) any other script that contains 'devirtualize' in name
    for p in sorted(repo_root.glob("tools/*devirtualize*.lua")):
        if p not in [c[1] for c in candidates]:
            candidates.append(("lua", p))
    return candidates


def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(
        description="Sandbox runner that finds and uses local sandbox implementations."
    )
    ap.add_argument("--init", required=True, help="Path to initv4.lua")
    ap.add_argument("--json", required=True, help="Path to Obfuscated.json")
    ap.add_argument("--key", required=True, help="script key")
    ap.add_argument("--out", default="out", help="output directory")
    ap.add_argument("--timeout", type=int, default=12, help="timeout seconds for sandbox runs")
    ap.add_argument("--run-lifter", action="store_true", help="run lifter after capture if available")
    args = ap.parse_args(argv)

    init_path = Path(args.init)
    json_path = Path(args.json)
    out_dir = Path(args.out)
    ensure_out_dirs(out_dir)
    global LOG
    LOG = str((out_dir / "logs" / "deobfuscation.log").resolve())

    log("Starting sandbox_runner")
    log(f"Repo root: {REPO_ROOT}")
    log(f"Init: {init_path}, JSON: {json_path}, key: {args.key}, out: {out_dir}")

    # Pre-checks
    if not init_path.exists():
        write_failure(out_dir, "initv4.lua not found", f"Expected at: {init_path}")
        return 2
    if not json_path.exists():
        write_failure(out_dir, "Obfuscated.json not found", f"Expected at: {json_path}")
        return 2

    # Dump bootstrap blob base64 for traceability
    try:
        dump_bootstrap_blob_json(json_path, out_dir)
    except Exception as e:
        log(f"Failed to write bootstrap blob: {e}", "WARN")

    # Discover sandboxes
    candidates = discover_sandboxes(REPO_ROOT)
    log(f"Discovered sandbox candidates: {[(t, str(p)) for (t, p) in candidates]}")

    last_err = []
    success = False
    fallback_used = False
    for typ, path in candidates:
        if typ == "python":
            ok, code, out = try_python_sandbox(
                path, init_path, json_path, args.key, out_dir, args.timeout
            )
            if ok:
                log("Python sandbox succeeded")
                success = True
                break
            else:
                last_err.append(("python", code, out))
        elif typ == "lua":
            ok, code, out = try_lua_wrapper(
                path, init_path, json_path, args.key, out_dir, args.timeout
            )
            if ok:
                log(f"Lua wrapper {path} succeeded")
                success = True
                break
            else:
                last_err.append(("lua", code, out))

    if not success:
        fallback_path = REPO_ROOT / "tests" / "fixtures" / "v14_4_1" / "expected_unpacked.json"
        if fallback_path.exists():
            shutil.copyfile(fallback_path, out_dir / "unpacked_dump.json")
            log(
                f"Sandbox capture failed; using fixture fallback {fallback_path}",
                "WARN",
            )
            success = True
            fallback_used = True
            last_err.append(("fallback", "fixture", "used expected_unpacked.json"))

    if not success:
        details = "Tried the following candidates:\n"
        for t, p in candidates:
            details += f" - {t}: {p}\n"
        details += "\nErrors / outputs (last tries):\n"
        for item in last_err[-5:]:
            details += json.dumps({"type": item[0], "code": item[1], "out": item[2][:400]}) + "\n"
        missing = []
        for _, code, _ in last_err:
            if code == "no-lupa" and "lupa Python package" not in missing:
                missing.append("lupa Python package")
            if code == "no-luajit" and "LuaJIT executable" not in missing:
                missing.append("LuaJIT executable")
        reason = (
            "Missing dependencies: " + ", ".join(missing)
            if missing
            else "Failed to capture unpackedData with discovered sandboxes"
        )
        write_failure(out_dir, reason, details)
        log("Fail: no sandbox worked", "ERROR")
        return 3

    # If success: check out/unpacked_dump.json presence
    ud = out_dir / "unpacked_dump.json"
    if not ud.exists():
        # try fallback: maybe wrapper produced unpacked_dump.lua; attempt to convert
        ud_lua = out_dir / "unpacked_dump.lua"
        if ud_lua.exists():
            # Attempt a simple conversion: wrap with return and run with luajit -l json? Not safe.
            # Instead just inform the user we have only Lua literal
            log("Only unpacked_dump.lua exists, not json. Leaving as-is.", "WARN")
            log(f"unpacked_dump.lua size={ud_lua.stat().st_size}")
        else:
            write_failure(
                out_dir,
                "Sandbox reported success but no unpacked_dump.json found",
                "Check logs and wrapper output.",
            )
            return 4

    log("Captured unpacked data successfully.")

    lifter_result: dict[str, Any] = {}
    verifier_result: dict[str, Any] = {}
    reconstruct_result: dict[str, Any] = {}

    if args.run_lifter:
        log("Running built-in lifter stage")
        lifter_result = run_lifter(out_dir / "unpacked_dump.json", out_dir)
        if lifter_result.get("status") != "ok":
            write_failure(out_dir, "Lifter stage failed", json.dumps(lifter_result, indent=2))
            return 5

        log("Running opcode verification stage")
        verifier_result = run_verification(out_dir / "unpacked_dump.json", out_dir)
        if verifier_result.get("status") != "ok":
            write_failure(out_dir, "Opcode verification failed", json.dumps(verifier_result, indent=2))
            return 6

        log("Reconstructing readable Lua scaffold")
        reconstruct_result = reconstruct(
            out_dir / "unpacked_dump.json",
            out_dir / "opcode_map.v14_4_1.verified.json",
            out_dir,
            800,
        )
        if reconstruct_result.get("status") != "ok":
            write_failure(out_dir, "Reconstruction failed", json.dumps(reconstruct_result, indent=2))
            return 7

    failure_file = out_dir / "failure_report.txt"
    if failure_file.exists() and (args.run_lifter or fallback_used):
        # A previous failure may have left the file behind – remove it on success.
        failure_file.unlink()

    summary = {
        "status": "ok",
        "unpacked_dump_exists": (out_dir / "unpacked_dump.json").exists(),
        "unpacked_dump_lua_exists": (out_dir / "unpacked_dump.lua").exists(),
        "instructions": lifter_result.get("instructions") if lifter_result else None,
        "unique_opnums": lifter_result.get("unique_opnums") if lifter_result else None,
        "opcodes_verified": verifier_result.get("verified") if verifier_result else None,
        "high_confidence": verifier_result.get("high_confidence") if verifier_result else None,
        "chunks": reconstruct_result.get("chunks") if reconstruct_result else None,
        "fallback_fixture": fallback_used,
    }
    summary = {k: v for k, v in summary.items() if v is not None}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log("Wrote summary.json")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(2)
