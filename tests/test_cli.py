import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

try:  # pragma: no cover - guard against optional modules missing in this fork
    from src import main as cli_main  # type: ignore
    from src.versions.initv4 import InitV4Bootstrap  # type: ignore
    from src.versions.luraph_v14_4_1 import (  # type: ignore
        _BASE_OPCODE_TABLE,
        _apply_script_key_transform,
        _encode_base91,
        decode_blob,
    )
except Exception as exc:  # pragma: no cover
    pytest.skip(f"legacy CLI scaffolding unavailable: {exc}", allow_module_level=True)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = PROJECT_ROOT / "tests" / "golden"
V1441_SOURCE = PROJECT_ROOT / "examples" / "v1441_hello.lua"
V1441_GOLDEN = GOLDEN_DIR / "v1441_hello.lua.out"
INITV4_STUB = PROJECT_ROOT / "tests" / "fixtures" / "initv4_stub" / "initv4.lua"
COMPLEX_SOURCE = PROJECT_ROOT / "examples" / "complex_obfuscated"
SCRIPT_KEY = "x5elqj5j4ibv9z3329g7b"
DEFAULT_CONFIRM_ARGS = ("--confirm-ownership", "--confirm-voluntary-key")


def _prepare_v1441_source(
    tmp_path: Path, *, literal_key: bool = False, strip_script: bool = False
) -> Path:
    text = V1441_SOURCE.read_text(encoding="utf-8")
    if strip_script:
        marker = 'local payload = "'
        if marker in text:
            blob = text.split(marker, 1)[1].split('"', 1)[0]
            raw = decode_blob(blob, SCRIPT_KEY)
            try:
                data = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict) and data.pop("script", None) is not None:
                serialised = json.dumps(data, separators=(",", ":"))
                masked = _apply_script_key_transform(
                    serialised.encode("utf-8"), SCRIPT_KEY.encode("utf-8")
                )
                new_blob = _encode_base91(masked)
                text = text.replace(blob, new_blob)
    if literal_key:
        text = text.replace("getgenv().script_key", f'"{SCRIPT_KEY}"')
    target = tmp_path / V1441_SOURCE.name
    target.write_text(text, encoding="utf-8")
    return target


def _prepare_bootstrapper(tmp_path: Path) -> Path:
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    (stub_dir / "initv4.lua").write_text(INITV4_STUB.read_text(encoding="utf-8"), encoding="utf-8")
    return stub_dir


def _prepare_complex_json(tmp_path: Path) -> Path:
    target = tmp_path / "complex.json"
    target.write_text(COMPLEX_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _run_cli(
    target: Path,
    workdir: Path,
    *extra: str,
    check: bool = True,
    include_confirmation: bool = True,
) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PROJECT_ROOT / "main.py"), str(target)]
    if include_confirmation:
        cmd.extend(DEFAULT_CONFIRM_ARGS)
    cmd.extend(extra)
    return subprocess.run(cmd, cwd=workdir, check=check, capture_output=True)


def test_cli_emits_output_for_single_file(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path)

    output_lua = target.with_name(f"{target.stem}_deob.lua")
    output_json = target.with_name(f"{target.stem}_deob.json")
    assert output_lua.exists()
    assert output_lua.read_text().strip()
    assert output_json.exists()
    data = json.loads(output_json.read_text())
    assert data["output"].strip()


def test_cli_requires_usage_confirmation(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    proc = _run_cli(target, tmp_path, include_confirmation=False, check=False)
    assert proc.returncode == 2


def test_cli_accepts_directory(tmp_path):
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    sources = [
        PROJECT_ROOT / "example_obfuscated.lua",
        PROJECT_ROOT / "examples" / "json_wrapped.lua",
    ]
    for src in sources:
        (sample_dir / src.name).write_text(src.read_text())

    _run_cli(sample_dir, tmp_path)

    lua_outputs = sorted(sample_dir.glob("*_deob.lua"))
    json_outputs = sorted(sample_dir.glob("*_deob.json"))
    assert lua_outputs, "expected deobfuscated files in directory"
    assert len(lua_outputs) == len(json_outputs)
    for produced in lua_outputs:
        assert produced.read_text().strip()
    for sidecar in json_outputs:
        data = json.loads(sidecar.read_text())
        assert data["output"].strip()


def test_cli_smoke_complex_sample(tmp_path):
    complex_source = PROJECT_ROOT / "examples" / "complex_obfuscated"
    local_copy = tmp_path / "complex_obfuscated"
    local_copy.write_bytes(complex_source.read_bytes())

    _run_cli(local_copy, tmp_path)

    output_lua = local_copy.with_name("complex_obfuscated_deob.lua")
    output_json = local_copy.with_name("complex_obfuscated_deob.json")
    assert output_lua.exists()
    assert output_lua.stat().st_size > 0
    assert output_json.exists()
    json_data = json.loads(output_json.read_text(encoding="utf-8"))
    assert json_data["output"].strip()


def test_cli_reports_multi_chunk_payload(tmp_path):
    complex_source = PROJECT_ROOT / "examples" / "complex_obfuscated"
    source_text = complex_source.read_text(encoding="utf-8")
    expected_chunks = sum(
        1 for line in source_text.splitlines() if line.strip().startswith("local chunk_")
    )
    assert expected_chunks >= 2, "fixture should contain multiple payload chunks"

    local_copy = tmp_path / "complex_obfuscated"
    local_copy.write_text(source_text, encoding="utf-8")

    proc = _run_cli(local_copy, tmp_path, "--format", "json")
    stdout = proc.stdout.decode("utf-8")
    assert f"Decoded {expected_chunks} blobs" in stdout

    output_path = local_copy.with_name("complex_obfuscated_deob.json")
    lua_sidecar = local_copy.with_name("complex_obfuscated_deob.lua")
    assert output_path.exists()
    produced = sorted(local_copy.parent.glob("complex_obfuscated_deob.*"))
    filtered = [path for path in produced if not path.name.endswith(".top_level.json")]
    assert filtered == [output_path, lua_sidecar], "expected JSON and Lua outputs"

    data = json.loads(output_path.read_text(encoding="utf-8"))
    payload_meta = (
        data.get("passes", {})
        .get("payload_decode", {})
        .get("handler_payload_meta", {})
    )

    assert payload_meta.get("chunk_count") == expected_chunks
    assert payload_meta.get("chunk_success_count") == expected_chunks

    decoded_lengths = payload_meta.get("chunk_decoded_bytes") or []
    report = data.get("report", {})
    assert report.get("blob_count") == expected_chunks
    if decoded_lengths:
        assert report.get("decoded_bytes") == sum(decoded_lengths)
    chunks = report.get("chunks", [])
    assert isinstance(chunks, list) and len(chunks) == expected_chunks
    for chunk in chunks:
        assert {"index", "size", "decoded_byte_count", "lifted_instruction_count"}.issubset(
            chunk.keys()
        )

    output_text = data.get("output", "")
    for marker in ("Aimbot", "ESP", "KillAll"):
        assert marker in output_text, f"expected {marker} in merged output"


def test_cli_audit_log_encrypted(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    log_path = tmp_path / "confirm.log"
    secret = "passphrase"
    _run_cli(
        target,
        tmp_path,
        "--audit-log",
        str(log_path),
        "--audit-passphrase",
        secret,
        "--operator",
        "tester",
    )

    from src.usage_audit import load_audit_entries

    entries = load_audit_entries(log_path, secret)
    assert entries, "expected at least one confirmation entry"
    assert entries[-1]["operator"] == "tester"
    key_meta = entries[-1].get("key", {})
    assert key_meta.get("present") is False


def test_cli_supports_json_format(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path, "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text())
    assert data["output"]
    assert data["version"]
    assert data["timings"]
    lua_sidecar = target.with_name(f"{target.stem}_deob.lua")
    assert lua_sidecar.exists()


def test_cli_format_lua_skips_json(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path, "--format", "lua")

    output_lua = target.with_name(f"{target.stem}_deob.lua")
    assert output_lua.exists()
    output_json = target.with_name(f"{target.stem}_deob.json")
    assert not output_json.exists()


def test_cli_detect_only_reports_version(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path, "--detect-only")

    output = target.with_name(f"{target.stem}_deob.lua")
    text = output.read_text()
    assert text.startswith("-- detected Luraph version")
    json_sidecar = target.with_name(f"{target.stem}_deob.json")
    assert not json_sidecar.exists()


def test_cli_writes_artifacts(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    artifacts = tmp_path / "artifacts"
    _run_cli(target, tmp_path, "--write-artifacts", str(artifacts))

    produced = list(artifacts.rglob("render.lua"))
    assert produced, "expected render.lua artifact"


def test_cli_accepts_json_inputs(tmp_path):
    payload = ["print('json pipeline')\n"]
    source = tmp_path / "sample.json"
    source.write_text(json.dumps(payload))

    _run_cli(source, tmp_path)

    output_lua = source.with_name(f"{source.stem}_deob.lua")
    output_json = source.with_name(f"{source.stem}_deob.json")
    assert output_lua.exists()
    text = output_lua.read_text()
    assert "json pipeline" in text
    assert output_json.exists()
    data = json.loads(output_json.read_text())
    assert "json pipeline" in data.get("output", "")


def test_cli_dump_ir_creates_listing(tmp_path):
    source = PROJECT_ROOT / "examples" / "json_wrapped.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    dump_dir = tmp_path / "ir"
    _run_cli(target, tmp_path, "--dump-ir", str(dump_dir))

    listings = list(dump_dir.glob("*.ir"))
    assert listings, "expected IR listing"
    listing_text = listings[0].read_text()
    assert listing_text.strip()


def test_cli_v1441_script_key_only(tmp_path):
    target = _prepare_v1441_source(tmp_path)
    _run_cli(target, tmp_path, "--script-key", SCRIPT_KEY, "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["output"].strip() == V1441_GOLDEN.read_text(encoding="utf-8").strip()
    decoded = [entry.strip() for entry in data.get("decoded_payloads", [])]
    assert any("print(" in entry for entry in decoded)

    vm_meta = data.get("vm_metadata")
    assert isinstance(vm_meta, dict)
    assert "traps" in vm_meta
    lifter_meta = vm_meta.get("lifter")
    if lifter_meta is not None:
        assert isinstance(lifter_meta, dict)
    devirt_meta = vm_meta.get("devirtualizer")
    if devirt_meta is not None:
        assert isinstance(devirt_meta, dict)

    payload_meta = data.get("passes", {}).get("payload_decode", {}).get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("alphabet_source") in {"heuristic", "bootstrap"}
    bootstrap_meta = payload_meta.get("bootstrapper")
    assert isinstance(bootstrap_meta, dict)
    assert "path" in bootstrap_meta


def test_cli_env_script_key(tmp_path, monkeypatch):
    target = _prepare_v1441_source(tmp_path)
    monkeypatch.setenv("LURAPH_SESSION_KEY", SCRIPT_KEY)

    _run_cli(target, tmp_path, "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))

    payload_meta = (
        data.get("passes", {})
        .get("payload_decode", {})
        .get("handler_payload_meta", {})
    )
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("script_key_length") == len(SCRIPT_KEY)


def test_cli_report_metrics_v1441(tmp_path):
    target = _prepare_v1441_source(tmp_path)

    proc = _run_cli(target, tmp_path, "--script-key", SCRIPT_KEY)

    stdout = proc.stdout.decode("utf-8")
    assert "=== Deobfuscation Report ===" in stdout
    after_header = stdout.split("=== Deobfuscation Report ===", 1)[1]
    report_section = after_header.split("\n==", 1)[0]
    report_lines = [line.strip() for line in report_section.strip().splitlines() if line.strip()]

    assert any(
        line.startswith("Detected version: luraph_v14_4_initv4") for line in report_lines
    )

    report_text = "\n".join(report_lines)
    decoded_match = re.search(r"Decoded (\d+) blobs, total (\d+) bytes", report_text)
    assert decoded_match is not None
    blob_count = int(decoded_match.group(1))
    assert blob_count > 0

    assert "Opcode counts:" in report_lines
    assert "Unknown opcodes: none" in report_lines

    traps_line = next(line for line in report_lines if line.startswith("Traps removed:"))
    traps_removed = int(traps_line.split(":", 1)[1])
    assert traps_removed > 0

    consts_line = next(
        line for line in report_lines if line.startswith("Constants decrypted:")
    )
    constants_decrypted = int(consts_line.split(":", 1)[1])
    assert constants_decrypted > 0

    length_line = next(
        line for line in report_lines if line.startswith("Final output length:")
    )
    length_match = re.search(r"(\d+)", length_line)
    assert length_match is not None
    reported_length = int(length_match.group(1))

    output_path = target.with_name(f"{target.stem}_deob.lua")
    output_text = output_path.read_text(encoding="utf-8")
    assert reported_length == len(output_text)


def test_cli_v1441_bootstrapper_only(tmp_path):
    target = _prepare_v1441_source(tmp_path, literal_key=True)
    stub_dir = _prepare_bootstrapper(tmp_path)
    _run_cli(target, tmp_path, "--bootstrapper", str(stub_dir), "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["output"].strip() == V1441_GOLDEN.read_text(encoding="utf-8").strip()

    payload_meta = data.get("passes", {}).get("payload_decode", {}).get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "literal"
    assert payload_meta.get("alphabet_source") == "bootstrap"
    bootstrap_meta = payload_meta.get("bootstrapper") or {}
    assert bootstrap_meta.get("path", "").endswith("initv4.lua")
    assert bootstrap_meta.get("alphabet_length", 0) >= 85
    assert bootstrap_meta.get("opcode_map_entries", 0) >= 4
    root_bootstrap = data.get("bootstrapper_metadata") or {}
    assert root_bootstrap.get("alphabet_len", 0) >= 85
    assert root_bootstrap.get("alphabet_preview")
    assert root_bootstrap.get("opcode_map_count", 0) >= 16
    sample = root_bootstrap.get("opcode_map_sample")
    assert isinstance(sample, list) and sample, "expected opcode sample entries"
    artifacts = root_bootstrap.get("artifact_paths") or {}
    decoded_path = artifacts.get("decoded_blob_path")
    metadata_path = artifacts.get("metadata_path")
    assert decoded_path and (tmp_path / Path(decoded_path)).exists()
    assert metadata_path and (tmp_path / Path(metadata_path)).exists()
    assert root_bootstrap.get("extraction_method") in {
        "python_reimpl",
        "lua_fallback",
        "lua_sandbox",
    }
    assert root_bootstrap.get("function_name_source") in {
        "read",
        "mixed",
        "inferred",
        "unknown",
    }
    assert root_bootstrap.get("extraction_confidence") in {
        "high",
        "medium",
        "low",
        "unknown",
    }
    assert root_bootstrap.get("extraction_log")


def test_cli_v1441_script_key_and_bootstrapper(tmp_path):
    target = _prepare_v1441_source(tmp_path)
    stub_dir = _prepare_bootstrapper(tmp_path)
    _run_cli(
        target,
        tmp_path,
        "--script-key",
        SCRIPT_KEY,
        "--bootstrapper",
        str(stub_dir),
        "--format",
        "json",
    )

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["output"].strip() == V1441_GOLDEN.read_text(encoding="utf-8").strip()

    payload_meta = data.get("passes", {}).get("payload_decode", {}).get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("alphabet_source") == "bootstrap"
    bootstrap_meta = payload_meta.get("bootstrapper") or {}
    assert bootstrap_meta.get("alphabet_length", 0) >= 85
    assert bootstrap_meta.get("path", "").endswith("initv4.lua")
    assert payload_meta.get("decode_method") == "base91"
    root_bootstrap = data.get("bootstrapper_metadata") or {}
    assert root_bootstrap.get("opcode_map_count", 0) >= 16
    sample = root_bootstrap.get("opcode_map_sample")
    assert isinstance(sample, list) and sample
    artifacts = root_bootstrap.get("artifact_paths") or {}
    assert artifacts.get("decoded_blob_path")
    assert root_bootstrap.get("alphabet_preview")
    assert root_bootstrap.get("function_name_source") in {
        "read",
        "mixed",
        "inferred",
        "unknown",
    }
    assert root_bootstrap.get("extraction_confidence") in {
        "high",
        "medium",
        "low",
        "unknown",
    }
    method = root_bootstrap.get("extraction_method")
    needs_emulation = root_bootstrap.get("needs_emulation")
    if not needs_emulation:
        assert method in {"python_reimpl", "lua_fallback", "lua_sandbox", "manual_override"}
    else:
        assert method in {"python_reimpl", "lua_fallback", "lua_sandbox", "manual_override", "unknown"}
        instructions = root_bootstrap.get("instructions") or []
        assert instructions and any("--allow-lua-run" in msg for msg in instructions)
    assert root_bootstrap.get("extraction_log")


def test_cli_manual_bootstrap_overrides(tmp_path):
    source = _prepare_complex_json(tmp_path)
    stub_dir = _prepare_bootstrapper(tmp_path)

    bootstrap = InitV4Bootstrap.load(stub_dir)
    alphabet, _, table, _ = bootstrap.extract_metadata(_BASE_OPCODE_TABLE)
    assert alphabet, "expected bootstrapper alphabet"
    manual_alphabet = alphabet
    manual_map = {opcode: spec.mnemonic for opcode, spec in table.items()}
    assert manual_map, "expected opcode mappings from bootstrapper"

    opcode_path = tmp_path / "manual_opcodes.json"
    opcode_payload = {str(opcode): name for opcode, name in manual_map.items()}
    opcode_path.write_text(json.dumps(opcode_payload, sort_keys=True), encoding="utf-8")

    _run_cli(
        source,
        tmp_path,
        "--script-key",
        SCRIPT_KEY,
        "--alphabet",
        manual_alphabet,
        "--opcode-map-json",
        str(opcode_path),
        "--format",
        "json",
    )

    output = source.with_name(f"{source.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))

    payload_meta = (
        data.get("passes", {})
        .get("payload_decode", {})
        .get("handler_payload_meta", {})
    )
    assert payload_meta.get("alphabet_source") == "manual_override"

    root_bootstrap = data.get("bootstrapper_metadata") or {}
    assert root_bootstrap.get("extraction_method") == "manual_override"
    assert root_bootstrap.get("alphabet_len") == len(manual_alphabet)
    assert root_bootstrap.get("opcode_map_count") == len(manual_map)
    manual_info = root_bootstrap.get("manual_override") or {}
    assert manual_info.get("alphabet") is True
    assert manual_info.get("opcode_map") is True
    instructions = root_bootstrap.get("instructions") or []
    assert all("--allow-lua-run" not in msg for msg in instructions)


def test_debug_bootstrap_logging(tmp_path):
    target = _prepare_v1441_source(tmp_path)
    stub_dir = _prepare_bootstrapper(tmp_path)
    _run_cli(
        target,
        tmp_path,
        "--script-key",
        SCRIPT_KEY,
        "--bootstrapper",
        str(stub_dir),
        "--format",
        "json",
        "--debug-bootstrap",
    )

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    bootstrap_meta = data.get("bootstrapper_metadata") or {}
    raw_matches = bootstrap_meta.get("raw_matches") or {}
    assert raw_matches, "expected raw bootstrapper matches in metadata"
    bootstrap_raw = raw_matches.get("bootstrap_decoder") or {}
    assert bootstrap_raw.get("blobs") or bootstrap_raw.get("decoder_functions")
    assert bootstrap_meta.get("extraction_log")

    logs_dir = tmp_path / "logs"
    assert logs_dir.exists()
    debug_logs = list(logs_dir.glob("bootstrap_extract_debug_*.log"))
    assert debug_logs, "expected debug bootstrap logs"
    log_data = json.loads(debug_logs[-1].read_text(encoding="utf-8"))
    assert log_data.get("raw_matches")
    preview = log_data.get("metadata_preview") or {}
    assert preview.get("opcode_map_count", 0) >= 1


def test_cli_reports_missing_script_key(tmp_path):
    target = tmp_path / V1441_SOURCE.name
    target.write_text(V1441_SOURCE.read_text())

    proc = _run_cli(target, tmp_path, "--format", "json", check=False)
    assert proc.returncode != 0

    output_json = target.with_name(f"{target.stem}_deob.json")
    output_lua = target.with_name(f"{target.stem}_deob.lua")
    assert not output_json.exists()
    assert not output_lua.exists()

    log_path = tmp_path / "deobfuscator.log"
    assert log_path.exists()
    log_text = log_path.read_text(encoding="utf-8")
    assert "script key" in log_text.lower()


def test_cli_force_allows_missing_script_key(tmp_path):
    target = tmp_path / V1441_SOURCE.name
    target.write_text(V1441_SOURCE.read_text())

    proc = _run_cli(target, tmp_path, "--force", "--format", "json")
    assert proc.returncode == 0

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text())
    report = data.get("report", {})
    warnings = report.get("warnings", [])
    assert any("script key" in warning.lower() for warning in warnings)


def test_cli_safe_mode_writes_crash_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "safe_mode.lua"
    source.write_text("print('hi')\n", encoding="utf-8")

    def crash_passes(ctx, skip=None, only=None, profile=False):
        raise cli_main.pipeline.PipelineExecutionError(
            name="payload_decode",
            timings=[("detect", 0.01)],
            duration=0.02,
            cause=RuntimeError("boom"),
        )

    monkeypatch.setattr(cli_main.pipeline.PIPELINE, "run_passes", crash_passes)

    exit_code = cli_main.main(
        [
            str(source),
            "--safe-mode",
            "--format",
            "lua",
            "--confirm-ownership",
            "--confirm-voluntary-key",
        ]
    )
    assert exit_code == 1

    crash_dir = tmp_path / "out" / "crash_reports"
    reports = sorted(crash_dir.glob("*.json"))
    assert reports, "expected crash report to be written"
    payload = json.loads(reports[0].read_text(encoding="utf-8"))
    assert payload["safe_mode"] is True
    assert payload["failed_pass"] == "payload_decode"
    assert "TINY" not in json.dumps(payload)


def test_cli_dry_run_allows_missing_script_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "needs_key.lua"
    source.write_text("local payload = ''\nlocal initv4 = {}\n", encoding="utf-8")

    def stub_passes(ctx, skip=None, only=None, profile=False):
        assert ctx.options.get("dry_run") is True
        return [("detect", 0.001)]

    monkeypatch.setattr(cli_main.pipeline.PIPELINE, "run_passes", stub_passes)

    exit_code = cli_main.main(
        [
            str(source),
            "--dry-run",
            "--format",
            "lua",
            "--confirm-ownership",
            "--confirm-voluntary-key",
        ]
    )
    assert exit_code == 0

    output_path = source.with_name("needs_key_deob.lua")
    assert output_path.exists()
    crash_dir = tmp_path / "out" / "crash_reports"
    if crash_dir.exists():
        assert not any(crash_dir.iterdir())


def test_cli_complex_initv4_with_key_and_bootstrapper(tmp_path):
    source = _prepare_complex_json(tmp_path)
    stub_dir = _prepare_bootstrapper(tmp_path)

    _run_cli(
        source,
        tmp_path,
        "--script-key",
        SCRIPT_KEY,
        "--bootstrapper",
        str(stub_dir),
        "--format",
        "json",
    )

    output = source.with_name(f"{source.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    text = data.get("output", "")
    assert "Aimbot" in text
    assert "ESP" in text

    payload_meta = data.get("passes", {}).get("payload_decode", {})
    assert payload_meta.get("script_key_override") is True
    handler_name = payload_meta.get("handler")
    assert handler_name in {"luraph_v14_4_initv4", "luraph_v14_2_json"}


def test_cli_no_report_disables_output(tmp_path):
    target = _prepare_v1441_source(tmp_path)

    proc = _run_cli(
        target,
        tmp_path,
        "--script-key",
        SCRIPT_KEY,
        "--no-report",
        "--format",
        "json",
    )

    stdout = proc.stdout.decode("utf-8")
    assert "Deobfuscation Report" not in stdout

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert "report" not in data


def test_bootstrap_summary_instructions_when_no_fallback() -> None:
    meta = {
        "needs_emulation": True,
        "alphabet_len": 0,
        "opcode_map": {},
        "extraction_log": "out/logs/bootstrap_decode_trace_stub.log",
        "fallback_attempted": False,
        "fallback_executed": False,
    }
    summary = cli_main._summarise_bootstrap_metadata(meta)
    instructions = summary.get("instructions") or []
    assert instructions, "expected fallback guidance when emulation required"
    combined = " ".join(instructions).lower()
    assert "--allow-lua-run" in combined
    assert "metadata" in combined or "bootstrapper" in combined


def test_name_opcode_command_updates_mapping(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")

    reconstructed = tmp_path / "reconstructed.lua"
    reconstructed.write_text(
        "local function OP_42(value)\n    return value\nend\n",
        encoding="utf-8",
    )

    mapping_path = tmp_path / "mapping.json"
    output_path = tmp_path / "pretty.lua"
    upcodes = tmp_path / "upcodes.json"
    guesses = tmp_path / "guesses.json"

    upcodes.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "opcode": 42,
                        "mnemonic": "OP_42",
                        "frequency": 3,
                        "handler_table": "return_table",
                        "semantic": "unknown",
                        "sample_usage": [
                            {
                                "snippet": "handler=function() return value + 1 end",
                                "source": "handler_snippet",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    guesses.write_text(
        json.dumps(
            {
                "guesses": {
                    "42": {
                        "guess": "add_loop",
                        "confidence": 0.6,
                        "evidence": "frequency analysis",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli_main.main(
        [
            "name_opcode",
            "0x2A",
            "--name",
            "add_loop",
            "--mapping",
            str(mapping_path),
            "--source",
            str(reconstructed),
            "--output",
            str(output_path),
            "--upcodes",
            str(upcodes),
            "--guesses",
            str(guesses),
        ]
    )

    assert exit_code == 0
    mapping_payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    assert mapping_payload["OP_42"] == "ADD_LOOP"
    rendered = output_path.read_text(encoding="utf-8")
    assert "function ADD_LOOP" in rendered
