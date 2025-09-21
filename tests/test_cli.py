import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = PROJECT_ROOT / "tests" / "golden"
V1441_SOURCE = PROJECT_ROOT / "examples" / "v1441_hello.lua"
V1441_GOLDEN = GOLDEN_DIR / "v1441_hello.lua.out"
INITV4_STUB = PROJECT_ROOT / "tests" / "fixtures" / "initv4_stub" / "initv4.lua"


def _prepare_v1441_source(tmp_path: Path, *, literal_key: bool = False) -> Path:
    text = V1441_SOURCE.read_text(encoding="utf-8")
    if literal_key:
        text = text.replace("getgenv().script_key", '"ncbmxnbs6wrpkpaitt6dwj"')
    target = tmp_path / V1441_SOURCE.name
    target.write_text(text, encoding="utf-8")
    return target


def _prepare_bootstrapper(tmp_path: Path) -> Path:
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    (stub_dir / "initv4.lua").write_text(INITV4_STUB.read_text(encoding="utf-8"), encoding="utf-8")
    return stub_dir


def _run_cli(target: Path, workdir: Path, *extra: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PROJECT_ROOT / "main.py"), str(target), *extra]
    return subprocess.run(cmd, cwd=workdir, check=True, capture_output=True)


def test_cli_emits_output_for_single_file(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path)

    output = target.with_name(f"{target.stem}_deob.lua")
    assert output.exists()
    assert output.read_text().strip()


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

    outputs = list(sample_dir.glob("*_deob.lua"))
    assert outputs, "expected deobfuscated files in directory"
    for produced in outputs:
        assert produced.read_text().strip()


def test_cli_smoke_complex_sample(tmp_path):
    complex_source = PROJECT_ROOT / "examples" / "complex_obfuscated"
    local_copy = tmp_path / "complex_obfuscated"
    local_copy.write_bytes(complex_source.read_bytes())

    _run_cli(local_copy, tmp_path)

    output = local_copy.with_name("complex_obfuscated_deob.lua")
    assert output.exists()
    assert output.stat().st_size > 0


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


def test_cli_detect_only_reports_version(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path, "--detect-only")

    output = target.with_name(f"{target.stem}_deob.lua")
    text = output.read_text()
    assert text.startswith("-- detected Luraph version")


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

    output = source.with_name(f"{source.stem}_deob.lua")
    assert output.exists()
    text = output.read_text()
    assert "json pipeline" in text


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
    _run_cli(target, tmp_path, "--script-key", "ncbmxnbs6wrpkpaitt6dwj", "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["output"].strip() == V1441_GOLDEN.read_text(encoding="utf-8").strip()
    decoded = [entry.strip() for entry in data.get("decoded_payloads", [])]
    assert any("print(" in entry for entry in decoded)

    payload_meta = data.get("passes", {}).get("payload_decode", {}).get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("alphabet_source") == "default"
    assert "bootstrapper" not in payload_meta


def test_cli_v1441_bootstrapper_only(tmp_path):
    target = _prepare_v1441_source(tmp_path, literal_key=True)
    stub_dir = _prepare_bootstrapper(tmp_path)
    _run_cli(target, tmp_path, "--bootstrapper", str(stub_dir), "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["output"].strip() == V1441_GOLDEN.read_text(encoding="utf-8").strip()

    payload_meta = data.get("passes", {}).get("payload_decode", {}).get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "literal"
    assert payload_meta.get("alphabet_source") == "bootstrapper"
    bootstrap_meta = payload_meta.get("bootstrapper") or {}
    assert bootstrap_meta.get("path", "").endswith("initv4.lua")
    assert bootstrap_meta.get("alphabet_length", 0) >= 85
    assert bootstrap_meta.get("opcode_map_entries", 0) >= 4


def test_cli_v1441_script_key_and_bootstrapper(tmp_path):
    target = _prepare_v1441_source(tmp_path)
    stub_dir = _prepare_bootstrapper(tmp_path)
    _run_cli(
        target,
        tmp_path,
        "--script-key",
        "ncbmxnbs6wrpkpaitt6dwj",
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
    assert payload_meta.get("alphabet_source") == "bootstrapper"
    bootstrap_meta = payload_meta.get("bootstrapper") or {}
    assert bootstrap_meta.get("alphabet_length", 0) >= 85
    assert bootstrap_meta.get("path", "").endswith("initv4.lua")
    assert payload_meta.get("decode_method") == "base91"


def test_cli_reports_missing_script_key(tmp_path):
    target = tmp_path / V1441_SOURCE.name
    target.write_text(V1441_SOURCE.read_text())

    _run_cli(target, tmp_path, "--format", "json")

    output = target.with_name(f"{target.stem}_deob.json")
    data = json.loads(output.read_text())
    payload_meta = data.get("passes", {}).get("payload_decode", {})
    error_text = payload_meta.get("handler_bytecode_error", "")
    assert "script key" in error_text.lower()
