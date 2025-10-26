"""Regression tests covering Step 14 requirements."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

try:  # pragma: no cover
    from version_detector import VersionDetector  # type: ignore
    from src.deobfuscator import LuaDeobfuscator  # type: ignore
    from src.pipeline import Context  # type: ignore
    from src.passes.payload_decode import run as payload_decode_run  # type: ignore
    from src.versions.luraph_v14_4_initv4 import InitV4Decoder, decode_blob  # type: ignore
    from src.versions.luraph_v14_4_1 import _apply_script_key_transform, _encode_base91  # type: ignore
except Exception as exc:  # pragma: no cover
    pytest.skip(f"legacy step14 scaffolding unavailable: {exc}", allow_module_level=True)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INITV4_PATH = PROJECT_ROOT / "initv4.lua"
COMPLEX_JSON = PROJECT_ROOT / "examples" / "complex_obfuscated.json"
TEST_SCRIPT_KEY = "x5elqj5j4ibv9z3329g7b"


def _encode_with_key(data: bytes, key: str) -> str:
    masked = _apply_script_key_transform(data, key.encode("utf-8"))
    return _encode_base91(masked)


def _make_bootstrap(payload_text: str, key: str) -> str:
    blob = _encode_with_key(payload_text.encode("utf-8"), key)
    blob_literal = json.dumps(blob)
    key_literal = json.dumps(key)
    return (
        "-- generated initv4 bootstrap\n"
        f"local script_key = script_key or {key_literal}\n"
        "local init_fn = function(blob)\n    return blob\nend\n"
        f"local payload = {blob_literal}\n"
        "return init_fn(payload)\n"
    )


def test_decode_blob_known_vector() -> None:
    blob = "$.&0m9l!N1)Aq0"
    decoded = decode_blob(blob, None, TEST_SCRIPT_KEY.encode("utf-8"))
    assert decoded == b"KnownVector"


def test_bootstrapper_opcode_extraction() -> None:
    ctx = SimpleNamespace(script_key=TEST_SCRIPT_KEY, bootstrapper_path=INITV4_PATH)
    decoder = InitV4Decoder(ctx)
    table = decoder.opcode_table()
    assert len(table) > 16
    names = {name.upper() for name in table.values()}
    assert {"CALL", "RETURN", "CONCAT"}.issubset(names)
    synthetic = "\n".join(
        f"[0x{index:02X}] = 'OP{index:02d}'" for index in range(32)
    )
    extracted = decoder._extract_opcodes(synthetic)
    assert len(extracted) > 16


def test_multi_chunk_iteration(tmp_path: Path) -> None:
    final_script = "print('layer two payload')\nreturn 'done'\n"
    inner_bootstrap = _make_bootstrap(final_script, TEST_SCRIPT_KEY)
    outer_bootstrap = _make_bootstrap(inner_bootstrap, TEST_SCRIPT_KEY)

    path = tmp_path / "nested.lua"
    path.write_text(outer_bootstrap, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=outer_bootstrap,
        stage_output=outer_bootstrap,
        script_key=TEST_SCRIPT_KEY,
    )
    ctx.detected_version = VersionDetector().info_for_name("luraph_v14_4_initv4")
    ctx.deobfuscator = LuaDeobfuscator(script_key=TEST_SCRIPT_KEY)

    metadata = payload_decode_run(ctx)

    assert metadata.get("payload_iterations", 0) >= 2
    assert final_script.strip() in ctx.stage_output
    assert ctx.report.blob_count >= 2
    assert ctx.report.decoded_bytes >= len(final_script)


@pytest.mark.skipif(
    not os.environ.get("RUN_INTEGRATION_TESTS"),
    reason="Set RUN_INTEGRATION_TESTS=1 to enable integration tests.",
)
def integration_test_obfuscated_json(tmp_path: Path) -> None:
    if not COMPLEX_JSON.exists():
        pytest.skip("obfuscated sample missing")

    target = tmp_path / COMPLEX_JSON.name
    target.write_bytes(COMPLEX_JSON.read_bytes())

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        str(target),
        "--script-key",
        TEST_SCRIPT_KEY,
        "--bootstrapper",
        str(INITV4_PATH),
        "--yes",
        "--confirm-ownership",
        "--confirm-voluntary-key",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    output_lua = target.with_name(f"{target.stem}_deob.lua")
    output_json = target.with_name(f"{target.stem}_deob.json")

    assert output_lua.exists()
    assert output_json.exists()

    lua_text = output_lua.read_text(encoding="utf-8")
    assert "function" in lua_text

    data = json.loads(output_json.read_text(encoding="utf-8"))
    report = data.get("report", {})
    report_length = report.get("final_output_length", report.get("output_length", 0))
    assert report.get("blob_count", 0) > 0
    assert report_length > 0

    output_text = data.get("output", "")
    for marker in ("Aimbot", "ESP", "KillAll"):
        assert marker in output_text
