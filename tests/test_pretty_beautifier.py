from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.pretty.beautifier import BeautifyResult, beautify, main


def _write_ir(tmp_path: Path) -> Path:
    payload = {
        "program": {
            "blocks": [
                {
                    "id": "block_0",
                    "start_index": 0,
                    "end_index": 2,
                    "raw_offsets": [0, 1, 2],
                    "ops": [
                        {
                            "mnemonic": "LOADK",
                            "index": 0,
                            "raw": 0x10,
                            "operands": [
                                {"field": "a", "value": 0, "kind": "reg"},
                                {"field": "b", "value": 0, "kind": "const"},
                            ],
                        },
                        {
                            "mnemonic": "MOVE",
                            "index": 1,
                            "raw": 0x11,
                            "operands": [
                                {"field": "a", "value": 1, "kind": "reg"},
                                {"field": "b", "value": 0, "kind": "reg"},
                            ],
                        },
                        {
                            "mnemonic": "RETURN",
                            "index": 2,
                            "raw": 0x12,
                            "operands": [{"field": "a", "value": 0, "kind": "reg"}],
                        },
                    ],
                }
            ],
            "metadata": {"instruction_count": 3, "block_count": 1},
            "entry_block": "block_0",
        }
    }

    path = tmp_path / "program.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_constants(tmp_path: Path) -> Path:
    consts = ["hello", 42]
    path = tmp_path / "constants.json"
    path.write_text(json.dumps(consts), encoding="utf-8")
    return path


def test_beautify_pipeline_writes_output(tmp_path: Path) -> None:
    ir_path = _write_ir(tmp_path)
    constants_path = _write_constants(tmp_path)
    output_path = tmp_path / "beautified.lua"
    intermediate_dir = tmp_path / "intermediate"

    result = beautify(
        ir_path,
        constants_path,
        output_path=output_path,
        intermediate_dir=intermediate_dir,
        overwrite=True,
        provenance_profile={"stage": "test", "variant": "unit"},
        provenance_label="beautifier",
        version_hint="v14.4.2",
    )

    assert isinstance(result, BeautifyResult)
    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "-- PROVENANCE" in text
    assert "\"hello\"" in text  # constant was inlined
    assert result.inline_summary.inlined > 0
    assert result.reflow_stats.removed_gotos >= 0
    assert (intermediate_dir / "formatted.lua").exists()
    assert (intermediate_dir / "reflowed.lua").exists()


def test_beautify_respects_overwrite_guard(tmp_path: Path) -> None:
    ir_path = _write_ir(tmp_path)
    constants_path = _write_constants(tmp_path)
    output_path = tmp_path / "beautified.lua"
    output_path.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError):
        beautify(ir_path, constants_path, output_path=output_path, overwrite=False)


def test_beautify_cli_executes_pipeline(tmp_path: Path) -> None:
    ir_path = _write_ir(tmp_path)
    constants_path = _write_constants(tmp_path)
    output_path = tmp_path / "beautified.lua"
    intermediate_dir = tmp_path / "intermediate"

    exit_code = main(
        [
            str(ir_path),
            str(constants_path),
            "--output",
            str(output_path),
            "--intermediate-dir",
            str(intermediate_dir),
            "--overwrite",
            "--version-hint",
            "v14.4.2",
            "--profile-label",
            "cli",  # no profile file supplied but label should be harmless
        ]
    )

    assert exit_code == 0
    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "regs[1]" in text
