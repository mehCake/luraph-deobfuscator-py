from __future__ import annotations

import json
from pathlib import Path

from src.tools.visual_inspector import VisualInspector, main as inspector_main


def _write_sample_ir(tmp_path: Path) -> Path:
    raw_path = tmp_path / "sample.bin"
    raw_path.write_bytes(bytes(range(32)))

    payload = {
        "program": {
            "metadata": {"bytecode_path": "sample.bin"},
            "blocks": [
                {
                    "id": "block_0",
                    "start_index": 0,
                    "end_index": 0,
                    "raw_offsets": [0],
                    "ops": [
                        {
                            "mnemonic": "LOADK",
                            "index": 0,
                            "raw": 0xDEADBEEF,
                            "operands": [
                                {"field": "A", "value": 0, "kind": "reg"},
                                {
                                    "field": "Bx",
                                    "value": 1,
                                    "kind": "const",
                                    "resolved": "hello",
                                },
                            ],
                        }
                    ],
                },
                {
                    "id": "block_1",
                    "start_index": 1,
                    "end_index": 1,
                    "raw_offsets": [1],
                    "ops": [
                        {
                            "mnemonic": "RETURN",
                            "index": 1,
                            "raw": 0xFEEDFACE,
                            "operands": [
                                {"field": "A", "value": 0, "kind": "reg"},
                            ],
                        }
                    ],
                },
            ],
        }
    }

    ir_path = tmp_path / "sample_ir.json"
    ir_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return ir_path


def test_visual_inspector_navigation_and_alias(tmp_path: Path) -> None:
    ir_path = _write_sample_ir(tmp_path)
    payload = json.loads(ir_path.read_text(encoding="utf-8"))
    inspector = VisualInspector(payload, ir_path=ir_path)

    assert inspector.list_blocks() == ["block_0", "block_1"]
    assert "LOADK" in inspector.describe_current()

    inspector.set_alias("R0", "player")
    description = inspector.describe_current()
    assert "alias=player" in description

    # Step forward into the second block and ensure navigation succeeds.
    inspector.step(1)  # move into block_1
    assert "RETURN" in inspector.describe_current()

    # Preview the first few bytes from the associated raw payload.
    dump = inspector.preview_bytes(start=0, count=8)
    assert "0x00000000" in dump

    export_path = inspector.export_manual_map(out_dir=tmp_path / "rename_maps")
    export = json.loads(export_path.read_text(encoding="utf-8"))
    assert export["rename_map"]["R0"] == "player"


def test_visual_inspector_cli_commands(tmp_path: Path, monkeypatch) -> None:
    ir_path = _write_sample_ir(tmp_path)
    monkeypatch.chdir(tmp_path)

    exit_code = inspector_main(
        [
            str(ir_path),
            "--yes",
            "--commands",
            "show",
            "rename R0 ctx",
            "aliases",
            "save",
        ]
    )

    assert exit_code == 0

    manual_maps = list((tmp_path / "out" / "rename_maps").glob("manual-*.json"))
    assert manual_maps, "expected rename map export"
    payload = json.loads(manual_maps[0].read_text(encoding="utf-8"))
    assert payload["rename_map"]["R0"] == "ctx"
