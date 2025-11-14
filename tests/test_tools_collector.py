from pathlib import Path
from textwrap import dedent

from src.tools.collector import collect_pipeline_candidates


def test_collect_pipeline_candidates_includes_dispatcher_cfg() -> None:
    dispatcher_body = dedent(
        """
        ::entry::
        if opcode == 0 then
            return handler_zero(state)
        elseif opcode == 1 then
            return handler_one(state)
        end
        """
    )
    dispatcher = f"loadstring([[{dispatcher_body}]])()"
    chunks = [
        {
            "kind": "loadstring",
            "start": 0,
            "end": len(dispatcher),
            "text": dispatcher,
        }
    ]
    report = collect_pipeline_candidates(chunks)
    assert report.get("dispatcher_cfg_count") == 1
    chunk_entry = report["chunks"][0]
    cfg = chunk_entry.get("dispatcher_cfg")
    assert cfg is not None
    assert cfg["entry"] == "entry"
    assert any(block["kind"] == "branch" for block in cfg.get("blocks", []))


def test_collect_pipeline_candidates_aggregates_manifest_and_bytes(tmp_path) -> None:
    loop_body = "for i = 1, #t do t[i] = bit32.bxor(t[i], 0x5C) end return t"
    snippet = f"loadstring([[{loop_body}]])"
    numeric_snippet = "{0,1,2,3,4}"
    candidates = [
        {
            "type": "loadstring",
            "start_offset": 0,
            "end_offset": len(snippet),
            "snippet": snippet,
            "confidence": 0.9,
        },
        {
            "type": "numeric_array",
            "start_offset": 120,
            "end_offset": 140,
            "snippet": numeric_snippet,
            "confidence": 0.6,
        },
    ]
    manifest = [
        {
            "type": "escaped-string",
            "start_offset": 0,
            "end_offset": 50,
            "payload_length": 1500,
            "source_length": 50,
            "note": "string.char call",
        },
        {
            "type": "numeric_array",
            "start_offset": 200,
            "end_offset": 230,
            "payload_length": 5,
            "source_length": 30,
        },
    ]

    bytes_dir = tmp_path / "bytes"
    bytes_dir.mkdir()
    byte_file = bytes_dir / "000_load.bin"
    byte_file.write_bytes(b"\x00\x01\x02\x03")
    byte_metadata = [
        {
            "name": byte_file.name,
            "type": "loadstring",
            "path": str(byte_file),
            "size": 4,
            "endianness_hint": "little",
            "endianness_score": 0.75,
            "start_offset": 0,
            "end_offset": 4,
            "confidence": 0.8,
        }
    ]

    report = collect_pipeline_candidates(
        candidates,
        manifest=manifest,
        byte_metadata=byte_metadata,
        source_path=Path("Obfuscated3.lua"),
    )

    pipelines = report.get("pipelines")
    assert pipelines and isinstance(pipelines, list)
    first = pipelines[0]
    assert first["version_hint"] == "v14.4.2"
    assert first["preferred_presets"][0].startswith("v14.4.2")
    sequence = first["sequence"]
    assert "string-escape" in sequence
    assert "string.char" in sequence
    assert "xor" in sequence
    assert "permute" in sequence
    assert "hypothesis_score" in first
    assert first["hypothesis_score"]["components"]["pipeline"] >= 0.0

    assert report["byte_candidates"] == byte_metadata

    chunk_entry = report["chunks"][0]
    assert chunk_entry["xor_score"] > 0
