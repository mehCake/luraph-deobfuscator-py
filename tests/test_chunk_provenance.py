from src.lifter.runner import run_lifter_safe
from src.passes.payload_decode import _finalise_metadata, _merge_payload_meta


def _make_instruction(index: int) -> dict:
    return {
        "pc": index,
        "index": index,
        "opcode": 0,
        "opnum": 0,
        "mnemonic": "MOVE",
        "A": 0,
        "B": 0,
        "C": 0,
    }


def test_chunk_provenance_sorted_and_propagated():
    aggregated: dict = {}

    lua_meta = {
        "chunk_details": [
            {"chunk_index": 0, "source_kind": "lua", "header": "LPH!", "chunk_offset": 120}
        ],
        "handler_payload_meta": {
            "chunk_details": [
                {"chunk_index": 0, "source_kind": "lua", "header": "LPH!", "chunk_offset": 120}
            ]
        },
    }
    json_meta = {
        "chunk_details": [
            {"chunk_index": 0, "source_kind": "json", "header": "LPH~", "chunk_offset": 12}
        ],
        "handler_payload_meta": {
            "chunk_details": [
                {"chunk_index": 0, "source_kind": "json", "header": "LPH~", "chunk_offset": 12}
            ]
        },
    }

    _merge_payload_meta(aggregated, lua_meta)
    _merge_payload_meta(aggregated, json_meta)

    metadata = _finalise_metadata(aggregated, None)

    payload_meta = metadata.get("handler_payload_meta")
    assert isinstance(payload_meta, dict)
    details = payload_meta.get("chunk_details")
    assert isinstance(details, list)
    assert [entry["header"] for entry in details] == ["LPH!", "LPH~"]
    assert [entry["source_kind"] for entry in details] == ["lua", "json"]
    assert [entry["chunk_index"] for entry in details] == [0, 1]

    payload_chunks = [
        {
            "chunk_index": entry["chunk_index"],
            "source_kind": entry["source_kind"],
            "header": entry.get("header"),
            "chunk_offset": entry.get("chunk_offset"),
        }
        for entry in details
    ]

    result = run_lifter_safe(
        [_make_instruction(0)],
        [],
        {0: "MOVE"},
        vm_metadata={"payload_chunks": payload_chunks},
        time_limit=None,
    )

    assert result.metadata.get("chunk_details") == payload_chunks
