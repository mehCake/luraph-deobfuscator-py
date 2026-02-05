from src.versions.v14_3_writer_sim import (
    PrototypeSpec,
    V14_3Writer,
    simulate_v14_3_writer,
)


def test_writer_records_varint_and_bytes_offsets():
    writer = V14_3Writer()
    writer.write_u8(0x10, label="u8_test")
    writer.write_varint(300, label="varint_test")
    writer.write_bytes(b"abc", label="bytes_test")

    snapshot = writer.snapshot()
    assert snapshot["buf"][:1] == b"\x10"
    assert len(snapshot["log"]) == 3
    assert snapshot["log"][1]["op"] == "varint"
    assert snapshot["log"][1]["label"] == "varint_test"
    assert snapshot["log"][1]["offset"] == 1
    assert snapshot["log"][2]["size"] == 3


def test_simulate_writer_generates_structure():
    snapshot = simulate_v14_3_writer()
    log = snapshot["log"]
    assert log, "simulation should record write operations"
    assert any(entry.get("label") == "proto_count" for entry in log)
    string_tags = [entry for entry in log if entry.get("label", "").endswith("tag_string")]
    assert string_tags, "default scenario should include a string constant"


def test_simulation_accepts_custom_prototypes():
    prototype = PrototypeSpec(
        constants=({"kind": "integer", "value": 123},),
        instructions=(b"\x01\x02",),
        children=(),
    )
    snapshot = simulate_v14_3_writer([prototype])
    buf = snapshot["buf"]
    assert buf, "custom run should still emit bytes"
    labels = [entry.get("label") for entry in snapshot["log"]]
    assert any("const" in (label or "") for label in labels)
