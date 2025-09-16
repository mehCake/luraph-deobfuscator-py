import base64
import logging

from src.pipeline import Context
from src.passes.payload_decode import run as payload_decode_run


def _sample_payload() -> str:
    blob = base64.b64encode(b"hello world" * 30).decode()
    return (
        "local script_key = script_key or getgenv().script_key\n"
        "local init_fn = function(blob)\n"
        "    return loadstring(blob)()\n"
        "end\n"
        f"local payload = [[{{\"constants\": [\"{blob}\"], \"bytecode\": [1, 2, 3]}}]]\n"
        "return init_fn(payload)\n"
    )


def test_payload_decode_sets_vm_fields(tmp_path, caplog):
    sample = _sample_payload()
    path = tmp_path / "sample.lua"
    path.write_text(sample, encoding="utf-8")

    ctx = Context(input_path=path, raw_input=sample, stage_output=sample)

    caplog.set_level(logging.DEBUG)
    metadata = payload_decode_run(ctx)

    assert ctx.version is not None and ctx.version.name == "luraph_v14_2_json"
    assert ctx.vm.bytecode == b"\x01\x02\x03"
    assert ctx.vm.const_pool == [base64.b64encode(b"hello world" * 30).decode()]
    assert ctx.vm.meta["proto_count"] == 0
    assert ctx.vm.meta["endianness"] == "little"
    assert metadata["handler_payload_bytes"] == 3
    assert metadata["handler_const_count"] == 1
    assert "luraph_v14_2_json payload extracted" in caplog.text
