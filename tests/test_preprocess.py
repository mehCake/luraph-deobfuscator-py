import json

from src.passes.preprocess import flatten_json_to_lua, run as preprocess_run
from src.pipeline import Context


def test_flatten_json_to_lua_nested_lists() -> None:
    nested = [
        "print('hello')\n",
        ["print('world')\n", ["return 1"]],
        42,
    ]
    flattened = flatten_json_to_lua(nested)
    assert flattened == "print('hello')\nprint('world')\nreturn 1"


def test_preprocess_json_input(tmp_path) -> None:
    chunks = ["print('a')\n", "print('b')"]
    json_file = tmp_path / "payload.json"
    json_file.write_text(json.dumps(chunks))

    ctx = Context(input_path=json_file)
    metadata = preprocess_run(ctx)

    assert metadata.get("json_flattened") is True
    assert "print('a')" in ctx.stage_output
    assert "print('b')" in ctx.stage_output
    assert "reconstructed_lua" in ctx.temp_paths

    reconstructed = ctx.temp_paths["reconstructed_lua"]
    assert reconstructed.exists()
    assert reconstructed.read_text() == "".join(chunks)
