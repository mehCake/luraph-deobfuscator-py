from pathlib import Path

from src.pipeline import Context
from src.passes.cleanup import run as cleanup_run
from src.passes.render import run as render_run


def _make_context(tmp_path: Path, code: str) -> Context:
    input_path = tmp_path / "sample.lua"
    input_path.write_text(code)
    ctx = Context(input_path=input_path, raw_input=code, stage_output=code)
    ctx.working_text = code
    return ctx


def test_cleanup_removes_dead_code_and_trampolines(tmp_path) -> None:
    snippet = """
local function trampoline(...)
    return real_dispatch(...)
end

if false then
    print('unreachable')
end

local result = loadstring(loadstring("return 'hello'")())()
return result
""".strip()

    ctx = _make_context(tmp_path, snippet)
    metadata = cleanup_run(ctx)

    assert "unreachable" not in ctx.stage_output
    assert "loadstring(loadstring" not in ctx.stage_output
    assert metadata["dead_code_blocks"] >= 1
    assert metadata["vm_trampolines"] >= 1


def test_cleanup_strips_bootstrap_scaffolding(tmp_path) -> None:
    snippet = """
local script_key = script_key or getgenv().script_key
local init_fn = function(blob)
    while true do
        break
    end
    return blob
end

return init_fn("payload")
""".strip()

    ctx = _make_context(tmp_path, snippet)
    metadata = cleanup_run(ctx)

    assert "script_key" not in ctx.stage_output
    assert "init_fn" not in ctx.stage_output
    assert metadata["bootstrap_keys"] >= 1
    assert metadata["bootstrap_init_fn"] >= 1
    assert metadata["bootstrap_init_call"] >= 1
    assert "while true do" not in ctx.stage_output


def test_render_writes_output_file(tmp_path) -> None:
    code = "return 42"
    ctx = _make_context(tmp_path, code)
    destination = tmp_path / "output.lua"
    ctx.options["render_output"] = str(destination)

    metadata = render_run(ctx)

    assert ctx.output
    assert metadata["output_path"] == str(destination)
    assert metadata["written"] is True
    assert destination.exists()
    assert destination.read_text() == ctx.output
