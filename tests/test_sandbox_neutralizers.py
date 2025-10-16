from __future__ import annotations

import pytest

from src import sandbox


@pytest.mark.skipif(sandbox.LuaRuntime is None, reason="lupa not available")
def test_guard_neutralizers_allow_capture():
    lua = sandbox.LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    if hasattr(lua, "globals"):
        globals_table = lua.globals()
    else:
        globals_table = lua._globals  # type: ignore[attr-defined]

    logs: list[str] = []
    sandbox._install_safe_globals(lua, globals_table, log_callback=logs.append)

    is_fallback = getattr(lua, "is_fallback", False)

    if is_fallback:
        def guard():
            raise RuntimeError("analysis guard")

        handler = lambda err: err  # noqa: E731 - simple passthrough for stub runtime
    else:
        guard = lua.eval("function() error('analysis guard') end")
        handler = lua.eval("function(err) return err end")

    pcall_result = globals_table["pcall"](guard)
    assert isinstance(pcall_result, tuple)
    assert pcall_result[0] is True
    assert pcall_result[1] is None

    xpcall_result = globals_table["xpcall"](guard, handler)
    assert isinstance(xpcall_result, tuple)
    assert xpcall_result[0] is True
    assert xpcall_result[1] is None

    if not is_fallback:
        lua.execute(
            """
            guard_triggered = false
            function run_guard_checks()
                local ok = pcall(function() error('guard pcall') end)
                if not ok then guard_triggered = true end
                local ok2 = xpcall(function() error('guard xpcall') end, function() return 'handled' end)
                if not ok2 then guard_triggered = true end
            end
            """
        )

        lua.eval("run_guard_checks")()
        assert globals_table["guard_triggered"] is False

    assert globals_table["collectgarbage"]("count") == 0
    assert globals_table["debug"]["traceback"]("message") == ""
    assert globals_table["jit"]["status"]() is False

    guard_logs = [entry for entry in logs if "neutralized guard" in entry]
    assert guard_logs, f"expected guard neutralization logs, got: {logs}"
