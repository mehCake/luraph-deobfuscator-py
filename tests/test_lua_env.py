import os
import pytest

def test_lupa_available():
    try:
        import lupa  # noqa
    except Exception as e:
        pytest.fail(f"lupa not importable: {e}")

def test_lupa_runs_lua_snippet():
    from lupa import LuaRuntime
    lua = LuaRuntime(unpack_returned_tuples=True)
    # Minimal "vm-like" table to ensure our heuristics don't crash
    lua.execute("""
      data = {
        4, 0, {},
        { {nil,nil,4,0,nil,1,0,0}, {nil,nil,0,0,nil,2,1,nil} },
        {"print","hi"}, {}, 18, {"print","hi"}
      }
    """)
    assert lua.eval("type(data)") == "table"
    assert lua.eval("#data[4]") == 2
