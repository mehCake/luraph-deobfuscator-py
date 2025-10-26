"""Tests for the AST-driven safe renamer."""

from __future__ import annotations

import pytest

from utils import benchmark_recorder
from variable_renamer import safe_rename


def test_safe_rename_rewrites_identifiers_without_touching_literals():
    luaparser = pytest.importorskip("luaparser")

    source = """
-- comment with XD should remain untouched
local f = function(XD)
    local inner = "XD"
    local bracket = [=[XD]=]
    return XD .. inner, bracket, f -- another XD
end

local record = { key = XD, call = f(XD) }
return f(XD), record, obj.XD
"""

    renamed = safe_rename(source, {"f": "runtime", "XD": "decode_driver"})

    # Ensure literals and comments are preserved verbatim.
    assert "\"XD\"" in renamed
    assert "local bracket = 'XD'" in renamed
    # Renamed identifiers should appear in function definitions and calls.
    assert "local runtime = function(decode_driver)" in renamed
    assert "runtime(decode_driver)" in renamed
    # Property access through the dot notation should not be renamed.
    assert "obj.XD" in renamed

    # Validate the output remains syntactically correct Lua.
    luaparser.ast.parse(renamed)


def test_safe_rename_rejects_reserved_targets():
    pytest.importorskip("luaparser")
    with pytest.raises(ValueError):
        safe_rename("local foo = 1", {"foo": "end"})


def test_safe_rename_records_benchmark():
    pytest.importorskip("luaparser")
    recorder = benchmark_recorder()
    snapshot = recorder.take_snapshot()
    safe_rename("local f = 1; return f", {"f": "runtime"})
    summary = recorder.summarize(snapshot)
    categories = {entry["category"] for entry in summary}
    assert "ast_transform" in categories


def test_safe_rename_respects_shadowing() -> None:
    luaparser = pytest.importorskip("luaparser")

    source = """
local function outer(foo)
    local function use_outer()
        return foo + 1
    end

    local function make_shadow()
        local foo = 32
        return foo
    end

    do
        local foo = 99
        assert(foo == 99)
    end

    return foo, use_outer(), make_shadow()
end

return outer
"""

    renamed = safe_rename(
        source,
        {
            "foo": "outer_arg",
            "use_outer": "invoke_outer",
        },
    )

    # Outer parameter and references should be renamed.
    assert "function outer(outer_arg)" in renamed
    assert "return outer_arg, invoke_outer(), make_shadow()" in renamed
    assert "outer_arg + 1" in renamed

    # Shadowed locals must remain untouched.
    assert "local foo = 32" in renamed
    assert "local foo = 99" in renamed

    # The renamed module should still parse correctly.
    luaparser.ast.parse(renamed)
