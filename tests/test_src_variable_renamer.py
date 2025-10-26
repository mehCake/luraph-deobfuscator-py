"""Tests for the legacy ``src.variable_renamer`` module."""

from __future__ import annotations

import pytest

from src.variable_renamer import LuaVariableRenamer


def _parse_lua(source: str):
    luaparser = pytest.importorskip("luaparser")
    return luaparser.ast.parse(source)


def test_ast_renamer_preserves_literals_and_properties() -> None:
    _parse_lua("return true")  # ensure luaparser is available

    source = """
-- comment mentioning obfuscated name a
local function a(b)
    local c = "a"
    local d = [=[a]=]
    return a(b) + c + d + obj.a
end
"""

    renamer = LuaVariableRenamer()
    renamed = renamer.rename_variables(source)

    # Comments and literal strings should stay untouched.
    assert "comment mentioning obfuscated name a" in renamed
    assert '"a"' in renamed
    assert "[=[a]=]" in renamed

    # Dot-properties must not be renamed.
    assert "obj.a" in renamed

    # Function and locals should be renamed to safer identifiers.
    assert "function" in renamed and "local" in renamed
    assert "local function a(" not in renamed

    # The renamed result should remain valid Lua code.
    _parse_lua(renamed)


def test_ast_renamer_respects_scoped_shadowing() -> None:
    _parse_lua("return true")

    source = """
local function a(b)
    local c = 0
    local function d(b)
        local c = b + 1
        return c
    end

    for e = 1, 3 do
        local b = e
        c = c + b
    end

    return c + d(b)
end
"""

    renamer = LuaVariableRenamer()
    renamed = renamer.rename_variables(source)

    # Each scope should map the original "b" to a unique identifier.
    replacements = renamer.variable_map["b"]
    assert len(replacements) >= 2

    # Renamed code remains syntactically valid.
    _parse_lua(renamed)

