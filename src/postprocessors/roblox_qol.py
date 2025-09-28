"""Roblox-specific quality-of-life clean-ups for deobfuscated Lua scripts."""

from __future__ import annotations

import re

_DOUBLE_PATTERN = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*(?:\+|\.\.)\s*"([^"\\]*(?:\\.[^"\\]*)*)"')
_SINGLE_PATTERN = re.compile(r"'([^'\\]*(?:\\.[^'\\]*)*)'\s*(?:\+|\.\.)\s*'([^'\\]*(?:\\.[^'\\]*)*)'")

CLASSIFY_FUNCTION = """
local function classifyLoot(name)
    name = tostring(name or "")
    local lower = name:lower()
    local mapping = {
        ["medium safe"] = "Medium Safe",
        ["small safe"] = "Small Safe",
        ["atm"] = "ATM",
        ["cash register"] = "Cash Register",
        ["register"] = "Cash Register",
        ["vending"] = "Vending Machine",
        ["crate"] = "Loot Crate",
        ["drop"] = "Cash Drop",
    }

    for key, label in pairs(mapping) do
        if lower:find(key, 1, true) then
            return label
        end
    end

    return name
end
"""

TOGGLE_CONFIG = """
local qol_config = {
    view_medium_safe = true,
    view_small_safe = true,
    view_atm = true,
    loot_esp = true,
    boxes_corner = false,
    friendcheck = true,
}
"""

TOGGLE_BLOCK = """
local QoLToggles = {
    { id = "view_medium_safe", label = "View Medium Safes", default = true },
    { id = "view_small_safe", label = "View Small Safes", default = true },
    { id = "view_atm", label = "View ATMs", default = true },
    { id = "loot_esp", label = "Loot ESP", default = true },
    { id = "boxes_corner", label = "Boxes Corner", default = false },
    { id = "friendcheck", label = "Friend Check", default = true },
}

for _, toggle in ipairs(QoLToggles) do
    if qol_config[toggle.id] == nil then
        qol_config[toggle.id] = toggle.default
    end
end
"""


def _merge_literals(pattern: re.Pattern[str], text: str) -> tuple[str, bool]:
    def repl(match: re.Match[str]) -> str:
        left = match.group(1)
        right = match.group(2)
        return '"' + left + right + '"'

    replaced, count = pattern.subn(repl, text)
    return replaced, count > 0


def _merge_adjacent_strings(source: str) -> str:
    changed = True
    while changed:
        changed = False
        source, double_changed = _merge_literals(_DOUBLE_PATTERN, source)
        source, single_changed = _merge_literals(_SINGLE_PATTERN, source)
        changed = double_changed or single_changed
    return source


def _ensure_snippet(source: str, snippet: str) -> str:
    snippet = snippet.strip()
    if snippet and snippet not in source:
        return snippet + "\n\n" + source
    return source


def apply(source: str) -> str:
    """Return a cleaned Lua script tailored for Roblox QoL tooling."""

    cleaned = _merge_adjacent_strings(source)
    cleaned = _ensure_snippet(cleaned, CLASSIFY_FUNCTION)
    cleaned = _ensure_snippet(cleaned, TOGGLE_CONFIG)
    cleaned = _ensure_snippet(cleaned, TOGGLE_BLOCK)
    return cleaned


def postprocess(source: str) -> str:
    """Public entry point used by the CLI."""

    return apply(source)


__all__ = ["apply", "postprocess", "CLASSIFY_FUNCTION", "TOGGLE_CONFIG", "TOGGLE_BLOCK"]

