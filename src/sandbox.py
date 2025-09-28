"""Lua sandbox helpers for capturing ``unpackedData`` tables."""

from __future__ import annotations

from typing import Optional

from lupa import LuaRuntime

_HOOK_SNIPPET = r"""
local captured_unpacked = nil

local function is_vm_data_shape(t)
    if type(t) ~= "table" then return false end
    local instr = t[4]
    if type(instr) ~= "table" or #instr == 0 then return false end
    local first = instr[1]
    if type(first) ~= "table" or type(first[3]) ~= "number" then return false end
    if type(t[5]) ~= "table" then return false end
    return true
end

function __luraph_capture_setup()
    captured_unpacked = nil
    debug.sethook(function(event)
        if event == "call" then
            local i = 1
            while true do
                local name, value = debug.getlocal(2, i)
                if not name then break end
                if type(value) == "table" and is_vm_data_shape(value) then
                    captured_unpacked = value
                    debug.sethook()
                    return
                end
                i = i + 1
            end
        end
    end, "c")
end

function __luraph_capture_result()
    return captured_unpacked
end

function __luraph_trigger_candidates()
    local names = {"VMRun", "Run", "Init", "bootstrap", "main"}
    for _, name in ipairs(names) do
        local fn = _G[name]
        if type(fn) == "function" then
            pcall(function()
                fn("LPH!tick", _G)
            end)
        end
    end
end
"""


def _looks_like_vm_data(lua_table) -> bool:
    try:
        t4 = lua_table[4]
        return (
            t4 is not None
            and hasattr(t4, "__len__")
            and len(t4) > 0
            and isinstance(t4[1], (dict, type(lua_table)))
            and isinstance(lua_table[5], (dict, type(lua_table)))
        )
    except Exception:
        return False


def capture_unpacked(initv4_path: str, script_key: Optional[str] = None):
    """Execute ``initv4.lua`` inside LuaJIT and capture ``unpackedData``."""

    lua = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    lua.execute(_HOOK_SNIPPET)

    if script_key:
        lua.execute(f"_G.script_key = {repr(script_key)}")

    with open(initv4_path, "r", encoding="utf-8", errors="ignore") as handle:
        code = handle.read()

    try:
        lua.eval("__luraph_capture_setup")()
    except Exception:
        pass

    try:
        lua.execute(code)
    except Exception:
        # The bootstrap often raises after scheduling the VM. We ignore errors
        # here because the hook/global scans below usually still succeed.
        pass

    globals_table = lua.globals()

    if globals_table.get("LPH_UnpackData"):
        try:
            unpacked = globals_table["LPH_UnpackData"]()
            if _looks_like_vm_data(unpacked):
                return unpacked
        except Exception:
            pass

    try:
        captured = lua.eval("__luraph_capture_result")()
        if captured and _looks_like_vm_data(captured):
            return captured
    except Exception:
        pass

    try:
        lua.eval("__luraph_capture_setup")()
        lua.eval("__luraph_trigger_candidates")()
        captured = lua.eval("__luraph_capture_result")()
        if captured and _looks_like_vm_data(captured):
            return captured
    except Exception:
        pass

    for key in list(globals_table.keys()):
        try:
            value = globals_table[key]
            if _looks_like_vm_data(value):
                return value
        except Exception:
            continue

    return None
