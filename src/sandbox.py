from __future__ import annotations
from typing import Optional

# Lupa embeds LuaJIT into Python; great for controlled captures.
from lupa import LuaRuntime

def _looks_like_vm_data(lua_table) -> bool:
    try:
        t4 = lua_table[4]
        return (t4 is not None
                and hasattr(t4, "__len__")
                and len(t4) > 0
                and isinstance(t4[1], (dict, type(lua_table)))
                and isinstance(lua_table[5], (dict, type(lua_table))))
    except Exception:
        return False

def capture_unpacked(initv4_path: str, script_key: Optional[str] = None):
    """
    Load initv4.lua, set script_key, and attempt to capture 'unpackedData'
    (the VM data table). Returns a Lua table proxy (convertible to Python).
    """
    lua = LuaRuntime(unpack_returned_tuples=True, register_eval=False)

    if script_key:
        lua.execute(f"_G.script_key = {repr(script_key)}")

    with open(initv4_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    # Run bootstrap; failures after globals are OK.
    try:
        lua.execute(code)
    except Exception:
        pass

    g = lua.globals()

    # Preferred path: direct LPH_UnpackData()
    if g.get("LPH_UnpackData"):
        try:
            data = g["LPH_UnpackData"]()
            if _looks_like_vm_data(data):
                return data
        except Exception:
            pass

    # Fallback: scan global table for vm-like data
    for k in list(g.keys()):
        try:
            v = g[k]
            if _looks_like_vm_data(v):
                return v
        except Exception:
            continue

    return None
