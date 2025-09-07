from lupa import LuaRuntime

def run_lua_script(script_content):
    lua = LuaRuntime(unpack_returned_tuples=True)
    try:
        func = lua.execute(script_content)
        return func
    except Exception as e:
        print(f"[Lua VM] Execution failed: {e}")
        return None
