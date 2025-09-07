import lupa
from lupa import LuaRuntime
import luaparser
from luaparser import ast

# Step 1: Unpack Luraph data (handles "LPH!" prefix and repeaters)
def unpack_lph_data(lph_string):
    if not lph_string.startswith("LPH!"):
        raise ValueError("Invalid LPH string")
    
    # Remove prefix and process hex pairs with repeaters
    data = lph_string[4:]  # Skip "LPH!"
    unpacked = []
    i = 0
    while i < len(data):
        if data[i].isdigit():  # Repeater like "3X" -> repeat "X" 3 times
            count = int(data[i])
            value = data[i+1]
            unpacked.extend([value] * count)
            i += 2
        else:
            # Hex pair to byte (assume 2-char hex)
            byte = int(data[i:i+2], 16)
            unpacked.append(byte)
            i += 2
    return unpacked

# Step 2: Simulate Lua execution to dump unpacked data
def dump_unpacked_data(obf_script):
    lua = LuaRuntime(unpack_lua_libs=True)  # Embed Lua runtime
    
    # Mock Roblox/Lua globals (for Roblox-specific Luraph scripts)
    globals_dict = {
        'game': lua.eval('{}'),  # Empty table for game
        'getgenv': lua.eval('function() return {} end'),  # Mock getgenv
        'script_key': "your_script_key_here"  # Replace with actual key if known
    }
    lua.globals().update(globals_dict)
    
    # Hook loadstring to capture decrypted code (if used)
    def hooked_loadstring(s):
        print("Captured decrypted code:", s)
        return lua.eval('loadstring')(s)
    lua.globals()['loadstring'] = hooked_loadstring
    
    # Execute the obfuscated script and capture unpacked data
    try:
        # Run script in Lua runtime
        func = lua.eval(obf_script)
        # Simulate VMRun call (adjust based on script; assumes it returns a function)
        result = func()
        # Dump key data (e.g., assume unpackedData is in globals after run)
        unpacked_data = lua.globals().get('unpackedData', None)  # Hook this in your script if needed
        return unpacked_data or result
    except Exception as e:
        raise RuntimeError(f"Simulation failed: {e}")

# Step 3: Lift Luraph opcodes to Lua (basic mapping; expand for v4)
LURAPH_TO_LUA_OPCODES = {
    1: 'OP_MOVE',      # Example mappings from guides
    2: 'OP_LOADK',
    3: 'OP_LOADBOOL',
    4: 'OP_LOADNIL',
    # Add more from analysis (e.g., from Ferib's blog: opcodes <16 branch into sub-ops)
    # For v4, analyze IF trees in interpreter function
}

def lift_opcodes(unpacked_data):
    if not unpacked_data:
        return "No data to lift"
    
    # Assume unpacked_data[3] is instructions list
    instructions = unpacked_data[3] if len(unpacked_data) > 3 else unpacked_data
    lifted = []
    for instr in instructions:
        opcode = instr[2] if isinstance(instr, list) and len(instr) > 2 else instr  # Adjust index per version
        lua_op = LURAPH_TO_LUA_OPCODES.get(opcode, f'UNKNOWN_OP_{opcode}')
        lifted.append(f"{lua_op} {instr}")  # Simplified; build full Lua instr
    return '\n'.join(lifted)

# Step 4: Reconstruct and pretty-print Lua script
def reconstruct_lua(lifted_code):
    # Parse lifted code as Lua AST
    tree = luaparser.parse(lifted_code)
    # Pretty-print (deobfuscate names, etc.)
    deobf_ast = ast.to_pretty_str(tree)
    return deobf_ast

# Main function
def deobfuscate_luraph(obf_script_path, lph_string=None):
    with open(obf_script_path, 'r') as f:
        obf_script = f.read()
    
    # If LPH string provided (from JSON/hex in your case)
    if lph_string:
        unpacked = unpack_lph_data(lph_string)
    else:
        unpacked = dump_unpacked_data(obf_script)
    
    lifted = lift_opcodes(unpacked)
    deobf_script = reconstruct_lua(lifted)
    return deobf_script

# Example usage
if __name__ == "__main__":
    # Replace with your file and hex string from the JSON
    obf_path = "obfuscated.lua"  # Your Luraph script
    hex_string = "your_hex_string_here"  # From JSON[0]
    result = deobfuscate_luraph(obf_path, f"LPH!{hex_string}")
    print("Deobfuscated script:\n", result)
    # Save to file
    with open("deobfuscated.lua", "w") as f:
        f.write(result)
