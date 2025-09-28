# User-run Lua Environment (Windows 11 / LuaJIT)

## What you get
- **Devirtualizer Runner** – executes your `initv4.lua` bootstrap with your `script_key` to recover the decoded Lua.
- **Reformatter** – turns the decoded Lua into readable, consistently formatted code.

## Prereqs
- Windows 11
- A LuaJIT (or Lua 5.1) executable on your PATH (`luajit -v` should print version).
- Files in the same folder:
  - `initv4.lua`
  - `Obfuscated.json`

## Quick start (PowerShell)
```powershell
# From the repo root
./tools/user_env/run_all.ps1 -ScriptKey "ppcg208ty9nze5wcoldxh"
```

### Outputs
- `decoded_output.lua` or `decoded_chunk_###.lua`
- `readable.lua` or `chunkN_readable.lua`

If you see “No decoded output recovered”, edit `devirtualize.lua`’s `try_extract()` to call the exact function your `initv4.lua` defines (e.g., `Run`, `Init`, `bootstrap`, etc.).
