# Development Notes

This repository now targets Luraph v14.4.x bootstraps.  The init shim and
runtime capture stack assume the helper names and macro semantics exposed by the
`initv4.lua` bootstrap packaged with that series.

## Init shim helper coverage

The shim in `tools/shims/initv4_shim.lua` mirrors the helper globals that the
bootstrap expects to be present before it executes:

| Helper | Behaviour |
| --- | --- |
| `L1` | Byte-wise XOR helper, supports tables and strings, honours numeric/script key salts |
| `L2` | 32-bit rotate left, bridges to `bit` library when available |
| `L3` | 32-bit rotate right |
| `Y1` | Table join/flatten, used to reassemble fragmented payloads |
| `Y2` | Converts a numeric byte table into a Lua string |
| `Y3` | Slice helper for pulling sub-ranges out of fragmented tables |
| `G1`, `Q1` | Join/identity utilities used during bootstrap normalisation |
| `Z1` | Truthy no-op (feature flags) |

The shim also tracks macro definitions (`LPH_*` identifiers) and installs
wrappers for `load`, `loadstring`, and `loadfile` so closures and upvalues can be
inspected for the `unpackedData` table.  The first VM-shaped table encountered is
serialised to `out/unpacked_dump.json` in the same layout expected by the lifter.

## Runtime capture decision flow

`src/sandbox_runner.py` drives capture using the following order:

1. **Frida** – attaches to `luajit.exe` (or a pre-recorded trace) and hooks
   `LPH_UnpackData` / `luaL_loadbuffer`.  Dumps land in `out/capture_traces/` and
   are translated through `src/runtime_capture/trace_to_unpacked.py`.
2. **LuaJIT wrapper** – executes `tools/devirtualize_v3.lua` with the shim
   preloaded.  Works on Windows 11 without additional shell tools.
3. **Unicorn emulator** – when available, the decoder is executed in a minimal
   sandbox to recover XOR/compressed buffers.
4. **In-process sandbox** – falls back to the `lupa`-based runner.

If macros such as `LPH_NO_VIRTUALIZE` are detected the CLI automatically enters a
partial mode where the lifter/verifier stages are skipped.

## Static + runtime detection

`src/detect_protections.py` inspects the bootstrap for XOR loops, compression,
fragmentation patterns, macros, and configuration tables.  The new
`src/protections.py` module performs complementary analysis on captured buffers –
it attempts to reverse simple XOR schemes, detect compression, identify
fragmentation, and flag polymorphic payloads.  Both sets of findings are embedded
in `out/summary.json` to drive later tooling.

## Windows compatibility

All subprocesses use `shell=False` and `pathlib.Path` for join/normalisation so
commands run identically in PowerShell and Command Prompt.  The helper script
`tools/run_capture_windows.cmd` automates virtual environment creation and runs
the sandbox with optional arguments.
