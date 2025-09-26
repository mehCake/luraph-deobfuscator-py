# initv4 Reverse Engineering Plan

## Current Findings
- Added Lua sandbox compatibility fixes (`src/sandbox_lua.py`) to support running initv4 bootstrap loaders under Lua 5.4 with explicit byte/str bridging, custom `bit32` stubs, and helper accessors.
- Established ability to install a native Lua runtime inside the container for fallback execution when Python emulation is blocked.
- Identified outstanding runtime errors (`table`, `bit32`, `coroutine`, and function field lookups such as `L1`) that must be satisfied to let the bootstrapper finish initialisation and expose metadata.
- Derived the default v14.4.1 opcode shuffle from static analysis: `0x00→BXOR`, `0x01→CLOSURE`, `0x02→UNM`, `0x03→SETGLOBAL`, `0x04→LT`, `0x05→TESTSET`, `0x11→LOADK`, `0x1C→LOADNIL`, `0x1F→MOVE`, `0x24→LOADN`, `0x27→PUSHK` (remaining IDs match the baseline table).

## Step-by-step Plan
1. **Stabilise Sandbox Execution**
   - Finalise the Lua sandbox helpers by providing all globals the bootstrapper expects (`bit32`, `bit`, `coroutine`, any missing helper tables such as `table.L1`/`string.L1`).
   - Once the sandbox executes without runtime errors, capture the returned table and log recorded alphabets/opcode tables.
   - Persist decoded artefacts under `out/logs/bootstrapper_metadata_*.json` for reproducibility.

2. **Extract Alphabet and Opcode Map**
   - With a successful bootstrap run, consolidate the collected alphabet candidates and opcode dispatch tables into a canonical map.
   - Document the recovered `initv4` alphabet (expected length ≥85) and opcode ID → mnemonic mapping in this plan for quick reference.
   - Add unit fixtures (under `tests/`) to guard the alphabet and opcode extraction pipeline.

3. **Implement `InitV4Decoder`**
   - Populate `src/versions/luraph_v14_4_initv4.py` with the recovered default opcode map and provide a working `InitV4Decoder` implementation that mirrors the bootstrapper’s decode pipeline (basE91, script-key XOR, index mixing).
   - Update `src/versions/initv4.py` imports once the decoder is available to remove temporary mocking.
   - Extend CLI detection in `src/main.py`/`src/passes/payload_decode.py` to use the extracted metadata when decoding payload chunks.

4. **Decode `Obfuscated.json` Sample**
   - Run `python -m src.main Obfuscated.json --script-key fkyc1zs6polofhc39f4y5s --bootstrapper initv4.lua --yes` after decoder integration.
   - Verify deobfuscated Lua output and ensure opcode lifting works by cross-checking with VM simulator tools.
   - Commit decoded artefacts (Lua + JSON reports) to `examples/` or `out/` as reference fixtures.

5. **Regression Coverage & Documentation**
   - Add regression tests that invoke the payload decoder against the supplied sample to ensure future changes keep the alphabet/opcode map intact.
   - Document the recovered alphabet/opcode map in `README.md` (or dedicated docs) and describe how to feed new script keys/bootstrapper pairs into the pipeline.
