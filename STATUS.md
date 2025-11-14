# Implementation Status: Luraph v14.4.1

The repository now ships the full scaffolding required to analyse and lift
Luraph v14.4.1 bootstrappers end-to-end:

* **Unpacked capture hooks** – `tools/devirtualize_v2.lua` injects the provided
 script key (`zkzhqwk4b58pjnudvikpf`), intercepts `LPH_UnpackData` via
  `debug.sethook`, and writes both `unpacked_dump.lua` and
  `unpacked_dump.json`.
* **Opcode inference** – Lua and Python inference layers score opcode
  candidates, persist `lift_opcodes.json`, and expose the data through
  `src/utils/opcode_inference.py` for downstream tooling.
* **Bytecode reconstruction** – the sandbox capture pipeline feeds
  `src/utils/luraph_vm.rebuild_vm_bytecode`, emitting `reconstructed.luac` and
  structured instruction metadata for regression tests.
* **Reference fixtures** – `tests/fixtures/v14_4_1` provides an initv4 bootstrap,
  obfuscated payload, expected opcode map, unpacked data, and clean Lua output.
* **Regression tests** – pytest suites exercise capture, opcode inference, and
  bytecode reconstruction; they automatically skip when LuaJIT is unavailable.

With these components in place the project no longer lacks the critical hooks
and validation artefacts required for safe Luraph v14.4.1 devirtualisation.

## Standalone VM (v14.3) Reporting

The version detector and protection scanner now cooperate to surface the
standalone VM used by ``Obfuscated4.lua``.  When the legacy
``luraph_deobfuscator.py`` shim analyses the script it logs a consolidated
summary such as ``Luraph v14.3 (VM, Real Life HIGH, strings encrypted,
double-packed constants)``, tying together the detected version, Real Life
score, string encryption flag, and the new double-packed constant heuristic.
