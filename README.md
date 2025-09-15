# Lua Deobfuscator

Utilities for decoding Lua scripts obfuscated with Luraph/Luarmor styles.  The
project ships a small command line interface together with a handful of helper
modules located under `src/`.  A tiny stack based virtual machine is included
for experimenting with devirtualisation of custom bytecode formats.  The VM is
implemented in a modular fashion under `src/vm/` with separate files for state
management, opcode handlers and the emulator itself.  It is not a full
re‑implementation of Luraph's VM but provides a foundation for further work.
Building on top of the VM, the `src/passes/devirtualizer.py` module illustrates
how control‑flow graphs, taint tracking and symbolic execution can be combined
to reconstruct readable Lua from simple bytecode traces.

Heuristics in `src/deobfuscator.py` attempt to detect the Luraph version used
in a script.  Version specific tweaks live in `src/versions/` and are applied
automatically when the virtual machine executes embedded bytecode (currently
covering v14.0.2 through v14.2).

## Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/example/luraph-deobfuscator-py.git
cd luraph-deobfuscator-py
pip install -r requirements.txt  # installs networkx, sympy, and test tools
```

## Usage

Deobfuscate a file or directory and write the result next to the input with a
`_deob.lua` suffix.  The CLI now focuses on the staged pipeline exposed by
`src.deobfuscator` and keeps only a handful of flags for convenience.

```bash
python main.py path/to/obfuscated.lua
python main.py examples/

# run the full pipeline on the complex fixtures with tracing and four workers
python main.py examples/complex_obfuscated --jobs 4 --max-iterations 3 --trace
```

Key options:

- `-o/--output` – explicit output file (only valid with a single input file)
- `--max-iterations N` – rerun the pipeline up to *N* times until convergence
- `--version V` – override version detection heuristics
- `--trace` – enable opcode-level tracing written to `deobfuscator.log`
- `--jobs N` – process inputs in parallel using up to *N* worker threads

The `examples/` directory contains small samples that can be used for quick
testing.  The CLI remains a thin wrapper around
`src.deobfuscator.LuaDeobfuscator`, which can also be used directly from Python
code.

## Project map

The repository keeps long-lived helper modules at the top level for
backwards-compatible workflows while new development happens inside the
`src/` package.  The most relevant entry points are:

- **Command line** – `main.py` provides the modern CLI, whereas `run.py` and
  `luraph_deobfuscator.py` expose legacy flows that internally reuse the same
  helpers.
- **Decoding pipeline** – `src/pipeline.py` wires the pass registry used by the
  CLI.  Pass implementations live in `src/passes/` and operate on the shared
  context object defined there.
- **Core analysis** – `version_detector.py`, `lph_handler.py`,
  `string_decryptor.py`, `constant_reconstructor.py`, `opcode_lifter.py`,
  `pattern_analyzer.py`, `trap_detector.py`, and `variable_renamer.py` handle
  heuristics, decoding, and cleanup tasks.  Their modern counterparts expose
  class-based APIs under `src/` for programmatic use.
- **VM and devirtualization** – `src/vm/` contains the modular virtual machine
  (state, opcode handlers, emulator) and `src/passes/devirtualizer.py` lifts VM
  traces into an intermediate representation defined in `src/ir.py` and
  `src/lua_ast.py`.

All components are pure Python and can be extended without altering the
existing structure.  New Luraph versions can register extra handlers under
`src/versions/` and opt-in through the pass pipeline.

The deobfuscator recognises JSON payloads stored inside Lua long
strings—commonly used by Luraph—to automatically extract and decode the hidden
source.  Constant pools are decrypted on the fly, including Luraph v14
``LPH_ENCFUNC`` tables for both strings and numbers.  String constants embedded
in VM payloads are XOR-decoded with the built-in key (e.g.
``hxsk0st7cyvjkicxnibhbm``).  Registers and function
parameters are renamed to readable identifiers (``R0`` → ``a``; ``arg1``) and
upvalues gain ``uv1``/``uv2`` style names.

Known anti‑debugging traps such as line checks via `debug.getinfo`, `pcall`
format guards or closure integrity tests are automatically replaced with benign
runtime stubs so protected scripts continue to execute cleanly during analysis.

### Virtual Machine input

`LuaDeobfuscator` understands a very small JSON format describing VM
bytecode.  The structure is:

```json
{
  "constants": ["hello"],
  "bytecode": [["LOADK", 0], ["RETURN"]]
}
```

Running the deobfuscator on such a file yields the constant `"hello"` by
executing the bytecode on the bundled VM.

The VM currently understands a growing instruction set roughly matching Lua 5.1
semantics.  Supported opcodes include:

- `LOADK`, `LOADN`, `LOADB/LOADBOOL`, `LOADNIL`, `MOVE`
- global and upvalue access: `GETGLOBAL`, `SETGLOBAL`, `GETUPVAL`, `SETUPVAL`
- arithmetic operations `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `UNM` and
  `CONCAT` with basic metamethod support
- comparison and logic `EQ`, `NE`, `LT`, `LE`, `GT`, `GE`, `NOT`
- bitwise ops `BAND`, `BOR`, `BXOR`, `BNOT`, `SHL`, `SHR`
- table handling `NEWTABLE`, `SETTABLE`, `GETTABLE`, `LEN` (respecting
  `__index`/`__newindex`/`__len` metamethods)
- varargs and closures via `VARARG` and `CLOSURE`
- flow control `JMP`, `JMPIF`, `JMPIFNOT`, `FORPREP`, `FORLOOP`
- object and list helpers `SELF`, `SETLIST`, `CLOSE`
- conditional tests `TEST`, `TESTSET`
- function invocation via `CALL`/`TAILCALL`
- `RETURN`

The generic iterator opcode `TFORLOOP` is wired into the dispatch table and will
raise an explicit error if encountered.  A basic
control‑flow graph builder can recover ``if``/``while``/``for`` structures from
IR and, when the CLI is invoked with ``--dump-cfg``, produces Graphviz DOT files
for visual inspection.  Dead branches introduced by opaque predicates are pruned
during this analysis.

VM execution is protected by a configurable instruction budget (default
50,000 steps) and an execution timeout (default five seconds) so adversarial
payloads cannot hang the tool.  These limits apply both when the VM is invoked
from the CLI and when helper utilities such as ``utils.decode_virtual_machine``
run standalone payloads.

## Examples

The `examples/` directory contains sample obfuscated scripts used by the test
suite.  Running the CLI on these files yields readable output containing markers
such as `script_key` or `hello world`.  When ``--dump-cfg`` is supplied a
companion ``.dot`` file is written next to the deobfuscated output.

## Guarantees

- **Offline only.**  The tool intentionally rejects `http://` and `https://`
  inputs so that all work happens on local files.  This makes automated testing
  deterministic and avoids surprising network access.
- **Deterministic output.**  Helpers normalise whitespace and output paths, and
  the pass registry keeps a stable ordering so consecutive runs produce
  identical artefacts.
- **Sandboxed VM execution.**  The bundled virtual machine enforces instruction
  and wall-clock limits so malformed payloads cannot hang the process.
- **Extensible by construction.**  Version-specific tweaks live in
  `src/versions/` and the pass registry makes it simple to insert or disable
  passes when experimenting with new Luraph variants.

## Known limits

- The VM focuses on Luraph v14.x semantics.  Exotic third-party opcode packs
  may require additional handlers.
- Reconstruction favours readability over byte-perfect reproduction; formatting
  may differ from the original unobfuscated script.
- Only local filesystem inputs are supported.  Remote URLs must be downloaded
  manually before running the tool.

## Adding support for new Luraph versions

Version-specific behaviour is described declaratively in
`src/versions/config.json`.  To onboard a new release:

1. Create a module under `src/versions/` (for example `v14_3.py`) exporting a
   `process(vm: LuraphVM) -> None` function to patch opcode handlers or apply
   runtime bypasses.
2. Extend `config.json` with a new entry under `"versions"` referencing the
   module and mapping observed opcode identifiers.
3. Capture detection heuristics (loader signatures, constant table hints,
   prologue shapes) so `VersionDetector` can automatically select the new
   handler.
4. Add regression samples to `examples/` and golden outputs to `tests/golden/`,
   then extend `tests/test_versions.py` so the new heuristics are covered.

### `config.json` schema

Each entry under `"versions"` provides:

- `module` – the Python module name under `src/versions/` exposing `process`.
- `opcode_map` – a mapping from canonical opcode names (`LOADK`, `CALL`, …) to
  version-specific identifiers.  The devirtualizer uses this to lift bytecode
  into the shared IR.
- `heuristics` – structured hints used during detection.  Supported keys:
  - `signatures`: regex strings matched against the raw source.
  - `loaders`: regexes representing loader shapes.
  - `upvalues`: markers for closure usage.
  - `long_strings`: regexes used when scanning Lua long strings.
  - `constants`: strings expected in decoded constant pools.
  - `prologues`: regexes for instruction or function prologues.
- `known_traps` – identifiers consumed by `trap_detector` to enable targeted
  bypasses.

`VersionDetector` scores heuristics and selects the best match.  Missing fields
default to empty lists, so partial descriptors are accepted while iterating on
new samples.

## Development

Run basic checks before committing:

```bash
python -m py_compile $(git ls-files '*.py')
pytest -q
```

External dependencies such as `networkx` and `sympy` are used for control-flow
analysis and symbolic simplification; install them with `pip install -r
requirements.txt`.

Additional regression suites focus on fuzzing and performance hardening:

- `pytest -q tests/test_vm_fuzz.py` exercises random VM programs against a
  reference interpreter to ensure opcode semantics remain stable.
- `pytest -q tests/test_vm_limits.py tests/test_parallel.py` checks that
  instruction limits, timeouts, and the parallel dispatcher behave correctly.
- ``src.utils.benchmark_parallel`` compares sequential and parallel runs and
  raises when the parallel pass exceeds twice the baseline duration.

### Contributing

Support for future Luraph variants hinges on a solid test suite.  When adding a
new opcode:

1. Implement its handler in `src/vm/opcodes.py` and register it in the
   `OPCODE_HANDLERS` dispatch table.
2. Add a focused regression test to `tests/test_vm.py` demonstrating its
   behaviour (include closure/vararg/metamethod scenarios if relevant).
3. For end‑to‑end samples, drop an obfuscated file in `examples/`, create the
   expected deobfuscated output under `tests/golden/`, and extend
   `tests/test_examples.py`.

Pull requests are validated by continuous integration which runs `py_compile`,
`mypy`, and `pytest` on every push.

