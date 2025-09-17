# Lua Deobfuscator (IN BETA MIGHT NOT WORK YET.)

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

The modern CLI drives the pass-based pipeline and emits a timing summary for
every processed file.  Inputs can be provided either positionally or with the
`--in` flag.  Outputs default to `<name>_deob.lua` (or `.json` when
`--format json` is requested).

```bash
# basic invocation with positional argument
python main.py path/to/obfuscated.lua

# explicitly select JSON output and request per-pass artefacts
python main.py --in examples/json_wrapped.lua --format json --write-artifacts artefacts/

# run the complex sample with multiple workers and iteration fixpoint
python main.py examples/complex_obfuscated --jobs 4 --max-iterations 3 --profile
```

Frequently used flags:

| Flag | Description |
| --- | --- |
| `-o/--out/--output` | Explicit output path (only valid for a single input file) |
| `--format {lua,json}` | Choose Lua source or a JSON metadata bundle |
| `--max-iterations N` | Re-run the pipeline until convergence or the limit is reached |
| `--skip-passes` / `--only-passes` | Comma separated pass names to disable or exclusively enable |
| `--profile` | Print a timing table for the executed passes |
| `--verbose` | Enable colourised console logging alongside `deobfuscator.log` |
| `--vm-trace`/`--trace` | Capture VM instruction traces when the simulator runs |
| `--detect-only` | Stop after version detection and emit a textual report |
| `--write-artifacts DIR` | Persist per-pass Lua/JSON artefacts for inspection |
| `--jobs N` | Process inputs in parallel using up to `N` worker threads |

Every execution prints a compact summary similar to:

```
== examples/json_wrapped.lua ==
Version: v14.1
Pass            Duration
detect          0.004s
preprocess      0.001s
payload_decode  0.013s
vm_lift         0.000s
vm_devirtualize 0.021s
cleanup         0.002s
render          0.005s
```

JSON mode (`--format json`) writes the rendered Lua alongside pass metadata,
detected version details, and the per-pass timing information shown above.
Supplying `--write-artifacts DIR` produces files such as `preprocess.lua` or
`vm_devirtualize.lua` for each processed input, which greatly simplifies
debugging new samples.

The `examples/` directory contains small samples that can be used for quick
testing.  The CLI remains a thin wrapper around
`src.deobfuscator.LuaDeobfuscator`, which can also be used directly from Python
code.

## JSON input (Luraph v14.2 JSON variant)

When a `.json` file is supplied the preprocessing stage flattens nested arrays
of strings into a single Lua chunk before handing control to the detector.  The
reconstructed source is also written to a temporary `_reconstructed.lua` file or
an artifacts directory so you can inspect the loader that ships with the JSON
payload.【F:src/passes/preprocess.py†L16-L61】

Run the variant end to end (with VM tracing enabled) using:

```bash
python main.py init.json -o ./out --trace
```

When the `-o/--out` flag targets a directory (whether or not it already exists),
the CLI will create a `<input>_deob.lua` file within that folder.  Supplying a
path with an explicit suffix writes to that file instead, matching the pipeline
logic used by the pass runner.【F:src/main.py†L95-L115】【F:src/main.py†L270-L287】

The JSON handler extracts the encoded payload, decodes the bytecode and
constant pool, inlines decrypted strings, and renames recovered registers so
the resulting Lua chunk contains the true program logic with no residual
obfuscation blobs.【F:src/passes/payload_decode.py†L16-L79】【F:src/passes/vm_devirtualize.py†L12-L84】【F:src/passes/devirtualizer.py†L1-L199】

### Detection and overrides

The high-priority `luraph_v14_2_json` handler looks for the short
`init_fn(...)` bootstrap, script-key initialisation, and long high-entropy blobs
that characterise this release.  It also walks embedded JSON/long-string blocks
to locate the payload before extracting bytecode and constants.【F:src/versions/luraph_v14_2_json.py†L13-L79】

If detection misfires you can inspect what the detector sees via
`--detect-only` or skip heuristics entirely with
`--force-version luraph_v14_2_json` on the CLI.  The override hooks straight
into the pipeline and bypasses automatic detection for the current run.【F:src/main.py†L205-L243】

### Limits & troubleshooting

- Detailed logs are always written to `deobfuscator.log`; enable `--verbose` to
  mirror them to the console while keeping the file on disk.【F:src/main.py†L1-L52】
- Unknown VM opcodes are reported with their program counter.  Check the log for
  `unknown opcode 0x..` entries when output still contains VM scaffolding.【F:src/passes/vm_lift.py†L77-L95】
- Capture a textual VM IR listing with `--dump-ir` and attach it alongside the
  original sample when filing an issue; it helps pinpoint unsupported patterns in
  the lifter or devirtualiser.【F:src/main.py†L226-L234】

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

