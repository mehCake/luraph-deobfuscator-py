# Lua Deobfuscator (IN BETA MIGHT NOT WORK YET.)
# Dev #ishowgoat on discord

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

## Supported releases

- **Luraph v14.4.1 (initv4)** – full bootstrap support with `--script-key`
  decoding and optional `--bootstrapper` extraction for opcode maps/alphabet
  tables supplied by `initv4.lua`.
- **Earlier 14.x JSON loaders** – automatic payload recovery for the
  `luraph_v14_2_json` family and compatible builds.

Heuristics in `src/deobfuscator.py` attempt to detect the Luraph version used
in a script.  Version specific tweaks live in `src/versions/` and are applied
automatically when the virtual machine executes embedded bytecode (currently
covering v14.0.2 through v14.4.1, including the ``initv4`` bootstrap that ships
encrypted script payloads).

## Installation

Clone the repository and install the required dependencies. The toolkit targets
Python **3.10 – 3.11** to remain compatible with the bundled `lupa` release:

```bash
git clone https://github.com/example/luraph-deobfuscator-py.git
cd luraph-deobfuscator-py
pip install -r requirements.txt
```

## Quickstart

### Windows

The repository bundles a 64-bit LuaJIT runtime under `bin/`, so no additional
system setup is needed. All helper scripts (including the initv4 shim and the
runtime capture helpers) are written with Windows 11 Command Prompt/PowerShell
compatibility in mind—no POSIX-only shell features are required. A convenience
wrapper is provided under `tools/run_capture_windows.cmd` if you prefer a
single command:

```powershell
pip install -r requirements.txt
python src/sandbox_runner.py --init initv4.lua --json Obfuscated.json --key <script_key> --out out --run-lifter
# or
tools\run_capture_windows.cmd --key <script_key>
```

### Linux / macOS

Install LuaJIT and `lua-cjson`, then install the Python dependencies:

```bash
sudo apt-get install -y luajit luarocks
sudo luarocks install lua-cjson
pip install -r requirements.txt
python src/sandbox_runner.py --init initv4.lua --json Obfuscated.json --key <script_key> --out out --run-lifter
```

Run `python tools/check_deps.py` at any time to confirm that both lupa and a
LuaJIT executable are available. The script automatically prefers the bundled
`bin/luajit.exe` when present. The Lua shim logs to `out/shim_usage.txt` and
captures fallback payloads to `out/unpacked_dump.lua.json` for post-mortem
analysis.

### Protection detection & runtime capture

The sandbox runner exposes additional instrumentation helpers for analysing
heavily protected payloads:

```bash
# Scan initv4.lua (and supporting version shims) for known protection patterns
python src/sandbox_runner.py --init initv4.lua --json Obfuscated.json \
    --key <script_key> --out out --detect-protections

# Directly run the static detector if you only need the report
python detect_protections.py initv4.lua -o out/protection_report.json

# Attempt a runtime capture using the Frida helper against a prerecorded trace
python src/sandbox_runner.py --init initv4.lua --json Obfuscated.json \
    --key <script_key> --out out --capture-runtime frida \
    --capture-target file://path/to/trace.bin

# Force the LuaJIT wrapper capture with extended logging
python src/sandbox_runner.py --init initv4.lua --json Obfuscated.json \
    --key <script_key> --out out --capture-runtime luajit --capture-timeout 20

# Run in partial mode when macros disable virtualization
python src/sandbox_runner.py --init initv4.lua --json Obfuscated.json \
    --key <script_key> --out out --force-partial
```

Runtime capture requests follow the fallback chain **Frida → LuaJIT wrapper →
emulator → in-process sandbox**. When a method fails the runner logs the error
and automatically proceeds to the next stage, ensuring static analysis still
occurs even if dynamic tooling is unavailable. The detector also adapts the
plan based on discovered macros/settings (e.g. `LPH_NO_VIRTUALIZE` will skip the
heavy lifter).

Runtime captures are written to `out/capture_traces/` (customisable via
`--capture-output`) and automatically translated into `unpacked_dump.json`
through `src/runtime_capture/trace_to_unpacked.py`. Frida integration relies on
the script shipped under `tools/frida-scripts/luraph_hook.js`; feel free to
extend it with additional symbol hooks for non-standard bootstrappers.  The
optional Unicorn- and Triton-based helpers live in
`src/runtime_capture/emulator.py` and `src/runtime_capture/symbolic_stub.py`; install
`unicorn`/`triton` if you want to experiment with those paths.

For helper coverage, runtime capture internals, and Windows-specific notes see
[`DEVELOPMENT.md`](DEVELOPMENT.md).

## Local Lua environment

We vendor a Python↔Lua bridge so you (and CI/Codex) can run Lua from the repo:

- Python deps: `pip install -r requirements.txt`
- Linux/macOS Lua setup: `bash scripts/setup_lua.sh`
- Windows setup: `powershell -ExecutionPolicy Bypass -File scripts\\setup_lua.ps1`

Smoke test:

```
python -c "from lupa import LuaRuntime; print(LuaRuntime().eval('1+1'))"
luajit -v
```

The pipeline can now load `initv4.lua` and capture `unpackedData` via `src/sandbox.py`
(using embedded LuaJIT through lupa).

### Reproducible environments

- The `requirements.txt` file now pins the Python packages required for
  bootstrap decoding (`lupa`, `construct`, `pycryptodome`, `base91`) alongside
  developer tooling such as `pytest`, `black`, and `ruff`.
- A ready-to-build container image lives under `docker/Dockerfile`; it installs
  LuaJIT, `lua-cjson`, Stylua, and the Python toolchain. Build it with:

  ```bash
  docker build -t luraph-deobfuscator -f docker/Dockerfile .
  ```

- For opt-in Lua execution the helper in `src/sandbox.py` uses `lupa` to load
  `initv4.lua` inside a restricted interpreter and capture the `unpackedData`
  table without leaving Python.

## Usage

The modern CLI drives the pass-based pipeline and emits a timing summary for
every processed file.  Inputs can be provided either positionally or with the
`--in` flag.  Outputs default to `<name>_deob.lua` *and* `<name>_deob.json`,
providing both the cleaned Lua script and a merged JSON report.  Use
`--format lua` to suppress the JSON sidecar or `--format json` to route the
report to the primary output path while still emitting the Lua file.

```bash
# Quick start against the bundled v14.4.1 sample
python main.py Obfuscated.json --script-key <your_key> --bootstrapper initv4.lua --yes

# Basic invocation with positional argument
python main.py path/to/obfuscated.lua

# Explicitly select JSON output and request per-pass artefacts
python main.py --in examples/json_wrapped.lua --format json --write-artifacts artefacts/

# Run the complex sample with multiple workers and iteration fixpoint
python main.py examples/complex_obfuscated --jobs 4 --max-iterations 3 --profile
```

Frequently used flags:

| Flag | Description |
| --- | --- |
| `-o/--out/--output` | Explicit output path (only valid for a single input file) |
| `--format {lua,json,both}` | Select Lua-only output, JSON-focused output, or both (default) |
| `--max-iterations N` | Re-run the pipeline until convergence or the limit is reached |
| `--skip-passes` / `--only-passes` | Comma separated pass names to disable or exclusively enable |
| `--profile` | Print a timing table for the executed passes |
| `--script-key KEY` | Provide the decryption key required by Luraph v14.4.x payloads |
| `--bootstrapper PATH` | Load an initv4 stub to recover its alphabet/opcode table automatically |
| `--debug-bootstrap` | Dump detailed bootstrapper extraction logs and raw regex matches |
| `--allow-lua-run` | Permit the sandboxed Lua fallback when Python decoding fails |
| `--alphabet STRING` | Force a manual initv4 alphabet and skip bootstrap extraction |
| `--opcode-map-json PATH` | Provide a JSON opcode dispatch map instead of extracting it |
| `--yes` | Auto-confirm detected versions and bootstrapper prompts |
| `--force` | Continue even if required data (such as `--script-key`) is missing |
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
detected version details, and the per-pass timing information shown above while
keeping the formatted Lua script next to the report for inspection.
Supplying `--write-artifacts DIR` produces files such as `preprocess.lua` or
`vm_devirtualize.lua` for each processed input, which greatly simplifies
debugging new samples.

### Luraph v14.4.1 bootstrap workflows

Luraph v14.4.1 ships an `initv4` bootstrapper that hides VM bytecode inside
high-entropy blobs and decrypts them with the user-visible `script_key`.  The
CLI exposes two options that mirror this workflow:

- `--script-key` – supply the key handed out with the protected download.  Runs
  that target initv4 payloads abort when no key is available unless `--force`
  is explicitly provided.
- `--bootstrapper` – point at the accompanying `initv4.lua` (or a directory
  containing it) so the deobfuscator can harvest the custom alphabet and opcode
  dispatch table automatically.
- `--alphabet` / `--opcode-map-json` – supply trusted overrides for the
  bootstrap alphabet or opcode table.  When either flag is used the tool skips
  bootstrap extraction entirely and relies on the provided data.

When both arguments are present the CLI favours the script key on the command
line but still uses the bootstrapper metadata to remap opcodes.  If the key is
embedded in the obfuscated script the detector reuses it, otherwise you must
provide `--script-key` (or run with `--force` to request a best-effort decode)
before devirtualisation proceeds.  `--bootstrapper` can then focus purely on
opcode/alphabet extraction.

When initv4 hides metadata inside high-entropy blobs, the extractor first tries
to reproduce the Lua decode routine in pure Python.  If those heuristics fall
short, the pipeline can **optionally** retry inside a sandboxed LuaJIT runtime
powered by [`lupa`](https://pypi.org/project/lupa/).  This dual-mode flow
defaults to the safer Python implementation and only executes Lua when:

1. the Python reimplementation failed to recover usable metadata,
2. `lupa` is installed locally, and
3. you explicitly pass `--allow-lua-run` (or run unattended with `--force` and
   `--debug-bootstrap`).

The sandbox replaces the global environment, blocks file system and network
primitives, enforces an instruction budget, and intercepts `load`/`loadstring`
to capture the decoded chunk without executing arbitrary payloads.  **Because
any third-party Lua code might still be hostile, only enable `--allow-lua-run`
on machines you trust and that can be discarded if compromised. Never run the
fallback on production hosts or with secrets accessible to the process.**
Installing `lupa>=1.8.0` (LuaJIT must be available on the system) enables this
fallback path; without it the extractor logs that emulation is required and
keeps the partially decoded blob under `out/logs/` for manual analysis.

### User-run Lua environment (debug hook toolkit)

Researchers that prefer to experiment outside of the Python pipeline can use
the tooling under `tools/` (or the mirrored `tools/user_env/` directory) to
capture and analyse initv4 payloads with their own LuaJIT binary:

1. `devirtualize_v2.lua` injects the `script_key`, attaches a `debug.sethook`
   handler, runs `initv4.lua`, and dumps the captured `unpackedData` table to
   `unpacked_dump.lua`/`unpacked_dump.json`.  Once recovered it automatically
   invokes `lifter.lua` to render a pseudo-IR listing (`lift_ir.lua`) together
   with a short diagnostic report (`lift_report.txt`).
2. `lifter.lua` exposes a Lua-based opcode scaffolding where opcode numbers can
   be mapped to mnemonics incrementally.  The default implementation prints the
   instruction stream using the canonical Lua 5.1 opcode table.
3. `reformat_v2.lua` performs block-aware indentation and string merging on
   decoded Lua text so that the lifted scripts remain readable.

Minimal example (Windows PowerShell shown, adjust for your shell):

```powershell
cd path\to\luraph-deobfuscator-py
    luajit tools/devirtualize_v2.lua zkzhqwk4b58pjnudvikpf
luajit tools/reformat_v2.lua decoded_output.lua > readable.lua
```

The versions under `tools/user_env/` remain available for backwards
compatibility; both sets of scripts share the same behaviour so researchers can
copy whichever layout they prefer next to `initv4.lua` and `Obfuscated.json`.

See `examples/mini_vm/` for a toy payload and its `expected.lua` output that the
integration tests use to keep the toolkit exercised.

All bootstrapper transforms now ship with a pure-Python basE91 decoder, so the
`base91` dependency is optional.  When the library is installed it is used for
speed; otherwise the bundled implementation transparently takes over.  Missing
`lupa` simply disables the Lua fallback while the Python pipeline continues to
run.

Debugging bootstrapper extraction works best with `--debug-bootstrap`, which
prints the recovered alphabet length, opcode previews, and extraction notes to
the console and writes a full trace to `out/logs/bootstrap_extract_debug_*.log`.
The decoded blobs and JSON metadata live under `out/logs/bootstrap_decoded_*.bin`
and `out/logs/bootstrapper_metadata_*.json` respectively, making it easy to
compare Python-vs-Lua paths or inspect partially decoded payloads.

Practical combinations look like:

```bash
# Decode a standalone payload with the script key that Luraph provided
python main.py --script-key x5elqj5j4ibv9z3329g7b examples/v1441_hello.lua

# Reuse the script key embedded in the file but supply a bootstrapper directory
# so opcode mappings and the alphabet are recovered from initv4.lua automatically
python main.py --bootstrapper tests/fixtures/initv4_stub examples/v1441_hello.lua

# Provide both arguments – the explicit key wins while the bootstrapper enriches
# metadata and remaps opcodes for custom builds
python main.py --script-key x5elqj5j4ibv9z3329g7b --bootstrapper tests/fixtures/initv4_stub/initv4.lua \
    examples/v1441_hello.lua
```

The `examples/` directory contains small samples that can be used for quick
testing.  The CLI remains a thin wrapper around
`src.deobfuscator.LuaDeobfuscator`, which can also be used directly from Python
code.

### Script key policy and interactive confirmations

- **Always provide `--script-key` for full initv4 decoding.** Keys rotate
  frequently and the deobfuscator aborts before VM lifting when no key is
  available.  Use `--force` only when you intentionally want a best-effort run
  that skips encrypted payloads.
- **No built-in production keys.** The tool never iterates over a list of
  defaults; it only honours the explicit value you supply (or one embedded in
  the script).  For CI and reproducible testing we keep a dedicated test vector
  key (`x5elqj5j4ibv9z3329g7b`, previously `8ta4sq5m2gqw1fy1tq1sh`) inside the
  test suite.  These helpers are not used at runtime.
- **Bootstrapper checks remain interactive.** When detection spots a Luraph
  banner or a supplied bootstrapper, the CLI requests confirmation before
  proceeding.  Pass `--yes` for unattended workflows or CI pipelines.

The CLI emits `<input>_deob.lua` together with `<input>_deob.json` by default.

### User-run Lua environment (Windows / LuaJIT)
If you want to run the bootstrap locally and get **readable Lua outputs** without touching the Python tooling, see the helper scripts under `tools/user_env/`:

- `tools/user_env/devirtualize.lua`
- `tools/user_env/reformat.lua`
- `tools/user_env/run_all.ps1`
- `tools/user_env/README_user_env.md`

Example PowerShell usage from the repository root:

```powershell
./tools/user_env/run_all.ps1 -ScriptKey "zkzhqwk4b58pjnudvikpf"
```

This writes `readable.lua` (or chunked `chunkN_readable.lua`) next to your input files.
The Lua file contains the cleaned, formatted script; the JSON sidecar captures
detected version data, confirmation status, decoded chunk statistics, VM
metadata (opcode counts, traps removed, jump tables), warnings, and errors.  Use
`--format lua` to skip the JSON report or `--format json` to prioritise the
report while still writing the Lua file alongside it.

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

### Luraph v14.4.1 initv4 payloads

Luraph 14.4.1 distributes bytecode through an `initv4` bootstrap that stores
the VM program inside a high-entropy blob.  The bootstrap XORs that blob with a
per-script `script_key` prior to handing it to the VM.  When running the
deobfuscator you must supply that key so the payload decoder can recover the
embedded bytecode:

```bash
python main.py --script-key <your_key> examples/v1441_hello.lua
```

Keys are issued alongside protected scripts by Luraph.  For automated runs you
can also set the `LURAPH_SCRIPT_KEY` environment variable.  Successful decoding
produces readable Lua just like earlier versions, with the VM scaffolding
removed and the recovered script formatted via the built-in beautifier.  The
`examples/v1441_hello.lua` sample together with the corresponding golden output
under `tests/golden/` can be used as a quick smoke test when validating the
pipeline.

