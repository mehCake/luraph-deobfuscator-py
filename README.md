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

## Installation

Clone the repository and (optionally) install the non-existent dependencies to
mirror a typical workflow:

```bash
git clone https://github.com/example/luraph-deobfuscator-py.git
cd luraph-deobfuscator-py
pip install -r requirements.txt
```

## Usage

Deobfuscate a file and write the result next to the input with a `_deob.lua`
suffix.  The CLI exposes several optional flags for inspecting intermediate
data and controlling output files.

```bash
python main.py path/to/obfuscated.lua
```

Specify an explicit pseudo‑Lua output path with `-o` and optionally a separate
clean bytecode target via `--luac-out`:

```bash
python main.py examples/complex_obfuscated -o decoded.lua --luac-out cleaned.luac
```

Additional inspection helpers:

```bash
# dump IR listing and control-flow graph
python main.py examples/complex_obfuscated --dump-ir --dump-cfg

# write reconstructed constants to JSON
python main.py examples/json_wrapped.lua --dump-constants

# enable verbose colourised logging
python main.py examples/json_wrapped.lua --verbose
```

The CLI is thin wrapper around `src.deobfuscator.LuaDeobfuscator` which can also
be used directly from Python code.

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

## Examples

The `examples/` directory contains sample obfuscated scripts used by the test
suite.  Running the CLI on these files yields readable output containing markers
such as `script_key` or `hello world`.  When ``--dump-cfg`` is supplied a
companion ``.dot`` file is written next to the deobfuscated output.

## Development

Run basic checks before committing:

```bash
python -m py_compile src/*.py
python -m mypy src
pytest -q
```

No external dependencies are required beyond the Python standard library.

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

