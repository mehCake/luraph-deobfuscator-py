# Lua Deobfuscator

Utilities for decoding Lua scripts obfuscated with Luraph/Luarmor styles.  The
project ships a small command line interface together with a handful of helper
modules located under `src/`.  A tiny stack based virtual machine is included
for experimenting with devirtualisation of custom bytecode formats.  It is not
a full re‑implementation of Luraph's VM but provides a foundation for further
work.

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
suffix:

```bash
python main.py path/to/obfuscated.lua
```

Specify an explicit output path with `-o`:

```bash
python main.py examples/complex_obfuscated -o decoded.lua
```

The CLI is thin wrapper around `src.deobfuscator.LuaDeobfuscator` which can also
be used directly from Python code.

The deobfuscator can also recognise JSON payloads stored inside Lua long
strings—commonly used by Luraph—to automatically extract and decode the hidden
source.

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

The VM currently understands only a tiny instruction set.  Supported opcodes
include:

- `LOADK`, `LOADN`, `LOADB/LOADBOOL`, `LOADNIL`, `MOVE`
- `GETGLOBAL`, `SETGLOBAL`
- arithmetic operations `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `UNM` and `CONCAT`
- comparison and logic `EQ`, `NE`, `LT`, `LE`, `GT`, `GE`, `NOT`
- bitwise ops `BAND`, `BOR`, `BXOR`, `BNOT`, `SHL`, `SHR`
- table handling `NEWTABLE`, `SETTABLE`, `GETTABLE`, `LEN`
- flow control `JMP`, `JMPIF`, `JMPIFNOT`, `FORPREP`, `FORLOOP`
- function invocation via `CALL`
- `RETURN`

This list grows over time as devirtualisation support is expanded.

## Examples

The `examples/` directory contains sample obfuscated scripts used by the test
suite.  Running the CLI on these files yields readable output containing markers
such as `script_key` or `hello world`.

## Development

Run basic checks before committing:

```bash
python -m py_compile src/*.py
pytest -q
```

No external dependencies are required beyond the Python standard library.

