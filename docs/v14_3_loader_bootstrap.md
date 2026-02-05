# v14.3 Bootstrap Helper Pipeline (Analysis Notes)

This note accompanies `src/versions/v14_3_helper_analysis.py` and captures the
reasoning process used to translate the obfuscated helpers inside
`Obfuscated4.lua` into a structured specification.

## Source references

* **`__index` metatable (offset ≈6082)** – decodes five-character tokens by
  treating each character as a base-85 digit. The arithmetic
  `(Y-33) + (j-0b10001)*0x55 + (I-0x21)*7225 + (U-0b100001)*614125 + (P-0b1000001)*52200625`
  is visible in the Lua source and hashes tokens into an integer `g` that indexes
  the literal table `y("\62\073\u{0034}", g)`.
* **`N(u, 0x5)` (offset ≈9836)** – entry point that receives the session key
  (`u`) and the literal depth `0x5`. It exports the closure labelled `q3` that
  walks opcode tables `D`, `m`, `T`, etc. The dispatcher writes into the
  prototype descriptors consumed by `Y3`.
* **Arithmetic helpers (`C3.a`, `C3.s`, `C3.b`, `C3._`)** – implement
  left/right shifts and rotations used when mixing cached slots `F3[...]`. These
  helpers apply the session key by rotating and XOR-ing cache values before the
  keystream touches the serialized chunk.

## Helper summaries

The table below matches the content of `HELPER_SUMMARIES` but is provided here
for quick reference.

| Helper | Role | Key-touching behaviour |
|--------|------|------------------------|
| `Y3` | Writes the prototype count and invokes `o` per prototype. | None |
| `o` | Emits constant/instruction/child counts, then calls `M`/`r`/`O3`. | None |
| `M` | Implements the tag/payload constant encoding including opaque blob tags (`0x18`, `0x9D`, `0xA0`, `0xDA`, `0xE8`). | Indirect (opaque blobs later unpacked using the keystream) |
| `r` | Writes length-prefixed instruction payloads. | None |
| `O3` | Recursively reuses `o` for child prototypes. | None |
| `a3` | Shared little-endian base-128 varint writer. | None |
| `N` | Builds the VM-like dispatcher (`q3`) that applies the keystream, copies arithmetic results into `g`, and exposes prototypes to `Y3`. | Direct: consumes the session key table `u` via the `C3` helpers. |
| `C3` | Shift/rotate helpers referenced inside `N` when deriving keystream bytes. | Direct |

## High-level pipeline (decoded from Lua helpers)

1. **Token hashing** – Each helper token (e.g., `C3.a`, `F3[...]`) is lazily
   materialised through the metatable `__index`. The base-85 decoder converts the
   visible token strings into numeric IDs used to index the literal table `y`.
2. **Key schedule construction** – When `N(u, 0x5)` executes, it clones the
   literal tables, copies user-provided key material (`u`) into the cache vector
   `Y`, and derives the keystream using `C3` rotations and XORs. The helper slots
   `F3[...]` referenced throughout the Lua script are populated during this phase.
3. **Dispatcher execution** – The closure returned by `N` behaves like a tiny VM.
   It iterates the opcode array `D`, reads auxiliary arrays (`m`, `T`, `k3`, …),
   and executes arithmetic/table operations (branching, comparisons, keystream
   merges). Writes go into `g`, which mirrors the serialized prototype structure
   fed to `Y3`.
4. **Chunk serialization** – Once `g` contains fully populated prototype records,
   the plain helpers (`Y3`, `o`, `M`, `r`, `O3`, `a3`) serialize them using the
   layout described in `docs/v14_3_serialized_format_spec.md`.

The analysis above is purely descriptive—no executable decoder logic lives in
this document. Instead it captures the pipeline so future work can reimplement
the keystream generator and hook it up to the existing serialized chunk parser.
