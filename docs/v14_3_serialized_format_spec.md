# Luraph v14.3 Serialized Chunk Format (Spec)

> _This document captures the current understanding of the v14.3 serialized
> payload emitted by `Obfuscated4.lua`. The layout is inferred from the static
> analysis harness (`probe_v14_3_blob`), the instrumented writer simulator
> (`V14_3Writer` + `simulate_v14_3_writer`), and direct inspection of the Lua
> loader helpers (`Y3`, `o`, `M`, `r`, `a3`, `O3`, …). When evidence is
> inconclusive, the adopted interpretation is stated explicitly so downstream
> tooling has a consistent contract._

## 1. High-Level Layout

The loader emits a single byte stream that the embedded VM later interprets as a
serialized chunk. The stream is organised as:

1. **Chunk header** – a varint prototype count followed by a header for each
   prototype.
2. **Per-prototype payloads** – each prototype encodes:
   - constant count
   - instruction count
   - child prototype count
   - the constant table
   - the instruction stream
   - nested prototypes (recursively encoded in the same format)
3. **No explicit footer** – consumers stop once all prototypes and their
   children have been processed. This matches the control flow in the Lua helper
   `Y3`, which only loops over the known prototype count.

The byte order is little-endian for multi-byte integers; varints use a base-128
continuation scheme. Floating-point payloads are written as big-endian IEEE754
(`struct.pack('>d', value)`) by helper `M` when `kind == "double"`.

## 2. Primitive Encodings

| Primitive | Encoding | Notes |
|-----------|----------|-------|
| `varint`  | Repeated 7-bit payload + MSB continuation (little-endian base 128) | Implemented by helper `a3` and mirrored in `decode_varint`. Values are unsigned; signed values use zig-zag. |
| `zig-zag` integers | `(value << 1) ^ (value >> 63)` | Used before writing integer constants so small negative numbers remain compact. |
| `double`  | 8-byte big-endian IEEE754 | `_encode_f64` packs via `struct.pack('>d', value)`. |
| `bytes`   | Varint length prefix + raw bytes | Used for strings, byte arrays, instruction payloads, and nested prototype blobs. |
| `boolean` | Tag byte + `0x00` / `0x01` payload | See constant table below. |
| `nil`     | Tag byte only | Marker for Lua `nil`. |

The harness’ `dump_bytes_preview` confirms that the first 128 bytes of the real
blob contain no printable strings and are dominated by low-valued bytes typical
of varint-heavy headers. The first dozen varints decoded by
`read_varints_preview` include large spikes (>500k), which line up with
instruction/constant bulk sizes.

## 3. Chunk / Prototype Header Fields

Per the translated helpers (`Y3` and `o`) and the writer simulation logs:

1. `proto_count` – `a3(len(prototypes))`. Every serialized blob begins with the
   number of prototype records encoded as a varint.
2. For each prototype `i` (emitted in breadth-first order):
   - `proto[i].constant_count` – varint; equals the number of constant entries
     written immediately afterwards. Logged as `const_count`.
   - `proto[i].instruction_count` – varint; number of encoded instructions for
     this prototype. Logged as `instr_count`.
   - `proto[i].child_count` – varint; number of nested prototypes (recursive
     invocations of `o`). Logged as `child_count`.
   - `proto[i].constants` – `constant_count` entries using the tag/payload
     layout described in §4.
   - `proto[i].instructions` – `instruction_count` entries, each encoded as a
     varint byte-length followed by that many opcode bytes (see §5).
   - `proto[i].children` – recursively encoded prototypes written immediately
     after the instruction stream; each child uses the exact same header and
     payload layout.

The constant/instruction/child counts are independent; the loader does not mix
data from different sections. Writer logs show the offsets are strictly
monotonic, so no backtracking or patching occurs.

## 4. Constant Table Encoding

Helper `M` writes a tag byte followed by the payload. The simulated writer log
labels show the following mapping, which matches the structures seen in the real
blob (e.g., frequent tag `0x05` patterns near short ASCII runs). Every constant
occupies exactly one tag/payload pair and constants are emitted in the order
defined by the constant table in the VM prototype.

| Tag | Meaning        | Payload |
|-----|----------------|---------|
| `0x01` | `nil`        | none |
| `0x02` | `boolean`    | single byte (`0x00` false, `0x01` true) |
| `0x03` | `integer`    | varint zig-zag encoded |
| `0x04` | `double`     | 8-byte big-endian IEEE754 |
| `0x05` | `string`     | varint length + UTF-8 bytes |
| `0x06` | `bytes`      | varint length + raw bytes |
| `0x18` | `blob_a` (best-effort) | varint length + opaque bytes.  Appears in the top-level constant pool with ~12–13 KB payloads.  Probe dumps show long runs of `\x00`/`\x06` separators, suggesting the blob nests additional tables that the loader inflates at runtime. |
| `0x9D` | `blob_b` (best-effort) | varint length + opaque bytes.  Always follows `0xE8` in the real payload and clocks in around 10 KB.  Payload starts with structured ASCII-free data and recurring 32-bit boundaries, consistent with a serialized lookup table. |
| `0xA0` | `blob_c` (best-effort) | varint length + bytes, roughly 100–120 B.  Located directly after the short `0x06` byte constant; writer logs label the surrounding fields as cache metadata, so this blob is presumed to contain precomputed cache descriptors. |
| `0xDA` | `bootstrap_blob` (best-effort) | varint length + bytes, ~6–7 KB.  This is always the first constant emitted by prototype 0 in the real chunk and lines up with the loader helpers’ initial cache bootstrap (the payload is later unpacked to seed the VM environment). |
| `0xE8` | `blob_d` (best-effort) | varint length + opaque bytes (~9 KB).  Appears before the `0x9D` entry; probes show high-entropy data reminiscent of packed instruction arrays, so tooling should treat it as another composite chunk until fully decoded. |

**Examples from instrumentation:**

```text
proto[0].const[2].tag_int    = 0x03
proto[0].const[2].int        = zig_zag(42) -> 0x54
proto[0].const[4].tag_string = 0x05
proto[0].const[4].strlen     = 5
proto[0].const[4].strdata    = "hello"
```

**Observations on the real blob:**

- `probe_v14_3_blob` finds repeating `[0x05, <len>, …]` clusters around regions
  that also register printable ASCII sequences, reinforcing that string constants
  follow the same tag order.
- Large clumps of varints with small numeric values are constant counts and
  string lengths; spikes that immediately precede 8-byte blocks in the probe are
  consistent with `0x04` double payloads.
- Zig-zag encoded integers always appear with tag `0x03`, matching the loader’s
  `encode_integer` path.
- Tags `0x18`, `0x9D`, `0xA0`, `0xDA`, and `0xE8` only show up in real payloads.
  The scanner reports that each of them is immediately followed by a length
  varint and a high-entropy byte range, confirming they are length-prefixed
  opaque blobs.  Their offsets mirror the bootstrap helper sequence (cache
  descriptor → byte table → cache metadata → VM image blobs), so tooling should
  preserve the emission order even before the payloads are fully decoded.

## 5. Instruction Encoding

Helper `r` emits each instruction as `varint byte_length + raw bytes`. The
writer log labels the length with `instr_len` and the payload with
`instr_payload`. While the real blob contains much longer sequences than the
fixtures, cross-correlation against the log shows the same pattern: a varint that
monotonically advances the buffer offset followed by that many bytes. The
payload bytes correspond to the lifted VM instruction encoding (e.g., packed
opcodes/operands); no additional compression has been observed. Consumers that
need to reconstruct high-level instructions should read the length, consume the
payload verbatim, and hand it to the VM lifter.

## 6. Known Invariants & Uncertainties

- The loader always emits prototypes breadth-first (header, constants,
  instructions, children) because helper `o` strictly follows that order. No
  padding or alignment bytes have been observed in the probe outputs.
- Varints are unsigned; negative integers rely on zig-zag conversion.
- `0x06` byte-array constants are rare in the real payload, but the writer
  simulator proves the encoding path exists and uses the same length-prefixed
  layout as strings.
- Instruction payloads appear high-entropy because they encode VM opcodes and
  operands; there is no evidence of additional compression or encryption beyond
  the length-prefixed framing described above.
- Child-prototype counts align with the VM prototype tree: every time `o`
  encounters `child_count > 0`, it immediately serializes that many nested
  prototypes by recursively invoking itself.

## 7. Next Steps

1. Use `simulate_v14_3_writer` to craft targeted prototype specs and compare the
   resulting buffers/logs against analogous regions in the real blob to refine
   field labelling.
2. Extend the analysis harness to automatically align writer log entries with
   blob offsets (e.g., by pattern matching the `[tag,len,data]` triads).
3. Feed the spec back into higher-level tooling (e.g., the opcode lifter) so the
   decoded prototype tree drives VM reconstruction end-to-end.

This document will evolve as additional invariants are proven, but it now fully
describes the header, constants, and instruction framing required for decoding.
