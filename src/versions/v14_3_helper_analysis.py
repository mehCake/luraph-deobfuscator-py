"""Hand-written analysis of the v14.3 loader helper network.

This module does **not** participate in the decoding pipeline directly; it serves
as living documentation extracted from the obfuscated helpers inside
``Obfuscated4.lua``.  The goal is to keep a machine-readable snapshot of what
each helper does so that future reverse-engineering work can script against the
findings without reopening the Lua source.

The notes below were assembled by reading the ``Y3``/``o``/``M``/``r``/``a3``/
``O3`` helpers in the Lua file and correlating them with the previously built
``V14_3Writer`` simulator and probe harness.  The offsets listed in
:class:`HelperSummary` refer to byte offsets inside ``Obfuscated4.lua``'s single
line payload (see the ``python`` snippets under ``docs/v14_3_loader_bootstrap.md``
for reproduction steps).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class HelperSummary:
    """Structured description of one loader helper."""

    name: str
    params: List[str]
    responsibilities: str
    buffer_writes: str
    key_usage: str
    pseudocode: str
    source_offset_hint: int


HELPER_SUMMARIES: Dict[str, HelperSummary] = {
    "Y3": HelperSummary(
        name="Y3",
        params=["writer", "prototypes"],
        responsibilities=(
            "Entry closure invoked by the bootstrap. It writes the global "
            "prototype count via ``a3`` (varint encoder) and iterates each "
            "prototype in breadth-first order before handing control to ``o``."
        ),
        buffer_writes=(
            "Always performs exactly one varint write per invocation before "
            "delegating to ``o``. No key material is consumed at this level; "
            "the helper only orchestrates structure."),
        key_usage="None (acts on plain prototype metadata only).",
        pseudocode="""
function Y3(writer, prototypes)
  a3(writer, #prototypes, label="proto_count")
  for index, proto in ipairs(prototypes) do
    o(writer, proto, index=index)
  end
end
""",
        source_offset_hint=10037,
    ),
    "o": HelperSummary(
        name="o",
        params=["writer", "proto", "index"],
        responsibilities=(
            "Serialises a prototype header by emitting the constant, "
            "instruction, and child counts before delegating to ``M``/``r``/``O3``."),
        buffer_writes=(
            "Three varints for the counts followed by the flattened constant "
            "table (via ``M``), instruction streams (via ``r``), and recursive "
            "child encodings (via ``O3``)."),
        key_usage="None; this helper only consumes already-decoded tables.",
        pseudocode="""
function o(writer, proto, index)
  a3(writer, #proto.constants, label=sprintf("proto[%d].constant_count", index))
  a3(writer, #proto.instructions, label=sprintf("proto[%d].instruction_count", index))
  a3(writer, #proto.children, label=sprintf("proto[%d].child_count", index))
  for const_index, constant in ipairs(proto.constants) do
    M(writer, constant, label=sprintf("proto[%d].const[%d]", index, const_index))
  end
  for inst_index, inst in ipairs(proto.instructions) do
    r(writer, inst, label=sprintf("proto[%d].instr[%d]", index, inst_index))
  end
  for child_index, child in ipairs(proto.children) do
    O3(writer, child, label=sprintf("proto[%d].child[%d]", index, child_index))
  end
end
""",
        source_offset_hint=10210,
    ),
    "M": HelperSummary(
        name="M",
        params=["writer", "constant", "label"],
        responsibilities=(
            "Implements the constant-tag encoder described in the spec.  Tags "
            "0x01–0x06 cover canonical Lua types while 0x18/0x9D/0xA0/0xDA/0xE8 "
            "wrap the opaque bootstrap blobs observed in the real payload."),
        buffer_writes=(
            "One tag byte followed by a type-specific payload: zig-zag varints "
            "for integers, IEEE754 doubles, length-prefixed UTF-8/byte arrays, "
            "or bulk blobs."),
        key_usage=(
            "None for plain types.  Bootstrap blob tags are keyed indirectly "
            "because the VM later walks them using the keystream derived by ``N``."),
        pseudocode="""
function M(writer, constant, label)
  case constant.kind of
    "nil":     writer:write_u8(0x01)
    "boolean": writer:write_u8(0x02); writer:write_u8(constant.value and 1 or 0)
    "integer": writer:write_u8(0x03); write_zigzag(constant.value)
    "double":  writer:write_u8(0x04); writer:write_bytes(pack_be_double(value))
    "string":  writer:write_u8(0x05); writer:write_varint(#bytes); writer:write_bytes(bytes)
    "bytes":   writer:write_u8(0x06); writer:write_varint(#bytes); writer:write_bytes(bytes)
    blob_*:     writer:write_u8(tag); writer:write_varint(#blob); writer:write_bytes(blob)
  end
end
""",
        source_offset_hint=10512,
    ),
    "r": HelperSummary(
        name="r",
        params=["writer", "instruction", "label"],
        responsibilities="Encodes a VM instruction as length-prefixed raw bytes.",
        buffer_writes="Varint byte-length then verbatim instruction bytes.",
        key_usage="None (instructions are already obfuscated at the VM level).",
        pseudocode="""
function r(writer, instruction, label)
  writer:write_varint(#instruction)
  writer:write_bytes(instruction)
end
""",
        source_offset_hint=10745,
    ),
    "O3": HelperSummary(
        name="O3",
        params=["writer", "child", "label"],
        responsibilities="Recursively serialize a nested prototype using ``o``.",
        buffer_writes="Indirect; delegates completely to ``o``.",
        key_usage="None.",
        pseudocode="""
function O3(writer, child, label)
  o(writer, child, index=child.ordinal)
end
""",
        source_offset_hint=10820,
    ),
    "a3": HelperSummary(
        name="a3",
        params=["writer", "value", "label"],
        responsibilities="Little-endian base-128 varint encoder shared by all helpers.",
        buffer_writes="Repeated 7-bit payload bytes with MSB continuation bit.",
        key_usage="None.",
        pseudocode="""
function a3(writer, value, label)
  repeat
    local byte = value & 0x7F
    value = value >> 7
    if value ~= 0 then byte = byte | 0x80 end
    writer:write_u8(byte)
  until value == 0
end
""",
        source_offset_hint=11092,
    ),
    "N": HelperSummary(
        name="N",
        params=["Y", "g"],
        responsibilities=(
            "Bridges the encrypted bootstrap data and the plain serialized chunk. "
            "`Y` is the cache vector seeded by the key (`u` in the Lua source) "
            "while `g` exposes the prototype descriptors.  `N` builds the "
            "`q3` closure that iterates the bytecode tables `D`, `m`, `T`, etc., "
            "and emits decoded bytes into the structures consumed by `Y3`."),
        buffer_writes=(
            "Operates on in-memory tables (`l3`, `m3`, `k3`) and writes to them "
            "via indexed assignments.  The helper toggles between copy, XOR, "
            "and arithmetic opcodes depending on the dispatcher value `a`."),
        key_usage=(
            "Consumes the session key through the tables passed in `Y`.  The ``N(u,0x5)``"
            " call observed near offset 6082 feeds the `u` structure (derived "
            "from the user key) and the literal depth `0x5`.  Within `N`, the "
            "`C3` bit helpers and `F3[...]` slots combine shifts, rotations, and "
            "XORs to generate the keystream used for bootstrap blobs."),
        pseudocode="""
function N(Y, g)
  local cache = Y[0b10_01]
  local opcode_tables = {
    B = Y[0x4], l = Y[0x1], J = Y[10], b = Y[0b101],
    k3 = Y[0x3], D = Y[0b1011], m = Y[0x6], T = Y[0b10],
  }
  local function q3(...)
    local registers = O3(cache)   -- clone template registers
    local args, env = U(...)
    local ip = 1
    while true do
      local opcode = D[ip]
      dispatch(opcode)            -- giant switch seen in Lua snippet
      ip = ip + 1
    end
  end
  return q3
end
""",
        source_offset_hint=9836,
    ),
    "C3": HelperSummary(
        name="C3 arithmetic helpers",
        params=["value", "shift"],
        responsibilities=(
            "Implements the bit manipulation family referenced as `C3.a` (left "
            "shift), `C3.s` (right shift), `C3.b` (left rotate), and `C3._` (right "
            "rotate).  These helpers are heavily used when combining cached key "
            "slots from `F3[...]` before XORing with the encrypted payload."),
        buffer_writes="Pure arithmetic; results are written back into the `F3` cache entries.",
        key_usage=(
            "These helpers are the only place where the user-provided key `u` "
            "touches the arithmetic pipeline.  For example ``C3.a(C3.s(F3[A]+F3[B],F3[C]),F3[C])`` "
            "matches the Lua snippet around offset 6100 and corresponds to "
            "`((F3[A] + F3[B]) >> F3[C]) << F3[C]`, effectively masking numeric "
            "windows when deriving keystream bytes."),
        pseudocode="""
function C3.a(value, amount) return (value << amount) & 0xFFFFFFFFFFFFFFFF end
function C3.s(value, amount) return (value >> amount) & 0xFFFFFFFFFFFFFFFF end
function C3.b(value, amount) return rotate_left(value, amount) end
function C3._(value, amount) return rotate_right(value, amount) end
""",
        source_offset_hint=6050,
    ),
}

PIPELINE_DESCRIPTION = """High-level decoding pipeline inferred from the Lua helpers.

1. **Token hashing** – The metatable ``__index`` decodes five-character tokens by
   interpreting them in base-85 (see the arithmetic involving 33, 0x55, 7225,
   614125, and 52 200 625 near offset 6082).  The resulting integer indexes into
   ``y("\\62\\073\\u{0034}", g)`` which yields ASCII fragments used to build the
   helper tables (``Y``, ``C3``, ``F3``, etc.).
2. **Key schedule construction** – ``N(u,0x5)`` is invoked with the session key
   table ``u`` and literal depth ``0x5``.  Inside ``N`` the helper family ``C3``
   mixes cached constants ``F3[...]`` via XORs, shifts, and rotations to produce
   a keystream.  The keystream seeds the opcode/constant tables that drive the
   VM-like dispatcher within ``q3``.
3. **Chunk assembly** – The ``q3`` closure produced by ``N`` iterates the opcode
   table ``D`` and performs register manipulations (arithmetic, table updates,
   conditional jumps).  Writes into ``g`` correspond to populating the prototype
   descriptors consumed by ``Y3``.
4. **Serialization** – Once the prototype descriptors are materialised, the
   plain helpers ``Y3``/``o``/``M``/``r``/``O3`` apply the layout documented in
   ``docs/v14_3_serialized_format_spec.md`` to produce the byte stream consumed
   by the embedded VM.
"""

__all__ = ["HelperSummary", "HELPER_SUMMARIES", "PIPELINE_DESCRIPTION"]
