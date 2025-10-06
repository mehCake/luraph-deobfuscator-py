"""Unit tests for the bootstrap dispatch parser."""

from __future__ import annotations

from src.bootstrap_extractor import BootstrapParser


SAMPLE_BOOTSTRAP = """
local dispatch = {}

dispatch[0x10] = function(state, a, b)
  -- moves a register into another
  state.registers[a + 1] = state.registers[b + 1]
  return state
end -- MOVE

dispatch[0x11] = function(state, a, bx)
  local constant = state.constants[bx]
  state.registers[a + 1] = constant
  return constant
end -- LOADK

dispatch[0x12] = function(state, a, b, c)
  state:call(a, b, c)
  return state:call(a, b, c)
end -- CALL

dispatch[0x13] = function(state, a, b)
  return state:return_values(a, b)
end -- RETURN

dispatch[0x14] = function(state, a, b, c)
  return state.concat(state[a], state[b], state[c])
end -- CONCAT

for opcode, func in pairs(dispatch) do
  register_opcode(opcode, func)
end
"""


def test_parser_discovers_expected_handlers() -> None:
    parser = BootstrapParser()
    result = parser.parse(SAMPLE_BOOTSTRAP)
    table = result.opcode_table

    assert len(table) >= 5
    assert 0x10 in table
    assert table[0x10].mnemonic == "MOVE"
    assert table[0x10].operands == "A B"

    assert table[0x11].mnemonic == "LOADK"
    assert table[0x11].operands == "A Bx"

    assert table[0x12].mnemonic == "CALL"
    assert table[0x12].trust == "high"

    assert table[0x13].mnemonic == "RETURN"
    assert table[0x13].trust == "high"

    assert table[0x14].mnemonic == "CONCAT"
    assert table[0x14].operands.startswith("A B C")
