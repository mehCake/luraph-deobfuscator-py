import hashlib

from variable_renamer import VariableRenamer
from src import utils


SAMPLE_SOURCE = """
function R0(R1, R2)
  local R3 = { ["b"] = 2, ["a"] = 1 }
  for R4 = 1, #R3 do
    local R5 = R3[R4]
    if R5 > 2 then
      R2 = R2 + R5
    end
  end
  return R2
end
"""


def test_pretty_printer_snapshot():
    renamer = VariableRenamer()
    formatter = utils.LuaFormatter()
    renamed = renamer.rename_variables(SAMPLE_SOURCE)
    pretty = formatter.format_source(renamed)
    digest = hashlib.sha256(pretty.encode("utf-8")).hexdigest()
    assert digest == "d1de5cb8fc3b31572e472c8cfeec506681c65cda36118c09607f04e46d50e4a4"


def test_variable_names_are_stable():
    renamer = VariableRenamer()
    first = renamer.rename_variables(SAMPLE_SOURCE)
    second = VariableRenamer().rename_variables(SAMPLE_SOURCE)
    assert first == second


def test_nested_function_scope_isolated():
    code = """
function R0(R1)
  local R2 = 1
  local function R3(R4)
    local R5 = R4 + R2
    return R5
  end
  return R3(R2)
end
"""
    renamed = VariableRenamer().rename_variables(code)
    assert "local function c(arg1)" in renamed
    assert "return c(b)" in renamed
    assert "arg1 + b" in renamed
    assert "R0" not in renamed and "R2" not in renamed and "R3" not in renamed


def test_usage_pattern_heuristics_and_readability():
    code = """
function R0(R1)
  local R2 = 1
  local R3 = string.byte(R1, R2)
  local R4 = R1[R2]
  local R5 = bit32.band(R3, 0xFF)
  local R6 = bit32.band(R5, 0xF0)
  return R3, R4, R5, R6
end
"""
    renamer = VariableRenamer()
    renamed = renamer.rename_variables(code)
    assert "byte_indexer" in renamed
    assert "mask" in renamed
    stats = renamer.last_stats
    assert stats.get("readability", 0) >= 55
    assert stats.get("replacements") >= 1
