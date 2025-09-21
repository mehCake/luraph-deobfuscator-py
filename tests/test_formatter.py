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
    assert digest == "69e10a546742a8d4927bae707e5baf1e8362f0a56b9312733a11014f2aa4a83a"


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
