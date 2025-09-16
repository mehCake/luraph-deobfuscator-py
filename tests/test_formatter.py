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
