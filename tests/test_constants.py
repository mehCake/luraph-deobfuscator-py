import pytest

from constant_reconstructor import ConstantReconstructor
from variable_renamer import VariableRenamer


def test_lph_encfunc_string_and_number():
    code = 'local a = LPH_ENCFUNC("ABC", 1)\nlocal b = LPH_ENCFUNC(0x10, 5)'
    recon = ConstantReconstructor()
    strings = recon.extract_string_constants(code)
    numbers = recon.extract_numeric_constants(code)
    assert strings['LPH_ENCFUNC("ABC", 1)'] == '"@CB"'
    assert numbers['LPH_ENCFUNC(0x10, 5)'] == 0x10 ^ 5


def test_variable_renamer_registers_and_params():
    code = (
        'function R0(R1, R2)\n'
        '  local UPVAL0 = 5\n'
        '  return R1 + R2 + UPVAL0\n'
        'end\n'
    )
    renamer = VariableRenamer()
    renamed = renamer.rename_variables(code)
    assert 'function a(arg1, arg2)' in renamed
    assert 'uv1' in renamed
    assert 'R1' not in renamed and 'R2' not in renamed


def test_table_lookup_inlining_and_summary():
    code = (
        'local CONST = {"foo", "bar"}\n'
        'local value = CONST[1] .. CONST[2]\n'
    )
    recon = ConstantReconstructor()
    result = recon.reconstruct(code, None)
    assert 'CONST[1]' not in result['content']
    assert '"foo" .. "bar"' in result['content']
    summary = recon.reconstruct_all_constants(code)['summary']
    assert summary['total_tables'] == 1
