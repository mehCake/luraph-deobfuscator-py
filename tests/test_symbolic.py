from src.analysis.symbolic import SymbolicValue, SymbolicAdd, SymbolicXor


def test_add_simplify():
    expr = SymbolicAdd(SymbolicValue(2), SymbolicValue(3))
    result = expr.simplify()
    assert isinstance(result, SymbolicValue)
    assert result.value == 5


def test_xor_self_is_zero():
    expr = SymbolicXor(SymbolicValue(5), SymbolicValue(5))
    result = expr.simplify()
    assert isinstance(result, SymbolicValue)
    assert result.value == 0


def test_xor_concrete():
    expr = SymbolicXor(SymbolicValue(5), SymbolicValue(3))
    result = expr.simplify()
    assert isinstance(result, SymbolicValue)
    assert result.value == 5 ^ 3
