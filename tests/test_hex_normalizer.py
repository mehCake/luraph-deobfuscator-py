import pytest

from hex_number_normalizer import HexNumberNormalizer


@pytest.mark.parametrize(
    "literal",
    ["0xff", "0X10", "0x1p4", "42", "3.5", "1e2", "-0x1"],
)
def test_canonicalize_preserves_value(literal: str) -> None:
    normalizer = HexNumberNormalizer()
    value = normalizer.parse_literal(literal)
    canonical = normalizer.canonicalize_literal(literal)
    parsed = normalizer.parse_literal(canonical)
    if isinstance(value, float) and not value.is_integer():
        assert parsed == pytest.approx(value)
    else:
        assert parsed == value

    prefer_hex = literal.lower().startswith("0x")
    round_trip = normalizer.format_literal(value, prefer_hex=prefer_hex)
    parsed_round_trip = normalizer.parse_literal(round_trip)
    if isinstance(value, float) and not value.is_integer():
        assert parsed_round_trip == pytest.approx(value)
    else:
        assert parsed_round_trip == value


def test_normalize_all_numbers_rewrites_hex() -> None:
    normalizer = HexNumberNormalizer()
    code = "local a = 0xff; local b = 1e2; local c = 3.140000"
    normalized = normalizer.normalize_all_numbers(code)
    assert "0xff" not in normalized
    assert "255" in normalized
