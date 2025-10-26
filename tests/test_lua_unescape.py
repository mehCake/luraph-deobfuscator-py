import pytest

from lua_literal_parser import canonicalize_escapes, lu_unescape


@pytest.mark.parametrize(
    "literal, expected",
    [
        (r"\n\r\t\\\"'", "\n\r\t\\\"'"),
        (r"\255\300", chr(255) + chr(300 % 256)),
        (r"\x41\x42", "AB"),
        (r"\u{1F600}", "\U0001F600"),
        (r"\u{41 42}", "AB"),
        (r"\u{0041 030A}", "\u00C5"),
        (r"\u{1F_600}", "\U0001F600"),
        (r"\1234", chr(123) + "4"),
    ],
)
def test_lu_unescape_sequences(literal, expected):
    assert lu_unescape(literal) == expected


def test_lu_unescape_zaps_whitespace_sequences():
    literal = "line1\\z  \n   \r\n\t  \nline2"
    assert lu_unescape(literal) == "line1line2"


def test_lu_unescape_invalid_sequences_preserved():
    assert lu_unescape(r"\x4G") == r"\x4G"
    assert lu_unescape(r"\u{ZZ}") == r"\u{ZZ}"
    assert lu_unescape(r"\u{ }") == r"\u{ }"


@pytest.mark.parametrize(
    "literal, expected",
    [
        (r"\n\t", r"\x0A\x09"),
        (r"\123", r"\x7B"),
        (r"\x41", r"\x41"),
        (r"\u{1f600}", r"\u{1F600}"),
        (r"\u{41 42}", r"\x41\x42"),
        (r"\u{0041 030A}", r"\x41\u{030A}"),
        (r"\u{1F_600}", r"\u{1F600}"),
        (r"plain", "plain"),
    ],
)
def test_canonicalize_escapes_normalises_sequences(literal, expected):
    assert canonicalize_escapes(literal) == expected


def test_canonicalize_escapes_strips_z_whitespace():
    literal = r"prefix\z   \n\r\t suffix"
    assert canonicalize_escapes(literal) == r"prefix\x0A\x0D\x09 suffix"
