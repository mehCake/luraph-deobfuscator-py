from pathlib import Path

from lph_handler import extract_payload


def test_extract_payload_from_long_string() -> None:
    payload = extract_payload(Path('examples/json_wrapped.lua').read_text())
    assert payload is not None
    assert payload['constants'] == ['script_key']
    assert payload['bytecode'] == []


def test_extract_payload_with_bytecode() -> None:
    raw = '{"constants": ["hello"], "bytecode": [["LOADK", 0], ["RETURN"]]}'
    payload = extract_payload(raw)
    assert payload is not None
    assert payload['constants'] == ['hello']
    assert payload['bytecode'][0][0] == 'LOADK'
    assert payload['code'][1][0] == 'RETURN'
