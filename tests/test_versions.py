from pathlib import Path
from typing import Iterable

import base64

from version_detector import VersionDetector
from src.deobfuscator import LuaDeobfuscator
from src.vm.emulator import LuraphVM
from src.versions import VersionHandler, decode_constant_pool, get_handler


def test_detect_version_examples() -> None:
    detector = VersionDetector()
    json_wrapped = Path('examples/json_wrapped.lua').read_text()
    simple = Path('examples/simple_obfuscated or remote for complex_obfuscated').read_text()
    complex_payload = Path('examples/complex_obfuscated').read_text()

    assert detector.detect_version(json_wrapped).name == 'v14.0.2'
    assert detector.detect_version(simple).name == 'v14.1'
    assert detector.detect_version(complex_payload).name in {
        'v14.2',
        'luraph_v14_2_json',
        'v14.4.1',
    }

    deob = LuaDeobfuscator()
    assert deob.detect_version(json_wrapped).name == 'v14.0.2'
    assert deob.detect_version(complex_payload).name in {
        'v14.2',
        'luraph_v14_2_json',
        'v14.4.1',
    }


def test_v142_pcall_bypass() -> None:
    vm = LuraphVM(bytecode=[["PCALL", 2611], ["RETURN"]])
    handler = get_handler("v14.2")
    handler.process(vm)
    assert vm.state.bytecode[0][1] == 1
    vm.run()  # should not raise


def test_get_handler_unknown() -> None:
    import pytest

    with pytest.raises(KeyError):
        get_handler("v0")


def test_luraph_v142_json_handler_detection() -> None:
    blob = base64.b64encode(b"hello world" * 30).decode()
    sample = (
        "local script_key = script_key or getgenv().script_key\n"
        "local init_fn = function(blob)\n"
        "    return loadstring(blob)()\n"
        "end\n"
        f"local payload = [[{{\"constants\": [\"{blob}\"], \"bytecode\": [1, 2, 3]}}]]\n"
        "return init_fn(payload)\n"
    )

    handler = get_handler("luraph_v14_2_json")
    assert isinstance(handler, VersionHandler)
    assert handler.matches(sample)
    payload = handler.locate_payload(sample)
    assert payload is not None
    raw_constants: Iterable[object] = []
    if payload.data:
        value = payload.data.get("constants")
        if isinstance(value, list):
            raw_constants = value
    decoder = handler.const_decoder()
    assert decoder is not None
    decoded_constants = decode_constant_pool(decoder, raw_constants)
    assert any("hello world" in entry for entry in decoded_constants if isinstance(entry, str))
    assert handler.extract_bytecode(payload) == b"\x01\x02\x03"

    detector = VersionDetector()
    detected = detector.detect(sample)
    assert detected.name == "luraph_v14_2_json"

    deob = LuaDeobfuscator()
    assert deob.detect_version(sample).name == "luraph_v14_2_json"
