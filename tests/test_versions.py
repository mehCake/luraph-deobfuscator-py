from pathlib import Path

from version_detector import VersionDetector
from src.deobfuscator import LuaDeobfuscator
from src.vm.emulator import LuraphVM
from src.versions import get_handler


def test_detect_version_examples() -> None:
    detector = VersionDetector()
    json_wrapped = Path('examples/json_wrapped.lua').read_text()
    simple = Path('examples/simple_obfuscated or remote for complex_obfuscated').read_text()
    complex_payload = Path('examples/complex_obfuscated').read_text()

    assert detector.detect_version(json_wrapped).name == 'v14.0.2'
    assert detector.detect_version(simple).name == 'v14.1'
    assert detector.detect_version(complex_payload).name == 'v14.2'

    deob = LuaDeobfuscator()
    assert deob.detect_version(json_wrapped).name == 'v14.0.2'
    assert deob.detect_version(complex_payload).name == 'v14.2'


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
