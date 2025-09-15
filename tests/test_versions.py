from src.deobfuscator import LuaDeobfuscator
from src.vm.emulator import LuraphVM
from src.versions import get_handler


def test_detect_version_regex() -> None:
    d = LuaDeobfuscator()
    content = "-- header\n-- Luraph v14.1\nprint('hi')"
    assert d.detect_version(content) == "v14.1"


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
