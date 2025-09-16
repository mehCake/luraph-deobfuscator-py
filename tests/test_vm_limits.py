import pytest

from src.exceptions import VMEmulationError
from src.vm.emulator import LuraphVM


def test_vm_step_limit_triggers():
    vm = LuraphVM(constants=[], bytecode=[["JMP", 0]], max_steps=5, timeout=None)
    with pytest.raises(VMEmulationError, match="step limit"):
        vm.run()


def test_vm_timeout(monkeypatch):
    timeline = iter([0.0, 0.0, 1.0])

    def fake_monotonic():
        return next(timeline)

    monkeypatch.setattr("src.vm.emulator.time.monotonic", fake_monotonic)
    vm = LuraphVM(constants=[], bytecode=[["JMP", 0]], max_steps=50, timeout=0.5)
    with pytest.raises(VMEmulationError, match="timed out"):
        vm.run()

