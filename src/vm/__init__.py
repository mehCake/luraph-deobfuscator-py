"""Virtual machine components for the Luraph deobfuscator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - used only for type checkers
    from src.vm.emulator import LuraphVM
    from src.vm.state import VMState

__all__ = ["LuraphVM", "VMState"]


def __getattr__(name: str) -> Any:
    if name == "LuraphVM":
        from src.vm.emulator import LuraphVM as _LuraphVM
        return _LuraphVM
    if name == "VMState":
        from src.vm.state import VMState as _VMState
        return _VMState
    raise AttributeError(name)
