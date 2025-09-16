from __future__ import annotations

from dataclasses import dataclass, field
import json
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Protocol, Tuple, Type, runtime_checkable

if False:  # pragma: no cover - typing helpers
    from ..vm.emulator import LuraphVM

_CONFIG_PATH = Path(__file__).with_name("config.json")
_DATA = json.loads(_CONFIG_PATH.read_text())
_VERSIONS: Dict[str, Dict[str, Any]] = _DATA.get("versions", {})


@dataclass
class PayloadInfo:
    """Location metadata for an extracted payload blob."""

    text: str
    start: int
    end: int
    data: Dict[str, Any] | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpSpec:
    """Description of an opcode provided by a handler."""

    mnemonic: str
    operands: Tuple[str, ...] = ()
    description: str | None = None


@runtime_checkable
class ConstDecoder(Protocol):
    """Decode constants for a given version variant."""

    def decode_string(self, data: bytes, *, index: int | None = None) -> str: ...

    def decode_number(self, value: int | bytes, *, index: int | None = None) -> int | float: ...

    def decode_pool(self, values: Iterable[Any]) -> list[Any]: ...


def decode_constant_pool(decoder: ConstDecoder, values: Iterable[Any]) -> list[Any]:
    """Decode *values* using ``decoder`` while preserving the original order."""

    decode_pool = getattr(decoder, "decode_pool", None)
    if callable(decode_pool):
        return list(decode_pool(values))

    result: list[Any] = []
    for index, value in enumerate(values):
        result.append(_decode_single_constant(decoder, index, value))
    return result


def _decode_single_constant(decoder: ConstDecoder, index: int, value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return decoder.decode_string(bytes(value), index=index)
    if isinstance(value, str):
        return decoder.decode_string(value.encode("utf-8"), index=index)
    if isinstance(value, int):
        return decoder.decode_number(value, index=index)
    return value


class VersionHandler:
    """Interface implemented by version specific helpers."""

    name: str = "unknown"
    priority: int = 0

    # --- Detection -------------------------------------------------
    def matches(self, text: str) -> bool:
        return False

    def locate_payload(self, text: str) -> PayloadInfo | None:
        return None

    # --- Normalisation ---------------------------------------------
    def extract_bytecode(self, payload: PayloadInfo) -> bytes:
        raise NotImplementedError

    def opcode_table(self) -> Dict[int, OpSpec]:  # pragma: no cover - optional
        return {}

    def const_decoder(self) -> Optional[ConstDecoder]:
        return None

    # --- VM integration --------------------------------------------
    def process(self, vm: "LuraphVM") -> None:  # pragma: no cover - default no-op
        decoder = self.const_decoder()
        if decoder is not None:
            vm.state.constants = decode_constant_pool(decoder, vm.state.constants)


_HANDLER_REGISTRY: Dict[str, Type[VersionHandler]] = {}


def register_handler(handler: Type[VersionHandler]) -> None:
    """Register ``handler`` so it can later be retrieved by name."""

    _HANDLER_REGISTRY[handler.name] = handler


def iter_registered_handlers() -> Iterator[VersionHandler]:
    """Yield registered handler instances ordered by priority."""

    for cls in sorted(
        _HANDLER_REGISTRY.values(),
        key=lambda item: getattr(item, "priority", 0),
        reverse=True,
    ):
        yield cls()


def _instantiate_handler(name: str) -> VersionHandler | None:
    cls = _HANDLER_REGISTRY.get(name)
    if cls is None:
        return None
    return cls()


def get_handler(version: str) -> Any:
    """Return the handler or module implementing *version*."""

    handler = _instantiate_handler(version)
    if handler is not None:
        return handler

    descriptor = _VERSIONS.get(version)
    if descriptor is None:
        raise KeyError(version)
    modname = descriptor.get("module")
    if not isinstance(modname, str):  # pragma: no cover - defensive
        raise KeyError(version)
    module = import_module(f"{__name__}.{modname}")
    candidate = getattr(module, "HANDLER", None)
    if isinstance(candidate, VersionHandler):
        return candidate
    return module


def iter_descriptors() -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Yield ``(version, descriptor)`` pairs from the configuration."""

    return _VERSIONS.items()


def get_descriptor(version: str) -> Dict[str, Any]:
    """Return a shallow copy of the descriptor for *version*."""

    descriptor = _VERSIONS.get(version)
    if descriptor is None:
        raise KeyError(version)
    return dict(descriptor)


__all__ = [
    "ConstDecoder",
    "decode_constant_pool",
    "OpSpec",
    "PayloadInfo",
    "VersionHandler",
    "get_handler",
    "get_descriptor",
    "iter_descriptors",
    "iter_registered_handlers",
    "register_handler",
]


# Ensure built-in handlers register themselves on import.
try:  # pragma: no cover - import side effect
    from . import luraph_v14_2_json  # noqa: F401
except Exception:  # pragma: no cover - optional handler may fail to load
    pass
