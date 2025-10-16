"""Utility helpers for Luraph decoding.

Historically the project exposed a ``src.utils`` module (``src/utils.py``)
containing a large collection of helpers.  Newer code, including the tests in
this repository, imports from the package namespace ``src.utils`` instead.  To
stay backwards compatible we re-export the implementations from the legacy
module when it is present.  This ensures features such as
``LuaSyntaxValidator`` and ``run_parallel`` behave identically regardless of
which import style the caller prefers.
"""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any, Callable, Sequence

import sys

LEGACY_PATH = Path(__file__).resolve().parents[1] / "utils.py"
_legacy_utils = None
if LEGACY_PATH.exists():  # pragma: no branch - normal test path
    spec = spec_from_file_location("src._legacy_utils", LEGACY_PATH)
    if spec and spec.loader:  # pragma: no branch - defensive
        module = module_from_spec(spec)
        loader = spec.loader
        assert loader is not None
        loader.exec_module(module)  # type: ignore[misc]
        sys.modules.setdefault("src._legacy_utils", module)
        _legacy_utils = module

from .io_utils import atomic_write, chunk_lines, ensure_out, write_b64_text, write_json, write_text  # noqa: F401
from .lph_decoder import parse_escaped_lua_string, try_xor  # noqa: F401
from .luraph_vm import looks_like_vm_bytecode, rebuild_vm_bytecode  # noqa: F401
from .opcode_inference import infer_opcode_map  # noqa: F401


def _missing(name: str) -> Callable[..., Any]:  # pragma: no cover - defensive
    def _raiser(*_: Any, **__: Any) -> Any:
        raise AttributeError(f"{name} is not available; legacy utils module missing")

    return _raiser


if _legacy_utils is not None:
    # Mirror the legacy module's public surface so existing imports keep
    # working.  Tests exercise helpers such as ``safe_read_file`` and
    # ``decode_simple_obfuscations`` which previously lived in
    # ``src/utils.py``.  Importing them eagerly keeps attribute access fast
    # while still deferring the actual module import until runtime.
    _private_exports = {"_is_printable"}
    for _name in dir(_legacy_utils):  # pragma: no branch - executed in tests
        if _name.startswith("_") and _name not in _private_exports:
            continue
        globals()[_name] = getattr(_legacy_utils, _name)

    # ``__all__`` advertises the combined API.  The explicit list makes the
    # package play nicely with tools such as ``from src import utils`` that
    # rely on :mod:`pkgutil` style introspection.
    __all__ = sorted(
        {
            "chunk_lines",
            "ensure_out",
            "atomic_write",
            "parse_escaped_lua_string",
            "try_xor",
            "write_b64_text",
            "write_json",
            "write_text",
            "rebuild_vm_bytecode",
            "looks_like_vm_bytecode",
            "infer_opcode_map",
            *_legacy_utils.__dict__.keys(),
            *_private_exports,
        }
        - {name for name in dir(_legacy_utils) if name.startswith("_") and name not in _private_exports}
    )
else:  # pragma: no cover - minimal fallback when legacy helpers unavailable
    from .LuaFormatter import LuaFormatter  # noqa: F401

    LuaSyntaxValidator = _missing("LuaSyntaxValidator")  # type: ignore[assignment]

    def run_parallel(
        tasks: Sequence[Callable[[], Any]], *_, **__
    ):  # type: ignore[override]
        return [task() for task in tasks]

    benchmark_parallel = _missing("benchmark_parallel")  # type: ignore[assignment]
    serialise_metadata = _missing("serialise_metadata")  # type: ignore[assignment]
    summarise_metadata = _missing("summarise_metadata")  # type: ignore[assignment]


    __all__ = [
        "chunk_lines",
        "ensure_out",
        "atomic_write",
        "parse_escaped_lua_string",
        "try_xor",
        "write_b64_text",
        "write_json",
        "write_text",
        "rebuild_vm_bytecode",
        "looks_like_vm_bytecode",
        "infer_opcode_map",
        "LuaFormatter",
        "LuaSyntaxValidator",
        "run_parallel",
        "benchmark_parallel",
        "serialise_metadata",
        "summarise_metadata",
    ]
