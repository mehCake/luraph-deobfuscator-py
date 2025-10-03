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

from .io_utils import chunk_lines, ensure_out, write_b64_text, write_json, write_text  # noqa: F401
from .lph_decoder import parse_escaped_lua_string, try_xor  # noqa: F401
from .luraph_vm import looks_like_vm_bytecode, rebuild_vm_bytecode  # noqa: F401
from .opcode_inference import infer_opcode_map  # noqa: F401


def _missing(name: str) -> Callable[..., Any]:  # pragma: no cover - defensive
    def _raiser(*_: Any, **__: Any) -> Any:
        raise AttributeError(f"{name} is not available; legacy utils module missing")

    return _raiser


if _legacy_utils is not None:
    LuaFormatter = _legacy_utils.LuaFormatter  # type: ignore[attr-defined]
    LuaSyntaxValidator = _legacy_utils.LuaSyntaxValidator  # type: ignore[attr-defined]
    run_parallel = _legacy_utils.run_parallel  # type: ignore[attr-defined]
    benchmark_parallel = _legacy_utils.benchmark_parallel  # type: ignore[attr-defined]
    serialise_metadata = _legacy_utils.serialise_metadata  # type: ignore[attr-defined]
    summarise_metadata = _legacy_utils.summarise_metadata  # type: ignore[attr-defined]
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
