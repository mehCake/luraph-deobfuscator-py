"""Utility helpers for Luraph decoding."""

from .. import utils as _legacy_utils
from .io_utils import chunk_lines, ensure_out, write_b64_text, write_json, write_text  # noqa: F401
from .lph_decoder import parse_escaped_lua_string, try_xor  # noqa: F401
from .luraph_vm import looks_like_vm_bytecode, rebuild_vm_bytecode  # noqa: F401
from .opcode_inference import infer_opcode_map  # noqa: F401
from .LuaFormatter import LuaFormatter  # noqa: F401

run_parallel = _legacy_utils.run_parallel

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
    "run_parallel",
]
