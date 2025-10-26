from __future__ import annotations

import ast as py_ast
import base64
import binascii
import copy
import csv
import datetime
import difflib
import gzip
import hashlib
import json
import math
import os
import random
import re
import struct
import string
import textwrap
import zipfile
import zlib
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
import unicodedata
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
    Union,
)

from src.utils_pkg import strings as string_utils
from src.usage_audit import require_usage_confirmation


@dataclass(frozen=True)
class PipelineStageDoc:
    """Documentation metadata for an automated pipeline stage."""

    name: str
    function: str
    summary: str
    inputs: Sequence[str]
    outputs: Sequence[str]
    failure_modes: Sequence[str]
    remedies: Sequence[str]
    runtime_guidance: Optional[str] = None

from lua_literal_parser import (
    LuaTable,
    canonicalize_escapes,
    lua_literal_to_string,
    lu_unescape,
    parse_lua_expression,
)

from pattern_analyzer import (
    simulate_vm,
    _find_function_end,
    _offset_to_line_col,
    generate_upcode_table,
)
from src.beautifier import LuaBeautifier
from src.decoders.initv4_prga import apply_prga
from src.decoders.lph85 import decode_lph85
from src.ir import VMFunction, VMInstruction
from src.license_audit import run_license_audit
from src.sandbox import run_fragment_safely
from src.versions import iter_descriptors
from variable_renamer import LUA_GLOBALS, LUA_KEYWORDS, safe_rename
from utils import benchmark, byte_diff


_JSON_INIT_RE = re.compile(r"(?:do\s+)?local\s+init_fn\s*=\s*function", re.IGNORECASE)
_JSON_SCRIPT_KEY_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*getgenv\(\)\.script_key",
    re.IGNORECASE,
)

_HELPER_DEF_RE = re.compile(r"([A-Za-z0-9_]+)\s*=\s*function\b")
_TABLE_HELPER_ENTRY_RE = re.compile(
    r"(?P<key>\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<func>function\b)",
    re.MULTILINE,
)
_TABLE_ASSIGN_RE = re.compile(
    r"(?P<local>local\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{",
    re.MULTILINE,
)
_TABLE_RETURN_RE = re.compile(r"return\s+\{", re.MULTILINE)
_DIRECT_RETURN_RE = re.compile(
    r"^return\s*(?:\{|\(|function\b)", re.IGNORECASE | re.DOTALL
)

_INITV4_INIT_RE = re.compile(r"\binit_fn\s*\(", re.IGNORECASE)
_INITV4_SCRIPT_KEY_RE = re.compile(
    r"\bscript_key\s*=\s*(?:script_key\s*or\s*)?(?:getgenv\(\)\.script_key|['\"]([^'\"]*)['\"])",
    re.IGNORECASE,
)
_INITV4_ALPHABET_CHARS = re.escape(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)

_INITV4_BLOB_RE = re.compile(r"s8W-[!-~]{64,}")
_INITV4_JSON_BLOB_RE = re.compile(r"\[\s*['\"](s8W-[!-~]{128,})['\"]", re.IGNORECASE)
_INITV4_ALPHABET_RE = re.compile(
    r"alphabet\s*=\s*['\"]([0-9A-Za-z!#$%&()*+,\-./:;<=>?@\[\]^_`{|}~]{85,})['\"]",
    re.IGNORECASE,
)
_INITV4_JSON_ARRAY_KEY_RE = re.compile(
    rf"\"(?:bytecode|payload|chunks)\"\s*:\s*\[[^\]]*\"[{_INITV4_ALPHABET_CHARS}]{{80,}}\"",
    re.IGNORECASE,
)
_INITV4_QUOTED_CHUNK_RE = re.compile(rf'(["\'])([{_INITV4_ALPHABET_CHARS}]{{80,}})\1')
_INITV4_LONG_BLOB_RE = re.compile(rf"[{_INITV4_ALPHABET_CHARS}]{{160,}}")

_EMBEDDED_BOOTSTRAP_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("alphabet_literal", re.compile(r"\balphabet\s*=\s*['\"]", re.IGNORECASE)),
    ("base91_marker", _INITV4_BLOB_RE),
    ("loadstring_call", re.compile(r"\bloadstring\s*\(", re.IGNORECASE)),
    ("script_key_literal", re.compile(r"\bscript_key\b", re.IGNORECASE)),
    ("unpackedData", re.compile(r"\bunpackedData\b", re.IGNORECASE)),
)

_FINGERPRINT_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("prga_defs", re.compile(r"\bfunction\s+PRGA\b")),
    ("initv4_refs", re.compile(r"\binitv4\b", re.IGNORECASE)),
    ("bit32_ops", re.compile(r"\bbit32\.", re.IGNORECASE)),
    ("string_byte_calls", re.compile(r"\bstring\s*\.\s*byte\b", re.IGNORECASE)),
    ("string_char_calls", re.compile(r"\bstring\s*\.\s*char\b", re.IGNORECASE)),
    (
        "load_calls",
        re.compile(r"\b(?:loadstring|load)\s*\(", re.IGNORECASE),
    ),
    (
        "env_mutations",
        re.compile(r"\b(?:getfenv|setfenv|_ENV)\b", re.IGNORECASE),
    ),
    (
        "dispatcher_if_chain",
        re.compile(r"elseif\s+[A-Za-z_][A-Za-z0-9_]*\s*==\s*(?:0x[0-9A-Fa-f]+|\d+)", re.IGNORECASE),
    ),
    ("hex_opcodes", re.compile(r"0x[0-9A-Fa-f]{2,}")),
)
_FINGERPRINT_HELPER_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_LUA_SIGNATURE = b"\x1bLua"

_DANGEROUS_CALL_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("os.execute", re.compile(r"\bos\s*[\.:]\s*execute\b", re.IGNORECASE)),
    (
        "os.process",
        re.compile(
            r"\bos\s*[\.:]\s*(?:spawn|popen|remove|rename|tmpname|setenv|getenv)\b",
            re.IGNORECASE,
        ),
    ),
    ("io.popen", re.compile(r"\bio\s*[\.:]\s*popen\b", re.IGNORECASE)),
    (
        "http access",
        re.compile(r"\bhttp(?:s)?\s*[\.:]", re.IGNORECASE),
    ),
    (
        "game:http",
        re.compile(r"\bgame\s*[:\.]\s*Http(?:Get|Post|Service)\b", re.IGNORECASE),
    ),
    ("syn.request", re.compile(r"\bsyn\s*[\.:]\s*request\b", re.IGNORECASE)),
    ("http_request", re.compile(r"\bhttp_request\b", re.IGNORECASE)),
    ("socket", re.compile(r"\bsocket\s*[\.:]", re.IGNORECASE)),
    ("websocket", re.compile(r"\bwebsocket\b", re.IGNORECASE)),
)
_LUA_TAIL = b"\x19\x93\r\n\x1a\n"
_LUA_RK_MASK = 1 << 8
_LUA_MAX_RK = _LUA_RK_MASK - 1


@dataclass
class LuaBytecodeHeader:
    version: int
    version_string: str
    format: int
    int_size: int
    size_t_size: int
    instruction_size: int
    number_size: int
    integral_flag: int
    endianness: str


@dataclass
class LuaInstruction:
    opcode: str
    mode: str
    a: int
    b: Optional[int]
    c: Optional[int]
    bx: Optional[int]
    sbx: Optional[int]
    raw: int


@dataclass
class LuaPrototype:
    source: Optional[str]
    line_defined: int
    last_line_defined: int
    nups: int
    num_params: int
    is_vararg: int
    max_stack_size: int
    instructions: List[LuaInstruction]
    constants: List[Any]
    prototypes: List["LuaPrototype"]
    line_info: List[int]
    loc_vars: List[Dict[str, Any]]
    upvalues: List[Optional[str]]


_LUA51_OPCODES: List[Tuple[str, str]] = [
    ("MOVE", "iABC"),
    ("LOADK", "iABx"),
    ("LOADBOOL", "iABC"),
    ("LOADNIL", "iABC"),
    ("GETUPVAL", "iABC"),
    ("GETGLOBAL", "iABx"),
    ("GETTABLE", "iABC"),
    ("SETGLOBAL", "iABx"),
    ("SETUPVAL", "iABC"),
    ("SETTABLE", "iABC"),
    ("NEWTABLE", "iABC"),
    ("SELF", "iABC"),
    ("ADD", "iABC"),
    ("SUB", "iABC"),
    ("MUL", "iABC"),
    ("DIV", "iABC"),
    ("MOD", "iABC"),
    ("POW", "iABC"),
    ("UNM", "iABC"),
    ("NOT", "iABC"),
    ("LEN", "iABC"),
    ("CONCAT", "iABC"),
    ("JMP", "iAsBx"),
    ("EQ", "iABC"),
    ("LT", "iABC"),
    ("LE", "iABC"),
    ("TEST", "iABC"),
    ("TESTSET", "iABC"),
    ("CALL", "iABC"),
    ("TAILCALL", "iABC"),
    ("RETURN", "iABC"),
    ("FORLOOP", "iAsBx"),
    ("FORPREP", "iAsBx"),
    ("TFORLOOP", "iABC"),
    ("SETLIST", "iABC"),
    ("CLOSE", "iABC"),
    ("CLOSURE", "iABx"),
    ("VARARG", "iABC"),
]


def _lua_version_string(version: int) -> str:
    major = (version >> 4) & 0xF
    minor = version & 0x0F
    if major == 0:
        return str(version)
    return f"{major}.{minor}"


class _LuaByteReader:
    def __init__(
        self,
        data: bytes,
        *,
        int_size: int,
        size_t_size: int,
        instruction_size: int,
        number_size: int,
        integral_flag: int,
        endianness: str = "little",
    ) -> None:
        self._data = data
        self._offset = 0
        self.int_size = int_size
        self.size_t_size = size_t_size
        self.instruction_size = instruction_size
        self.number_size = number_size
        self.integral_flag = integral_flag
        self.endianness = endianness

    def _ensure(self, length: int) -> None:
        if self._offset + length > len(self._data):
            raise ValueError("unexpected end of bytecode stream")

    def read_bytes(self, length: int) -> bytes:
        self._ensure(length)
        start = self._offset
        end = start + length
        self._offset = end
        return self._data[start:end]

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_int(self) -> int:
        raw = self.read_bytes(self.int_size)
        return int.from_bytes(raw, self.endianness, signed=False)

    def read_size_t(self) -> int:
        raw = self.read_bytes(self.size_t_size)
        return int.from_bytes(raw, self.endianness, signed=False)

    def read_number(self) -> float | int:
        raw = self.read_bytes(self.number_size)
        if self.integral_flag:
            return int.from_bytes(raw, self.endianness, signed=True)
        if self.number_size == 8:
            fmt = "<d" if self.endianness == "little" else ">d"
            return struct.unpack(fmt, raw)[0]
        if self.number_size == 4:
            fmt = "<f" if self.endianness == "little" else ">f"
            return struct.unpack(fmt, raw)[0]
        raise ValueError(f"unsupported lua_Number size: {self.number_size}")

    def read_string(self) -> Optional[str]:
        length = self.read_size_t()
        if length == 0:
            return None
        raw = self.read_bytes(length)
        if raw and raw[-1] == 0:
            raw = raw[:-1]
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return raw.decode("latin-1", errors="ignore")

    def read_constant(self) -> Any:
        tag = self.read_byte()
        if tag == 0:
            return None
        if tag == 1:
            return bool(self.read_byte())
        if tag == 3:
            return self.read_number()
        if tag == 4:
            return self.read_string() or ""
        # best-effort fallback: represent unknown tag types textually
        return {"type": tag, "value": self.read_string()}

    def read_instruction(self) -> LuaInstruction:
        if self.instruction_size != 4:
            raise ValueError("only 32-bit instructions are supported")
        raw = int.from_bytes(self.read_bytes(4), self.endianness, signed=False)
        opcode_index = raw & 0x3F
        if opcode_index < len(_LUA51_OPCODES):
            opcode, mode = _LUA51_OPCODES[opcode_index]
        else:
            opcode = f"OP_{opcode_index}"
            mode = "iABC"
        a = (raw >> 6) & 0xFF
        c = (raw >> 14) & 0x1FF
        b = (raw >> 23) & 0x1FF
        bx = raw >> 14
        sbx = bx - 131071
        if mode == "iABx":
            b_val: Optional[int] = None
            c_val: Optional[int] = None
        elif mode == "iAsBx":
            b_val = None
            c_val = None
        else:
            b_val = b
            c_val = c
        return LuaInstruction(
            opcode=opcode,
            mode=mode,
            a=a,
            b=b_val,
            c=c_val,
            bx=bx if mode in {"iABx", "iAsBx"} else None,
            sbx=sbx if mode == "iAsBx" else None,
            raw=raw,
        )

    def read_prototype(self, parent_source: Optional[str]) -> LuaPrototype:
        source = self.read_string() or parent_source
        line_defined = self.read_int()
        last_line_defined = self.read_int()
        nups = self.read_byte()
        num_params = self.read_byte()
        is_vararg = self.read_byte()
        max_stack_size = self.read_byte()

        code_size = self.read_int()
        instructions = [self.read_instruction() for _ in range(code_size)]

        constant_size = self.read_int()
        constants = [self.read_constant() for _ in range(constant_size)]

        proto_count = self.read_int()
        prototypes = [self.read_prototype(source) for _ in range(proto_count)]

        line_info_size = self.read_int()
        line_info = [self.read_int() for _ in range(line_info_size)]

        loc_var_size = self.read_int()
        loc_vars: List[Dict[str, Any]] = []
        for _ in range(loc_var_size):
            name = self.read_string()
            start_pc = self.read_int()
            end_pc = self.read_int()
            loc_vars.append({"name": name, "start_pc": start_pc, "end_pc": end_pc})

        upvalue_size = self.read_int()
        upvalues = [self.read_string() for _ in range(upvalue_size)]

        return LuaPrototype(
            source=source,
            line_defined=line_defined,
            last_line_defined=last_line_defined,
            nups=nups,
            num_params=num_params,
            is_vararg=is_vararg,
            max_stack_size=max_stack_size,
            instructions=instructions,
            constants=constants,
            prototypes=prototypes,
            line_info=line_info,
            loc_vars=loc_vars,
            upvalues=upvalues,
        )

    @property
    def offset(self) -> int:
        return self._offset


def _parse_lua_bytecode(data: bytes) -> Dict[str, Any]:
    if not data.startswith(_LUA_SIGNATURE):
        raise ValueError("missing Lua bytecode signature")
    if len(data) < 17:
        raise ValueError("truncated Lua bytecode header")

    version = data[4]
    format_byte = data[5]
    tail = data[6:12]
    if tail != _LUA_TAIL:
        raise ValueError("unexpected Lua header marker")

    int_size = data[12]
    size_t_size = data[13]
    instruction_size = data[14]
    number_size = data[15]
    integral_flag = data[16]

    if format_byte not in (0,):
        raise ValueError(f"unsupported Lua bytecode format: {format_byte}")
    if instruction_size != 4:
        raise ValueError("unsupported instruction size")
    if int_size not in (4, 8) or size_t_size not in (4, 8):
        raise ValueError("unsupported integer sizing in Lua chunk")

    header = LuaBytecodeHeader(
        version=version,
        version_string=_lua_version_string(version),
        format=format_byte,
        int_size=int_size,
        size_t_size=size_t_size,
        instruction_size=instruction_size,
        number_size=number_size,
        integral_flag=integral_flag,
        endianness="little",
    )

    reader = _LuaByteReader(
        data[17:],
        int_size=int_size,
        size_t_size=size_t_size,
        instruction_size=instruction_size,
        number_size=number_size,
        integral_flag=integral_flag,
        endianness="little",
    )

    prototype = reader.read_prototype(None)
    consumed = 17 + reader.offset

    return {"header": header, "prototype": prototype, "size": consumed}


def _shorten(text: str, limit: int = 60) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _format_constant(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        escaped = (
            value.replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{_shorten(escaped, 60)}"'
    return repr(value)


def _constant_preview(proto: LuaPrototype, index: int | None) -> Optional[str]:
    if index is None:
        return None
    if index < 0 or index >= len(proto.constants):
        return None
    return _format_constant(proto.constants[index])


def _format_rk_argument(proto: LuaPrototype, value: Optional[int]) -> str:
    if value is None:
        return "-"
    if value >= _LUA_RK_MASK:
        const_index = value - _LUA_RK_MASK
        preview = _constant_preview(proto, const_index)
        if preview:
            return f"K{const_index} {preview}"
        return f"K{const_index}"
    return f"R{value}"


def _instruction_comment(proto: LuaPrototype, instr: LuaInstruction) -> str:
    if instr.opcode in {"LOADK", "GETGLOBAL", "SETGLOBAL"} and instr.bx is not None:
        preview = _constant_preview(proto, instr.bx)
        return preview or ""
    if instr.opcode in {"SETTABLE", "GETTABLE", "SELF"}:
        parts: List[str] = []
        if instr.b is not None and instr.b >= _LUA_RK_MASK:
            preview_b = _constant_preview(proto, instr.b - _LUA_RK_MASK)
            if preview_b:
                parts.append(f"B={preview_b}")
        if instr.c is not None and instr.c >= _LUA_RK_MASK:
            preview_c = _constant_preview(proto, instr.c - _LUA_RK_MASK)
            if preview_c:
                parts.append(f"C={preview_c}")
        return ", ".join(parts)
    if instr.opcode == "CLOSURE" and instr.bx is not None:
        return f"proto {instr.bx}"
    return ""


def _format_instruction_line(
    proto: LuaPrototype, instr: LuaInstruction, index: int, *, indent: str = ""
) -> str:
    prefix = f"{indent}[{index + 1:04}] {instr.opcode:<9}"
    args: List[str] = []

    if instr.mode == "iABC":
        args.append(f"R{instr.a}")
        if instr.opcode == "LOADBOOL":
            args.append("true" if instr.b else "false")
            args.append("jump" if instr.c else "cont")
        elif instr.opcode in {"RETURN", "VARARG"}:
            args.append(str(instr.b or 0))
            args.append(str(instr.c or 0))
        elif instr.opcode in {"CALL", "TAILCALL"}:
            args.append(f"{instr.b or 0} args")
            args.append(f"{instr.c or 0} returns")
        elif instr.opcode == "SETLIST":
            args.append(str(instr.b or 0))
            args.append(str(instr.c or 0))
        elif instr.opcode in {"TEST", "TESTSET"}:
            args.append(_format_rk_argument(proto, instr.b))
            args.append("if true" if instr.c else "if false")
        else:
            args.append(_format_rk_argument(proto, instr.b))
            args.append(_format_rk_argument(proto, instr.c))
    elif instr.mode == "iABx":
        args.append(f"R{instr.a}")
        if instr.opcode == "CLOSURE":
            args.append(f"proto {instr.bx}")
        else:
            args.append(f"K{instr.bx}")
    elif instr.mode == "iAsBx":
        args.append(f"R{instr.a}")
        args.append(f"{instr.sbx:+d}")
    else:
        args.append(f"A={instr.a}")
        if instr.b is not None:
            args.append(f"B={instr.b}")
        if instr.c is not None:
            args.append(f"C={instr.c}")

    line = prefix
    if args:
        line += " " + ", ".join(arg for arg in args if arg not in {"-", "", None})

    comment = _instruction_comment(proto, instr)
    if comment:
        line += f"    ; {comment}"
    return line


def _render_prototype_listing(
    header: LuaBytecodeHeader,
    proto: LuaPrototype,
    *,
    depth: int = 0,
    index: Optional[int] = None,
) -> str:
    indent = "  " * depth
    lines: List[str] = []
    title = f"{indent}-- Prototype"
    if index is not None:
        title += f" #{index}"
    if proto.source:
        title += f" ({proto.source})"
    lines.append(title)
    lines.append(
        f"{indent}-- lines {proto.line_defined}-{proto.last_line_defined}"
        f" params={proto.num_params} upvalues={proto.nups}"
        f" vararg={(proto.is_vararg & 1) != 0} stack={proto.max_stack_size}"
    )

    if proto.loc_vars:
        locs = ", ".join((entry.get("name") or "<anon>") for entry in proto.loc_vars)
        lines.append(f"{indent}-- locals: {locs}")
    if proto.upvalues:
        ups = ", ".join((name or "<anon>") for name in proto.upvalues)
        lines.append(f"{indent}-- upvalues: {ups}")

    lines.append(f"{indent}-- constants ({len(proto.constants)}):")
    if proto.constants:
        for const_index, value in enumerate(proto.constants):
            lines.append(f"{indent}--   [{const_index}] = {_format_constant(value)}")
    else:
        lines.append(f"{indent}--   <none>")

    lines.append(f"{indent}-- instructions ({len(proto.instructions)}):")
    for idx, instr in enumerate(proto.instructions):
        lines.append(_format_instruction_line(proto, instr, idx, indent=indent))

    for child_index, child in enumerate(proto.prototypes):
        lines.append("")
        lines.append(
            _render_prototype_listing(
                header, child, depth=depth + 1, index=child_index
            )
        )

    return "\n".join(lines)


def _render_bytecode_report(header: LuaBytecodeHeader, proto: LuaPrototype) -> str:
    lines = [
        f"-- Decompiled Lua chunk (Lua {header.version_string})",
        (
            "-- layout: format={fmt} int={int_size} size_t={size_t} "
            "instruction={instr} number={num} integral={integral}"
        ).format(
            fmt=header.format,
            int_size=header.int_size,
            size_t=header.size_t_size,
            instr=header.instruction_size,
            num=header.number_size,
            integral=header.integral_flag,
        ),
    ]

    listing = _render_prototype_listing(header, proto)
    if listing:
        lines.append(listing)

    return "\n".join(lines).rstrip() + "\n"
_INITV4_CHUNK_ASSIGN_RE = re.compile(r"local\s+chunk_\d+\s*=")
_INITV4_CHUNK_CONCAT_RE = re.compile(r"chunk_\d+\s*\.\.\s*chunk_\d+")
_BASE64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

_VERSION_BANNER_RE = re.compile(
    r"(?:lura\.ph|Luraph)\s*(?:Obfuscator\s*)?(?:v(?:ersion)?\s*)?(\d+(?:\.\d+)*)",
    re.IGNORECASE,
)
_LURAPH_URL_TOKEN_RE = re.compile(r"lura\.ph", re.IGNORECASE)
_VERSION_TOKEN_RE = re.compile(r"(?<![0-9A-Za-z_])v(?:ersion)?\s*(\d+(?:\.\d+)*)", re.IGNORECASE)
_TIMESTAMP_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{10}\b"),
)
_KEY_HINT_PATTERNS: Tuple[Tuple[str, re.Pattern[str], int], ...] = (
    (
        "tiny_hint",
        re.compile(r"(TINY-[A-Za-z0-9]{4,})"),
        1,
    ),
    (
        "key_assignment",
        re.compile(r"\bkey\s*=\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
        1,
    ),
    (
        "key_wording",
        re.compile(r"(key(?:[_-]?hint|[_-]?id)?[:=]\s*[A-Za-z0-9_-]{4,})", re.IGNORECASE),
        1,
    ),
)
_COMMENT_WORD_RE = re.compile(r"[A-Za-z]{3,}")
_COMMENT_SENTENCE_RE = re.compile(r"[.?!]")

_LONG_BRACKET_OPEN_RE = re.compile(r"\[(=*)\[")
_IDENT_KEY_RE = re.compile(r"(?:^|(?<=\{)|(?<=,))\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
_BRACKET_STRING_KEY_RE = re.compile(
    r"(?:^|(?<=\{)|(?<=,))\s*\[\s*([\"'])(.*?)\1\s*\]\s*=",
    re.DOTALL,
)

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LOCAL_DECL_RE = re.compile(
    r"\blocal\s+(?!function)([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)"
)
_LOCAL_FUNCTION_RE = re.compile(
    r"\blocal\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
)
_FUNCTION_DEF_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)(?:[:.]([A-Za-z_][A-Za-z0-9_]*))?\s*\(([^)]*)\)"
)
_ASSIGN_FUNCTION_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function\s*\(([^)]*)\)"
)
_ASSIGN_WITH_LOCAL_RE = re.compile(
    r"(?:local\s+)?([A-Za-z_][A-Za-z0-9_:.]*)\s*=\s*function\b"
)
_FUNCTION_TOKEN_RE = re.compile(r"\bfunction\b")
_ASSIGN_PREFIX_RE = re.compile(r"(?:local\s+)?[A-Za-z_][A-Za-z0-9_:.]*\s*=\s*$")
_RETURN_PREFIX_RE = re.compile(r"return\s*$")
_LOCAL_PREFIX_RE = re.compile(r"local\s*$")
_FOR_LOOP_RE = re.compile(
    r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?\s+in"
)
_NUMERIC_FOR_RE = re.compile(
    r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s*=",
)

_LUA_LIBRARIES: FrozenSet[str] = frozenset(
    {
        "math",
        "string",
        "table",
        "bit32",
        "coroutine",
        "debug",
        "utf8",
        "io",
        "os",
        "package",
    }
)

_RESERVED_IDENTIFIERS: FrozenSet[str] = frozenset(LUA_KEYWORDS) | frozenset(LUA_GLOBALS) | _LUA_LIBRARIES


def detect_bootstrapper_source_from_text(
    text: str, *, file_path: Path | None = None
) -> Dict[str, object]:
    """Heuristically determine how a payload obtains its bootstrapper."""

    info: Dict[str, object] = {
        "mode": "unknown",
        "bootstrapper": None,
        "reason": "no markers",
        "alphabet_strategy": "unknown",
    }
    if file_path is not None:
        info["path"] = str(file_path)

    stripped = text.lstrip()
    if not stripped:
        info.update({"mode": "empty", "reason": "empty input"})
        return info

    if _DIRECT_RETURN_RE.match(stripped):
        info.update(
            {
                "mode": "self_contained",
                "reason": "direct_return",
                "alphabet_strategy": "self",
            }
        )
        return info

    if _JSON_INIT_RE.search(text) and _JSON_SCRIPT_KEY_RE.search(text):
        info.update(
            {
                "mode": "external",
                "bootstrapper": "initv4",
                "reason": "json_init_stub",
                "alphabet_strategy": "external_initv4",
            }
        )
        return info

    if _INITV4_INIT_RE.search(text) and _INITV4_SCRIPT_KEY_RE.search(text):
        info.update(
            {
                "mode": "external",
                "bootstrapper": "initv4",
                "reason": "initv4_markers",
                "alphabet_strategy": "external_initv4",
            }
        )
        return info

    for reason, pattern in _EMBEDDED_BOOTSTRAP_PATTERNS:
        if pattern.search(text):
            info.update(
                {
                    "mode": "embedded",
                    "reason": reason,
                    "alphabet_strategy": "embedded",
                }
            )
            return info

    info.update(
        {
            "mode": "self_contained",
            "reason": "no_bootstrapper_markers",
            "alphabet_strategy": "self",
        }
    )
    return info


def detect_bootstrapper_source(path: str | Path) -> Dict[str, object]:
    """Inspect ``path`` and classify how its bootstrapper should be sourced."""

    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return {
            "mode": "unreadable",
            "bootstrapper": None,
            "reason": f"io_error: {exc}",
            "alphabet_strategy": "unknown",
            "path": str(file_path),
        }

    return detect_bootstrapper_source_from_text(text, file_path=file_path)


def _extract_versions_from_luraph_url(text: str) -> List[str]:
    """Return raw version strings from lines mentioning ``lura.ph``."""

    versions: List[str] = []
    for url_match in _LURAPH_URL_TOKEN_RE.finditer(text):
        start = max(0, url_match.start() - 120)
        end = min(len(text), url_match.end() + 120)
        window = text[start:end]
        for match in _VERSION_TOKEN_RE.finditer(window):
            versions.append(match.group(1))
    return versions


def detect_luraph_header_from_text(
    text: str, *, path: str | Path | None = None
) -> Dict[str, object]:
    """Return Luraph metadata extracted from ``text``."""

    version: Optional[str] = None
    url_versions = _extract_versions_from_luraph_url(text)
    if url_versions:
        version = url_versions[0]
    else:
        banner_match = _VERSION_BANNER_RE.search(text)
        if banner_match:
            version = banner_match.group(1)

    structure = _detect_top_level_structure(text)
    top_keys: List[str] = []

    if structure == "return({...})":
        table_src = _extract_returned_table(text)
        if table_src:
            top_keys = _extract_top_level_keys(table_src)

    file_path = Path(path) if path is not None else None
    bootstrap_meta = detect_bootstrapper_source_from_text(text, file_path=file_path)

    result = {"version": version, "structure": structure, "top_keys": top_keys}
    result["bootstrapper"] = bootstrap_meta
    return result


def detect_luraph_header(path: str | Path) -> Dict[str, object]:
    """Inspect a Lua file for Luraph metadata and structure information.

    Parameters
    ----------
    path:
        Filesystem path to the Lua file that should be analysed.

    Returns
    -------
    Dict[str, object]
        A dictionary containing the detected version string (if any), the
        top-level structure description and the keys defined by a returned
        table constructor.
    """

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")

    return detect_luraph_header_from_text(text, path=file_path)


def _fingerprint_feature_counts(text: str) -> Tuple[Dict[str, int], List[str]]:
    """Return pattern hit counts and helper samples for fingerprinting."""

    counts: Dict[str, int] = {}
    for name, pattern in _FINGERPRINT_PATTERNS:
        matches = pattern.findall(text)
        counts[name] = len(matches) if matches else 0

    helper_names = [name for name in _FINGERPRINT_HELPER_RE.findall(text) if name]
    helper_counter = Counter(helper_names)
    helper_sample = [name for name, _ in helper_counter.most_common(12)]

    return counts, helper_sample


def _compute_luraph_fingerprint(
    text: str,
    *,
    input_path: Path | None = None,
    metadata: Mapping[str, object] | None = None,
) -> Optional[Dict[str, object]]:
    """Build a stable fingerprint payload for Luraph v14 payloads."""

    metadata = metadata or {}
    if not metadata:
        metadata = detect_luraph_header_from_text(text)

    version = metadata.get("version") if isinstance(metadata, Mapping) else None
    if not isinstance(version, str) or not version.startswith("14."):
        return None

    structure = metadata.get("structure") if isinstance(metadata, Mapping) else None
    top_keys = []
    if isinstance(metadata, Mapping):
        raw_top_keys = metadata.get("top_keys")
        if isinstance(raw_top_keys, Sequence):
            top_keys = [str(key) for key in list(raw_top_keys)[:16]]

    feature_counts, helper_sample = _fingerprint_feature_counts(text)
    sha256 = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    helper_signature = "|".join(helper_sample[:6]) if helper_sample else ""
    top_key_signature = "|".join(top_keys[:6]) if top_keys else ""

    fingerprint = {
        "version": version,
        "variant": f"luraph_v{version}",
        "structure": structure,
        "top_keys": top_keys,
        "top_key_signature": top_key_signature,
        "helper_sample": helper_sample,
        "helper_signature": helper_signature,
        "feature_counts": feature_counts,
        "hash": sha256,
        "source": str(input_path) if input_path is not None else None,
        "generated_at": _normalise_datetime(datetime.datetime.utcnow()),
    }

    return fingerprint


def _write_fingerprint_report(
    fingerprint: Dict[str, object], *, output_path: Path
) -> Dict[str, object]:
    """Append *fingerprint* to ``fingerprints.json`` near *output_path*."""

    report_path = output_path.with_name("fingerprints.json")
    existing_payload: Dict[str, object]
    if report_path.exists():
        try:
            existing_payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing_payload = {}
    else:
        existing_payload = {}

    entries = existing_payload.get("fingerprints")
    if not isinstance(entries, list):
        entries = []

    existing_hashes = {
        entry.get("hash")
        for entry in entries
        if isinstance(entry, dict) and "hash" in entry
    }

    added = False
    if fingerprint.get("hash") not in existing_hashes:
        entries.append(fingerprint)
        added = True

    payload = {
        "generated_at": _normalise_datetime(datetime.datetime.utcnow()),
        "fingerprints": entries,
    }
    report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    return {"path": str(report_path), "fingerprints": entries, "added": added}


def fingerprint_obfuscation_patterns(
    text: str,
    *,
    output_path: str | Path,
    input_path: str | Path | None = None,
    metadata: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    """Fingerprint Luraph payloads and persist entries for reuse.

    Returns an empty report when the payload is not recognised as a Luraph v14
    variant so callers can safely skip caching.
    """

    fingerprint = _compute_luraph_fingerprint(
        text,
        input_path=Path(input_path) if input_path is not None else None,
        metadata=metadata,
    )
    if not fingerprint:
        return {"path": None, "fingerprints": [], "added": False}

    return _write_fingerprint_report(fingerprint, output_path=Path(output_path))


def _normalise_datetime(value: datetime.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _normalise_timestamp(raw: str) -> Dict[str, str]:
    cleaned = raw.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y/%m/%dT%H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        return {
            "original": cleaned,
            "iso": _normalise_datetime(parsed),
            "source": "formatted",
        }
    return {"original": cleaned, "source": "formatted"}


def _normalise_epoch(raw: str) -> Optional[Dict[str, str]]:
    cleaned = raw.strip()
    try:
        value = int(cleaned)
    except ValueError:
        return None
    # Consider epochs from year 2000 up to 2100 to avoid false positives.
    if not (946684800 <= value <= 4102444800):
        return None
    timestamp = datetime.datetime.utcfromtimestamp(value)
    return {
        "original": cleaned,
        "iso": _normalise_datetime(timestamp),
        "source": "epoch",
    }


def _extract_timestamps(text: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for pattern in _TIMESTAMP_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            if pattern is _TIMESTAMP_PATTERNS[-1]:
                normalised = _normalise_epoch(raw)
                if not normalised:
                    continue
            else:
                normalised = _normalise_timestamp(raw)
            key = normalised.get("iso") or normalised["original"]
            if key in seen:
                continue
            seen.add(key)
            results.append(normalised)
    return results


def _sanitize_key_hint(value: str) -> Dict[str, Any]:
    trimmed = value.strip()
    digest = hashlib.sha256(trimmed.encode("utf-8", "ignore")).hexdigest()
    preview = trimmed
    if len(trimmed) > 5:
        preview = f"{trimmed[:5]}…"
    return {"hash": digest, "preview": preview, "length": len(trimmed)}


def _extract_key_hints(text: str) -> List[Dict[str, Any]]:
    hints: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for label, pattern, group_index in _KEY_HINT_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(group_index)
            if not value:
                continue
            record = _sanitize_key_hint(value)
            if record["hash"] in seen:
                continue
            seen.add(record["hash"])
            hints.append({
                "pattern": label,
                "preview": record["preview"],
                "length": record["length"],
                "hash": record["hash"],
            })
    return hints


def _extract_comment_markers(text: str) -> List[Dict[str, Any]]:
    markers: List[Dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), 1):
        if "--" not in line:
            continue
        comment = line.split("--", 1)[1]
        if re.search(
            r"lura\.ph|luraph|version|key|tiny|\d{4}[-/]\d{2}[-/]\d{2}",
            comment,
            re.IGNORECASE,
        ):
            snippet = comment.strip()
            if snippet:
                markers.append({"line": idx, "text": snippet[:240]})
    return markers


def extract_metadata_provenance(
    path: str | Path,
    *,
    output_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Extract metadata and provenance markers from a Lua payload."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")

    header = detect_luraph_header_from_text(text)
    timestamps = _extract_timestamps(text)
    key_hints = _extract_key_hints(text)
    comment_markers = _extract_comment_markers(text)
    url_versions = _extract_versions_from_luraph_url(text)

    report: Dict[str, Any] = {
        "input": str(file_path),
        "generated_at": _normalise_datetime(datetime.datetime.utcnow()),
        "size_bytes": file_path.stat().st_size,
        "line_count": text.count("\n") + 1,
        "header": header,
        "url_versions": url_versions,
        "timestamps": timestamps,
        "key_hints": key_hints,
        "comment_markers": comment_markers,
    }

    if output_path is not None:
        output_path = Path(output_path)
        output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    return report


def extract_fragments(path: str | Path) -> List[Dict[str, object]]:
    """Collect Lua string and concatenation fragments preserving source order.

    Parameters
    ----------
    path:
        Filesystem path pointing to the Lua source that should be analysed.

    Returns
    -------
    List[Dict[str, object]]
        A list of dictionaries describing each fragment.  Every entry contains
        ``type`` (``"long_quoted"``, ``"long_bracket"`` or ``"concat"``), the
        fragment ``text`` itself and its ``start``/``end`` offsets relative to
        the original source.
    """

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")

    fragments: List[Dict[str, object]] = []
    n = len(text)
    i = 0
    line_comment = False
    block_comment: Optional[int] = None

    while i < n:
        if line_comment:
            if text[i] in "\r\n":
                line_comment = False
            i += 1
            continue

        if block_comment is not None:
            closing = "]" + "=" * block_comment + "]"
            if text.startswith(closing, i):
                i += len(closing)
                block_comment = None
                continue
            i += 1
            continue

        ch = text[i]

        if ch == "-" and text.startswith("--", i):
            equals = _match_long_bracket(text, i + 2)
            if equals is not None:
                block_comment = equals
                i += 2 + 2 + equals
                continue
            line_comment = True
            i += 2
            continue

        if ch in {'"', "'"}:
            start = i
            end = _consume_short_string(text, i)
            fragments.append(
                {"type": "long_quoted", "text": text[start:end], "start": start, "end": end}
            )
            i = end
            continue

        if ch == "[":
            equals = _match_long_bracket(text, i)
            if equals is not None:
                start = i
                end = _consume_long_bracket(text, i, equals)
                fragments.append(
                    {
                        "type": "long_bracket",
                        "text": text[start:end],
                        "start": start,
                        "end": end,
                        "equals": equals,
                    }
                )
                i = end
                continue

        if ch == "." and text.startswith("..", i):
            if i + 2 < n and text[i + 2] == ".":
                i += 1
                continue
            fragments.append({"type": "concat", "text": "..", "start": i, "end": i + 2})
            i += 2
            continue

        i += 1

    return fragments


def reconstruct_text(fragments: Iterable[Mapping[str, object]]) -> str:
    """Recreate a Lua string by concatenating extracted fragments.

    Parameters
    ----------
    fragments:
        Iterable of fragment dictionaries as produced by :func:`extract_fragments`.

    Returns
    -------
    str
        The reconstructed string payload assembled in the same order Lua would
        evaluate the concatenation expression.
    """

    return "".join(decoded for _, decoded in _iter_decoded_fragments(fragments))


def _iter_decoded_fragments(
    fragments: Iterable[Mapping[str, object]]
) -> Iterable[Tuple[Mapping[str, object], str]]:
    ordered = sorted(fragments, key=lambda frag: frag.get("start", 0))
    for fragment in ordered:
        kind = fragment.get("type")
        text = fragment.get("text")
        if not isinstance(text, str):
            continue
        if kind == "concat":
            continue
        if kind == "long_quoted":
            yield fragment, _decode_short_fragment(text)
            continue
        if kind == "long_bracket":
            yield fragment, _decode_long_fragment(text)


@dataclass(frozen=True)
class _StageCandidate:
    name: str
    predicate: Callable[[bytes, str], bool]
    transform: Callable[[bytes], Tuple[bytes, Dict[str, Any]]]


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in {9, 10, 13})
    return printable / len(data)


def _coerce_fragment_bytes(fragment: Mapping[str, object] | str | bytes) -> Tuple[bytes, Dict[str, Any]]:
    metadata: Dict[str, Any] = {}
    if isinstance(fragment, Mapping):
        metadata = {
            key: fragment.get(key)
            for key in ("index", "start", "end", "type")
            if key in fragment
        }
        text = fragment.get("text")
        if isinstance(text, str):
            data = text.encode("latin-1", errors="ignore")
        elif isinstance(text, bytes):
            data = text
        else:
            data = str(text or "").encode("latin-1", errors="ignore")
    elif isinstance(fragment, bytes):
        data = fragment
    else:
        data = str(fragment).encode("latin-1", errors="ignore")
    return data, metadata


def _decode_base64_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    stripped = re.sub(rb"\s+", b"", data)
    decoded = base64.b64decode(stripped, validate=False)
    return decoded, {"alphabet": "base64", "length": len(decoded)}


def _decode_ascii85_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    stripped = data.strip()
    decoded = base64.a85decode(stripped, adobe=False, ignorechars=" \t\r\n")
    return decoded, {"alphabet": "ascii85", "length": len(decoded)}


def _decode_hex_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    stripped = re.sub(rb"[^0-9a-fA-F]", b"", data)
    decoded = binascii.unhexlify(stripped)
    return decoded, {"alphabet": "hex", "length": len(decoded)}


def _decode_zlib_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    decoded = zlib.decompress(data)
    return decoded, {"method": "zlib", "length": len(decoded)}


def _decode_gzip_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    decoded = gzip.decompress(data)
    return decoded, {"method": "gzip", "length": len(decoded)}


def _reverse_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    reversed_bytes = data[::-1]
    return reversed_bytes, {"mode": "reverse"}


def _rotate_left_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if not data:
        return data, {"mode": "rotate_left"}
    rotated = data[1:] + data[:1]
    return rotated, {"mode": "rotate_left", "shift": 1}


def _even_odd_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if len(data) < 4:
        return data, {"mode": "even_odd"}
    even = data[0::2]
    odd = data[1::2]
    permuted = even + odd
    return permuted, {"mode": "even_odd_interleave"}


def _single_byte_xor_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if not data:
        return data, {"mode": "single_byte_xor"}
    sample = data[: min(len(data), 1024)]
    best_key = None
    best_score = 0.0
    best_ratio = 0.0
    for key in range(1, 256):
        plain = bytes(byte ^ key for byte in sample)
        score = _printable_ratio(plain)
        try:
            text_hint = plain.decode("latin-1", errors="ignore")
        except Exception:
            text_hint = ""
        if _looks_like_lua_snippet(text_hint):
            score += 0.4
        if score > best_score:
            best_key = key
            best_score = score
            best_ratio = _printable_ratio(plain)
    if best_key is None or best_ratio < 0.6:
        raise ValueError("single-byte xor score too low")
    decoded = bytes(byte ^ best_key for byte in data)
    decoded_text = decoded.decode("latin-1", errors="ignore")
    metadata = {
        "mode": "single_byte_xor",
        "key": f"0x{best_key:02x}",
        "score": round(best_ratio, 3),
    }
    if _looks_like_lua_snippet(decoded_text):
        metadata["lua_markers"] = True
    return decoded, metadata


def _repeating_xor_stage(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if len(data) < 12:
        raise ValueError("payload too small for repeating xor detection")
    best_key: Optional[bytes] = None
    best_score = 0.0
    best_plain = b""
    max_len = min(16, max(2, len(data) // 8))
    for key_len in range(2, max_len + 1):
        key_bytes: List[int] = []
        scores: List[float] = []
        for offset in range(key_len):
            slice_bytes = data[offset::key_len]
            if not slice_bytes:
                break
            best_slice_key = None
            best_slice_score = 0.0
            for candidate in range(256):
                plain = bytes(byte ^ candidate for byte in slice_bytes)
                score = _printable_ratio(plain)
                if score > best_slice_score:
                    best_slice_score = score
                    best_slice_key = candidate
            if best_slice_key is None or best_slice_score < 0.55:
                key_bytes = []
                break
            key_bytes.append(best_slice_key)
            scores.append(best_slice_score)
        if key_bytes and len(key_bytes) == key_len:
            if len(set(key_bytes)) == 1:
                continue
            decoded = bytes(byte ^ key_bytes[i % key_len] for i, byte in enumerate(data))
            score = _printable_ratio(decoded)
            if score > best_score:
                best_score = score
                best_key = bytes(key_bytes)
                best_plain = decoded
    if best_key is None or best_score < 0.6:
        raise ValueError("repeating xor score too low")
    return best_plain, {
        "mode": "repeating_xor",
        "key": [f"0x{byte:02x}" for byte in best_key],
        "score": round(best_score, 3),
    }


def _looks_like_base64_text(text: str) -> bool:
    if not text:
        return False
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 16 or len(stripped) % 4 not in (0, 2):
        return False
    if _looks_like_hex_text(stripped):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", stripped))


def _looks_like_ascii85_text(text: str) -> bool:
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 10:
        return False
    return all(33 <= ord(ch) <= 117 for ch in stripped)


def _looks_like_hex_text(text: str) -> bool:
    if not text or len(text) < 10:
        return False
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) % 2 != 0:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))


def _should_try_xor(data: bytes) -> bool:
    ratio = _printable_ratio(data)
    unique = len(set(data[: min(len(data), 256)]))
    return ratio <= 0.8 and unique > 4 and ratio > 0.1


def _should_try_permutation(data: bytes, text: str) -> bool:
    ratio = _printable_ratio(data)
    if ratio < 0.15:
        return False
    looks_like = _looks_like_lua_snippet(text)
    if _looks_like_hex_text(text) or _looks_like_base64_text(text):
        return False
    if looks_like and ratio >= 0.85:
        return False
    return ratio < 0.85 or not looks_like


def detect_multistage(
    fragment: Mapping[str, object] | str | bytes,
    *,
    max_depth: int = 3,
    max_candidates: int = 5,
) -> Dict[str, Any]:
    """Attempt to identify multi-stage encodings for ``fragment``.

    The detector applies lightweight heuristics to select staged transforms
    (base64/hex decoding, XOR attempts, byte permutations and compression
    routines) and evaluates their outputs for Lua-like characteristics.  The
    best candidate pipelines are returned together with decoded previews so
    analysts can triage likely multi-stage encodings.
    """

    raw_bytes, metadata = _coerce_fragment_bytes(fragment)
    initial_text = raw_bytes.decode("latin-1", errors="ignore")
    queue: deque[Tuple[bytes, List[Dict[str, Any]]]] = deque()
    queue.append((raw_bytes, []))
    visited: Set[bytes] = {raw_bytes}
    candidates: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    stage_factories: Tuple[_StageCandidate, ...] = (
        _StageCandidate(
            "base64",
            lambda data, text: _looks_like_base64_text(text)
            or string_utils.maybe_base64(text) is not None,
            lambda data: _decode_base64_stage(data),
        ),
        _StageCandidate(
            "ascii85",
            lambda data, text: _looks_like_ascii85_text(text),
            lambda data: _decode_ascii85_stage(data),
        ),
        _StageCandidate(
            "hex",
            lambda data, text: _looks_like_hex_text(text),
            lambda data: _decode_hex_stage(data),
        ),
        _StageCandidate(
            "zlib",
            lambda data, text: len(data) > 8 and _looks_like_zlib_header(data),
            lambda data: _decode_zlib_stage(data),
        ),
        _StageCandidate(
            "gzip",
            lambda data, text: len(data) > 10 and _looks_like_gzip_header(data),
            lambda data: _decode_gzip_stage(data),
        ),
        _StageCandidate(
            "single_byte_xor",
            lambda data, text: _should_try_xor(data),
            lambda data: _single_byte_xor_stage(data),
        ),
        _StageCandidate(
            "repeating_xor",
            lambda data, text: len(data) > 24 and _should_try_xor(data),
            lambda data: _repeating_xor_stage(data),
        ),
        _StageCandidate(
            "reverse",
            lambda data, text: _should_try_permutation(data, text),
            lambda data: _reverse_stage(data),
        ),
        _StageCandidate(
            "rotate_left",
            lambda data, text: _should_try_permutation(data, text),
            lambda data: _rotate_left_stage(data),
        ),
        _StageCandidate(
            "even_odd",
            lambda data, text: _should_try_permutation(data, text),
            lambda data: _even_odd_stage(data),
        ),
    )

    while queue and len(candidates) < max_candidates:
        current_bytes, pipeline = queue.popleft()
        text = current_bytes.decode("latin-1", errors="ignore")
        ratio = _printable_ratio(current_bytes)
        looks_like = _looks_like_lua_snippet(text)

        if pipeline and (looks_like or ratio > 0.8):
            candidates.append(
                {
                    "stages": pipeline,
                    "decoded": text,
                    "looks_like_lua": looks_like,
                    "printable_ratio": round(ratio, 3),
                }
            )
            if len(candidates) >= max_candidates:
                break

        if len(pipeline) >= max_depth:
            continue

        for stage in stage_factories:
            if not stage.predicate(current_bytes, text):
                continue
            try:
                transformed, details = stage.transform(current_bytes)
            except Exception as exc:  # pragma: no cover - defensive logging
                errors.append(
                    {
                        "stages": [entry.get("name") for entry in pipeline] + [stage.name],
                        "error": str(exc),
                    }
                )
                continue
            if not transformed:
                continue
            if transformed in visited:
                continue
            visited.add(transformed)
            pipeline_entry = {"name": stage.name, "detail": details}
            queue.append((transformed, pipeline + [pipeline_entry]))

    result: Dict[str, Any] = {
        **metadata,
        "initial_ratio": round(_printable_ratio(raw_bytes), 3),
        "initial_preview": initial_text[:200],
        "pipelines": candidates,
        "errors": errors,
    }
    return result


def detect_compressed_fragments(
    path: str | Path,
    *,
    fragments: Iterable[Mapping[str, object]] | None = None,
) -> List[Dict[str, object]]:
    """Identify compressed fragments and attempt to decompress them.

    Parameters
    ----------
    path:
        Path to the Lua source file that should be scanned.  Only used when
        ``fragments`` is ``None``.
    fragments:
        Optional iterable of fragment dictionaries as returned by
        :func:`extract_fragments`.  When omitted, fragments are extracted from
        ``path``.

    Returns
    -------
    List[Dict[str, object]]
        Per-fragment compression metadata describing signature matches,
        decompression attempts and Lua-detection heuristics.
    """

    file_path = Path(path)
    if fragments is None:
        fragments = extract_fragments(file_path)

    indexed_fragments: List[Dict[str, object]] = []
    for index, fragment in enumerate(fragments):
        if isinstance(fragment, Mapping):
            entry = dict(fragment)
        else:
            entry = dict(fragment or {})
        entry.setdefault("index", index)
        indexed_fragments.append(entry)

    results: List[Dict[str, object]] = []

    for fragment, decoded in _iter_decoded_fragments(indexed_fragments):
        try:
            data = decoded.encode("latin-1")
        except UnicodeEncodeError:
            continue

        for label, detector, decompressor in _iter_compression_candidates():
            if not detector(data):
                continue

            record: Dict[str, object] = {
                "fragment_index": fragment.get("index"),
                "start": fragment.get("start"),
                "end": fragment.get("end"),
                "type": fragment.get("type"),
                "compression": label,
                "signature": True,
                "success": False,
            }

            try:
                decompressed = decompressor(data)
            except Exception as exc:  # pragma: no cover - best-effort logging
                record["error"] = str(exc)
                results.append(record)
                continue

            record["success"] = True
            record["decoded_length"] = len(decompressed)

            text = _coerce_compressed_text(decompressed)
            record["looks_like_lua"] = _looks_like_lua_snippet(text)
            if text:
                record["decoded_preview"] = text[:160]

            results.append(record)

    return results


def detect_embedded_bytecode(
    path: str | Path,
    *,
    fragments: Iterable[Mapping[str, object]] | None = None,
    output_dir: str | Path | None = None,
) -> List[Dict[str, object]]:
    """Scan decoded fragments for embedded Lua bytecode chunks."""

    file_path = Path(path)
    if fragments is None:
        fragments = extract_fragments(file_path)

    indexed: List[Dict[str, Any]] = []
    for index, fragment in enumerate(fragments):
        entry = dict(fragment) if isinstance(fragment, Mapping) else dict(fragment or {})
        entry.setdefault("index", index)
        indexed.append(entry)

    output_directory = Path(output_dir) if output_dir is not None else None
    created_dir = False
    results: List[Dict[str, Any]] = []

    for fragment in indexed:
        chunk_counter = 0
        for _, decoded in _iter_decoded_fragments([fragment]):
            try:
                data = decoded.encode("latin-1")
            except UnicodeEncodeError:
                continue

            search_offset = 0
            while search_offset < len(data):
                signature_index = data.find(_LUA_SIGNATURE, search_offset)
                if signature_index == -1:
                    break

                candidate = data[signature_index:]
                try:
                    parsed = _parse_lua_bytecode(candidate)
                except Exception as exc:
                    results.append(
                        {
                            "fragment_index": fragment.get("index"),
                            "start": fragment.get("start"),
                            "end": fragment.get("end"),
                            "offset": signature_index,
                            "error": str(exc),
                        }
                    )
                    search_offset = signature_index + 1
                    continue

                header: LuaBytecodeHeader = parsed["header"]
                prototype: LuaPrototype = parsed["prototype"]
                report = _render_bytecode_report(header, prototype)

                output_path: Optional[Path] = None
                if output_directory is not None:
                    if not created_dir:
                        output_directory.mkdir(parents=True, exist_ok=True)
                        created_dir = True
                    fragment_index = fragment.get("index", 0)
                    output_path = output_directory / (
                        f"fragment_{int(fragment_index):03d}_chunk_{chunk_counter:02d}.lua"
                    )
                    output_path.write_text(report, encoding="utf-8")

                record: Dict[str, Any] = {
                    "fragment_index": fragment.get("index"),
                    "start": fragment.get("start"),
                    "end": fragment.get("end"),
                    "offset": signature_index,
                    "bytecode_size": parsed["size"],
                    "version": header.version_string,
                    "format": header.format,
                    "instructions": len(prototype.instructions),
                    "constants": len(prototype.constants),
                    "prototypes": len(prototype.prototypes),
                    "report": report,
                }
                if output_path is not None:
                    record["output"] = str(output_path)

                results.append(record)
                chunk_counter += 1

                next_offset = signature_index + parsed["size"]
                if next_offset <= signature_index:
                    next_offset = signature_index + 1
                search_offset = next_offset

    return results


def cluster_fragments_by_similarity(
    path: str | Path,
    *,
    fragments: Iterable[Mapping[str, object]] | None = None,
    min_length: int = 12,
    similarity_threshold: float = 0.62,
    ngram: int = 4,
) -> List[Dict[str, object]]:
    """Group decoded fragments that look like repeated templates.

    The function performs a lightweight clustering pass that combines a
    Levenshtein-style similarity score (via :func:`difflib.SequenceMatcher`)
    with n-gram Jaccard overlap.  Each produced cluster is annotated with a
    suggested helper name and a preview that can be fed back into the
    reconstruction pipeline when proposing macros.
    """

    file_path = Path(path)
    if fragments is None:
        fragments = extract_fragments(file_path)

    indexed_fragments: List[Dict[str, object]] = []
    for index, fragment in enumerate(fragments):
        entry = dict(fragment) if isinstance(fragment, Mapping) else dict(fragment or {})
        entry.setdefault("index", index)
        indexed_fragments.append(entry)

    candidates: List[Dict[str, object]] = []
    for fragment, decoded in _iter_decoded_fragments(indexed_fragments):
        normalized = _normalise_similarity_text(decoded)
        if len(normalized) < min_length:
            continue
        candidates.append(
            {
                "fragment": fragment,
                "decoded": decoded,
                "normalized": normalized,
                "ngrams": _ngram_set(normalized, n=ngram),
            }
        )

    clusters: List[Dict[str, object]] = []

    for candidate in candidates:
        best_cluster: Optional[Dict[str, object]] = None
        best_score = 0.0
        for cluster in clusters:
            prototype = cluster["prototype"]
            score = _combined_similarity_score(candidate, prototype, ngram)
            if score >= similarity_threshold and score > best_score:
                best_cluster = cluster
                best_score = score

        if best_cluster is None:
            clusters.append(
                {
                    "prototype": candidate,
                    "members": [candidate],
                    "scores": [1.0],
                }
            )
            continue

        best_cluster["members"].append(candidate)
        best_cluster.setdefault("scores", []).append(best_score)
        prototype = best_cluster.get("prototype")
        if isinstance(prototype, Mapping):
            proto_score = best_cluster.get("prototype_score", 0.0)
            if best_score > proto_score:
                best_cluster["prototype"] = candidate
                best_cluster["prototype_score"] = best_score

    cluster_results: List[Dict[str, object]] = []

    for cluster_id, cluster in enumerate(clusters, start=1):
        members = cluster.get("members", [])
        if len(members) < 2:
            continue

        prototype = cluster.get("prototype", {})
        prototype_decoded = (
            str(prototype.get("decoded", "")) if isinstance(prototype, Mapping) else ""
        )

        suggested_name = _suggest_macro_name(prototype_decoded, cluster_id)
        macro_hint = _build_macro_hint(prototype_decoded)

        member_entries: List[Dict[str, object]] = []
        for member in members:
            fragment = member.get("fragment", {}) if isinstance(member, Mapping) else {}
            preview = str(member.get("decoded", ""))[:160]
            member_entries.append(
                {
                    "index": fragment.get("index"),
                    "start": fragment.get("start"),
                    "end": fragment.get("end"),
                    "type": fragment.get("type"),
                    "decoded_preview": preview,
                }
            )

        scores = cluster.get("scores", [])
        average_score = sum(scores) / len(scores) if scores else 1.0

        cluster_results.append(
            {
                "cluster_id": cluster_id,
                "size": len(members),
                "prototype": prototype_decoded,
                "suggested_name": suggested_name,
                "macro_hint": macro_hint,
                "average_similarity": round(average_score, 4),
                "members": member_entries,
            }
        )

    return cluster_results


def infer_encoding_order(
    path: str | Path,
    *,
    fragments: Iterable[Mapping[str, object]] | None = None,
    source: str | None = None,
) -> Dict[str, Any]:
    """Infer how string fragments are reassembled at runtime."""

    file_path = Path(path)
    if fragments is None:
        fragments = extract_fragments(file_path)

    indexed_fragments: List[Dict[str, Any]] = []
    for index, fragment in enumerate(fragments):
        entry = dict(fragment) if isinstance(fragment, Mapping) else dict(fragment or {})
        entry.setdefault("index", index)
        indexed_fragments.append(entry)

    ordered_indices: List[int] = []
    for position, (fragment, _) in enumerate(_iter_decoded_fragments(indexed_fragments)):
        fragment_index = int(fragment.get("index", position))
        ordered_indices.append(fragment_index)

    if not ordered_indices:
        return {"strategy": "unknown", "order": [], "natural_order": [], "evidence": []}

    if source is None:
        source = file_path.read_text(encoding="utf-8", errors="ignore")

    natural_order = list(range(len(ordered_indices)))
    evidence: List[Dict[str, Any]] = []

    order_candidates: List[Dict[str, Any]] = []
    for match in _TABLE_ASSIGN_RE.finditer(source):
        name = match.group("name")
        literal_info = _extract_balanced_braces(source, match.end() - 1)
        if literal_info is None:
            continue
        literal, literal_end = literal_info
        try:
            parsed = parse_lua_expression(literal)
        except Exception:  # pragma: no cover - best effort parsing
            continue
        if not isinstance(parsed, LuaTable):
            continue
        sequence = _lua_table_to_sequence(parsed)
        if not sequence:
            continue
        if not all(_is_int_like(value) for value in sequence if value is not None):
            continue
        ints = [int(value) for value in sequence if value is not None]
        order_candidates.append(
            {
                "name": name,
                "values": ints,
                "start": match.start(),
                "end": literal_end,
            }
        )

    selected: Optional[Dict[str, Any]] = None
    nested_template = r"\b([A-Za-z_]\w*)\s*\[\s*{order}\s*\[\s*[A-Za-z_]\w*\s*\]\s*\]"

    for candidate in order_candidates:
        order_name = candidate["name"]
        usage_patterns = [
            re.compile(rf"ipairs\s*\(\s*{re.escape(order_name)}\s*\)", re.IGNORECASE),
            re.compile(rf"#\s*{re.escape(order_name)}\b"),
            re.compile(rf"{re.escape(order_name)}\s*\["),
        ]
        if not any(pattern.search(source) for pattern in usage_patterns):
            candidate["used"] = False
            continue

        candidate["used"] = True
        nested_re = re.compile(nested_template.format(order=re.escape(order_name)))
        nested_match = nested_re.search(source)
        if nested_match:
            candidate["target_table"] = nested_match.group(1)

        if selected is None or len(candidate["values"]) > len(selected["values"]):
            selected = candidate

    strategy = "sequential"
    order: List[int] = natural_order.copy()

    if selected is not None and selected.get("values"):
        converted: List[int] = []
        for value in selected["values"]:
            index = int(value) - 1
            if 0 <= index < len(ordered_indices):
                converted.append(ordered_indices[index])
            else:
                converted.append(index)

        preview = " ".join(source[selected["start"] : selected["end"]].split())
        if len(preview) > 160:
            preview = preview[:159] + "…"

        evidence.append(
            {
                "type": "order_array",
                "name": selected["name"],
                "length": len(selected["values"]),
                "preview": preview,
            }
        )
        if "target_table" in selected:
            evidence.append(
                {
                    "type": "index_usage",
                    "order": selected["name"],
                    "target": selected["target_table"],
                }
            )

        trimmed_natural = natural_order[: len(converted)]
        if converted == trimmed_natural and len(converted) == len(natural_order):
            strategy = "sequential_loop"
            order = converted
        else:
            strategy = "indexed_reassembly"
            order = converted
    else:
        if re.search(r"table\\.concat\s*\(", source):
            evidence.append({"type": "table_concat"})

    return {
        "strategy": strategy,
        "order": order,
        "natural_order": natural_order,
        "evidence": evidence,
    }


def extract_embedded_comments(
    paths: str | Path | Sequence[str | Path],
    *,
    output_path: str | Path = "EXTRACTED_NOTES.md",
    min_length: int = 18,
    min_words: int = 4,
    printable_ratio: float = 0.85,
) -> Dict[str, object]:
    """Extract comment-like string literals and persist them to Markdown."""

    expanded_paths = _expand_comment_scan_paths(paths)
    notes: List[Dict[str, object]] = []
    grouped: DefaultDict[Path, List[Dict[str, object]]] = defaultdict(list)

    for file_path in expanded_paths:
        fragments = extract_fragments(file_path)
        indexed: List[Dict[str, object]] = []
        for index, fragment in enumerate(fragments):
            entry = dict(fragment) if isinstance(fragment, Mapping) else dict(fragment or {})
            entry.setdefault("index", index)
            indexed.append(entry)

        for fragment, decoded in _iter_decoded_fragments(indexed):
            comment = _normalise_embedded_comment(
                decoded,
                min_length=min_length,
                min_words=min_words,
                printable_ratio=printable_ratio,
            )
            if not comment:
                continue

            record = {
                "path": str(file_path),
                "fragment_index": fragment.get("index"),
                "start": fragment.get("start"),
                "end": fragment.get("end"),
                "text": comment,
            }
            notes.append(record)
            grouped[file_path].append(record)

    output = Path(output_path)
    output_lines = [
        "# Extracted Notes",
        "",
        "Generated on {}".format(datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"),
        "",
    ]

    if not grouped:
        output_lines.append("_No comment-like strings were detected._")
    else:
        for file_path in sorted(grouped):
            header = detect_luraph_header(file_path)
            version = header.get("version") or "unknown"
            structure = header.get("structure") or "unknown"

            output_lines.append(f"## {file_path}")
            output_lines.append("")
            output_lines.append(f"- Version: `{version}`  •  Structure: `{structure}`")
            output_lines.append("")

            for record in grouped[file_path]:
                start = record.get("start")
                end = record.get("end")
                fragment_index = record.get("fragment_index")
                location_bits: List[str] = []
                if fragment_index is not None:
                    location_bits.append(f"fragment {fragment_index}")
                if isinstance(start, int) and isinstance(end, int):
                    location_bits.append(f"offsets {start}–{end}")
                elif isinstance(start, int):
                    location_bits.append(f"offset {start}")

                location = "; ".join(location_bits)
                if location:
                    output_lines.append(f"- {location}:")
                else:
                    output_lines.append("- Fragment:")
                output_lines.append("")
                output_lines.append("```")
                output_lines.append(record["text"])
                output_lines.append("```")
                output_lines.append("")

    output.write_text("\n".join(output_lines).rstrip() + "\n", encoding="utf-8")

    return {
        "output_path": str(output),
        "notes": notes,
        "files": [str(path) for path in expanded_paths],
    }


def _iter_compression_candidates() -> Iterable[
    Tuple[str, Callable[[bytes], bool], Callable[[bytes], bytes]]
]:
    yield "zlib", _looks_like_zlib_header, zlib.decompress
    yield "gzip", _looks_like_gzip_header, gzip.decompress


def _normalise_similarity_text(text: str) -> str:
    lowered = text.lower()
    collapsed = re.sub(r"\s+", " ", lowered)
    return collapsed.strip()


def _ngram_set(text: str, *, n: int = 4) -> Set[str]:
    if n <= 1:
        return {text}
    if len(text) <= n:
        return {text}
    return {text[i : i + n] for i in range(len(text) - n + 1)}


def _combined_similarity_score(
    candidate: Mapping[str, object],
    prototype: Mapping[str, object] | None,
    ngram: int,
) -> float:
    if not isinstance(prototype, Mapping):
        return 0.0

    a = str(candidate.get("normalized", ""))
    b = str(prototype.get("normalized", ""))
    if not a or not b:
        return 0.0

    seq_ratio = difflib.SequenceMatcher(None, a, b).ratio()

    ngrams_a = candidate.get("ngrams")
    ngrams_b = prototype.get("ngrams")
    if not isinstance(ngrams_a, set) or not isinstance(ngrams_b, set):
        ngrams_a = _ngram_set(a, n=ngram)
        ngrams_b = _ngram_set(b, n=ngram)

    if ngrams_a and ngrams_b:
        jaccard = len(ngrams_a & ngrams_b) / len(ngrams_a | ngrams_b)
    else:
        jaccard = 0.0

    return (seq_ratio + jaccard) / 2.0


_MACRO_STOPWORDS = {
    "local",
    "return",
    "function",
    "end",
    "then",
    "do",
    "if",
    "for",
    "while",
}


def _suggest_macro_name(prototype: str, cluster_id: int) -> str:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", prototype)
    for token in tokens:
        lowered = token.lower()
        if lowered in LUA_KEYWORDS or lowered in LUA_GLOBALS:
            continue
        if lowered in _MACRO_STOPWORDS:
            continue
        if lowered:
            return f"{lowered}_helper"
    return f"macro_{cluster_id:02d}"


def _build_macro_hint(prototype: str) -> str:
    if not prototype:
        return ""
    lines = [line.strip() for line in prototype.strip().splitlines() if line.strip()]
    if not lines:
        return ""
    preview = "\n".join(lines[:3])
    if len(lines) > 3:
        preview += "\n..."
    return preview


def _expand_comment_scan_paths(paths: str | Path | Sequence[str | Path]) -> List[Path]:
    if isinstance(paths, (str, Path)):
        candidates: Sequence[str | Path] = [paths]
    elif isinstance(paths, Sequence):
        candidates = paths
    else:
        raise TypeError("paths must be a path-like or a sequence of path-likes")

    expanded: List[Path] = []
    seen: Set[Path] = set()

    for entry in candidates:
        path_obj = Path(entry)
        resolved = path_obj.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)

        if path_obj.is_dir():
            for lua_path in sorted(path_obj.rglob("*.lua")):
                if not lua_path.is_file():
                    continue
                lua_resolved = lua_path.resolve()
                if lua_resolved in seen:
                    continue
                seen.add(lua_resolved)
                expanded.append(lua_path)
        elif path_obj.is_file():
            expanded.append(path_obj)

    return expanded


def _normalise_embedded_comment(
    text: str,
    *,
    min_length: int,
    min_words: int,
    printable_ratio: float,
) -> Optional[str]:
    if not text:
        return None

    normalized = text.strip().replace("\r\n", "\n").replace("\r", "\n")
    if len(normalized) < min_length:
        return None

    printable = sum(1 for ch in normalized if ch.isprintable())
    if printable / len(normalized) < printable_ratio:
        return None

    alpha = sum(1 for ch in normalized if ch.isalpha())
    if not alpha or alpha / len(normalized) < 0.35:
        return None

    collapsed = re.sub(r"\s+", " ", normalized)
    words = _COMMENT_WORD_RE.findall(collapsed)
    if len(words) < min_words:
        return None

    space_count = collapsed.count(" ")
    if space_count == 0:
        return None

    space_ratio = space_count / len(collapsed)
    if space_ratio < 0.05:
        return None

    lower = collapsed.lower()
    has_marker = any(marker in lower for marker in ("--", "//", "/*", "note", "warning", "todo", "caution"))
    has_sentence = bool(_COMMENT_SENTENCE_RE.search(collapsed))
    multi_word = collapsed.count(" ") >= max(1, min_words - 1)

    if not (has_marker or has_sentence or multi_word):
        return None

    return normalized


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _classify_entropy(entropy: float, length: int) -> str:
    if length < 16:
        return "short"
    if entropy >= 7.0:
        return "high"
    if entropy >= 5.0:
        return "medium"
    return "low"


def entropy_detector(
    path: str | Path,
    *,
    fragments: Iterable[Mapping[str, object]] | None = None,
) -> List[Dict[str, object]]:
    """Rank decoded fragments by Shannon entropy."""

    file_path = Path(path)
    if fragments is None:
        fragments = extract_fragments(file_path)

    indexed_fragments: List[Dict[str, object]] = []
    for index, fragment in enumerate(fragments):
        if isinstance(fragment, Mapping):
            entry = dict(fragment)
        else:
            entry = dict(fragment or {})
        entry.setdefault("index", index)
        indexed_fragments.append(entry)

    ranked: List[Dict[str, object]] = []

    for fragment, decoded in _iter_decoded_fragments(indexed_fragments):
        if not isinstance(decoded, str):
            continue
        try:
            data = decoded.encode("latin-1")
        except UnicodeEncodeError:
            data = decoded.encode("utf-8", errors="ignore")
        if not data:
            continue

        entropy = _shannon_entropy(data)
        length = len(data)
        classification = _classify_entropy(entropy, length)

        ranked.append(
            {
                "fragment_index": fragment.get("index"),
                "start": fragment.get("start"),
                "end": fragment.get("end"),
                "type": fragment.get("type"),
                "length": length,
                "entropy": round(entropy, 3),
                "classification": classification,
                "decoded": decoded,
                "preview": decoded[:80],
            }
        )

    ranked.sort(key=lambda item: (item.get("entropy", 0.0), item.get("length", 0)), reverse=True)
    return ranked


def _looks_like_zlib_header(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    if cmf & 0x0F != 8:
        return False
    if ((cmf << 8) + flg) % 31 != 0:
        return False
    return True


def _looks_like_gzip_header(data: bytes) -> bool:
    if len(data) < 3:
        return False
    return data[0] == 0x1F and data[1] == 0x8B and data[2] == 8


def _coerce_compressed_text(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="ignore")


def _looks_like_lua_snippet(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    score = 0
    for token in ("function", "local", "return", "end", "for", "while"):
        if token in lowered:
            score += 1
    if score >= 2:
        return True
    if "=" in text and "(" in text and ")" in text:
        return True
    return False


def _detect_top_level_structure(text: str) -> str:
    return_table_patterns = [r"return\s*\(\s*\{", r"return\s*\{"]
    for pattern in return_table_patterns:
        if re.search(pattern, text):
            return "return({...})"
    if re.search(r"return\s+function", text):
        return "return function"
    if re.search(r"return\s+\w", text):
        return "return expression"
    return "other"


def _match_long_bracket(text: str, pos: int) -> Optional[int]:
    match = _LONG_BRACKET_OPEN_RE.match(text, pos)
    if match:
        return len(match.group(1))
    return None


def _extract_balanced_braces(text: str, brace_index: int) -> Optional[Tuple[str, int]]:
    if brace_index < 0 or brace_index >= len(text) or text[brace_index] != "{":
        return None

    depth = 0
    i = brace_index
    length = len(text)
    in_string: Optional[str] = None

    while i < length:
        ch = text[i]
        if in_string is not None:
            if ch == "\\" and i + 1 < length:
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in {'"', "'"}:
            in_string = ch
            i += 1
            continue

        if ch == "[":
            equals = _match_long_bracket(text, i)
            if equals is not None:
                closing = "]" + "=" * equals + "]"
                end_idx = text.find(closing, i + 2 + equals)
                if end_idx == -1:
                    return None
                i = end_idx + len(closing)
                continue

        if ch == "-" and text.startswith("--", i):
            if i + 2 < length and text[i + 2] == "[":
                equals = _match_long_bracket(text, i + 2)
                if equals is not None:
                    closing = "]" + "=" * equals + "]"
                    end_idx = text.find(closing, i + 2 + 2 + equals)
                    if end_idx == -1:
                        return None
                    i = end_idx + len(closing)
                    continue
            newline = text.find("\n", i + 2)
            if newline == -1:
                return None
            i = newline + 1
            continue

        if ch == "{":
            depth += 1
            i += 1
            continue

        if ch == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return text[brace_index:i], i
            continue

        i += 1

    return None


def _lua_table_to_sequence(table: LuaTable) -> List[Any]:
    values: List[Any] = list(table.array)
    numeric_mapping: Dict[int, Any] = {}
    for key, value in table.mapping:
        if isinstance(key, bool):
            continue
        if isinstance(key, (int, float)) and float(key).is_integer():
            numeric_mapping[int(key)] = value

    for index in sorted(numeric_mapping):
        value = numeric_mapping[index]
        target = index - 1
        if target < 0:
            continue
        if target < len(values):
            values[target] = value
            continue
        while len(values) < target:
            values.append(None)
        values.append(value)

    return values


def _is_int_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, float) and float(value).is_integer():
        return True
    return False


def _consume_short_string(text: str, start: int) -> int:
    delimiter = text[start]
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == delimiter:
            return i + 1
        if ch in "\r\n":
            return i
        i += 1
    return n


def _consume_long_bracket(text: str, start: int, equals: int) -> int:
    closing = "]" + "=" * equals + "]"
    search_pos = start + 2 + equals
    while True:
        idx = text.find(closing, search_pos)
        if idx == -1:
            return len(text)
        return idx + len(closing)


def _normalize_long_bracket_fragment_text(fragment: str) -> Tuple[str, Optional[int]]:
    """Return *fragment* with a minimal delimiter level that preserves content."""

    match = _LONG_BRACKET_OPEN_RE.match(fragment)
    if not match:
        return fragment, None

    original_equals = len(match.group(1))
    end = _consume_long_bracket(fragment, 0, original_equals)
    closing = "]" + "=" * original_equals + "]"
    if end <= len(closing):
        return fragment, original_equals

    body_start = len(match.group(0))
    body_end = end - len(closing)
    if body_end < body_start:
        return fragment, original_equals

    body = fragment[body_start:body_end]

    limit = len(body) + 2
    target_equals: Optional[int] = None
    for level in range(limit):
        candidate = "]" + "=" * level + "]"
        if candidate not in body:
            target_equals = level
            break

    if target_equals is None:
        return fragment, original_equals

    opening = "[" + "=" * target_equals + "["
    closing_norm = "]" + "=" * target_equals + "]"
    normalized = opening + body + closing_norm
    return normalized, target_equals


def _normalize_long_bracket_literals(text: str) -> Tuple[str, Dict[str, int]]:
    """Normalise long-bracket strings in *text* while skipping comments."""

    stats = {
        "total": 0,
        "normalized": 0,
        "unchanged": 0,
        "reduced": 0,
        "increased": 0,
    }

    if not text:
        return text, stats

    n = len(text)
    i = 0
    last = 0
    result: List[str] = []

    line_comment = False
    block_comment: Optional[int] = None
    short_quote: Optional[str] = None

    while i < n:
        if line_comment:
            if text[i] in "\r\n":
                line_comment = False
            i += 1
            continue

        if block_comment is not None:
            closing = "]" + "=" * block_comment + "]"
            if text.startswith(closing, i):
                block_comment = None
                i += len(closing)
            else:
                i += 1
            continue

        if short_quote is not None:
            if text[i] == "\\" and i + 1 < n:
                i += 2
                continue
            if text[i] == short_quote:
                short_quote = None
            i += 1
            continue

        ch = text[i]

        if ch == "-" and text.startswith("--", i):
            equals = _match_long_bracket(text, i + 2)
            if equals is not None:
                block_comment = equals
                i += 2 + 2 + equals
                continue
            line_comment = True
            i += 2
            continue

        if ch in {'"', "'"}:
            short_quote = ch
            i += 1
            continue

        if ch == "[":
            equals = _match_long_bracket(text, i)
            if equals is not None:
                end = _consume_long_bracket(text, i, equals)
                original = text[i:end]
                normalized, target_equals = _normalize_long_bracket_fragment_text(original)
                stats["total"] += 1
                target_equals = target_equals if target_equals is not None else equals
                if normalized != original:
                    stats["normalized"] += 1
                    if target_equals > equals:
                        stats["increased"] += 1
                    elif target_equals < equals:
                        stats["reduced"] += 1
                    if last < i:
                        result.append(text[last:i])
                    result.append(normalized)
                    last = end
                else:
                    stats["unchanged"] += 1
                i = end
                continue

        i += 1

    if not result:
        return text, stats

    if last < n:
        result.append(text[last:])

    normalized_text = "".join(result)
    return normalized_text, stats


def normalize_bracket_literals(text: str) -> Tuple[str, Dict[str, int]]:
    """Public wrapper around :func:`_normalize_long_bracket_literals`."""

    normalized, stats = _normalize_long_bracket_literals(text)
    return normalized, stats.copy()


_UNICODE_CONTROL_WHITELIST = {"\n", "\r", "\t"}


def _normalize_unicode_text(value: str) -> str:
    if not value:
        return ""
    return unicodedata.normalize("NFC", value)


def _decode_short_fragment(fragment: str) -> str:
    if not fragment:
        return ""
    delimiter = fragment[0]
    if delimiter not in {'"', "'"}:
        return fragment
    body = fragment[1:]
    if len(fragment) >= 2 and fragment[-1] == delimiter:
        body = fragment[1:-1]
    return _normalize_unicode_text(lu_unescape(body))


def _decode_long_fragment(fragment: str) -> str:
    match = _LONG_BRACKET_OPEN_RE.match(fragment)
    if not match:
        return fragment
    equals = match.group(1)
    closing = "]" + "=" * len(equals) + "]"
    start = len(match.group(0))
    if fragment.endswith(closing):
        end = len(fragment) - len(closing)
        body = fragment[start:end]
    else:
        body = fragment[start:]
    if body.startswith("\r\n"):
        body = body[2:]
    elif body.startswith("\n") or body.startswith("\r"):
        body = body[1:]
    return _normalize_unicode_text(body)


def _escape_lua_string_body(value: str) -> str:
    """Return a canonical escaped representation for a Lua short-string body."""

    if not value:
        return ""

    out: List[str] = []
    for ch in value:
        code = ord(ch)
        category = unicodedata.category(ch)
        if 32 <= code <= 126 and ch not in {'\\', '"', "'"}:
            out.append(ch)
            continue
        if ch == "\ufeff" or (
            (category.startswith("C") or category in {"Zl", "Zp"})
            and ch not in _UNICODE_CONTROL_WHITELIST
        ):
            out.append(_escape_utf8_bytes(ch))
            continue
        if code <= 0xFF:
            out.append(f"\\x{code:02X}")
            continue
        out.append(f"\\u{{{code:04X}}}")
    return "".join(out)


def _escape_utf8_bytes(value: str) -> str:
    return "".join(f"\\x{byte:02X}" for byte in value.encode("utf-8"))


def _is_problematic_unicode(ch: str) -> bool:
    if ch in _UNICODE_CONTROL_WHITELIST:
        return False
    if ch == "\ufeff":
        return True
    category = unicodedata.category(ch)
    if category.startswith("C"):
        return True
    return category in {"Zl", "Zp"}


def _scan_unicode_anomalies(
    decoded_pairs: Iterable[Tuple[Mapping[str, object], str]]
) -> Dict[str, object]:
    bom_count = 0
    control_count = 0
    samples: List[Dict[str, object]] = []

    for index, (fragment, decoded) in enumerate(decoded_pairs):
        occurrences: List[Dict[str, object]] = []
        for offset, ch in enumerate(decoded):
            if ch == "\ufeff":
                bom_count += 1
                occurrences.append(
                    {
                        "offset": offset,
                        "kind": "bom",
                        "codepoint": f"U+{ord(ch):04X}",
                        "escaped": _escape_utf8_bytes(ch),
                    }
                )
                continue
            if _is_problematic_unicode(ch):
                control_count += 1
                occurrences.append(
                    {
                        "offset": offset,
                        "kind": "control",
                        "codepoint": f"U+{ord(ch):04X}",
                        "escaped": _escape_utf8_bytes(ch),
                    }
                )
        if occurrences:
            sample = {
                "fragment_index": fragment.get("index", index),
                "fragment_type": fragment.get("type"),
                "start": fragment.get("start"),
                "occurrences": occurrences,
            }
            samples.append(sample)

    return {
        "bom_count": bom_count,
        "control_count": control_count,
        "samples": samples,
    }


def _verify_decoded_string_roundtrip(
    decoded_fragments: Iterable[Tuple[Mapping[str, object], str]]
) -> Dict[str, int]:
    """Ensure decoded fragments survive canonical escape round-trips."""

    mismatches: List[Dict[str, object]] = []
    checked = 0
    for index, (fragment, decoded) in enumerate(decoded_fragments):
        if fragment.get("type") != "long_quoted":
            continue
        raw_text = fragment.get("text")
        if not isinstance(raw_text, str) or not raw_text:
            continue

        delimiter = raw_text[0]
        if delimiter not in {'"', "'"}:
            continue
        body = raw_text[1:]
        if raw_text.endswith(delimiter):
            body = raw_text[1:-1]

        canonical_body = canonicalize_escapes(body)
        pipeline_value = lu_unescape(canonical_body)
        if pipeline_value != decoded:
            mismatches.append(
                {
                    "index": index,
                    "reason": "unescape-mismatch",
                    "expected": pipeline_value,
                    "decoded": decoded,
                    "start": fragment.get("start"),
                }
            )
            continue

        escaped_body = _escape_lua_string_body(pipeline_value)
        round_trip = lu_unescape(escaped_body)
        if round_trip != decoded:
            fallback: Optional[str] = None
            try:
                fallback_bytes = round_trip.encode("latin-1")
            except UnicodeEncodeError:
                fallback_bytes = None
            if fallback_bytes is not None:
                try:
                    fallback = fallback_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    fallback = None
            if fallback == decoded:
                checked += 1
                continue

            mismatches.append(
                {
                    "index": index,
                    "reason": "escape-roundtrip-mismatch",
                    "decoded": decoded,
                    "round_trip": round_trip,
                    "start": fragment.get("start"),
                }
            )
            continue

        checked += 1

    if mismatches:
        first = mismatches[0]
        reason = first.get("reason", "mismatch")
        start = first.get("start")
        raise AssertionError(
            "String reconstruction verification failed ({reason}) at fragment"
            " {index} (start={start}): expected {expected!r}, got {decoded!r}".format(
                reason=reason,
                index=first.get("index"),
                start=start,
                expected=first.get("expected", first.get("decoded")),
                decoded=first.get("decoded"),
            )
        )

    return {"checked": checked}


def verify_reconstructed_strings(
    fragments: Iterable[Mapping[str, object]]
) -> Dict[str, int]:
    """Public helper to validate decoded fragments generated from *fragments*."""

    decoded = list(_iter_decoded_fragments(fragments))
    return _verify_decoded_string_roundtrip(decoded)


def _compute_boundary_report(
    decoded_fragments: Iterable[Tuple[Mapping[str, object], str]]
) -> List[Dict[str, int]]:
    report: List[Dict[str, int]] = []
    offset = 0
    for fragment, decoded in decoded_fragments:
        length = len(decoded)
        start_raw = fragment.get("start")
        end_raw = fragment.get("end")
        try:
            start = int(start_raw) if start_raw is not None else -1
        except (TypeError, ValueError):
            start = -1
        try:
            end = int(end_raw) if end_raw is not None else -1
        except (TypeError, ValueError):
            end = -1
        report.append(
            {
                "type": str(fragment.get("type")),
                "original_start": start,
                "original_end": end,
                "output_start": offset,
                "output_end": offset + length,
            }
        )
        offset += length
    return report


def _summarise_boundary_diff(report: List[Dict[str, int]]) -> Dict[str, object]:
    mismatches: List[Dict[str, int]] = []
    if report != sorted(report, key=lambda entry: (entry.get("original_start", -1), entry.get("original_end", -1))):
        for index, entry in enumerate(report):
            mismatches.append({"index": index, "original_start": entry.get("original_start", -1)})
    for idx in range(1, len(report)):
        prev = report[idx - 1]
        curr = report[idx]
        if prev.get("output_end", 0) > curr.get("output_start", 0):
            mismatches.append(
                {
                    "index": idx,
                    "output_start": curr.get("output_start", -1),
                    "previous_output_end": prev.get("output_end", -1),
                }
            )
    return {"reordered": bool(mismatches), "mismatches": mismatches}


def _dump_fragment_metadata(
    output_path: Path, decoded_pairs: Sequence[Tuple[Mapping[str, object], str]]
) -> Path:
    fragment_path = Path(str(output_path) + ".fragments.json")

    fragments_payload: List[Dict[str, object]] = []
    for index, (fragment, decoded) in enumerate(decoded_pairs):
        entry = dict(fragment)
        entry.setdefault("index", index)
        entry["decoded"] = decoded
        entry["escaped"] = _escape_lua_string_body(decoded)
        fragments_payload.append(entry)

    payload = {
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "count": len(fragments_payload),
        "fragments": fragments_payload,
    }

    fragment_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return fragment_path


def _dedupe_paths(candidates: Iterable[Path]) -> List[Path]:
    seen: Set[str] = set()
    unique: List[Path] = []
    for candidate in candidates:
        text = str(candidate)
        if text in seen:
            continue
        seen.add(text)
        unique.append(candidate)
    return unique


def _first_existing_path(paths: Sequence[Path]) -> Optional[Path]:
    for candidate in paths:
        if candidate.exists():
            return candidate
    return None


def _candidate_upcodes_paths(output_path: Path) -> List[Path]:
    base = output_path.parent
    candidates = [
        base / "upcodes.md",
        base.parent / "upcodes.md",
        Path("upcodes.md"),
    ]
    return _dedupe_paths(candidates)


def _candidate_manifest_paths(output_path: Path) -> List[Path]:
    base = output_path.parent
    candidates = [
        base / "run_manifest.json",
        base / "candidates" / "run_manifest.json",
        base.parent / "run_manifest.json",
        Path("run_manifest.json"),
        Path("candidates") / "run_manifest.json",
    ]
    return _dedupe_paths(candidates)


def _candidate_identifier_plan_paths(output_path: Path) -> List[Path]:
    base = output_path.parent
    candidates = [
        output_path.with_name(f"{output_path.stem}_identifier_plan.csv"),
        base / "identifier_plan.csv",
        base / "candidates" / "identifier_plan.csv",
        base.parent / "identifier_plan.csv",
        Path("identifier_plan.csv"),
        Path("candidates") / "identifier_plan.csv",
    ]
    return _dedupe_paths(candidates)


def _create_evidence_archive(
    output_path: Path,
    *,
    original_path: Path,
    fragment_dump_path: Path,
    mapping_path: Path,
    upcodes_candidates: Sequence[Path],
    manifest_candidates: Sequence[Path],
    license_paths: Sequence[Path | None],
    dangerous_path: Path | None = None,
    fingerprint_path: Path | None = None,
) -> Dict[str, object]:
    evidence_path = output_path.parent / "evidence.zip"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    included: List[Dict[str, object]] = []
    missing: List[str] = []

    entries: List[Tuple[str, Optional[Path]]] = [
        ("original", original_path),
        ("fragments", fragment_dump_path),
        ("deobfuscated", output_path),
        ("mapping", mapping_path),
        ("upcodes", _first_existing_path(upcodes_candidates)),
        ("run_manifest", _first_existing_path(manifest_candidates)),
    ]

    for license_path in license_paths:
        if license_path is not None:
            entries.append(("license_audit", license_path))

    if dangerous_path is not None:
        entries.append(("dangerous_calls", dangerous_path))

    if fingerprint_path is not None:
        entries.append(("fingerprint", fingerprint_path))

    with zipfile.ZipFile(evidence_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for label, candidate in entries:
            if candidate is None or not candidate.exists():
                missing.append(label)
                continue

            arcname = f"{label}/{candidate.name}"
            archive.write(candidate, arcname=arcname)
            included.append(
                {"label": label, "path": str(candidate), "arcname": arcname}
            )

    return {
        "evidence_archive_path": str(evidence_path),
        "evidence_included": included,
        "evidence_missing": missing,
    }




def _load_fragment_dump(path: Path) -> Optional[Dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    fragments = payload.get("fragments")
    if not isinstance(fragments, list):
        return None

    return {
        "count": int(payload.get("count", len(fragments))),
        "fragments": fragments,
    }


def _write_mapping_lock(
    mapping_path: Path,
    *,
    functions_total: int,
    functions_renamed: int,
    runtime_flagged: Optional[int],
    runtime_total: Optional[int],
    completeness_score: float,
) -> Dict[str, object]:
    lock_path = _mapping_lock_path(mapping_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        mapping_bytes = mapping_path.read_bytes()
    except OSError as exc:  # pragma: no cover - unexpected I/O failure
        raise RuntimeError(f"failed to read mapping file for lock: {exc}") from exc

    digest = hashlib.sha256(mapping_bytes).hexdigest()
    relative = os.path.relpath(mapping_path, lock_path.parent)

    payload: Dict[str, object] = {
        "locked_at": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "mapping_path": relative,
        "mapping_sha256": digest,
        "functions_total": int(functions_total),
        "functions_renamed": int(functions_renamed),
        "runtime_flagged": int(runtime_flagged or 0),
        "runtime_total": int(runtime_total or functions_total or 0),
        "renamed_fraction": (
            float(functions_renamed) / float(functions_total)
            if functions_total
            else 1.0
        ),
        "completeness_score": round(float(completeness_score or 0.0), 4),
        "high_confidence": True,
    }

    lock_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return payload


def _mapping_lock_path(mapping_path: Path) -> Path:
    """Return the canonical lockfile path for *mapping_path*."""

    return mapping_path.with_name("mapping.lock")


def _load_mapping_lock(lock_path: Path) -> Optional[Dict[str, object]]:
    """Return lock metadata from ``mapping.lock`` or ``None`` if invalid."""

    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    return dict(payload)


def _mapping_from_lock(lock_path: Path) -> Optional[Path]:
    metadata = _load_mapping_lock(lock_path)
    if metadata is None:
        return None

    mapping_value = metadata.get("mapping_path")
    if isinstance(mapping_value, str) and mapping_value:
        candidate = Path(mapping_value)
        if not candidate.is_absolute():
            candidate = (lock_path.parent / mapping_value).resolve()
    else:
        candidate = lock_path.with_name("mapping.json")

    if not candidate.exists():
        return None

    digest = metadata.get("mapping_sha256")
    if isinstance(digest, str) and digest:
        try:
            actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        except OSError:
            return None
        if actual != digest:
            return None

    return candidate


def _resolve_mapping_path(
    mapping_path: Optional[str | Path], source: Path, reconstructed: Optional[Path]
) -> Optional[Path]:
    candidates: List[Path] = []

    if mapping_path is not None:
        direct = Path(mapping_path)
        if direct.suffix == ".lock":
            locked = _mapping_from_lock(direct)
            if locked is not None:
                return locked
            candidates.append(direct.with_name("mapping.json"))
        candidates.append(direct)
        candidates.append(_mapping_lock_path(direct))

    if reconstructed is not None:
        base = reconstructed.parent
        candidates.append(base / "mapping.lock")
        candidates.append(base / "mapping.json")

    source_parent = source.parent
    candidates.extend(
        [
            source.with_name("mapping.lock"),
            source.with_name("mapping.json"),
            source_parent / "mapping.lock",
            source_parent / "mapping.json",
            Path("mapping.lock"),
            Path("mapping.json"),
        ]
    )

    for candidate in _dedupe_paths(candidates):
        if candidate.name == "mapping.lock":
            locked = _mapping_from_lock(candidate)
            if locked is not None:
                return locked
            continue
        if candidate.exists():
            return candidate
    return None


def _load_top_level_entries(
    top_level_path: Optional[Path], reconstructed_path: Optional[Path]
) -> Optional[Dict[str, Dict[str, object]]]:
    if top_level_path is not None and top_level_path.exists():
        try:
            payload = json.loads(top_level_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        if isinstance(payload, dict):
            return payload
        return None

    if reconstructed_path is None:
        return None

    try:
        report = introspect_top_level_table(reconstructed_path)
    except Exception:  # pragma: no cover - best-effort guard
        return None

    entries = report.get("entries") if isinstance(report, Mapping) else None
    if isinstance(entries, dict):
        return entries
    return None


def _coerce_parity_success(report: object) -> Optional[bool]:
    if report is None:
        return None
    if isinstance(report, bool):
        return bool(report)
    if isinstance(report, Mapping):
        if "match" in report:
            return bool(report.get("match"))
        if "success" in report:
            return bool(report.get("success"))
    success_attr = getattr(report, "success", None)
    if isinstance(success_attr, bool):
        return success_attr
    return None


def _load_identifier_plan(
    paths: Iterable[Path],
) -> Tuple[Optional[List[Dict[str, str]]], Optional[Path]]:
    for candidate in _dedupe_paths(list(paths)):
        if not candidate.exists():
            continue
        try:
            with candidate.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                rows: List[Dict[str, str]] = []
                for row in reader:
                    if not row:
                        continue
                    normalised = {str(key): (value or "") for key, value in row.items()}
                    if any(value for value in normalised.values()):
                        rows.append(normalised)
        except Exception:
            continue
        else:
            return rows, candidate
    return None, None


def _clamp_01(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if math.isnan(value):  # pragma: no cover - defensive guard
        return None
    return max(0.0, min(1.0, value))


def _looks_like_plain_key(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 6:
        return False
    if stripped.lower().startswith("0x"):
        return False
    if all(ch in string.hexdigits for ch in stripped):
        return False
    if not any(ch.isalpha() for ch in stripped):
        return False
    return True


def _audit_manifest_for_keys(path: Path) -> Dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"passed": False, "detail": "unable to read manifest"}

    violations: List[str] = []

    def _scan(obj: object, context: str = "root") -> None:
        if isinstance(obj, Mapping):
            for key, value in obj.items():
                key_str = str(key)
                next_context = f"{context}.{key_str}" if context else key_str
                lower = key_str.lower()
                if lower == "keys" and isinstance(value, list):
                    for index, entry in enumerate(value):
                        if not isinstance(entry, Mapping):
                            continue
                        entry_context = f"{next_context}[{index}]"
                        unexpected = [
                            field
                            for field in entry
                            if field not in {"ref", "hmac", "length"}
                        ]
                        if unexpected:
                            violations.append(
                                f"unexpected fields {unexpected} in {entry_context}"
                            )
                        for field, field_value in entry.items():
                            if (
                                isinstance(field_value, str)
                                and field not in {"hmac", "ref"}
                                and _looks_like_plain_key(field_value)
                            ):
                                violations.append(
                                    f"potential key material in {entry_context}.{field}"
                                )
                    continue
                if "key" in lower and isinstance(value, str):
                    if _looks_like_plain_key(value):
                        violations.append(
                            f"potential key material in {next_context}"
                        )
                _scan(value, next_context)
        elif isinstance(obj, list):
            for index, value in enumerate(obj):
                _scan(value, f"{context}[{index}]")

    _scan(payload)

    return {
        "passed": not violations,
        "detail": {"violations": violations},
    }


def evaluate_deobfuscation_checklist(
    source_path: str | Path,
    *,
    reconstructed_path: str | Path | None = None,
    fragment_dump_path: str | Path | None = None,
    mapping_path: str | Path | None = None,
    top_level_path: str | Path | None = None,
    upcodes_path: str | Path | None = None,
    parity_reports: Iterable[object] | None = None,
    parity_report_paths: Iterable[str | Path] | None = None,
    manifest_path: str | Path | None = None,
    write_lock_if_high_confidence: bool = False,
) -> Dict[str, object]:
    """Return checklist status indicating whether a run can be marked complete."""

    source = Path(source_path)
    reconstructed = Path(reconstructed_path) if reconstructed_path else None
    fragment_dump = Path(fragment_dump_path) if fragment_dump_path else None
    top_level = Path(top_level_path) if top_level_path else None

    checks: List[Dict[str, object]] = []
    overall_passed = True

    expected_fragments = 0
    processed_fragments = 0
    fragment_fraction: Optional[float] = None
    functions: List[str] = []
    missing: List[str] = []
    total_opcodes = 0
    named_opcodes = 0
    opcodes_fraction: Optional[float] = None
    opcodes_unmapped = 0
    parity_statuses: List[bool] = []
    parity_passed = 0
    parity_rate: Optional[float] = None
    runtime_flagged: Optional[int] = None
    runtime_total: Optional[int] = None
    runtime_source: Optional[str] = None
    rename_map: Dict[str, str] = {}
    renamed_count = 0
    lock_metadata: Optional[Dict[str, object]] = None
    lock_path: Optional[Path] = None
    confidence_history_info: Optional[Dict[str, object]] = None

    def _record(name: str, ok: bool, detail: Mapping[str, object]) -> None:
        nonlocal overall_passed
        entry = {"name": name, "passed": bool(ok), "detail": dict(detail)}
        checks.append(entry)
        if not ok:
            overall_passed = False

    try:
        fragments = extract_fragments(source)
        expected_fragments = sum(
            1
            for fragment in fragments
            if fragment.get("type") in {"long_quoted", "long_bracket"}
        )
    except Exception as exc:  # pragma: no cover - defensive
        _record(
            "fragments_processed",
            False,
            {"error": f"failed to extract fragments: {exc}"},
        )
        fragment_fraction = 0.0
    else:
        processed_info: Optional[Dict[str, object]] = None
        fragment_path_resolved: Optional[Path] = None
        candidate_paths: List[Path] = []
        if fragment_dump is not None:
            candidate_paths.append(fragment_dump)
        if reconstructed is not None:
            candidate_paths.append(Path(str(reconstructed) + ".fragments.json"))
        for candidate in candidate_paths:
            processed_info = _load_fragment_dump(candidate)
            if processed_info is not None:
                fragment_path_resolved = candidate
                break

        if processed_info is None:
            _record(
                "fragments_processed",
                False,
                {"expected": expected_fragments, "error": "fragment dump missing"},
            )
            fragment_fraction = 0.0
        else:
            processed_fragments = len(processed_info["fragments"])
            if expected_fragments <= 0:
                fragment_fraction = 1.0
            else:
                fragment_fraction = processed_fragments / expected_fragments
            _record(
                "fragments_processed",
                processed_fragments == expected_fragments,
                {
                    "expected": expected_fragments,
                    "processed": processed_fragments,
                    "fragment_dump": str(fragment_path_resolved)
                    if fragment_path_resolved
                    else None,
                },
            )

    mapping_resolved = _resolve_mapping_path(mapping_path, source, reconstructed)
    entries = _load_top_level_entries(top_level, reconstructed)
    if mapping_resolved is not None:
        lock_path = _mapping_lock_path(mapping_resolved)
        if lock_path.exists():
            lock_metadata = _load_mapping_lock(lock_path)
    if mapping_resolved is None or entries is None:
        _record(
            "top_level_functions_renamed",
            False,
            {
                "mapping_path": str(mapping_resolved) if mapping_resolved else None,
                "top_level_available": entries is not None,
            },
        )
    else:
        try:
            rename_map = _load_mapping_file(mapping_resolved)
        except Exception as exc:
            _record(
                "top_level_functions_renamed",
                False,
                {"error": f"failed to load mapping: {exc}"},
            )
        else:
            functions = [
                name
                for name, meta in entries.items()
                if isinstance(meta, Mapping) and meta.get("type") == "function"
            ]
            missing = [
                name
                for name in functions
                if rename_map.get(name) in (None, name)
            ]
            renamed_count = len(functions) - len(missing)
            _record(
                "top_level_functions_renamed",
                not missing,
                {
                    "total": len(functions),
                    "renamed": renamed_count,
                    "missing": missing,
                    "mapping_path": str(mapping_resolved),
                },
            )

            identifier_candidates: List[Path] = []
            if reconstructed is not None:
                identifier_candidates.extend(
                    _candidate_identifier_plan_paths(reconstructed)
                )
            identifier_candidates.extend(
                _candidate_identifier_plan_paths(mapping_resolved)
            )
            identifier_candidates.extend(
                _candidate_identifier_plan_paths(source)
            )
            plan_rows, plan_path = _load_identifier_plan(identifier_candidates)
            if plan_rows is not None:
                flagged = 0
                total_candidates = 0
                for row in plan_rows:
                    usage = str(row.get("usage_type", "")).strip().lower()
                    recommended = str(row.get("recommended_name", "")).strip()
                    if usage:
                        total_candidates += 1
                        if usage == "core_runtime":
                            flagged += 1
                    elif recommended:
                        total_candidates += 1
                        if recommended.startswith("runtime_"):
                            flagged += 1
                runtime_flagged = flagged
                runtime_total = total_candidates if total_candidates else len(functions)
                runtime_source = str(plan_path)
            else:
                flagged = sum(
                    1
                    for value in rename_map.values()
                    if isinstance(value, str) and value.startswith("runtime_")
                )
                if flagged or functions:
                    runtime_flagged = flagged
                    runtime_total = len(functions) if functions else max(1, flagged)
                    runtime_source = str(mapping_resolved)

    upcodes_candidates: List[Path] = []
    if upcodes_path is not None:
        upcodes_candidates.append(Path(upcodes_path))
    if reconstructed is not None:
        upcodes_candidates.extend(_candidate_upcodes_paths(reconstructed))
    else:
        upcodes_candidates.extend(
            _candidate_upcodes_paths(source.with_name("reconstructed.lua"))
        )

    upcodes_payload: Optional[Dict[str, object]] = None
    upcodes_resolved: Optional[Path] = None
    for candidate in upcodes_candidates:
        if candidate.exists():
            try:
                upcodes_payload = json.loads(candidate.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            upcodes_resolved = candidate
            break

    tracked_entries: List[Mapping[str, object]] = []

    if upcodes_payload is None:
        _record("upcodes_mapped", False, {"error": "upcodes.json not found"})
    else:
        entries_payload = upcodes_payload.get("entries")
        failing: List[int] = []
        if isinstance(entries_payload, list):
            for entry in entries_payload:
                if not isinstance(entry, Mapping):
                    continue
                total_opcodes += 1
                mnemonic = str(entry.get("mnemonic") or "").strip()
                semantic = str(entry.get("semantic") or "").strip()
                if mnemonic:
                    named_opcodes += 1
                    continue
                if semantic.upper() == "UNKNOWN":
                    continue
                opcode = entry.get("opcode")
                if isinstance(opcode, int):
                    failing.append(opcode)
                else:
                    failing.append(total_opcodes - 1)
        if isinstance(entries_payload, list):
            for entry in entries_payload:
                if isinstance(entry, Mapping):
                    tracked_entries.append(entry)
        if total_opcodes and named_opcodes == 0:
            named_opcodes = total_opcodes - len(failing)
        if total_opcodes:
            opcodes_unmapped = len(failing)
            opcodes_fraction = (total_opcodes - opcodes_unmapped) / total_opcodes
        _record(
            "upcodes_mapped",
            not failing and total_opcodes > 0,
            {
                "total": total_opcodes,
                "unmapped": failing,
                "path": str(upcodes_resolved) if upcodes_resolved else None,
            },
        )

    if parity_reports:
        for report in parity_reports:
            status = _coerce_parity_success(report)
            if status is not None:
                parity_statuses.append(status)
    if parity_report_paths:
        for raw_path in parity_report_paths:
            candidate = Path(raw_path)
            if not candidate.exists():
                continue
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            status = _coerce_parity_success(payload)
            if status is not None:
                parity_statuses.append(status)

    parity_pass = bool(parity_statuses) and all(parity_statuses)
    if parity_statuses:
        parity_passed = sum(1 for status in parity_statuses if status)
        parity_rate = parity_passed / len(parity_statuses)
    else:
        parity_rate = 0.0
    _record(
        "parity_tests_passed",
        parity_pass,
        {
            "total": len(parity_statuses),
            "passed": sum(1 for status in parity_statuses if status),
        },
    )

    manifest_candidates: List[Path] = []
    if manifest_path is not None:
        manifest_candidates.append(Path(manifest_path))
    if reconstructed is not None:
        manifest_candidates.extend(_candidate_manifest_paths(reconstructed))
    else:
        manifest_candidates.extend(_candidate_manifest_paths(source))

    manifest_result: Optional[Dict[str, object]] = None
    manifest_resolved: Optional[Path] = None
    for candidate in manifest_candidates:
        if candidate.exists():
            manifest_result = _audit_manifest_for_keys(candidate)
            manifest_resolved = candidate
            break

    if manifest_result is None:
        _record(
            "key_material_not_saved",
            False,
            {"error": "run_manifest.json not found"},
        )
    else:
        detail = dict(manifest_result.get("detail", {}))
        detail["path"] = str(manifest_resolved) if manifest_resolved else None
        _record(
            "key_material_not_saved",
            bool(manifest_result.get("passed", False)),
            detail,
        )

    if fragment_fraction is None:
        if expected_fragments == 0:
            fragment_fraction = 1.0
    fragment_fraction = _clamp_01(fragment_fraction)

    if total_opcodes and opcodes_fraction is None:
        opcodes_fraction = (total_opcodes - opcodes_unmapped) / total_opcodes
    opcodes_fraction = _clamp_01(opcodes_fraction)

    parity_rate = _clamp_01(parity_rate)

    if runtime_flagged is not None:
        denominator = runtime_total if runtime_total else runtime_flagged
        ratio = runtime_flagged / denominator if denominator else 1.0
        runtime_component = 1.0 - (_clamp_01(ratio) or 0.0)
    else:
        runtime_component = None
    runtime_component = _clamp_01(runtime_component)

    component_values = [
        value
        for value in (fragment_fraction, opcodes_fraction, parity_rate, runtime_component)
        if value is not None
    ]
    score = sum(component_values) / len(component_values) if component_values else 0.0

    completeness = {
        "score": round(score, 4),
        "components": {
            "fragments_fraction": fragment_fraction,
            "opcodes_fraction": opcodes_fraction,
            "parity_rate": parity_rate,
            "runtime_component": runtime_component,
        },
        "inputs": {
            "fragments": {
                "expected": expected_fragments,
                "processed": processed_fragments,
            },
            "opcodes": {
                "total": total_opcodes,
                "named": named_opcodes,
                "unmapped": opcodes_unmapped,
            },
            "parity": {
                "total": len(parity_statuses),
                "passed": parity_passed,
            },
            "runtime": {
                "flagged": runtime_flagged,
                "total": runtime_total,
                "source": runtime_source,
            },
        },
    }

    if tracked_entries and upcodes_resolved is not None:
        history_path = _confidence_history_path(source, mapping_resolved, reconstructed)
        confidence_history_info = _update_confidence_history(
            history_path,
            tracked_entries,
            source=source,
            mapping_path=mapping_resolved,
            upcodes_path=upcodes_resolved,
            completeness_score=completeness["score"],
        )

    mapping_high_confidence = bool(
        mapping_resolved
        and rename_map
        and functions
        and not missing
        and (runtime_flagged in (None, 0))
    )

    lock_present = bool(lock_path and lock_path.exists())
    if lock_present and lock_metadata is None and lock_path is not None:
        lock_metadata = _load_mapping_lock(lock_path)

    lock_exists = bool(lock_metadata)
    if (
        write_lock_if_high_confidence
        and mapping_high_confidence
        and mapping_resolved is not None
        and not lock_exists
    ):
        lock_metadata = _write_mapping_lock(
            mapping_resolved,
            functions_total=len(functions),
            functions_renamed=renamed_count,
            runtime_flagged=runtime_flagged,
            runtime_total=runtime_total,
            completeness_score=completeness["score"],
        )
        lock_present = True
        lock_exists = True
        lock_path = _mapping_lock_path(mapping_resolved)

    mapping_summary: Dict[str, object] = {
        "path": str(mapping_resolved) if mapping_resolved else None,
        "lock_path": str(lock_path) if lock_path else None,
        "lock_present": lock_present,
        "lock_exists": lock_exists,
        "high_confidence": mapping_high_confidence,
        "functions_total": len(functions),
        "functions_renamed": renamed_count,
        "missing": list(missing),
        "runtime_flagged": runtime_flagged,
        "runtime_total": runtime_total,
        "rename_entries": len(rename_map),
        "completeness_score": completeness["score"],
    }
    if lock_metadata:
        mapping_summary["lock_metadata"] = lock_metadata
        locked_at = lock_metadata.get("locked_at")
        if isinstance(locked_at, str):
            mapping_summary.setdefault("locked_at", locked_at)

    result = {
        "passed": overall_passed,
        "checks": checks,
        "completeness": completeness,
        "mapping_summary": mapping_summary,
    }
    if confidence_history_info is not None:
        result["confidence_history"] = confidence_history_info
    return result


def evaluate_quality_gate(
    checklist: Mapping[str, object],
    *,
    threshold: float = 0.85,
    require_parity: bool = True,
) -> Dict[str, object]:
    """Return the status of the quality gate for a completed run."""

    if not isinstance(checklist, Mapping):
        raise TypeError("quality gate requires a checklist mapping")

    completeness = checklist.get("completeness")
    score_raw: Optional[float] = None
    if isinstance(completeness, Mapping):
        score_value = completeness.get("score")
        if isinstance(score_value, (int, float)):
            score_raw = float(score_value)

    threshold_clamped = max(0.0, min(1.0, float(threshold)))
    score_clamped: Optional[float]
    if score_raw is None or math.isnan(score_raw):  # pragma: no cover - defensive
        score_clamped = None
    else:
        score_clamped = max(0.0, min(1.0, score_raw))

    parity_entry: Optional[Mapping[str, object]] = None
    checks = checklist.get("checks")
    if isinstance(checks, Sequence):
        for entry in checks:
            if isinstance(entry, Mapping) and entry.get("name") == "parity_tests_passed":
                parity_entry = entry
                break

    parity_detail = parity_entry.get("detail") if isinstance(parity_entry, Mapping) else None
    parity_total: Optional[int] = None
    parity_passed: Optional[int] = None
    parity_ok = bool(parity_entry.get("passed")) if isinstance(parity_entry, Mapping) else False
    if isinstance(parity_detail, Mapping):
        total_value = parity_detail.get("total")
        if isinstance(total_value, int):
            parity_total = total_value
        passed_value = parity_detail.get("passed")
        if isinstance(passed_value, int):
            parity_passed = passed_value

    parity_total_int = max(0, parity_total if parity_total is not None else 0)
    parity_passed_int = max(0, parity_passed if parity_passed is not None else 0)
    if parity_total_int and parity_passed_int == 0 and parity_ok:
        parity_passed_int = parity_total_int

    failures: List[str] = []
    passed = True

    if score_clamped is None:
        passed = False
        failures.append("completeness score unavailable")
    elif score_clamped + 1e-9 < threshold_clamped:
        passed = False
        failures.append(
            f"completeness score {score_clamped:.3f} below threshold {threshold_clamped:.3f}"
        )

    if require_parity:
        if parity_total_int <= 0:
            passed = False
            parity_ok = False
            failures.append("no parity tests executed")
        elif not parity_ok:
            passed = False
            failures.append(
                f"parity tests failed ({parity_passed_int}/{parity_total_int})"
            )
    else:
        parity_ok = parity_ok or parity_total_int <= 0

    return {
        "passed": passed,
        "score": score_clamped,
        "threshold": threshold_clamped,
        "require_parity": bool(require_parity),
        "parity": {
            "ok": bool(parity_ok),
            "total": parity_total_int,
            "passed": parity_passed_int,
        },
        "failures": failures,
    }

def _normalize_whitespace(text: str) -> str:
    if not text:
        return ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    normalized = "\n".join(line.rstrip() for line in lines)
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


_NUM_LITERAL_RE = re.compile(
    r"(?<![\w.])(-?0[xX][0-9A-Fa-f]+|-?0[bB][01]+)"
)


def _replace_numeric_literals(text: str) -> Tuple[str, List[Dict[str, object]]]:
    if not text:
        return text, []

    protected = _collect_protected_ranges(text)
    mapping: List[Dict[str, object]] = []

    result_chunks: List[str] = []
    cursor = 0
    normalized_length = 0

    for match in _NUM_LITERAL_RE.finditer(text):
        start = match.start(1)
        end = match.end(1)
        literal = match.group(1)

        if cursor < start:
            segment = text[cursor:start]
            result_chunks.append(segment)
            normalized_length += len(segment)

        convertible = not (
            _position_in_ranges(start, protected)
            or _position_in_ranges(end - 1, protected)
        )

        replacement: Optional[str] = None
        if convertible:
            sign = ""
            body = literal
            if body.startswith("-"):
                sign = "-"
                body = body[1:]

            prefix = body[:2].lower()
            digits = body[2:] if prefix in {"0x", "0b"} else body
            base = 16 if prefix == "0x" else 2 if prefix == "0b" else 10
            try:
                value = int(digits, base)
            except ValueError:
                convertible = False
            else:
                replacement = f"{sign}{value}"

        if replacement is None:
            result_chunks.append(literal)
            normalized_length += len(literal)
        else:
            normalized_start = normalized_length
            result_chunks.append(replacement)
            normalized_length += len(replacement)
            mapping.append(
                {
                    "original": literal,
                    "normalized": replacement,
                    "original_start": start,
                    "original_end": end,
                    "normalized_start": normalized_start,
                    "normalized_end": normalized_start + len(replacement),
                }
            )

        cursor = end

    if cursor < len(text):
        tail = text[cursor:]
        result_chunks.append(tail)
        normalized_length += len(tail)

    normalized_text = "".join(result_chunks) if result_chunks else text
    return normalized_text, mapping


def _collect_protected_ranges(text: str) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "-" and text.startswith("--", i):
            start = i
            i += 2
            equals = _match_long_bracket(text, i)
            if equals is not None:
                end = _consume_long_bracket(text, i, equals)
                ranges.append((start, end))
                i = end
                continue
            while i < n and text[i] not in "\r\n":
                i += 1
            ranges.append((start, i))
            continue
        if ch in {'"', "'"}:
            start = i
            end = _consume_short_string(text, i)
            ranges.append((start, end))
            i = end
            continue
        if ch == "[":
            equals = _match_long_bracket(text, i)
            if equals is not None:
                start = i
                end = _consume_long_bracket(text, i, equals)
                ranges.append((start, end))
                i = end
                continue
        i += 1
    ranges.sort()
    return ranges


def _position_in_ranges(pos: int, ranges: List[Tuple[int, int]]) -> bool:
    for start, end in ranges:
        if pos < start:
            return False
        if start <= pos < end:
            return True
    return False


def _find_matching_brace(text: str, open_index: int) -> Optional[int]:
    depth = 0
    i = open_index
    n = len(text)
    line_comment = False
    block_comment_closing: Optional[str] = None
    short_quote: Optional[str] = None
    long_string_closing: Optional[str] = None

    while i < n:
        if line_comment:
            if text[i] == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment_closing is not None:
            if text.startswith(block_comment_closing, i):
                i += len(block_comment_closing)
                block_comment_closing = None
            else:
                i += 1
            continue

        if short_quote is not None:
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == short_quote:
                short_quote = None
            i += 1
            continue

        if long_string_closing is not None:
            if text.startswith(long_string_closing, i):
                i += len(long_string_closing)
                long_string_closing = None
            else:
                i += 1
            continue

        if text.startswith("--", i):
            if text.startswith("--[", i):
                eq = 0
                j = i + 3
                while j < n and text[j] == "=":
                    eq += 1
                    j += 1
                if j < n and text[j] == "[":
                    block_comment_closing = "]" + "=" * eq + "]"
                    i = j + 1
                    continue
            line_comment = True
            i += 2
            continue

        ch = text[i]
        if ch in {'"', "'"}:
            short_quote = ch
            i += 1
            continue

        if ch == "[":
            eq = _match_long_bracket(text, i)
            if eq is not None:
                long_string_closing = "]" + "=" * eq + "]"
                i += 2 + eq
                continue

        if ch == "{":
            depth += 1
            i += 1
            continue

        if ch == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue

        i += 1

    return None


def _iter_function_positions(text: str) -> Iterable[int]:
    length = len(text)
    i = 0
    line_comment = False
    block_comment_closing: Optional[str] = None
    short_quote: Optional[str] = None
    long_string_closing: Optional[str] = None

    while i < length:
        if line_comment:
            if text[i] == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment_closing is not None:
            if text.startswith(block_comment_closing, i):
                i += len(block_comment_closing)
                block_comment_closing = None
            else:
                i += 1
            continue

        if short_quote is not None:
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == short_quote:
                short_quote = None
            i += 1
            continue

        if long_string_closing is not None:
            if text.startswith(long_string_closing, i):
                i += len(long_string_closing)
                long_string_closing = None
            else:
                i += 1
            continue

        if text.startswith("--", i):
            if text.startswith("--[", i):
                eq = 0
                j = i + 3
                while j < length and text[j] == "=":
                    eq += 1
                    j += 1
                if j < length and text[j] == "[":
                    block_comment_closing = "]" + "=" * eq + "]"
                    i = j + 1
                    continue
            line_comment = True
            i += 2
            continue

        ch = text[i]
        if ch in {'"', "'"}:
            short_quote = ch
            i += 1
            continue

        if ch == "[":
            eq = 0
            j = i + 1
            while j < length and text[j] == "=":
                eq += 1
                j += 1
            if j < length and text[j] == "[":
                long_string_closing = "]" + "=" * eq + "]"
                i = j + 1
                continue

        if text.startswith("function", i):
            tail = i + len("function")
            prev_ok = i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")
            next_ok = tail >= length or not (text[tail].isalnum() or text[tail] == "_")
            if prev_ok and next_ok:
                yield i
                i = tail
                continue

        i += 1


def _derive_function_start(text: str, func_pos: int) -> int:
    line_start = text.rfind("\n", 0, func_pos)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    start = line_start
    prefix = text[line_start:func_pos]
    stripped = prefix.rstrip()

    if stripped:
        assign_match = _ASSIGN_PREFIX_RE.search(stripped)
        if assign_match:
            start = line_start + assign_match.start()
        elif _RETURN_PREFIX_RE.search(stripped):
            start = line_start + stripped.rfind("return")
        elif _LOCAL_PREFIX_RE.search(stripped):
            start = line_start + stripped.rfind("local")
        else:
            delimiter_index = -1
            for delimiter in (";", ","):
                delimiter_index = prefix.rfind(delimiter)
                if delimiter_index != -1:
                    start = delimiter_index + 1
                    break
            if delimiter_index != -1:
                while start < func_pos and text[start] in " \t":
                    start += 1

    return max(0, min(start, func_pos))


def _classify_function_header(header_line: str) -> Tuple[Optional[str], str]:
    stripped = header_line.strip()
    if not stripped:
        return None, "unknown"

    local_match = _LOCAL_FUNCTION_RE.match(stripped)
    if local_match:
        return local_match.group(1), "local"

    global_match = _FUNCTION_DEF_RE.match(stripped)
    if global_match:
        base = global_match.group(1)
        method = global_match.group(2)
        if method:
            return f"{base}_{method}", "method"
        return base, "global"

    assign_match = _ASSIGN_WITH_LOCAL_RE.match(stripped)
    if assign_match:
        name = assign_match.group(1).replace(":", "_").replace(".", "_")
        return name, "assignment"

    if stripped.startswith("return function"):
        return None, "return"

    return None, "anonymous"


def _sanitise_function_basename(
    name: Optional[str],
    index: int,
    kind: str,
    counter: DefaultDict[str, int],
) -> Tuple[str, str]:
    if name:
        base = re.sub(r"[^0-9A-Za-z_]+", "_", name)
    else:
        if kind == "return":
            base = "return_fn"
        else:
            base = "function"

    if not base:
        base = "function"

    counter[base] += 1
    suffix = counter[base]
    if suffix > 1:
        unique = f"{base}_{suffix}"
    else:
        unique = base

    file_stem = f"{index:03d}_{unique}"
    return unique, file_stem


def _record_rebuild_history(output_path: Path, content: str) -> Dict[str, object]:
    """Persist a snapshot of *content* and diff it against the prior run."""

    history_dir = output_path.parent / f"{output_path.stem}_history"
    history_dir.mkdir(parents=True, exist_ok=True)

    previous_entries = sorted(
        entry for entry in history_dir.glob("*.lua") if entry.is_file()
    )

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    candidate = history_dir / f"{timestamp}.lua"
    if candidate.exists():
        counter = 1
        while True:
            candidate = history_dir / f"{timestamp}_{counter:02d}.lua"
            if not candidate.exists():
                break
            counter += 1

    candidate.write_text(content, encoding="utf-8")

    previous_path = previous_entries[-1] if previous_entries else None
    diff_path: Optional[Path] = None
    diff_summary: Optional[Dict[str, object]] = None

    if previous_path is not None:
        prev_content = previous_path.read_text(encoding="utf-8", errors="ignore")
        diff_lines = list(
            difflib.unified_diff(
                prev_content.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=previous_path.name,
                tofile=candidate.name,
            )
        )

        if not diff_lines:
            diff_lines = [
                f"--- {previous_path.name}\n",
                f"+++ {candidate.name}\n",
                "@@ identical @@\n",
            ]

        added = sum(
            1
            for line in diff_lines
            if line.startswith("+") and not line.startswith("+++")
        )
        removed = sum(
            1
            for line in diff_lines
            if line.startswith("-") and not line.startswith("---")
        )

        diff_path = history_dir / f"{candidate.stem}.diff"
        diff_path.write_text("".join(diff_lines), encoding="utf-8")
        diff_summary = {
            "added": added,
            "removed": removed,
            "is_identical": added == 0 and removed == 0,
        }

    return {
        "history_dir": str(history_dir),
        "history_entry_path": str(candidate),
        "history_previous_path": str(previous_path) if previous_path else None,
        "history_diff_path": str(diff_path) if diff_path else None,
        "history_diff_summary": diff_summary,
    }


def _confidence_history_path(
    source: Path,
    mapping: Optional[Path],
    reconstructed: Optional[Path],
) -> Path:
    candidates: List[Path] = []
    if mapping is not None:
        candidates.append(mapping.parent / "confidence_history.json")
    if reconstructed is not None:
        candidates.append(reconstructed.parent / "confidence_history.json")
    candidates.append(source.parent / "confidence_history.json")
    candidates.append(Path("confidence_history.json"))

    deduped = _dedupe_paths(candidates)
    existing = _first_existing_path(deduped)
    if existing is not None:
        return existing
    return deduped[0]


def _load_confidence_history(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {"runs": [], "timeline": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"runs": [], "timeline": {}}
    if not isinstance(payload, Mapping):
        return {"runs": [], "timeline": {}}
    timeline = payload.get("timeline")
    runs = payload.get("runs")
    if not isinstance(timeline, Mapping):
        timeline = {}
    if not isinstance(runs, list):
        runs = []
    return {
        "runs": runs,
        "timeline": dict(timeline),
        "updated_at": payload.get("updated_at"),
        "run_count": payload.get("run_count"),
    }


def _timeline_sort_key(key: str) -> Tuple[int, object]:
    key_str = str(key)
    if key_str.isdigit():
        return (0, int(key_str))
    return (1, key_str.lower())


def _update_confidence_history(
    history_path: Path,
    entries: Iterable[Mapping[str, object]],
    *,
    source: Optional[Path] = None,
    mapping_path: Optional[Path] = None,
    upcodes_path: Optional[Path] = None,
    completeness_score: Optional[float] = None,
) -> Optional[Dict[str, object]]:
    snapshot = _load_confidence_history(history_path)
    timeline: Dict[str, List[Dict[str, object]]] = {
        str(key): list(value)
        for key, value in snapshot.get("timeline", {}).items()
        if isinstance(key, str) and isinstance(value, list)
    }
    runs: List[Dict[str, object]] = [
        dict(entry)
        for entry in snapshot.get("runs", [])
        if isinstance(entry, Mapping)
    ]

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    run_id = uuid.uuid4().hex

    run_entry: Dict[str, object] = {
        "timestamp": timestamp,
        "run_id": run_id,
        "opcodes": {},
    }
    if source is not None:
        run_entry["source"] = str(source)
    if mapping_path is not None:
        run_entry["mapping_path"] = str(mapping_path)
    if upcodes_path is not None:
        run_entry["upcodes_path"] = str(upcodes_path)
    if isinstance(completeness_score, (int, float)):
        run_entry["completeness_score"] = round(float(completeness_score), 6)

    updated: Dict[str, Dict[str, object]] = {}

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        opcode = entry.get("opcode")
        mnemonic = str(entry.get("mnemonic") or "").strip()
        semantic = str(entry.get("semantic") or "").strip()
        confidence_raw = entry.get("confidence")
        confidence: Optional[float]
        if isinstance(confidence_raw, (int, float)):
            confidence = float(confidence_raw)
        else:
            confidence = None

        key: Optional[str]
        if isinstance(opcode, int):
            key = str(opcode)
        else:
            candidate = mnemonic or semantic
            key = candidate or None
        if key is None:
            continue

        detail: Dict[str, object] = {}
        if mnemonic:
            detail["mnemonic"] = mnemonic
        if semantic:
            detail["semantic"] = semantic
        if confidence is not None:
            detail["confidence"] = round(confidence, 6)

        run_entry["opcodes"][key] = detail

        timeline_entry: Dict[str, object] = {
            "timestamp": timestamp,
            "run_id": run_id,
        }
        timeline_entry.update(detail)
        if isinstance(completeness_score, (int, float)):
            timeline_entry["completeness"] = round(float(completeness_score), 6)

        record_list = timeline.setdefault(key, [])
        if record_list:
            last = record_list[-1]
            same_conf = (
                ("confidence" not in detail and "confidence" not in last)
                or (
                    "confidence" in detail
                    and "confidence" in last
                    and math.isclose(
                        float(detail["confidence"]),
                        float(last.get("confidence", 0.0)),
                        rel_tol=1e-9,
                        abs_tol=1e-9,
                    )
                )
            )
            same_mnemonic = detail.get("mnemonic") == last.get("mnemonic")
            same_semantic = detail.get("semantic") == last.get("semantic")
            if same_conf and same_mnemonic and same_semantic:
                continue
            if "confidence" in detail and "confidence" in last:
                delta = float(detail["confidence"]) - float(last["confidence"])
                if not math.isclose(delta, 0.0, abs_tol=1e-9):
                    timeline_entry["delta"] = round(delta, 6)

        record_list.append(timeline_entry)
        updated[key] = timeline_entry

    if not run_entry["opcodes"]:
        return None

    runs.append(run_entry)

    ordered_timeline = {
        key: timeline[key]
        for key in sorted(timeline.keys(), key=_timeline_sort_key)
    }

    history_payload = {
        "updated_at": timestamp,
        "run_count": len(runs),
        "runs": runs,
        "timeline": ordered_timeline,
    }

    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(
        json.dumps(history_payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    return {
        "path": str(history_path),
        "timestamp": timestamp,
        "run_id": run_id,
        "updated_keys": sorted(updated.keys(), key=_timeline_sort_key),
        "latest": updated,
    }


def detect_dangerous_calls(
    path: str | Path,
    *,
    text: Optional[str] = None,
    output_path: str | Path | None = None,
    context_lines: int = 1,
) -> Dict[str, object]:
    """Scan reconstructed Lua text for potentially dangerous runtime calls."""

    file_path = Path(path)
    if text is None:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            raise FileNotFoundError(f"Unable to read {file_path}: {exc}") from exc

    if output_path is None:
        output_path = file_path.with_name("dangerous_calls.txt")
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = text.splitlines()
    findings: List[Dict[str, object]] = []

    for index, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue

        matched: List[str] = []
        for label, pattern in _DANGEROUS_CALL_PATTERNS:
            if pattern.search(line):
                if label not in matched:
                    matched.append(label)

        if not matched:
            continue

        start = max(1, index - context_lines)
        end = min(len(lines), index + context_lines)
        context = [
            f"{lineno:>5}: {lines[lineno - 1]}" for lineno in range(start, end + 1)
        ]

        findings.append(
            {
                "line": index,
                "matches": matched,
                "context": context,
                "code": line.strip(),
            }
        )

    report_lines: List[str] = []
    header = f"Dangerous call scan for {file_path.name}"
    report_lines.append(header)
    report_lines.append("=" * len(header))

    if findings:
        for entry in findings:
            report_lines.append("")
            labels = ", ".join(entry["matches"])
            report_lines.append(f"Line {entry['line']} → {labels}")
            report_lines.extend(entry["context"])
    else:
        report_lines.append("")
        report_lines.append("No dangerous call patterns detected.")

    output_path.write_text("\n".join(report_lines).rstrip() + "\n", encoding="utf-8")

    return {
        "path": str(output_path),
        "count": len(findings),
        "findings": findings,
        "patterns": [label for label, _ in _DANGEROUS_CALL_PATTERNS],
    }


def pipeline_static_rebuild(
    path: str | Path, *, output_path: str | Path | None = None
) -> Dict[str, object]:
    """Rebuild a static Lua payload with escape-preserving decoding and checks."""

    file_path = Path(path)
    fragments = extract_fragments(file_path)
    decoded_pairs = list(_iter_decoded_fragments(fragments))
    verification = _verify_decoded_string_roundtrip(decoded_pairs)
    unicode_report = _scan_unicode_anomalies(decoded_pairs)
    reconstructed = "".join(decoded for _, decoded in decoded_pairs)
    bracket_normalized, bracket_stats = _normalize_long_bracket_literals(reconstructed)
    normalized = _normalize_whitespace(bracket_normalized)
    canonical, numeric_map = _replace_numeric_literals(normalized)

    if output_path is None:
        output_path = file_path.with_name("reconstructed.lua")
    output_path = Path(output_path)
    output_path.write_text(canonical, encoding="utf-8")

    fragment_dump_path = _dump_fragment_metadata(output_path, decoded_pairs)

    history_info = _record_rebuild_history(output_path, canonical)

    dangerous_report = detect_dangerous_calls(
        output_path,
        text=canonical,
        output_path=output_path.with_name("dangerous_calls.txt"),
        context_lines=1,
    )
    dangerous_path = Path(dangerous_report["path"])

    mapping_path = Path(str(output_path) + ".numeric_map.json")
    mapping_payload = {
        "input": str(file_path),
        "output": str(output_path),
        "mappings": numeric_map,
    }
    mapping_path.write_text(
        json.dumps(mapping_payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    boundary_report = _compute_boundary_report(decoded_pairs)
    diff_summary = _summarise_boundary_diff(boundary_report)

    diff_path = Path(str(output_path) + ".boundaries.json")
    diff_payload = {
        "input": str(file_path),
        "output": str(output_path),
        "reordered": diff_summary["reordered"],
        "mismatches": diff_summary["mismatches"],
        "boundaries": boundary_report,
    }
    diff_path.write_text(json.dumps(diff_payload, indent=2, sort_keys=True), encoding="utf-8")

    bytecode_dir = output_path.parent / f"{output_path.stem}_bytecode"
    bytecode_reports = detect_embedded_bytecode(
        file_path,
        fragments=fragments,
        output_dir=bytecode_dir,
    )
    bytecode_dir_str = str(bytecode_dir) if bytecode_reports else None

    header_meta = detect_luraph_header_from_text(canonical)
    fingerprint_report = fingerprint_obfuscation_patterns(
        canonical,
        output_path=output_path,
        input_path=file_path,
        metadata=header_meta,
    )
    fingerprint_path = (
        Path(fingerprint_report["path"]) if fingerprint_report.get("path") else None
    )

    license_result = run_license_audit(output_path)
    license_paths = [
        Path(license_result["report_path"]),
        Path(license_result["text_report_path"]),
    ]

    evidence_info = _create_evidence_archive(
        output_path,
        original_path=file_path,
        fragment_dump_path=fragment_dump_path,
        mapping_path=mapping_path,
        upcodes_candidates=_candidate_upcodes_paths(output_path),
        manifest_candidates=_candidate_manifest_paths(output_path),
        license_paths=license_paths,
        dangerous_path=dangerous_path,
        fingerprint_path=fingerprint_path,
    )

    result: Dict[str, object] = {
        "output_path": str(output_path),
        "fragment_dump_path": str(fragment_dump_path),
        "boundary_report": boundary_report,
        "boundary_mismatch": diff_summary["reordered"],
        "diff_report_path": str(diff_path),
        "numeric_mapping_path": str(mapping_path),
        "numeric_literal_map": numeric_map,
        "string_verification": verification,
        "bracket_normalization": bracket_stats,
        "bytecode_reports": bytecode_reports,
        "bytecode_output_dir": bytecode_dir_str,
        "unicode_report": unicode_report,
        "license_audit": license_result,
        "dangerous_calls": dangerous_report,
        "dangerous_calls_path": dangerous_report["path"],
        "fingerprint_report": fingerprint_report,
    }

    result.update(history_info)
    result.update(evidence_info)

    return result


def complete_deobfuscate(
    path: str | Path,
    key: str | bytes,
    *,
    confirm_owner: bool,
    confirm_voluntary_key: bool,
    mapping_path: str | Path | None = None,
    parity_fragments: Sequence[int] = (0,),
    sandbox_runner: Callable[..., Dict[str, object]] | None = None,
    indent_size: int = 4,
) -> Dict[str, Any]:
    """Run the full deobfuscation pipeline and return aggregated artefacts.

    The orchestrator wraps the static rebuild, PRGA probing, VM analysis, and
    pretty-printing stages into a single helper suitable for scripted usage.  A
    valid ``key`` *must* be provided at runtime and the caller needs to confirm
    ownership of the analysed file via ``confirm_owner`` /
    ``confirm_voluntary_key``.  No key material is written to disk—only hashed
    metadata is captured through :func:`require_usage_confirmation`.
    """

    file_path = Path(path).resolve()
    if not file_path.exists():  # pragma: no cover - defensive guard
        raise FileNotFoundError(file_path)

    if isinstance(key, bytes):
        if not key:
            raise ValueError("key must be non-empty")
        key_bytes = key
        key_text = key.decode("utf-8", errors="ignore")
    else:
        key_text = key.strip()
        if not key_text:
            raise ValueError("key must be non-empty")
        key_bytes = key_text.encode("utf-8", "ignore")

    from key_usage_scanner import probe_prga as _probe_prga

    confirmation = require_usage_confirmation(
        confirm_ownership=confirm_owner,
        confirm_voluntary_key=confirm_voluntary_key,
        inputs=[file_path],
        script_key=key_text,
    )

    header_info = detect_luraph_header(file_path)
    fragments = extract_fragments(file_path)
    decoded_pairs = list(_iter_decoded_fragments(fragments))

    static_report = pipeline_static_rebuild(file_path)
    reconstructed_path = Path(static_report["output_path"])
    reconstructed_text = reconstructed_path.read_text(encoding="utf-8", errors="ignore")

    metadata_report = extract_metadata_provenance(
        reconstructed_path, output_path="metadata.json"
    )

    def _preview_bytes(data: bytes, limit: int = 160) -> str:
        snippet = data.decode("utf-8", errors="replace")
        cleaned = "".join(
            ch if 32 <= ord(ch) < 127 or ch in "\t\r\n" else "·" for ch in snippet
        )
        if len(cleaned) > limit:
            return cleaned[: limit - 1] + "…"
        return cleaned

    def _summarise_payload(payload: bytes) -> Dict[str, Any]:
        return {
            "length": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "printable_ratio": _printable_ratio(payload),
            "preview": _preview_bytes(payload),
        }

    full_prga = _probe_prga(key_bytes, file_path.read_bytes())
    full_prga_summary = {
        method: _summarise_payload(payload)
        for method, payload in full_prga.items()
    }

    fragment_prga: List[Dict[str, Any]] = []
    for position, fragment in enumerate(fragments):
        fragment_bytes, meta = _coerce_fragment_bytes(fragment)
        if not fragment_bytes:
            continue
        results: Dict[str, Any] = {}
        try:
            for method, payload in _probe_prga(key_bytes, fragment_bytes).items():
                results[method] = _summarise_payload(payload)
        except Exception:  # pragma: no cover - best-effort probing
            continue
        if not results:
            continue
        record = {
            "fragment_index": fragment.get("index", position),
            "byte_count": len(fragment_bytes),
            "results": results,
        }
        fragment_prga.append(record)

    try:
        upcode_report_raw = generate_upcode_table(reconstructed_text)
    except Exception as exc:  # pragma: no cover - defensive guard
        upcode_report_raw = {
            "entries": [],
            "metadata": {},
            "error": str(exc),
        }

    upcode_summary = {
        "entry_count": len(upcode_report_raw.get("entries", [])),
        "metadata": upcode_report_raw.get("metadata", {}),
        "output_markdown": upcode_report_raw.get("output_markdown"),
        "output_json": upcode_report_raw.get("output_json"),
        "output_csv": upcode_report_raw.get("output_csv"),
        "output_html": upcode_report_raw.get("output_html"),
        "error": upcode_report_raw.get("error"),
    }

    parity_outcomes: List[Dict[str, Any]] = []
    for fragment_index in parity_fragments:
        try:
            parity_result = parity_test(
                fragment_index,
                path=file_path,
                key=key_text,
                sandbox_runner=sandbox_runner,
            )
        except Exception as exc:  # pragma: no cover - parity is best-effort
            parity_outcomes.append(
                {
                    "fragment_index": fragment_index,
                    "match": False,
                    "error": str(exc),
                }
            )
        else:
            parity_outcomes.append(
                {
                    "fragment_index": fragment_index,
                    "match": bool(parity_result.get("match")),
                    "word_count": parity_result.get("word_count"),
                }
            )

    mapping_candidates: List[Path] = []
    if mapping_path is not None:
        mapping_candidates.append(Path(mapping_path))
    mapping_candidates.append(Path("mapping.lock"))
    mapping_candidates.append(Path("mapping.json"))

    resolved_mapping: Optional[Path] = next(
        (candidate for candidate in mapping_candidates if candidate.exists()),
        None,
    )

    final_output_path = reconstructed_path.with_name("deobfuscated_final.lua")
    if resolved_mapping is not None:
        try:
            pretty_result = pretty_print_with_mapping(
                reconstructed_path,
                resolved_mapping,
                output_path=final_output_path,
                indent_size=indent_size,
            )
        except RuntimeError as exc:
            final_output_path.write_text(reconstructed_text, encoding="utf-8")
            pretty_result = {
                "output_path": str(final_output_path),
                "renames": {},
                "rename_preview": [],
                "index_block": [],
                "error": str(exc),
            }
    else:
        final_output_path.write_text(reconstructed_text, encoding="utf-8")
        pretty_result = {
            "output_path": str(final_output_path),
            "renames": {},
            "rename_preview": [],
            "index_block": [],
        }

    try:
        checklist = evaluate_deobfuscation_checklist(
            file_path,
            reconstructed_path=reconstructed_path,
            write_lock_if_high_confidence=True,
        )
    except Exception as exc:  # pragma: no cover - checklist is best-effort
        checklist = {"error": str(exc)}

    completeness_score: Optional[float] = None
    components = checklist.get("completeness") if isinstance(checklist, Mapping) else {}
    if isinstance(components, Mapping):
        score_value = components.get("score")
        if isinstance(score_value, (int, float)):
            completeness_score = float(score_value)

    summary_path: Optional[Path] = None
    try:
        summary_path = generate_run_summary(
            checklist=checklist,
            report={"version_detected": header_info.get("version")},
            extras={
                "parity": parity_outcomes,
                "fragments": {
                    "total": len(fragments),
                    "decoded": len(decoded_pairs),
                },
            },
        )
    except Exception:  # pragma: no cover - summary best-effort
        summary_path = None

    static_summary_keys = {
        "output_path",
        "diff_report_path",
        "numeric_mapping_path",
        "dangerous_calls_path",
        "fragment_dump_path",
        "evidence_archive_path",
    }
    static_summary = {
        key: static_report.get(key) for key in static_summary_keys if key in static_report
    }
    static_summary["boundary_mismatch"] = static_report.get("boundary_mismatch")

    artifacts = {
        "evidence": static_report.get("evidence_archive_path"),
        "final_output": str(final_output_path),
        "reconstructed": str(reconstructed_path),
        "opcodes_markdown": upcode_summary.get("output_markdown"),
        "summary": str(summary_path) if summary_path else None,
        "metadata": "metadata.json",
    }

    return {
        "header": header_info,
        "usage_confirmation": {
            "log_path": str(confirmation.log_path) if confirmation.log_path else None,
            "entries": confirmation.entry_count,
        },
        "fragments": {
            "total": len(fragments),
            "decoded": len(decoded_pairs),
        },
        "static_rebuild": static_summary,
        "metadata": metadata_report,
        "prga": {
            "full_file": full_prga_summary,
            "fragments": fragment_prga,
        },
        "parity": parity_outcomes,
        "upcodes": upcode_summary,
        "pretty_print": pretty_result,
        "completeness": checklist,
        "completeness_score": completeness_score,
        "artifacts": artifacts,
    }


PIPELINE_STAGE_DOCS: Tuple[PipelineStageDoc, ...] = (
    PipelineStageDoc(
        name="Fragment discovery",
        function="extract_fragments",
        summary="Scans Lua sources for quoted and bracketed fragments while preserving source offsets for downstream reconstruction.",
        inputs=["Lua payload path"],
        outputs=["Ordered fragment entries with offsets and literal kinds"],
        failure_modes=[
            "Source file is missing or unreadable",
            "Malformed long-bracket delimiters prevent detection",
        ],
        remedies=[
            "Verify the input path and encoding; rerun with a fresh dump of the payload",
            "Inspect surrounding text to fix bracket depth or fall back to runtime capture of constructed strings",
        ],
        runtime_guidance="If no static fragments are discovered, the payload likely assembles data at runtime—capture output via `run_probe_harness` or sandbox tracing before re-running the pipeline.",
    ),
    PipelineStageDoc(
        name="Literal decoding",
        function="_iter_decoded_fragments / lu_unescape",
        summary="Normalises escape sequences, canonicalising Lua short-string bodies into decoded text for reconstruction.",
        inputs=["Fragment list"],
        outputs=["Decoded fragment/literal pairs"],
        failure_modes=[
            "Unsupported escape sequences or malformed numeric escapes",
            "Fragments remain encrypted or high-entropy after decoding",
        ],
        remedies=[
            "Update `lu_unescape` support or patch offending fragments before retrying",
            "Run PRGA candidates or parity harnesses with the session key to obtain plaintext",
        ],
        runtime_guidance="High-entropy outputs suggest runtime transforms; prioritise affected fragments with `entropy_detector` and feed them to `run_probe_harness` using the provided key.",
    ),
    PipelineStageDoc(
        name="Escape verification",
        function="_verify_decoded_string_roundtrip",
        summary="Ensures decoded literals survive a canonicalise → unescape → escape round-trip so no bytes are lost during reconstruction.",
        inputs=["Decoded fragment pairs"],
        outputs=["Verification report with mismatched indices (if any)"],
        failure_modes=[
            "Escape sequences that collapse to different literals after normalisation",
        ],
        remedies=[
            "Inspect the reported fragment offsets and adjust canonicalisation hints before continuing",
        ],
        runtime_guidance="When round-trip verification fails only for runtime-generated data, skip static rewriting for those fragments and prefer sandbox extraction.",
    ),
    PipelineStageDoc(
        name="Bracket normalisation",
        function="_normalize_long_bracket_literals",
        summary="Aligns Lua long-bracket delimiters to a canonical depth while tracking nesting statistics for audits.",
        inputs=["Concatenated decoded text"],
        outputs=["Bracket-normalised text", "Delimiter depth statistics"],
        failure_modes=[
            "Mismatched bracket depth that cannot be normalised",
        ],
        remedies=[
            "Review the reported delimiter span and repair the fragment ordering before re-running",
        ],
        runtime_guidance="Runtime builders occasionally emit long brackets on the fly; confirm static reconstruction order with `cluster_fragments_by_similarity` before rewriting.",
    ),
    PipelineStageDoc(
        name="Whitespace canonicalisation",
        function="_normalize_whitespace",
        summary="Collapses inconsistent indentation and spacing while preserving semantic boundaries for subsequent tooling.",
        inputs=["Bracket-normalised text"],
        outputs=["Whitespace-normalised Lua text"],
        failure_modes=[
            "Irrecoverable control characters in fragments",
        ],
        remedies=[
            "Strip or replace invalid bytes using the fragment offsets and rerun the pass",
        ],
        runtime_guidance="If control characters stem from runtime buffers, prefer executing the parity harness to capture clean output before normalisation.",
    ),
    PipelineStageDoc(
        name="Numeric literal mapping",
        function="_replace_numeric_literals",
        summary="Converts hexadecimal/binary numerics into decimal for readability and records a reversible mapping file.",
        inputs=["Whitespace-normalised text"],
        outputs=["Canonical text with decimal numerics", "numeric_map.json mapping"],
        failure_modes=[
            "Non-standard numeric forms that collide after normalisation",
        ],
        remedies=[
            "Review the generated numeric map and restore conflicting literals selectively",
        ],
        runtime_guidance="If numerics are computed at runtime, rely on the snapshot/resume harness to capture concrete values before applying static replacements.",
    ),
    PipelineStageDoc(
        name="Boundary diffing",
        function="_compute_boundary_report / _summarise_boundary_diff",
        summary="Compares reconstructed fragment boundaries against originals to ensure ordering and offsets remain stable.",
        inputs=["Decoded fragment pairs", "Reconstructed text"],
        outputs=["Boundary diff report", "boundaries.json artifact"],
        failure_modes=[
            "Fragments reordered or collapsed during reconstruction",
        ],
        remedies=[
            "Use the recorded mismatched offsets to repair fragment sequencing or force manual overrides",
        ],
        runtime_guidance="A high mismatch rate usually indicates runtime-only concatenation; switch to `parity_test` or the review UI to capture the executed order.",
    ),
    PipelineStageDoc(
        name="Bytecode detection",
        function="detect_embedded_bytecode",
        summary="Scans decoded fragments for Lua bytecode signatures and emits disassembly reports for embedded chunks.",
        inputs=["Reconstructed text", "Fragment list"],
        outputs=["Per-chunk bytecode reports", "disassembly artefacts"],
        failure_modes=[
            "Compressed or encrypted bytecode segments remain undecoded",
        ],
        remedies=[
            "Run compression detectors or PRGA candidates to obtain raw bytecode before re-running detection",
        ],
        runtime_guidance="If bytecode only materialises during execution, instrument the sandbox runner to dump the buffer prior to invoking the detector.",
    ),
    PipelineStageDoc(
        name="Obfuscator fingerprinting",
        function="fingerprint_obfuscation_patterns",
        summary="Records stable pattern fingerprints for Luraph v14 payloads so subsequent runs can short-circuit analysis.",
        inputs=["Reconstructed text", "Header metadata"],
        outputs=["fingerprints.json fingerprint cache"],
        failure_modes=[
            "Version banner missing or outside the v14 family",
            "Text cannot be fingerprinted because reconstruction failed",
        ],
        remedies=[
            "Repair header metadata via `detect_luraph_header_from_text` or supply version hints manually",
            "Re-run the static rebuild or capture runtime text before fingerprinting",
        ],
        runtime_guidance="Fingerprints accelerate later runs—commit them only after verifying the payload uses the supplied session key.",
    ),
    PipelineStageDoc(
        name="Function boundary export",
        function="split_functions_from_payload",
        summary="Splits the reconstructed payload into per-function files with metadata for manual review.",
        inputs=["Reconstructed Lua path"],
        outputs=["Function snippets", "boundary metadata"],
        failure_modes=[
            "Unbalanced `function`/`end` pairs impede splitting",
        ],
        remedies=[
            "Inspect the preview snippet in the metadata and correct syntax before rerunning the splitter",
        ],
        runtime_guidance="If the payload defines functions through runtime loaders, capture the executed module via the sandbox then rerun the splitter on the emitted text.",
    ),
    PipelineStageDoc(
        name="Metadata & provenance extraction",
        function="extract_metadata_provenance",
        summary="Pulls embedded banners, timestamps, and key hints into a structured metadata.json for auditing.",
        inputs=["Reconstructed Lua text"],
        outputs=["metadata.json with provenance signals"],
        failure_modes=[
            "No textual markers survive obfuscation",
        ],
        remedies=[
            "Re-run detection on alternate fragments or enable sandbox logging to capture runtime banners",
        ],
        runtime_guidance="Runtime loaders may print banners late; hook the sandbox console output and merge the logs into the metadata report.",
    ),
    PipelineStageDoc(
        name="Dangerous call scan",
        function="detect_dangerous_calls",
        summary="Looks for networking and OS interaction primitives and records contextual lines for manual review.",
        inputs=["Reconstructed Lua path"],
        outputs=["dangerous_calls.txt report", "Structured findings"],
        failure_modes=[
            "Runtime-only wrappers hide the dangerous call tokens",
        ],
        remedies=[
            "Extend the pattern list or capture executed code via the sandbox before re-running the scan",
        ],
        runtime_guidance="If the payload constructs request helpers dynamically, execute the sandbox parity harness to dump the generated source and feed it into the scanner.",
    ),
    PipelineStageDoc(
        name="Helper/module lifting",
        function="lift_helper_tables_to_modules",
        summary="Classifies helper tables and writes standalone Lua modules for string, bit, or VM operations.",
        inputs=["Reconstructed Lua text", "Optional luaparser AST"],
        outputs=["Generated helper modules", "classification report"],
        failure_modes=[
            "Helper tables exceed heuristic thresholds or use dynamic keys",
        ],
        remedies=[
            "Fallback to text-mode lifting or tune classification thresholds before retrying",
        ],
        runtime_guidance="If helper tables are populated dynamically, capture the table via the sandbox, serialise it, and feed the dump into the lifter.",
    ),
    PipelineStageDoc(
        name="Opcode & VM reporting",
        function="generate_upcode_table / opcode_semantics_guesses",
        summary="Aggregates lifted VM IR into opcode tables, semantic guesses, and Markdown/JSON artefacts for mapping work.",
        inputs=["Lifted VM IR", "Helper/opcode metadata"],
        outputs=["upcodes.json", "upcodes.md", "opcode_guesses.json"],
        failure_modes=[
            "Insufficient IR due to earlier decode failures",
        ],
        remedies=[
            "Re-run VM lifting after addressing earlier pipeline errors or regenerate IR from the sandbox trace",
        ],
        runtime_guidance="When IR cannot be lifted statically, use `simulate_vm` with sandbox inputs to harvest executed opcode traces before generating documentation.",
    ),
    PipelineStageDoc(
        name="Quality gate evaluation",
        function="evaluate_deobfuscation_checklist / evaluate_quality_gate",
        summary="Scores the reconstructed output, enforces completeness thresholds, and confirms parity harness coverage before a run is marked successful.",
        inputs=[
            "Checklist emitted by `evaluate_deobfuscation_checklist`",
            "Configured gate options (threshold, parity requirements)",
        ],
        outputs=[
            "Quality gate summary and failure reasons",
            "Optional mapping.lock updates when rename confidence is high",
        ],
        failure_modes=[
            "Checklist unavailable because reconstruction did not produce output",
            "Completeness score below the configured threshold",
            "Required parity tests missing or failing",
        ],
        remedies=[
            "Re-run the pipeline with `--quality-allow-parity-failures` when sandbox parity data is unavailable",
            "Inspect earlier pipeline stages or crash reports to restore completeness score inputs",
        ],
        runtime_guidance="Dynamic transforms that only complete under sandbox execution may leave parity totals at zero; either provide runtime traces or disable the parity requirement for the current session.",
    ),
)


def generate_pipeline_documentation(output_path: str | Path = "PIPELINE.md") -> Path:
    """Emit a Markdown overview of the deobfuscation pipeline stages."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    overview_rows = [
        "| Stage | Function | Summary |",
        "| --- | --- | --- |",
    ]

    for index, stage in enumerate(PIPELINE_STAGE_DOCS, start=1):
        overview_rows.append(
            f"| {index}. {stage.name} | `{stage.function}` | {stage.summary} |"
        )

    lines: List[str] = [
        "# Deobfuscation Pipeline",
        "",
        "This document is auto-generated by ``version_detector.generate_pipeline_documentation`` to summarise the static and analysis pipeline used by the tooling.",
        "",
        "## Stage overview",
        "",
        "\n".join(overview_rows),
        "",
        "Each section below expands on the inputs, outputs, and mitigation strategies for the corresponding stage.",
        "",
    ]

    for index, stage in enumerate(PIPELINE_STAGE_DOCS, start=1):
        lines.extend(
            [
                f"## {index}. {stage.name}",
                "",
                f"**Function:** `{stage.function}`",
                "",
                f"**Purpose:** {stage.summary}",
                "",
                "**Inputs**",
            ]
        )
        for item in stage.inputs:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("**Outputs**")
        for item in stage.outputs:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("**Failure modes**")
        for mode in stage.failure_modes:
            lines.append(f"- {mode}")
        lines.append("")
        lines.append("**Recommended remedies**")
        for remedy in stage.remedies:
            lines.append(f"- {remedy}")
        if stage.runtime_guidance:
            lines.extend(
                [
                    "",
                    "**Runtime-only guidance**",
                    f"- {stage.runtime_guidance}",
                ]
            )
        lines.append("")

    lines.extend(
        [
            "## Handling runtime-only transforms",
            "",
            "When a stage reports high entropy, missing fragments, or boundary mismatches, prefer executing ``run_probe_harness`` with the session key, capturing sandbox traces via ``parity_test`` or ``round_trip_test``, and resuming the snapshot-enabled search to gather concrete runtime artefacts before re-running the static pipeline.",
            "",
            "The manifest (``run_manifest.json``) records which stages ran and which transforms succeeded so pipeline reruns remain reproducible.",
            "",
        ]
    )

    output.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return output


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ensure_mapping(payload: Any) -> Dict[str, Any]:
    if payload is None:
        return {}
    if isinstance(payload, Mapping):
        return dict(payload)
    if hasattr(payload, "to_json"):
        try:
            json_payload = payload.to_json()  # type: ignore[attr-defined]
        except Exception:
            json_payload = None
        if isinstance(json_payload, Mapping):
            return dict(json_payload)
    result: Dict[str, Any] = {}
    for attribute in (
        "version_detected",
        "detected_version",
        "blob_count",
        "decoded_bytes",
        "opcode_stats",
        "unknown_opcodes",
        "warnings",
        "errors",
        "vm_metadata",
    ):
        if hasattr(payload, attribute):
            result[attribute] = getattr(payload, attribute)
    return result


def _format_ratio(numerator: Optional[int], denominator: Optional[int]) -> str:
    if denominator is None or denominator <= 0:
        if numerator is None:
            return "not recorded"
        return f"{numerator}"
    num = 0 if numerator is None else numerator
    ratio = (num / denominator) * 100 if denominator else 0.0
    return f"{num}/{denominator} ({ratio:.1f}%)"


def _format_opcode_list(values: Sequence[Any]) -> str:
    if not values:
        return "none"
    formatted: List[str] = []
    for index, value in enumerate(values):
        if index >= 10:
            formatted.append(f"+{len(values) - 10} more")
            break
        if isinstance(value, int):
            formatted.append(f"{value} (0x{value:X})")
        else:
            formatted.append(str(value))
    return ", ".join(formatted)


def generate_run_summary(
    output_path: str | Path = "SUMMARY.md",
    *,
    source: Union[str, Path, None] = None,
    report: Any = None,
    checklist: Mapping[str, Any] | None = None,
    extras: Mapping[str, Any] | None = None,
) -> Path:
    """Write a concise Markdown summary of the latest deobfuscation run."""

    report_data = _ensure_mapping(report)
    checklist_data = _ensure_mapping(checklist)
    extras_data = _ensure_mapping(extras)

    completeness: Mapping[str, Any] = {}
    if isinstance(checklist_data.get("completeness"), Mapping):
        completeness = checklist_data["completeness"]  # type: ignore[assignment]

    inputs = _ensure_mapping(completeness.get("inputs"))
    components = _ensure_mapping(completeness.get("components"))

    fragments_info = _ensure_mapping(inputs.get("fragments"))
    opcodes_info = _ensure_mapping(inputs.get("opcodes"))
    parity_info = _ensure_mapping(inputs.get("parity"))
    runtime_info = _ensure_mapping(inputs.get("runtime"))

    fragments_processed = _coerce_int(fragments_info.get("processed"))
    fragments_expected = _coerce_int(fragments_info.get("expected"))
    fragments_line = _format_ratio(fragments_processed, fragments_expected)

    opcodes_total = _coerce_int(opcodes_info.get("total"))
    opcodes_named = _coerce_int(opcodes_info.get("named"))
    opcodes_unmapped = _coerce_int(opcodes_info.get("unmapped"))
    mapped_line = _format_ratio(opcodes_named, opcodes_total)

    parity_total = _coerce_int(parity_info.get("total"))
    parity_passed = _coerce_int(parity_info.get("passed"))
    parity_line = _format_ratio(parity_passed, parity_total)

    runtime_flagged = _coerce_int(runtime_info.get("flagged"))
    runtime_total = _coerce_int(runtime_info.get("total"))
    runtime_source = runtime_info.get("source") if runtime_info else None
    if runtime_flagged is None:
        runtime_line = "not evaluated"
    elif runtime_flagged == 0:
        runtime_line = "none flagged"
    else:
        if runtime_total and runtime_total > 0:
            runtime_line = f"{runtime_flagged}/{runtime_total} flagged"
        else:
            runtime_line = f"{runtime_flagged} flagged"
        if runtime_source:
            runtime_line += f" (from {runtime_source})"

    completeness_score = completeness.get("score")
    if isinstance(completeness_score, (int, float)):
        completeness_text = f"{float(completeness_score):.3f}"
    else:
        completeness_text = "n/a"

    version_text = "unknown"
    version_candidate = report_data.get("version_detected") or report_data.get(
        "detected_version"
    )
    if isinstance(version_candidate, str) and version_candidate.strip():
        version_text = version_candidate.strip()

    unknown_opcodes = report_data.get("unknown_opcodes")
    if not isinstance(unknown_opcodes, Sequence) or isinstance(
        unknown_opcodes, (str, bytes)
    ):
        unknown_list: List[Any] = []
    else:
        unknown_list = list(unknown_opcodes)

    if opcodes_unmapped is not None and opcodes_unmapped > 0:
        unmapped_detail = opcodes_unmapped
    elif unknown_list:
        unmapped_detail = len(unknown_list)
    else:
        unmapped_detail = 0

    warnings = report_data.get("warnings")
    if not isinstance(warnings, Sequence) or isinstance(warnings, (str, bytes)):
        warning_list: List[str] = []
    else:
        warning_list = [str(entry) for entry in warnings]

    errors = report_data.get("errors")
    if not isinstance(errors, Sequence) or isinstance(errors, (str, bytes)):
        error_list: List[str] = []
    else:
        error_list = [str(entry) for entry in errors]

    dangerous_calls = _ensure_mapping(extras_data.get("dangerous_calls"))
    dangerous_count = _coerce_int(dangerous_calls.get("count")) or 0
    dangerous_path = dangerous_calls.get("path")

    findings: List[str] = []
    if unknown_list:
        findings.append(
            "Unmapped opcodes: " + _format_opcode_list([v for v in unknown_list if v is not None])
        )
    if warning_list:
        findings.extend(f"Warning: {entry}" for entry in warning_list)
    if error_list:
        findings.extend(f"Error: {entry}" for entry in error_list)
    if dangerous_count:
        location = f" ({dangerous_path})" if isinstance(dangerous_path, str) else ""
        findings.append(
            f"Dangerous runtime calls detected: {dangerous_count}{location}"
        )

    checks = checklist_data.get("checks") if isinstance(checklist_data.get("checks"), Sequence) else []
    if checks:
        for entry in checks:
            if not isinstance(entry, Mapping):
                continue
            if entry.get("name") == "upcodes_mapped" and not entry.get("passed"):
                detail = _ensure_mapping(entry.get("detail"))
                unmapped = detail.get("unmapped")
                if isinstance(unmapped, Sequence) and not isinstance(unmapped, (str, bytes)):
                    findings.append(
                        "Opcode mapping outstanding: "
                        + _format_opcode_list([item for item in unmapped if item is not None])
                    )

    next_steps: List[str] = []
    if fragments_expected and fragments_processed is not None and fragments_processed < fragments_expected:
        missing = fragments_expected - fragments_processed
        next_steps.append(
            f"Recover the remaining {missing} fragment(s) (decoded {fragments_processed}/{fragments_expected})."
        )
    if opcodes_total and (opcodes_named or 0) < opcodes_total:
        remaining = opcodes_total - (opcodes_named or 0)
        if remaining > 0:
            next_steps.append(
                f"Map the remaining {remaining} opcode(s) to complete the dispatcher table."
            )
    if runtime_flagged:
        runtime_note = f"Investigate {runtime_flagged} runtime-dependent identifier(s)"
        if runtime_source:
            runtime_note += f" noted in {runtime_source}"
        next_steps.append(runtime_note + ".")
    if parity_total and parity_passed is not None and parity_passed < parity_total:
        next_steps.append(
            f"Resolve parity mismatches ({parity_passed}/{parity_total} passing)."
        )
    if dangerous_count:
        next_steps.append("Review and neutralise flagged dangerous runtime calls before execution.")
    if warning_list:
        next_steps.extend(f"Address warning: {entry}" for entry in warning_list)
    if error_list:
        next_steps.extend(f"Resolve error: {entry}" for entry in error_list)
    if not next_steps:
        next_steps.append("No outstanding manual steps identified; verify reconstructed Lua as needed.")

    source_text: Optional[str]
    if source is None:
        source_text = None
    else:
        source_text = str(Path(source))

    lines: List[str] = ["# Deobfuscation Summary", ""]

    if source_text:
        lines.extend([f"**Target:** `{source_text}`", ""])

    lines.extend(
        [
            "## Overview",
            "",
            f"- **Version detected:** {version_text}",
            f"- **Completeness score:** {completeness_text}",
            f"- **Fragments decoded:** {fragments_line}",
            f"- **Opcodes mapped:** {mapped_line}",
            f"- **Runtime-dependent items:** {runtime_line}",
            f"- **Parity tests:** {parity_line}",
        ]
    )

    decoded_bytes = report_data.get("decoded_bytes")
    blob_count = report_data.get("blob_count")
    if isinstance(decoded_bytes, (int, float)) or isinstance(blob_count, (int, float)):
        decoded_parts: List[str] = []
        if isinstance(blob_count, (int, float)):
            decoded_parts.append(f"blobs={int(blob_count)}")
        if isinstance(decoded_bytes, (int, float)):
            decoded_parts.append(f"bytes={int(decoded_bytes)}")
        if decoded_parts:
            lines.append(f"- **Decoded payloads:** {', '.join(decoded_parts)}")

    lines.append("")

    lines.append("## Key findings")
    lines.append("")
    if findings:
        lines.extend(f"- {entry}" for entry in findings)
    else:
        lines.append("- No outstanding findings; all tracked checks passed.")
    lines.append("")

    lines.append("## Next manual steps")
    lines.append("")
    lines.extend(f"- {step}" for step in next_steps)
    lines.append("")

    components_entries = {
        "fragments": components.get("fragments_fraction"),
        "opcodes": components.get("opcodes_fraction"),
        "parity": components.get("parity_rate"),
        "runtime": components.get("runtime_component"),
    }
    component_lines = [
        f"  - {name}: {value:.3f}" for name, value in components_entries.items() if isinstance(value, (int, float))
    ]
    if component_lines:
        lines.extend(
            [
                "## Component breakdown",
                "",
                "These values contribute to the completeness score:",
                "",
            ]
        )
        lines.extend(component_lines)
        lines.append("")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return output
def split_functions_from_payload(
    path: str | Path,
    *,
    output_dir: str | Path | None = None,
    min_lines: int = 1,
) -> Dict[str, object]:
    """Split a reconstructed payload into individual function files."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    line_offsets = _compute_line_offsets(text)

    if output_dir is None:
        output_directory = file_path.with_name(f"{file_path.stem}_functions")
    else:
        output_directory = Path(output_dir)
    output_directory.mkdir(parents=True, exist_ok=True)

    metadata = detect_luraph_header_from_text(text)

    records: List[Dict[str, object]] = []
    processed_end = -1
    name_counter: DefaultDict[str, int] = defaultdict(int)

    minimum_lines = max(1, min_lines)

    for func_pos in _iter_function_positions(text):
        if func_pos < processed_end:
            continue

        end_pos = _find_function_end(text, func_pos + len("function"))
        if end_pos is None:
            continue

        start = _derive_function_start(text, func_pos)
        snippet = text[start:end_pos]
        if not snippet.strip():
            continue

        anchor = max(start, end_pos - 1)
        line_start, _ = _offset_to_line_col(start, line_offsets)
        line_end, _ = _offset_to_line_col(anchor, line_offsets)
        line_count = max(1, line_end - line_start + 1)
        if line_count < minimum_lines:
            continue

        first_line = snippet.splitlines()[0] if snippet else ""
        name, kind = _classify_function_header(first_line)
        display_name = name
        unique_name, file_stem = _sanitise_function_basename(name, len(records), kind, name_counter)

        output_path = output_directory / f"{file_stem}.lua"
        body = snippet if snippet.endswith("\n") else snippet + "\n"
        output_path.write_text(body, encoding="utf-8")

        preview = _preview_snippet(text, start, end_pos)
        record = {
            "index": len(records),
            "name": display_name or unique_name,
            "sanitized_name": unique_name,
            "kind": kind,
            "start_offset": start,
            "function_offset": func_pos,
            "end_offset": end_pos,
            "line_start": line_start,
            "line_end": line_end,
            "lines": line_count,
            "file": str(output_path),
            "header": first_line.strip(),
            "preview": preview,
        }
        records.append(record)
        processed_end = end_pos

    return {
        "source": str(file_path),
        "output_dir": str(output_directory),
        "count": len(records),
        "functions": records,
        "metadata": metadata,
    }


def divide_unit_of_work(
    path: str | Path,
    *,
    output_dir: str | Path | None = None,
    min_function_lines: int = 1,
) -> Dict[str, Any]:
    """Generate unit-of-work artefacts for large Lua payloads.

    The resulting directory contains sub-folders for raw fragments, lifted helper
    modules, and VM dispatcher sections so separate contributors can work on
    them independently.
    """

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    line_offsets = _compute_line_offsets(text)

    if output_dir is None:
        units_root = file_path.with_name(f"{file_path.stem}_units")
    else:
        units_root = Path(output_dir)
    units_root.mkdir(parents=True, exist_ok=True)

    metadata = detect_luraph_header_from_text(text)

    # Fragment extraction -------------------------------------------------
    fragments_dir = units_root / "fragments"
    fragments_dir.mkdir(parents=True, exist_ok=True)
    fragments = extract_fragments(file_path)
    fragment_entries: List[Dict[str, Any]] = []
    for index, fragment in enumerate(fragments):
        start = int(fragment.get("start", 0))
        end = int(fragment.get("end", start))
        size = max(0, end - start)
        anchor = max(start, end - 1)
        line_start, _ = _offset_to_line_col(start, line_offsets)
        line_end, _ = _offset_to_line_col(anchor, line_offsets)
        preview = _preview_snippet(text, start, end)

        fragment_text = fragment.get("text", "")
        fragment_path = fragments_dir / f"fragment_{index:04d}.lua"
        fragment_payload = fragment_text if fragment_text.endswith("\n") else fragment_text + "\n"
        fragment_path.write_text(fragment_payload, encoding="utf-8")

        fragment_entries.append(
            {
                "index": index,
                "type": fragment.get("type", "unknown"),
                "file": str(fragment_path),
                "start_offset": start,
                "end_offset": end,
                "size": size,
                "line_start": line_start,
                "line_end": line_end,
                "preview": preview,
            }
        )

    # Helper table lifting -----------------------------------------------
    helpers_dir = units_root / "helper_tables"
    helper_result = lift_helper_tables_to_modules(
        file_path,
        output_dir=helpers_dir,
        min_functions=min_function_lines,
    )
    helper_modules = helper_result.get("modules", [])

    # VM sections ---------------------------------------------------------
    vm_dir = units_root / "vm_sections"
    vm_dir.mkdir(parents=True, exist_ok=True)
    vm_entries: List[Dict[str, Any]] = []
    vm_skipped: List[str] = []
    try:
        from pattern_analyzer import find_vm_signatures  # type: ignore

        vm_signatures = find_vm_signatures(text)
    except RuntimeError as exc:
        vm_signatures = []
        vm_skipped.append(str(exc))
    except ImportError:
        vm_signatures = []
        vm_skipped.append("pattern_analyzer_missing")

    for index, signature in enumerate(vm_signatures):
        node = signature.get("ast")
        start_char = getattr(node, "start_char", None)
        stop_char = getattr(node, "stop_char", None)
        if isinstance(start_char, int) and isinstance(stop_char, int) and start_char < stop_char:
            snippet = text[start_char:stop_char]
        else:
            snippet = signature.get("summary", "")

        vm_path = vm_dir / f"vm_section_{index:02d}.lua"
        vm_payload = snippet if snippet.endswith("\n") else snippet + "\n"
        vm_path.write_text(vm_payload, encoding="utf-8")

        line_start, _ = _offset_to_line_col(start_char or 0, line_offsets)
        line_end, _ = _offset_to_line_col((stop_char - 1) if isinstance(stop_char, int) else 0, line_offsets)

        vm_entry = {
            "index": index,
            "name": signature.get("name"),
            "line": signature.get("line"),
            "line_start": line_start,
            "line_end": line_end,
            "summary": signature.get("summary"),
            "handler_tables": signature.get("handler_tables", []),
            "opcode_cases": signature.get("opcode_cases", []),
            "bit_ops": signature.get("bit_ops", []),
            "file": str(vm_path),
        }
        vm_entries.append(vm_entry)

    plan = {
        "source": str(file_path),
        "output_dir": str(units_root),
        "metadata": metadata,
        "fragments": {
            "output_dir": str(fragments_dir),
            "count": len(fragment_entries),
            "entries": fragment_entries,
        },
        "helper_tables": {
            "output_dir": str(helpers_dir),
            "count": len(helper_modules),
            "modules": helper_modules,
            "skipped": helper_result.get("skipped", []),
        },
        "vm_sections": {
            "output_dir": str(vm_dir),
            "count": len(vm_entries),
            "entries": vm_entries,
            "skipped": vm_skipped,
        },
    }

    unit_plan_path = units_root / "unit_of_work.json"
    unit_plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")

    return plan


def _helper_table_key_repr(astnodes, key: object, index: int) -> Tuple[str, str]:
    if key is None:
        return str(index), f"[{index}]"
    if isinstance(key, astnodes.Name):
        return key.id, key.id
    if isinstance(key, astnodes.String):
        value = key.s
        literal = json.dumps(value)
        return value, f"[{literal}]"
    if isinstance(key, astnodes.Number):
        number = key.n
        if isinstance(number, float) and number.is_integer():
            number = int(number)
        return str(number), f"[{number}]"
    return f"field_{index}", f"[\"field_{index}\"]"


def _helper_key_repr_from_text(raw_key: Optional[str], index: int) -> Tuple[str, str]:
    if not raw_key:
        return str(index), f"[{index}]"

    key = raw_key.strip()
    if not key:
        return str(index), f"[{index}]"

    if key.startswith("[") and key.endswith("]"):
        inner = key[1:-1].strip()
        display = inner
        if inner and inner[0] in {'"', "'"} and inner[-1] == inner[0]:
            try:
                display = py_ast.literal_eval(inner)
            except Exception:
                display = inner.strip(inner[0])
        return str(display), key

    return key, key


def _helper_table_classification(table_name: Optional[str], bodies: Sequence[str]) -> Tuple[str, str, Dict[str, int]]:
    lowered_name = (table_name or "").lower()
    text = "\n".join(bodies).lower()

    scores = {"string_helpers": 0, "bit_helpers": 0, "vm_ops": 0}

    string_keywords = [
        "string.",
        "string:",
        "byte",
        "char",
        "gsub",
        "sub",
        "upper",
        "lower",
    ]
    bit_keywords = [
        "bit32.",
        "bit32:",
        "bit.",
        "band",
        "bor",
        "bxor",
        "lshift",
        "rshift",
        "arshift",
        "bnot",
    ]
    vm_keywords = [
        "opcode",
        "dispatch",
        "vm",
        "stack",
        "pc",
        "register",
        "instruction",
    ]

    if any(token in lowered_name for token in ("str", "string", "text")):
        scores["string_helpers"] += 3
    if any(token in lowered_name for token in ("bit", "mask")):
        scores["bit_helpers"] += 3
    if any(token in lowered_name for token in ("vm", "opcode", "dispatch")):
        scores["vm_ops"] += 3

    for keyword in string_keywords:
        if keyword in text:
            scores["string_helpers"] += 2
    for keyword in bit_keywords:
        if keyword in text:
            scores["bit_helpers"] += 2
    for keyword in vm_keywords:
        if keyword in text:
            scores["vm_ops"] += 2

    best_category, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score == 0:
        sanitized = re.sub(r"[^0-9A-Za-z_]+", "_", (table_name or "helpers")).strip("_")
        if not sanitized:
            sanitized = "helpers"
        module_name = sanitized.lower()
        if not module_name.endswith("_helpers"):
            module_name = f"{module_name}_helpers"
        return module_name, "generic", scores

    return best_category, best_category, scores


def _rewrite_helper_body(accessor: str, body: str) -> str:
    stripped = textwrap.dedent(body).strip()
    index = stripped.find("function")
    if index == -1:
        return f"-- unable to rewrite helper {accessor}\n"
    suffix = stripped[index + len("function") :]
    rewritten = f"function {accessor}{suffix}"
    if not rewritten.endswith("\n"):
        rewritten += "\n"
    return rewritten


def _collect_helper_tables_ast(
    lua_ast,
    astnodes,
    tree,
    source: str,
    line_offsets: Sequence[int],
    min_functions: int,
    max_functions: int,
) -> List[Dict[str, Any]]:
    class _TableCollector(lua_ast.ASTVisitor):
        def __init__(self) -> None:
            super().__init__()
            self.tables: List[Dict[str, Any]] = []
            self._seen: Set[int] = set()

        def visit_LocalAssign(self, node):  # type: ignore[override]
            self._handle_assignment(node, local=True)

        def visit_Assign(self, node):  # type: ignore[override]
            self._handle_assignment(node, local=False)

        def visit_Return(self, node):  # type: ignore[override]
            for value in getattr(node, "values", []) or []:
                if isinstance(value, astnodes.Table):
                    self._record_table(value, None, "return")

        def _handle_assignment(self, node, *, local: bool) -> None:
            targets = getattr(node, "targets", []) or []
            values = getattr(node, "values", []) or []
            for target, value in zip(targets, values):
                if not isinstance(value, astnodes.Table):
                    continue
                table_name = _resolve_name_for_helpers(astnodes, target)
                context = "local" if local else "assign"
                self._record_table(value, table_name, context)

        def _record_table(self, table_node, table_name: Optional[str], context: str) -> None:
            if id(table_node) in self._seen:
                return
            self._seen.add(id(table_node))

            fields = getattr(table_node, "fields", []) or []
            helpers: List[Dict[str, Any]] = []
            bodies: List[str] = []
            for index, field in enumerate(fields, start=1):
                value = getattr(field, "value", None)
                if not isinstance(value, (astnodes.Function, getattr(astnodes, "AnonymousFunction", astnodes.Function))):
                    continue
                start = getattr(value, "start_char", None)
                stop = getattr(value, "stop_char", None)
                if start is None or stop is None:
                    continue
                text = source[start:stop]
                bodies.append(text)
                display_key, accessor = _helper_table_key_repr(astnodes, getattr(field, "key", None), index)
                line_start, col_start = _offset_to_line_col(start, line_offsets)
                line_end, col_end = _offset_to_line_col(stop - 1, line_offsets)
                helpers.append(
                    {
                        "key": display_key,
                        "accessor": accessor,
                        "start": start,
                        "stop": stop,
                        "line_start": line_start,
                        "line_end": line_end,
                        "column_start": col_start,
                        "column_end": col_end,
                        "body": text,
                        "preview": _preview_snippet(source, start, stop),
                    }
                )

            if len(helpers) < min_functions or len(helpers) > max_functions:
                return

            table_start = getattr(table_node, "start_char", None)
            table_stop = getattr(table_node, "stop_char", None)
            snippet = (
                _preview_snippet(source, table_start or 0, table_stop or 0)
                if table_start is not None and table_stop is not None
                else ""
            )
            line, column = _offset_to_line_col(table_start or 0, line_offsets) if table_start is not None else (1, 1)

            classification, category, scores = _helper_table_classification(table_name, bodies)

            self.tables.append(
                {
                    "name": table_name,
                    "context": context,
                    "helpers": helpers,
                    "snippet": snippet,
                    "line": line,
                    "column": column,
                    "classification": classification,
                    "category": category,
                    "scores": scores,
                }
            )

    def _resolve_name_for_helpers(astnodes, node: object) -> Optional[str]:
        if isinstance(node, astnodes.Name):
            return node.id
        if isinstance(node, astnodes.String):
            return node.s
        if isinstance(node, astnodes.Index):
            base = _resolve_name_for_helpers(astnodes, getattr(node, "value", None))
            suffix = _resolve_name_for_helpers(astnodes, getattr(node, "idx", None))
            if base and suffix:
                return f"{base}.{suffix}"
            return suffix or base
        return None

    collector = _TableCollector()
    collector.visit(tree)
    return collector.tables


def _extract_helpers_from_table(
    source: str,
    table_start: int,
    table_stop: int,
    line_offsets: Sequence[int],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    table_text = source[table_start:table_stop]
    protected = _collect_protected_ranges(table_text)
    helpers: List[Dict[str, Any]] = []
    bodies: List[str] = []

    for index, match in enumerate(_TABLE_HELPER_ENTRY_RE.finditer(table_text), start=1):
        local_pos = match.start("func")
        if _position_in_ranges(local_pos, protected):
            continue

        func_start = table_start + local_pos
        func_end = _find_function_end(source, func_start + len("function"))
        if func_end is None or func_end > table_stop:
            continue

        body = source[func_start:func_end]
        key_text = match.group("key")
        display_key, accessor = _helper_key_repr_from_text(key_text, index)

        line_start, col_start = _offset_to_line_col(func_start, line_offsets)
        line_end, col_end = _offset_to_line_col(func_end - 1, line_offsets)

        helpers.append(
            {
                "key": display_key,
                "accessor": accessor,
                "start": func_start,
                "stop": func_end,
                "line_start": line_start,
                "line_end": line_end,
                "column_start": col_start,
                "column_end": col_end,
                "body": body,
                "preview": _preview_snippet(source, func_start, func_end),
            }
        )
        bodies.append(body)

    return helpers, bodies


def _collect_helper_tables_textual(
    source: str,
    line_offsets: Sequence[int],
    min_functions: int,
    max_functions: int,
) -> List[Dict[str, Any]]:
    tables: List[Dict[str, Any]] = []
    seen_ranges: Set[Tuple[int, int]] = set()

    for match in _TABLE_ASSIGN_RE.finditer(source):
        brace_index = match.end() - 1
        table_stop = _find_matching_brace(source, brace_index)
        if table_stop is None:
            continue
        table_range = (brace_index, table_stop)
        if table_range in seen_ranges:
            continue
        seen_ranges.add(table_range)

        context = "local" if match.group("local") else "assign"
        table_name = match.group("name")
        helpers, bodies = _extract_helpers_from_table(source, brace_index, table_stop, line_offsets)
        if len(helpers) < min_functions or len(helpers) > max_functions:
            continue

        line, column = _offset_to_line_col(brace_index, line_offsets)
        snippet = _preview_snippet(source, brace_index, table_stop)
        classification, category, scores = _helper_table_classification(table_name, bodies)

        tables.append(
            {
                "name": table_name,
                "context": context,
                "helpers": helpers,
                "snippet": snippet,
                "line": line,
                "column": column,
                "classification": classification,
                "category": category,
                "scores": scores,
            }
        )

    for match in _TABLE_RETURN_RE.finditer(source):
        brace_index = match.end() - 1
        table_stop = _find_matching_brace(source, brace_index)
        if table_stop is None:
            continue
        table_range = (brace_index, table_stop)
        if table_range in seen_ranges:
            continue
        seen_ranges.add(table_range)

        helpers, bodies = _extract_helpers_from_table(source, brace_index, table_stop, line_offsets)
        if len(helpers) < min_functions or len(helpers) > max_functions:
            continue

        line, column = _offset_to_line_col(brace_index, line_offsets)
        snippet = _preview_snippet(source, brace_index, table_stop)
        classification, category, scores = _helper_table_classification(None, bodies)

        tables.append(
            {
                "name": None,
                "context": "return",
                "helpers": helpers,
                "snippet": snippet,
                "line": line,
                "column": column,
                "classification": classification,
                "category": category,
                "scores": scores,
            }
        )

    return tables



def lift_helper_tables_to_modules(
    path: str | Path,
    *,
    output_dir: str | Path | None = None,
    min_functions: int = 1,
    max_functions: int = 40,
) -> Dict[str, Any]:
    """Lift small helper tables into standalone Lua modules."""

    try:
        from luaparser import ast as lua_ast, astnodes
    except ImportError:  # pragma: no cover - dependency missing
        lua_ast = None
        astnodes = None

    skipped: List[str] = []
    if lua_ast is None:
        skipped.append("luaparser_missing")

    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8", errors="ignore")

    if output_dir is None:
        modules_dir = file_path.with_name(f"{file_path.stem}_modules")
    else:
        modules_dir = Path(output_dir)
    modules_dir.mkdir(parents=True, exist_ok=True)

    line_offsets = _compute_line_offsets(source)

    tables: List[Dict[str, Any]] = []
    if lua_ast is not None:
        try:
            tree = lua_ast.parse(source)
        except lua_ast.SyntaxException:
            skipped.append("syntax_error")
            tables = _collect_helper_tables_textual(source, line_offsets, min_functions, max_functions)
        else:
            tables = _collect_helper_tables_ast(
                lua_ast,
                astnodes,
                tree,
                source,
                line_offsets,
                min_functions,
                max_functions,
            )
            if not tables:
                fallback_tables = _collect_helper_tables_textual(
                    source,
                    line_offsets,
                    min_functions,
                    max_functions,
                )
                if fallback_tables:
                    tables = fallback_tables
                    skipped.append("textual_fallback")
    else:
        tables = _collect_helper_tables_textual(source, line_offsets, min_functions, max_functions)

    used_names: DefaultDict[str, int] = defaultdict(int)
    modules: List[Dict[str, Any]] = []

    for table in tables:
        base_name = table["classification"]
        used_names[base_name] += 1
        if used_names[base_name] > 1:
            module_name = f"{base_name}_{used_names[base_name]}"
        else:
            module_name = base_name

        module_path = modules_dir / f"{module_name}.lua"
        lines = ["local M = {}", ""]
        for helper in table["helpers"]:
            if helper["accessor"].startswith("["):
                accessor = f"M{helper['accessor']}"
            else:
                accessor = f"M.{helper['accessor']}"
            rewritten = _rewrite_helper_body(accessor, helper["body"])
            lines.append(rewritten.rstrip())
            lines.append("")
        lines.append("return M")
        lines.append("")
        module_text = "\n".join(lines)
        module_path.write_text(module_text, encoding="utf-8")

        modules.append(
            {
                "table_name": table["name"],
                "module_name": module_name,
                "category": table["category"],
                "scores": table["scores"],
                "file": str(module_path),
                "helper_count": len(table["helpers"]),
                "helpers": [
                    {
                        "key": helper["key"],
                        "accessor": helper["accessor"],
                        "module_accessor": f"M{helper['accessor']}" if helper["accessor"].startswith("[") else f"M.{helper['accessor']}",
                        "line_start": helper["line_start"],
                        "line_end": helper["line_end"],
                        "preview": helper["preview"],
                        "file": str(module_path),
                    }
                    for helper in table["helpers"]
                ],
            }
        )

    return {
        "source": str(file_path),
        "output_dir": str(modules_dir),
        "modules": modules,
        "tables_examined": len(tables),
        "skipped": skipped,
    }


def _resolve_parity_pipeline(file_path: Path, pipeline: str | None) -> str:
    """Infer which decode pipeline should be used for parity testing."""

    if pipeline:
        normalized = pipeline.strip().lower()
        if normalized != "initv4":
            raise ValueError(f"unsupported parity pipeline: {pipeline}")
        return "initv4"

    try:
        header = detect_luraph_header(file_path)
    except OSError:
        header = {}

    version = str(header.get("version") or "").strip().lower()
    name = file_path.name.lower()

    if name == "obfuscated.json" or version in {"14.4.1", "14.4"}:
        return "initv4"

    raise ValueError(
        "initv4 parity harness is only applicable to Obfuscated.json and other "
        "initv4 bootstrap contexts; provide pipeline='initv4' to override when "
        "working with synthetic fixtures."
    )


def parity_test(
    fragment_index: int,
    *,
    path: str | Path = "Obfuscated.json",
    key: str,
    word_count: int = 16,
    sandbox_runner: Callable[..., Dict[str, object]] | None = None,
    pipeline: str | None = None,
) -> Dict[str, object]:
    """Cross-check emulator PRGA output against a sandboxed Lua execution."""

    if not key:
        raise ValueError("a non-empty key is required for parity testing")

    file_path = Path(path)
    pipeline_kind = _resolve_parity_pipeline(file_path, pipeline)
    fragments = extract_fragments(file_path)
    if fragment_index < 0 or fragment_index >= len(fragments):
        raise IndexError("fragment_index out of range")

    fragment = fragments[fragment_index]
    decoded_pairs = list(_iter_decoded_fragments([fragment]))
    if not decoded_pairs:
        raise ValueError("selected fragment does not contain decodable text")

    decoded_text = decoded_pairs[0][1]
    payload = decode_lph85(decoded_text)
    key_bytes = key.encode("utf-8")
    prga_bytes = apply_prga(payload, key_bytes)

    program = VMFunction(
        constants=[prga_bytes],
        instructions=[
            VMInstruction(
                "LOADK",
                a=0,
                aux={"b_mode": "const", "const_b": prga_bytes},
            ),
            VMInstruction(
                "RETURN",
                a=0,
                b=2,
                aux={"b_mode": "immediate", "immediate_b": 2},
            ),
        ],
        register_count=1,
    )

    simulation = simulate_vm(program, inputs=[])
    emulator_output = simulation.output
    if isinstance(emulator_output, bytearray):
        emulator_output = bytes(emulator_output)
    elif isinstance(emulator_output, str):
        emulator_output = emulator_output.encode("latin-1", errors="ignore")
    elif not isinstance(emulator_output, (bytes, bytearray)):
        emulator_output = bytes(str(emulator_output), "utf-8", "ignore")
    else:
        emulator_output = bytes(emulator_output)

    sandbox_fn = sandbox_runner or run_fragment_safely
    lua_fragment = _build_lua_parity_snippet(decoded_text, key, max(0, word_count))
    sandbox_result = sandbox_fn(lua_fragment, expected=None)

    if not sandbox_result.get("success"):
        raise RuntimeError(f"Lua sandbox execution failed: {sandbox_result.get('error')}")

    values = sandbox_result.get("values") or []
    if not values:
        raise RuntimeError("Lua sandbox did not return any values")

    lua_words_raw = values[0]
    lua_bytes_raw = values[1] if len(values) > 1 else None

    max_words = min(max(0, word_count), len(emulator_output) // 4)
    python_words = _first_u32_words(emulator_output, max_words)
    lua_words = _coerce_lua_words(lua_words_raw, max_words)
    lua_bytes = _coerce_lua_bytes(lua_bytes_raw)

    compare_words = min(len(python_words), len(lua_words))
    if max_words:
        compare_words = min(compare_words, max_words)

    python_words_view = python_words[:compare_words]
    lua_words_view = lua_words[:compare_words]

    if compare_words and python_words_view != lua_words_view:
        mismatch_index = next(
            (index for index, (py_val, lu_val) in enumerate(zip(python_words_view, lua_words_view)) if py_val != lu_val),
            None,
        )
        raise AssertionError(
            "Word mismatch at index {idx}: python={py_val:#010x} lua={lu_val:#010x}\n"
            "python_words={py}\n"
            "lua_words={lu}".format(
                idx=mismatch_index if mismatch_index is not None else "?",
                py_val=python_words_view[mismatch_index] if mismatch_index is not None else None,
                lu_val=lua_words_view[mismatch_index] if mismatch_index is not None else None,
                py=python_words_view,
                lu=lua_words_view,
            )
        )

    expected_bytes = compare_words * 4
    python_prefix = emulator_output[:expected_bytes]
    if lua_bytes:
        lua_prefix = lua_bytes[:expected_bytes]
        if len(lua_prefix) < expected_bytes and compare_words:
            lua_prefix = _words_to_bytes(lua_words_view)
    else:
        lua_prefix = _words_to_bytes(lua_words_view)

    diff = byte_diff(python_prefix, lua_prefix)
    if not diff.get("match", False):
        index = diff.get("index")
        context_start = max(0, index - 8) if isinstance(index, int) else 0
        context_end = context_start + 16
        raise AssertionError(
            "Parity mismatch at byte {idx}: python={py} lua={lu}\n"
            "python[{s}:{e}]: {py_ctx}\n"
            "lua[{s}:{e}]: {lu_ctx}".format(
                idx=index,
                py=f"{diff.get('a_byte'):02x}" if diff.get("a_byte") is not None else "None",
                lu=f"{diff.get('b_byte'):02x}" if diff.get("b_byte") is not None else "None",
                s=context_start,
                e=context_end,
                py_ctx=diff.get("a_context", ""),
                lu_ctx=diff.get("b_context", ""),
            )
        )

    return {
        "match": True,
        "fragment_index": fragment_index,
        "path": str(file_path),
        "word_count": compare_words,
        "python_words": python_words[:compare_words],
        "lua_words": lua_words[:compare_words],
        "environment": sandbox_result.get("environment", {}),
        "pipeline": pipeline_kind,
    }


def pretty_print_with_mapping(
    reconstructed_path: str | Path,
    mapping_path: str | Path,
    *,
    output_path: str | Path | None = None,
    indent_size: int = 4,
) -> Dict[str, object]:
    """Rename identifiers using ``mapping_path`` and emit a formatted Lua file."""

    rename_map = _load_mapping_file(mapping_path)
    source_path = Path(reconstructed_path)
    text = source_path.read_text(encoding="utf-8", errors="ignore")

    if output_path is None:
        output_path = source_path.with_name("deobfuscated_pretty.lua")

    out_path = Path(output_path)

    with benchmark(
        "pretty_print",
        {
            "path": str(source_path),
            "renames": len(rename_map),
            "indent": indent_size,
        },
    ):
        # Validate the rename map via the AST-powered renamer to ensure the
        # requested identifiers are legal and scope-safe before mutating the
        # original source (which we keep to preserve comments).
        if rename_map:
            _ = safe_rename(text, rename_map)

        renamed_text = _apply_renames_preserving_comments(text, rename_map)
        if rename_map:
            renamed_text = _propagate_comment_headers(renamed_text, rename_map)

        preview = _build_rename_preview(text, renamed_text) if rename_map else []
        if preview:
            print("Rename preview:")
            for entry in preview:
                original = entry.get("original", "").rstrip()
                updated = entry.get("updated", "").rstrip()
                line = entry.get("line")
                if line is not None:
                    print(f"  L{line}: {original} -> {updated}")
                else:
                    print(f"  {original} -> {updated}")

        beautifier = LuaBeautifier(indent_size=indent_size)
        formatted = beautifier.beautify(renamed_text)

        index_lines = ["--[[", "-- Renamed identifiers:"]
        for original, target in _sorted_rename_items(rename_map):
            index_lines.append(f"--   {original} -> {target}")
        index_lines.extend(["--]]", ""])
        header = "\n".join(index_lines)
        output_text = header + formatted
        if not output_text.endswith("\n"):
            output_text += "\n"

        out_path.write_text(output_text, encoding="utf-8")

        result = {
            "output_path": str(out_path),
            "renames": rename_map,
            "index_block": index_lines,
            "rename_preview": preview,
        }

    return result


def ir_to_lua(
    vm_ir: Any,
    *,
    mapping_path: str | Path | None = None,
    output_path: str | Path | None = None,
    module_name: str = "M",
    docstring_threshold: int = 6,
) -> Dict[str, Any]:
    """Translate lifted VM IR into a readable Lua module."""

    program = _coerce_vm_function(vm_ir)
    instructions = list(getattr(program, "instructions", []) or [])
    if not instructions:
        raise ValueError("ir_to_lua requires at least one instruction")

    resolved_mapping: Optional[Path] = None
    if mapping_path is None:
        default_mapping = Path("mapping.json")
        if default_mapping.exists():
            resolved_mapping = default_mapping
    else:
        resolved_mapping = Path(mapping_path)

    rename_map: Dict[str, str] = {}
    if resolved_mapping is not None:
        try:
            rename_map = _load_mapping_file(resolved_mapping)
        except Exception:  # pragma: no cover - mapping is optional best-effort
            rename_map = {}

    metadata = getattr(program, "metadata", {}) or {}
    raw_name = metadata.get("function_name") or metadata.get("name") or "decoded_entry"
    if rename_map:
        for candidate in (
            raw_name,
            _sanitize_identifier(str(raw_name), str(raw_name)),
        ):
            if isinstance(candidate, str) and candidate in rename_map:
                raw_name = rename_map[candidate]
                break

    function_name = _sanitize_identifier(str(raw_name), "decoded_entry")
    module_ident = _sanitize_identifier(str(module_name or "M"), "M")

    register_names = _derive_register_names(program, rename_map)
    param_count = getattr(program, "num_params", 0) or 0
    param_names = [register_names.get(idx, f"arg{idx}") for idx in range(param_count)]
    locals_names = [
        register_names[idx]
        for idx in range(param_count, len(register_names))
        if register_names.get(idx)
    ]

    indent = "    "
    docstrings: List[Dict[str, Any]] = []

    function_lines: List[str] = [
        f"local function {function_name}({', '.join(param_names)})"
    ]

    if len(instructions) >= max(1, docstring_threshold):
        summary = f"Reconstructed from VM IR ({len(instructions)} instructions)"
        function_lines.append(f"{indent}--[[")
        function_lines.append(f"{indent}{summary}")
        original_name = metadata.get("function_name") or metadata.get("name")
        if isinstance(original_name, str) and original_name and original_name != function_name:
            function_lines.append(f"{indent}Original identifier: {original_name}")
        if rename_map:
            function_lines.append(
                f"{indent}Applied mapping entries: {min(len(rename_map), 10)}"
            )
        function_lines.append(f"{indent}--]]")
        docstrings.append({"opcode": "FUNCTION", "summary": summary, "pc": None})

    if locals_names:
        function_lines.append(f"{indent}local {', '.join(locals_names)}")

    for instr in instructions:
        line, doc = _translate_instruction(instr, register_names)
        if doc:
            docstrings.append(doc)
            for entry in doc.get("lines", []):
                function_lines.append(f"{indent}{entry}")
        function_lines.append(f"{indent}{line}")

    function_lines.append("end")

    module_lines: List[str] = [
        "-- Auto-generated module produced by ir_to_lua",
        f"local {module_ident} = {{}}",
        "",
    ]
    module_lines.extend(function_lines)
    module_lines.append("")
    module_lines.append(f"{module_ident}.{function_name} = {function_name}")
    module_lines.append("")
    module_lines.append(f"return {module_ident}")

    lua_source = "\n".join(module_lines) + "\n"

    if output_path is None:
        output_path = Path("deobfuscated_module.lua")
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(lua_source, encoding="utf-8")

    return {
        "output_path": str(out_path),
        "function_name": function_name,
        "module_name": module_ident,
        "register_map": register_names,
        "docstrings": docstrings,
        "lua_source": lua_source,
        "mapping_entries": len(rename_map),
        "mapping_path": str(resolved_mapping) if resolved_mapping is not None else None,
    }


def _first_u32_words(data: bytes, count: int) -> List[int]:
    if count <= 0:
        return []
    available = len(data) // 4
    n_words = min(count, available)
    if n_words <= 0:
        return []
    fmt = "<" + "I" * n_words
    return list(struct.unpack(fmt, data[: n_words * 4]))


def _coerce_lua_words(value: object, limit: int) -> List[int]:
    if value is None:
        return []

    words: List[int] = []
    target = limit if limit > 0 else None

    def _append(entry: object) -> None:
        nonlocal words
        try:
            words.append(int(entry))
        except (TypeError, ValueError):
            return

    iterable: Sequence[object] | None = None
    if isinstance(value, dict):
        iterable = [value[key] for key in sorted(value) if isinstance(key, int)]
    elif isinstance(value, (list, tuple)):
        iterable = value
    elif hasattr(value, "__iter__") and not isinstance(value, (str, bytes, bytearray)):
        try:
            iterable = list(value)  # type: ignore[arg-type]
        except TypeError:
            iterable = None

    if iterable is not None:
        for entry in iterable:
            _append(entry)
            if target and len(words) >= target:
                break
        return words[: target or len(words)]

    index = 1
    while True:
        try:
            entry = value[index]  # type: ignore[index]
        except Exception:
            break
        _append(entry)
        if target and len(words) >= target:
            break
        index += 1

    return words[: target or len(words)]


def _split_argument_list(argument_text: str) -> List[str]:
    if not argument_text:
        return []

    parts: List[str] = []
    current: List[str] = []
    depth = 0
    in_string: Optional[str] = None
    index = 0
    length = len(argument_text)

    while index < length:
        char = argument_text[index]
        if in_string:
            current.append(char)
            if char == "\\" and index + 1 < length:
                current.append(argument_text[index + 1])
                index += 2
                continue
            if char == in_string:
                in_string = None
            index += 1
            continue

        if char in {'"', "'"}:
            in_string = char
            current.append(char)
            index += 1
            continue

        if char in "({[":
            depth += 1
            current.append(char)
            index += 1
            continue

        if char in ")}]":
            if depth > 0:
                depth -= 1
            current.append(char)
            index += 1
            continue

        if char == "," and depth == 0:
            candidate = "".join(current).strip()
            if candidate:
                parts.append(candidate)
            current = []
            index += 1
            continue

        current.append(char)
        index += 1

    candidate = "".join(current).strip()
    if candidate:
        parts.append(candidate)

    return parts


def _normalise_argument(argument: str) -> Tuple[str, bool]:
    text = argument.strip()
    if not text:
        return "", False

    try:
        value = parse_lua_expression(text)
    except Exception:  # pragma: no cover - best effort parsing
        return text, False

    try:
        formatted = lua_literal_to_string(value)
    except Exception:  # pragma: no cover - fallback for exotic values
        if isinstance(value, str):
            formatted = value
        else:
            formatted = repr(value)
    return formatted, True


def _preview_snippet(text: str, start: int, end: int, limit: int = 160) -> str:
    snippet = text[start:end].strip()
    snippet = " ".join(snippet.split())
    if len(snippet) > limit:
        snippet = snippet[: limit - 1] + "…"
    return snippet


def _iter_small_helpers(text: str, *, max_length: int) -> Iterable[Tuple[str, int, int]]:
    for match in _HELPER_DEF_RE.finditer(text):
        name = match.group(1)
        body_start = match.end()
        body_end = _find_function_end(text, body_start)
        if body_end is None:
            continue
        if body_end - match.start() > max_length:
            continue
        yield name, match.start(), body_end


def _collect_helper_calls(
    text: str,
    name: str,
    *,
    limit: int,
    line_offsets: List[int],
) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    search_index = 0
    text_length = len(text)
    name_length = len(name)

    while len(calls) < limit:
        position = text.find(name, search_index)
        if position == -1:
            break
        if position > 0 and (text[position - 1].isalnum() or text[position - 1] == "_"):
            search_index = position + name_length
            continue

        cursor = position + name_length
        while cursor < text_length and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= text_length or text[cursor] != "(":
            search_index = cursor
            continue

        depth = 0
        arg_start = cursor + 1
        arg_end = arg_start
        while arg_end < text_length:
            char = text[arg_end]
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    break
                depth -= 1
            elif char in {'"', "'"}:
                quote = char
                arg_end += 1
                while arg_end < text_length:
                    next_char = text[arg_end]
                    if next_char == "\\":
                        arg_end += 2
                        continue
                    if next_char == quote:
                        break
                    arg_end += 1
            arg_end += 1
        else:
            break

        argument_text = text[arg_start:arg_end].strip()
        split_args = _split_argument_list(argument_text)
        normalised: List[Dict[str, Any]] = []
        for arg in split_args:
            normalised_value, parsed = _normalise_argument(arg)
            normalised.append({
                "text": arg,
                "normalized": normalised_value,
                "parsed": parsed,
            })

        line, column = _offset_to_line_col(position, line_offsets)
        calls.append(
            {
                "raw": argument_text,
                "arguments": normalised,
                "argument_count": len(split_args),
                "line": line,
                "column": column,
                "offset": position,
            }
        )
        search_index = arg_end + 1

    return calls


def _coerce_docstring_mapping(
    docstrings: Optional[Mapping[str, Any] | Sequence[Mapping[str, Any]]]
) -> Dict[str, str]:
    if docstrings is None:
        return {}

    mapping: Dict[str, str] = {}

    if isinstance(docstrings, Mapping):
        for key, value in docstrings.items():
            if isinstance(value, str):
                mapping[str(key)] = value
            elif isinstance(value, Mapping):
                summary = value.get("summary")
                if isinstance(summary, str):
                    mapping[str(key)] = summary
        return mapping

    for entry in docstrings:
        if not isinstance(entry, Mapping):
            continue
        name = entry.get("name") or entry.get("helper") or entry.get("function")
        summary = entry.get("summary") or entry.get("docstring")
        if isinstance(name, str) and isinstance(summary, str):
            mapping[name] = summary
    return mapping


def generate_helper_unit_tests(
    path: str | Path = "Obfuscated2.lua",
    *,
    docstrings: Optional[Mapping[str, Any] | Sequence[Mapping[str, Any]]] = None,
    per_helper: int = 3,
    max_helpers: Optional[int] = None,
    max_function_length: int = 800,
    sandbox_runner: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Produce helper call samples for auto-generated unit tests."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    line_offsets = _compute_line_offsets(text)
    doc_map = _coerce_docstring_mapping(docstrings)

    helpers: List[Dict[str, Any]] = []

    sandbox_fn = sandbox_runner or run_fragment_safely

    for name, start, end in _iter_small_helpers(text, max_length=max_function_length):
        cases = _collect_helper_calls(
            text,
            name,
            limit=max(0, per_helper),
            line_offsets=line_offsets,
        )
        if not cases:
            continue

        if cases and len(cases) < max(0, per_helper):
            target = max(0, per_helper)
            seed_cases = list(cases)
            idx = 0
            while len(cases) < target:
                template = seed_cases[idx % len(seed_cases)]
                duplicate = copy.deepcopy(template)
                duplicate["synthetic"] = True
                duplicate["synthetic_source"] = "duplicate"
                cases.append(duplicate)
                idx += 1

        helper_source = text[start:end]
        assertions = _populate_helper_assertions(
            name,
            helper_source,
            cases,
            sandbox_fn,
        )

        helper_entry: Dict[str, Any] = {
            "name": name,
            "cases": cases,
            "definition_start": start,
            "definition_end": end,
            "definition_preview": _preview_snippet(text, start, end),
        }
        if doc_map:
            helper_entry["docstring"] = doc_map.get(name)
        if assertions:
            helper_entry["assertions"] = assertions

        helpers.append(helper_entry)
        if max_helpers is not None and len(helpers) >= max_helpers:
            break

    return {
        "source_path": str(file_path),
        "helpers": helpers,
        "helper_count": len(helpers),
        "per_helper": max(0, per_helper),
    }


def _populate_helper_assertions(
    helper_name: str,
    helper_source: str,
    cases: List[Dict[str, Any]],
    sandbox_fn: Callable[[str], Dict[str, Any]],
) -> List[str]:
    assertions: List[str] = []

    for index, case in enumerate(cases):
        raw_arguments = case.get("raw", "")
        fragment = _build_helper_execution_fragment(helper_source, helper_name, raw_arguments)

        try:
            sandbox_result = sandbox_fn(fragment)
        except Exception as exc:  # pragma: no cover - defensive path
            case["assertion_error"] = str(exc)
            continue

        if not sandbox_result.get("success"):
            case["assertion_error"] = str(sandbox_result.get("error"))
            continue

        values = [_normalise_lua_value(value) for value in sandbox_result.get("values", [])]
        case["expected_values"] = values

        expected_literals: List[str] = []
        for value in values:
            try:
                literal = _python_to_lua_literal(value)
            except Exception:
                literal = repr(value)
            expected_literals.append(literal)

        case["expected_literals"] = expected_literals

        if not expected_literals:
            case["assertion_error"] = "no return values produced"
            continue

        assertion = _build_helper_assertion(helper_name, raw_arguments, expected_literals, index)
        case["assertion"] = assertion
        assertions.append(assertion)

    return assertions


def _build_helper_execution_fragment(helper_source: str, helper_name: str, arguments: str) -> str:
    call = f"{helper_name}({arguments})" if arguments else f"{helper_name}()"
    return textwrap.dedent(
        f"""
        {helper_source}

        return {call}
        """
    ).strip()


def _build_helper_assertion(
    helper_name: str,
    arguments: str,
    expected_literals: Sequence[str],
    index: int,
) -> str:
    call = f"{helper_name}({arguments})" if arguments else f"{helper_name}()"
    expected = "{" + ", ".join(expected_literals) + "}"
    case_label = f"{helper_name}_case_{index + 1}"
    return textwrap.dedent(
        f"""
        do
            local expected = {expected}
            local results = {{ {call} }}
            assert(#results == #expected, "{case_label}: unexpected return count")
            for i = 1, #expected do
                assert(results[i] == expected[i], "{case_label}: mismatch at index " .. i)
            end
        end
        """
    ).strip()


def _normalise_lua_value(value: Any) -> Any:
    if isinstance(value, (str, bytes, bytearray, int, float, bool)) or value is None:
        return value

    if isinstance(value, Mapping):
        return {key: _normalise_lua_value(val) for key, val in value.items()}

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalise_lua_value(item) for item in value]

    # Fallback for lupa LuaTable objects
    items = getattr(value, "items", None)
    if callable(items):
        try:
            return {key: _normalise_lua_value(val) for key, val in items()}
        except Exception:
            pass

    length = getattr(value, "__len__", None)
    getitem = getattr(value, "__getitem__", None)
    if callable(length) and callable(getitem):
        try:
            size = len(value)  # type: ignore[arg-type]
        except Exception:
            size = None
        if isinstance(size, int) and size >= 0:
            try:
                return [_normalise_lua_value(getitem(index)) for index in range(1, size + 1)]
            except Exception:
                pass

    return value


def _coerce_lua_bytes(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1", errors="ignore")
    if value is None:
        return b""
    return bytes(str(value), "utf-8", "ignore")


def _words_to_bytes(words: Sequence[int]) -> bytes:
    if not words:
        return b""
    out = bytearray(len(words) * 4)
    for index, word in enumerate(words):
        struct.pack_into("<I", out, index * 4, word & 0xFFFFFFFF)
    return bytes(out)


def _wrap_lua_long_string(text: str) -> str:
    for equals in range(0, 6):
        marker = "=" * equals
        closing = "]" + marker + "]"
        if closing not in text:
            return "[" + marker + "[" + text + "]" + marker + "]"
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def _python_to_lua_literal(value: object, *, depth: int = 0) -> str:
    if depth > 5:
        raise ValueError("value is too deeply nested for Lua literal conversion")

    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("cannot encode NaN or infinite values into Lua literals")
        return repr(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            text = bytes(value).decode("latin-1")
        except Exception as exc:  # pragma: no cover - extremely defensive
            raise ValueError(f"failed to decode bytes literal: {exc}") from exc
        return _wrap_lua_long_string(text)
    if isinstance(value, str):
        return _wrap_lua_long_string(value)
    if isinstance(value, Mapping):
        items: List[str] = []
        for key, sub_value in value.items():
            if not isinstance(key, str):
                raise TypeError("Lua literal conversion only supports string dictionary keys")
            key_literal = _wrap_lua_long_string(key)
            value_literal = _python_to_lua_literal(sub_value, depth=depth + 1)
            items.append(f"[{key_literal}] = {value_literal}")
        return "{" + (" " + ", ".join(items) + " " if items else "") + "}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        entries = [
            _python_to_lua_literal(item, depth=depth + 1)
            for item in value
        ]
        return "{" + (" " + ", ".join(entries) + " " if entries else "") + "}"

    raise TypeError(f"unsupported value type for Lua literal conversion: {type(value)!r}")


def _lua_inputs_literal(inputs: Sequence[object] | None) -> str:
    if not inputs:
        return "{}"
    return "{" + ", ".join(_python_to_lua_literal(value) for value in inputs) + "}"


def _build_lua_parity_snippet(fragment: str, key: str, word_count: int) -> str:
    fragment_literal = _wrap_lua_long_string(fragment)
    key_literal = _wrap_lua_long_string(key)
    limit = max(0, word_count)
    return textwrap.dedent(
        f"""
        local raw_fragment = {fragment_literal}
        local script_key = {key_literal}
        local limit = {limit}

        local function _normalise(text)
            text = text:gsub("%s+", "")
            text = text:gsub("z", "!!!!!")
            text = text:gsub("%.%.%.", "...")
            return text
        end

        local function decode_lph85(text)
            local prefix = text:sub(1, 4)
            if prefix:lower() == "lph!" or prefix:lower() == "lph~" then
                text = text:sub(5)
            end
            local cleaned = _normalise(text)
            local groups = math.ceil(#cleaned / 5)
            cleaned = cleaned .. string.rep("!", groups * 5 - #cleaned)
            local out = {{}}
            for index = 1, #cleaned, 5 do
                local chunk = cleaned:sub(index, index + 4)
                local acc = 0
                for i = 1, 5 do
                    acc = acc * 85 + (string.byte(chunk, i) - 33)
                end
                acc = acc % 4294967296
                local b4 = acc % 256
                acc = math.floor(acc / 256)
                local b3 = acc % 256
                acc = math.floor(acc / 256)
                local b2 = acc % 256
                acc = math.floor(acc / 256)
                local b1 = acc % 256
                out[#out + 1] = string.char(b1, b2, b3, b4)
            end
            return table.concat(out)
        end

        local function bxor8(a, b)
            if bit32 and bit32.bxor then
                return bit32.bxor(a, b)
            end
            local res = 0
            local bit = 1
            for _ = 1, 8 do
                local abit = a % 2
                local bbit = b % 2
                if abit ~= bbit then
                    res = res + bit
                end
                a = math.floor(a / 2)
                b = math.floor(b / 2)
                bit = bit * 2
            end
            return res
        end

        local function ror8(value, rotation)
            rotation = rotation % 8
            if rotation == 0 then
                return value % 256
            end
            value = value % 256
            local shifted = math.floor(value / (2 ^ rotation))
            local remainder = (value % (2 ^ rotation)) * (2 ^ (8 - rotation))
            return (shifted + remainder) % 256
        end

        local function apply_prga_bytes(data, key)
            if #key == 0 then
                error("key must be non-empty")
            end
            local out = {{}}
            for index = 1, #data do
                local value = string.byte(data, index)
                local key_byte = string.byte(key, ((index - 1) % #key) + 1)
                local mixed = bxor8(value, key_byte)
                out[index] = string.char(ror8(mixed, key_byte % 8))
            end
            return table.concat(out)
        end

        local decoded = decode_lph85(raw_fragment)
        local prga = apply_prga_bytes(decoded, script_key)
        local words = {{}}
        for idx = 0, limit - 1 do
            local base = idx * 4
            local b1 = string.byte(prga, base + 1) or 0
            local b2 = string.byte(prga, base + 2) or 0
            local b3 = string.byte(prga, base + 3) or 0
            local b4 = string.byte(prga, base + 4) or 0
            local value = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
            words[idx + 1] = value % 4294967296
        end

        return words, prga
        """
    ).strip()


def _normalise_sandbox_value(value: object, *, depth: int = 0) -> object:
    if depth > 6:
        return value
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, Mapping):
        result: Dict[str, object] = {}
        for key, sub_value in value.items():
            result[str(key)] = _normalise_sandbox_value(sub_value, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _normalise_sandbox_value(entry, depth=depth + 1)
            for entry in value
        ]
    for attr in ("items", "values", "keys"):
        if hasattr(value, attr):
            try:
                items = list(getattr(value, "items")())  # type: ignore[attr-defined]
                return {
                    str(key): _normalise_sandbox_value(val, depth=depth + 1)
                    for key, val in items
                }
            except Exception:
                break
    try:
        iterator = iter(value)  # type: ignore[arg-type]
    except TypeError:
        return value
    try:
        return [
            _normalise_sandbox_value(entry, depth=depth + 1)
            for entry in iterator
        ]
    except Exception:
        return value


def _normalise_sandbox_values(values: Sequence[object] | None) -> List[object]:
    if not values:
        return []
    return [
        _normalise_sandbox_value(value)
        for value in values
    ]


def _format_value_short(value: object, *, max_length: int = 120) -> str:
    text = repr(value)
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def _decode_coverage_lines(value: object) -> Set[int]:
    lines: Set[int] = set()
    if value is None:
        return lines
    if isinstance(value, Mapping):
        for key, flag in value.items():
            if not flag:
                continue
            try:
                lines.add(int(key))
            except (TypeError, ValueError):
                continue
        return lines
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for entry in value:
            try:
                lines.add(int(entry))
            except (TypeError, ValueError):
                continue
        return lines
    for attr in ("keys", "__iter__"):
        probe = getattr(value, attr, None)
        if probe is None:
            continue
        try:
            iterator = iter(value)  # type: ignore[arg-type]
        except TypeError:
            continue
        for entry in iterator:
            try:
                lines.add(int(entry))
            except (TypeError, ValueError):
                continue
        return lines
    return lines


def _sanitize_inputs_for_report(inputs: Sequence[object], key: str) -> List[object]:
    sanitized: List[object] = []
    for entry in inputs:
        if isinstance(entry, str) and key:
            sanitized.append(entry.replace(key, "<key>"))
        else:
            sanitized.append(entry)
    return sanitized


def _sanitize_output_value(value: object, key: str) -> object:
    if isinstance(value, str) and key:
        return value.replace(key, "<key>")
    return value


def _initial_fuzz_inputs(rng: random.Random) -> List[List[str]]:
    seeds: List[List[str]] = [
        [],
        [""],
        [" "],
        ["\n"],
        ["0"],
        ["1"],
        ["test"],
        ["payload"],
        ["!"]
    ]
    alphabet = "abcxyz"
    for _ in range(3):
        seeds.append([rng.choice(alphabet)])
    return seeds


def _mutate_inputs(inputs: Sequence[str], rng: random.Random) -> List[List[str]]:
    base = list(inputs)
    seed = base[0] if base else ""
    mutations: Set[str] = set()
    if seed:
        mutations.add(seed[:-1])
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789!?_%"
    for _ in range(4):
        char = rng.choice(alphabet)
        candidate = (seed + char)[-32:]
        if candidate:
            mutations.add(candidate)
    if not seed:
        mutations.add(rng.choice(["A", "B", "C"]))
    return [[value] for value in mutations if value != seed]


def _build_vm_fuzz_snippet(
    module_literal: str,
    entry_name: str,
    key_literal: str,
    inputs: Sequence[str],
    inputs_json: str,
) -> str:
    inputs_literal = _lua_inputs_literal(inputs)
    return textwrap.dedent(
        f"""
        -- fuzz_target: {entry_name}
        -- fuzz_inputs_json: {inputs_json}
        local module_source = {module_literal}
        local script_key = {key_literal}
        local fuzz_inputs = {inputs_literal}
        local coverage = {{}}
        local function _hook(event, line)
            if event == "line" then
                coverage[line] = true
            end
        end
        local chunk = assert(load(module_source, "fuzz_module", "t", _G))
        local exports = chunk()
        local target = nil
        if type(exports) == "table" then
            target = exports["{entry_name}"]
        end
        if script_key ~= nil then
            _G.script_key = script_key
        end
        if type(target) ~= "function" then
            return coverage, false, "target-not-function"
        end
        debug.sethook(_hook, "l")
        local call_results = {{pcall(function()
            if type(fuzz_inputs) ~= "table" or #fuzz_inputs == 0 then
                return target()
            end
            if type(table) == "table" and table.unpack then
                return target(table.unpack(fuzz_inputs))
            elseif unpack then
                return target(unpack(fuzz_inputs))
            end
            return target(fuzz_inputs[1])
        end)}}
        debug.sethook()
        local ok = table.remove(call_results, 1)
        return coverage, ok, table.unpack(call_results)
        """
    ).strip()


def fuzz_vm_behavior(
    reconstructed_path: str | Path,
    *,
    key: str,
    sandbox_runner: Optional[Callable[..., Mapping[str, object]]] = None,
    iterations_per_function: int = 64,
    seed: Optional[int] = None,
    target_functions: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Coverage-guided fuzzing harness for reconstructed Lua modules."""

    module_path = Path(reconstructed_path)
    source = module_path.read_text(encoding="utf-8", errors="ignore")

    introspection = introspect_top_level_table(module_path)
    entries = introspection.get("entries", {}) if isinstance(introspection, Mapping) else {}

    function_names = [
        name
        for name, meta in entries.items()
        if isinstance(meta, Mapping) and meta.get("type") == "function"
    ]

    if target_functions:
        allowed = set(target_functions)
        function_names = [name for name in function_names if name in allowed]

    sandbox_fn = sandbox_runner or run_fragment_safely
    rng = random.Random(seed if seed is not None else 0xF00DC0DE)
    module_literal = _wrap_lua_long_string(source)
    key_literal = _wrap_lua_long_string(key) if key else "nil"

    results: List[Dict[str, object]] = []
    total_iterations = 0

    for name in function_names:
        queue: deque[List[str]] = deque(_initial_fuzz_inputs(rng))
        seen_inputs: Set[Tuple[str, ...]] = set()
        coverage: Set[int] = set()
        attempts = 0
        interesting: List[Dict[str, object]] = []
        string_outputs: List[str] = []

        while queue and attempts < max(1, iterations_per_function):
            current = queue.popleft()
            key_tuple = tuple(current)
            if key_tuple in seen_inputs:
                continue
            seen_inputs.add(key_tuple)

            attempts += 1
            total_iterations += 1

            inputs_json = json.dumps(current)
            snippet = _build_vm_fuzz_snippet(
                module_literal=module_literal,
                entry_name=name,
                key_literal=key_literal,
                inputs=current,
                inputs_json=inputs_json,
            )

            try:
                response = sandbox_fn(snippet, allow_debug=True)
            except Exception as exc:  # pragma: no cover - sandbox failure path
                interesting.append(
                    {
                        "inputs": _sanitize_inputs_for_report(current, key),
                        "success": False,
                        "error": str(exc),
                        "coverage_gain": [],
                        "outputs": [],
                    }
                )
                continue

            values = response.get("values") if isinstance(response, Mapping) else None
            coverage_lines: Set[int] = set()
            success_flag = False
            outputs: List[object] = []
            error_text: Optional[str] = None

            if isinstance(values, list) and values:
                coverage_lines = _decode_coverage_lines(values[0])
                if len(values) >= 2:
                    success_flag = bool(values[1])
                    normalised = [
                        _normalise_sandbox_value(value)
                        for value in values[2:]
                    ]
                    outputs = [
                        _sanitize_output_value(value, key)
                        for value in normalised
                    ]
                    if not success_flag and outputs:
                        error_text = _format_value_short(outputs[0])
                        outputs = outputs[1:]
            else:
                alt_cov = response.get("coverage") if isinstance(response, Mapping) else None
                if alt_cov is not None:
                    coverage_lines = _decode_coverage_lines(alt_cov)

            new_lines = sorted(line for line in coverage_lines if line not in coverage)
            if new_lines:
                coverage.update(coverage_lines)
                queue.extend(_mutate_inputs(current, rng))
            elif not success_flag:
                queue.extend(_mutate_inputs(current, rng))

            if success_flag:
                string_values = [value for value in outputs if isinstance(value, str)]
                for value in string_values:
                    if value not in string_outputs:
                        string_outputs.append(value)

            if not success_flag and error_text is None and isinstance(response, Mapping):
                error_value = response.get("error")
                if error_value:
                    error_text = _format_value_short(
                        _sanitize_output_value(error_value, key)
                    )

            if success_flag or error_text or new_lines:
                record = {
                    "inputs": _sanitize_inputs_for_report(current, key),
                    "success": success_flag,
                    "outputs": [
                        _format_value_short(value) for value in outputs
                    ],
                    "coverage_gain": new_lines,
                }
                if error_text:
                    record["error"] = error_text
                interesting.append(record)

        results.append(
            {
                "name": name,
                "attempts": attempts,
                "coverage": len(coverage),
                "interesting_cases": interesting[:12],
                "string_outputs": string_outputs[:5],
            }
        )

    return {
        "path": str(module_path),
        "total_iterations": total_iterations,
        "functions": results,
    }


_ROUND_TRIP_HELPERS = textwrap.dedent(
    """
    local function _call_with_inputs(fn, args)
        if type(fn) ~= "function" then
            return fn
        end
        if type(table) == "table" and table.unpack then
            return fn(table.unpack(args))
        elseif unpack then
            return fn(unpack(args))
        end
        return fn(args)
    end

    local function _return_results(results)
        if type(table) == "table" and table.unpack then
            return table.unpack(results)
        elseif unpack then
            return unpack(results)
        end
        return results[1], results[2], results[3], results[4], results[5], results[6], results[7], results[8]
    end
    """
)


def _build_original_round_trip_snippet(
    source: str,
    key: str,
    entry_name: str | None,
    inputs: Sequence[object],
) -> str:
    source_literal = _wrap_lua_long_string(source)
    key_literal = _wrap_lua_long_string(key)
    entry_literal = _wrap_lua_long_string(entry_name) if entry_name else "nil"
    inputs_literal = _lua_inputs_literal(inputs)
    return textwrap.dedent(
        f"""
        -- round_trip: original
        local script_source = {source_literal}
        local script_key = {key_literal}
        local entry_name = {entry_literal}
        local inputs = {inputs_literal}
        {_ROUND_TRIP_HELPERS}
        _G.script_key = script_key
        local chunk = assert(load(script_source, "original", "t", _G))
        local exports = {{chunk()}}
        if entry_name ~= nil then
            local primary = exports[1]
            if type(primary) == "table" then
                local target = primary[entry_name]
                if target ~= nil then
                    return _call_with_inputs(target, inputs)
                end
            end
        end
        return _return_results(exports)
        """
    ).strip()


def _build_module_round_trip_snippet(
    source: str,
    key: str,
    entry_name: str | None,
    inputs: Sequence[object],
) -> str:
    source_literal = _wrap_lua_long_string(source)
    key_literal = _wrap_lua_long_string(key)
    entry_literal = _wrap_lua_long_string(entry_name) if entry_name else "nil"
    inputs_literal = _lua_inputs_literal(inputs)
    return textwrap.dedent(
        f"""
        -- round_trip: module
        local module_source = {source_literal}
        local script_key = {key_literal}
        local entry_name = {entry_literal}
        local inputs = {inputs_literal}
        {_ROUND_TRIP_HELPERS}
        _G.script_key = script_key
        local chunk = assert(load(module_source, "module", "t", _G))
        local exports = chunk()
        if entry_name ~= nil and type(exports) == "table" then
            local target = exports[entry_name]
            if target ~= nil then
                return _call_with_inputs(target, inputs)
            end
        end
        return exports
        """
    ).strip()


def round_trip_test(
    *,
    path: str | Path = "Obfuscated2.lua",
    module_path: str | Path = "deobfuscated_module.lua",
    key: str,
    inputs: Sequence[object] | None = None,
    entry_name: str | None = None,
    sandbox_runner: Callable[..., Dict[str, object]] | None = None,
    log_callback: Callable[[str], None] | None = None,
) -> Dict[str, object]:
    """Compare the behaviour of the original runtime and the deobfuscated module."""

    if not key:
        raise ValueError("a non-empty key is required for round-trip testing")

    file_path = Path(path)
    module_file = Path(module_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"original runtime not found: {file_path}")
    if not module_file.is_file():
        raise FileNotFoundError(f"deobfuscated module not found: {module_file}")

    original_source = file_path.read_text(encoding="utf-8", errors="ignore")
    module_source = module_file.read_text(encoding="utf-8", errors="ignore")

    call_inputs: List[object] = list(inputs or [])
    sandbox_fn = sandbox_runner or run_fragment_safely

    original_snippet = _build_original_round_trip_snippet(
        original_source, key, entry_name, call_inputs
    )
    module_snippet = _build_module_round_trip_snippet(
        module_source, key, entry_name, call_inputs
    )

    original_result = sandbox_fn(original_snippet, expected=None)
    if not original_result.get("success"):
        raise RuntimeError(
            f"original runtime sandbox execution failed: {original_result.get('error')}"
        )

    module_result = sandbox_fn(module_snippet, expected=None)
    if not module_result.get("success"):
        raise RuntimeError(
            f"deobfuscated module sandbox execution failed: {module_result.get('error')}"
        )

    original_values = _normalise_sandbox_values(original_result.get("values"))
    module_values = _normalise_sandbox_values(module_result.get("values"))

    differences: List[str] = []
    if original_values != module_values:
        max_len = max(len(original_values), len(module_values))
        for index in range(max_len):
            left = original_values[index] if index < len(original_values) else "<missing>"
            right = module_values[index] if index < len(module_values) else "<missing>"
            if left != right:
                differences.append(
                    f"value[{index}]: original={_format_value_short(left)} module={_format_value_short(right)}"
                )
                break
        if log_callback:
            for message in differences:
                log_callback(message)
        summary = differences[0] if differences else "values differ"
        raise AssertionError(
            "Round-trip mismatch between original runtime and module outputs: " + summary
        )

    if log_callback:
        for message in differences:
            log_callback(message)

    return {
        "match": True,
        "path": str(file_path),
        "module_path": str(module_file),
        "entry_name": entry_name,
        "inputs": call_inputs,
        "values": module_values,
        "environment_original": original_result.get("environment", {}),
        "environment_module": module_result.get("environment", {}),
    }


def _coerce_vm_function(vm_ir: Any) -> VMFunction:
    """Normalise supported IR inputs into a :class:`VMFunction` instance."""

    if isinstance(vm_ir, VMFunction):
        return vm_ir

    if isinstance(vm_ir, Mapping):
        instructions = vm_ir.get("instructions")
        if isinstance(instructions, Sequence) and all(
            isinstance(entry, VMInstruction) for entry in instructions
        ):
            return VMFunction(
                constants=list(vm_ir.get("constants") or []),
                instructions=list(instructions),
                prototypes=list(vm_ir.get("prototypes") or []),
                num_params=int(vm_ir.get("num_params") or 0),
                is_vararg=bool(vm_ir.get("is_vararg", False)),
                register_count=int(vm_ir.get("register_count") or 0),
                upvalue_count=int(vm_ir.get("upvalue_count") or 0),
                metadata=dict(vm_ir.get("metadata") or {}),
            )

    if isinstance(vm_ir, Sequence) and all(isinstance(entry, VMInstruction) for entry in vm_ir):
        return VMFunction(constants=[], instructions=list(vm_ir))

    raise TypeError("ir_to_lua expects a VMFunction, mapping, or iterable of VMInstruction objects")


def _is_valid_identifier(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


def _sanitize_identifier(name: str, fallback: str) -> str:
    candidate = re.sub(r"[^0-9A-Za-z_]", "_", name or "")
    if not candidate:
        candidate = fallback
    if candidate[0].isdigit():
        candidate = f"_{candidate}"
    if candidate in LUA_KEYWORDS or candidate in LUA_GLOBALS:
        candidate = f"{candidate}_value"
    return candidate or fallback


def _format_lua_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "nil"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("latin-1", errors="ignore")
        return _wrap_lua_long_string(text)
    if isinstance(value, str):
        return _wrap_lua_long_string(value)
    if isinstance(value, (list, dict, set, tuple)):
        try:
            json_text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            json_text = repr(value)
        return _wrap_lua_long_string(json_text)
    return repr(value)


def _extract_constant_from_aux(instr: VMInstruction, default: Any = None) -> Any:
    aux = getattr(instr, "aux", {}) or {}
    for key in (
        "const_b",
        "const_a",
        "const_value",
        "literal",
        "literal_a",
        "literal_b",
        "immediate_a",
        "immediate_b",
        "value",
    ):
        if key in aux:
            return aux[key]
    return default


def _format_operand(
    instr: VMInstruction,
    operand: str,
    register_names: Mapping[int, str],
) -> Optional[str]:
    aux = getattr(instr, "aux", {}) or {}
    lower_operand = operand.lower()
    mode = str(aux.get(f"{lower_operand}_mode", "")).lower()
    if mode in {"const", "constant", "immediate", "literal"}:
        for prefix in ("const", "literal", "immediate"):
            key = f"{prefix}_{lower_operand}"
            if key in aux:
                return _format_lua_value(aux[key])
    value = getattr(instr, operand, None)
    if isinstance(value, int):
        return register_names.get(value, f"r{value}")
    if isinstance(value, (bytes, bytearray, str, bool, float, int)) or value is None:
        return _format_lua_value(value)
    if value is not None:
        return repr(value)
    return None


def _docstring_for_instruction(
    instr: VMInstruction,
    register_names: Mapping[int, str],
) -> Optional[Dict[str, Any]]:
    opcode = str(instr.opcode).upper()
    complex_ops = {"CALL", "TFORLOOP", "FORLOOP", "FORPREP", "CLOSURE", "TFORCALL"}
    if opcode not in complex_ops:
        return None
    args: List[str] = []
    for operand in ("a", "b", "c"):
        formatted = _format_operand(instr, operand, register_names)
        if formatted is not None:
            args.append(f"{operand}={formatted}")
    pc = getattr(instr, "pc", None)
    summary = f"Complex sequence: {opcode}"
    if args:
        summary += f" ({', '.join(args)})"
    if isinstance(pc, int):
        summary += f" @pc {pc}"
    lines = ["--[[", summary]
    if args:
        lines.append(f"Operands: {', '.join(args)}")
    lines.append("--]]")
    return {"lines": lines, "opcode": opcode, "pc": pc, "summary": summary}


def _translate_instruction(
    instr: VMInstruction,
    register_names: Mapping[int, str],
) -> Tuple[str, Optional[Dict[str, Any]]]:
    opcode = str(instr.opcode).upper()
    dest_index = getattr(instr, "a", None)
    dest_name = register_names.get(dest_index) if isinstance(dest_index, int) else None
    aux = getattr(instr, "aux", {}) or {}

    doc = _docstring_for_instruction(instr, register_names)

    def _binary_expr(symbol: str) -> Optional[str]:
        if not dest_name:
            return None
        left = _format_operand(instr, "b", register_names)
        right = _format_operand(instr, "c", register_names)
        if left is None or right is None:
            return None
        return f"{dest_name} = {left} {symbol} {right}"

    if opcode == "LOADK" and dest_name:
        value = _extract_constant_from_aux(instr, getattr(instr, "b", None))
        return f"{dest_name} = {_format_lua_value(value)}", doc

    if opcode == "LOADBOOL" and dest_name:
        raw = _extract_constant_from_aux(instr, getattr(instr, "b", None))
        value = bool(raw)
        return f"{dest_name} = {'true' if value else 'false'}", doc

    if opcode == "LOADNIL" and dest_name:
        return f"{dest_name} = nil", doc

    if opcode == "MOVE" and dest_name:
        source = _format_operand(instr, "b", register_names) or "nil"
        return f"{dest_name} = {source}", doc

    arithmetic = {
        "ADD": "+",
        "SUB": "-",
        "MUL": "*",
        "DIV": "/",
        "MOD": "%",
        "POW": "^",
        "IDIV": "//",
        "BAND": "&",
        "BOR": "|",
        "BXOR": "~",
        "SHL": "<<",
        "SHR": ">>",
    }
    if opcode in arithmetic:
        expr = _binary_expr(arithmetic[opcode])
        if expr:
            return f"{expr}  -- {opcode}", doc

    if opcode == "CONCAT" and dest_name:
        expr = _binary_expr("..")
        if expr:
            return f"{expr}  -- CONCAT", doc

    if opcode in {"NOT", "UNM", "LEN"} and dest_name:
        operand = _format_operand(instr, "b", register_names)
        if operand is not None:
            prefix = {"NOT": "not ", "UNM": "-", "LEN": "#"}[opcode]
            return f"{dest_name} = {prefix}{operand}  -- {opcode}", doc

    if opcode == "RETURN":
        base = aux.get("base") if isinstance(aux, Mapping) else None
        if base is None:
            base = getattr(instr, "a", None)
        count_field = aux.get("count") if isinstance(aux, Mapping) else None
        if count_field is None:
            count_field = getattr(instr, "b", None)
        results: List[str] = []
        if isinstance(base, int) and isinstance(count_field, int) and count_field > 1:
            for offset in range(count_field - 1):
                reg = register_names.get(base + offset)
                if reg is not None:
                    results.append(reg)
        if results:
            return f"return {', '.join(results)}", doc
        return "return", doc

    if opcode == "CALL":
        func_index = getattr(instr, "a", None)
        func_name = register_names.get(func_index, f"r{func_index}") if isinstance(func_index, int) else "func"
        arg_count = getattr(instr, "b", None)
        result_count = getattr(instr, "c", None)
        args: List[str] = []
        if isinstance(func_index, int) and isinstance(arg_count, int) and arg_count > 1:
            for offset in range(arg_count - 1):
                reg = register_names.get(func_index + 1 + offset)
                if reg is not None:
                    args.append(reg)
        call_expr = f"{func_name}({', '.join(args)})" if args else f"{func_name}()"
        if isinstance(result_count, int) and result_count > 1:
            dests = [register_names.get(func_index + offset, f"r{func_index + offset}") for offset in range(result_count - 1)]
            dests = [name for name in dests if name is not None]
            if dests:
                return f"{', '.join(dests)} = {call_expr}", doc
        if isinstance(result_count, int) and result_count == 1:
            return call_expr, doc
        return f"{call_expr}  -- CALL", doc

    args: List[str] = []
    for operand in ("a", "b", "c"):
        formatted = _format_operand(instr, operand, register_names)
        if formatted is not None:
            args.append(f"{operand}={formatted}")
    rendered_args = " " + " ".join(args) if args else ""
    return f"-- {opcode}{rendered_args}", doc


def _derive_register_names(
    program: VMFunction, rename_map: Mapping[str, str]
) -> Dict[int, str]:
    instructions = list(getattr(program, "instructions", []) or [])
    declared = getattr(program, "register_count", 0) or 0
    highest_index = declared - 1
    for instr in instructions:
        for operand in ("a", "b", "c"):
            value = getattr(instr, operand, None)
            if isinstance(value, int):
                highest_index = max(highest_index, value)
    total = max(highest_index + 1, declared)
    if total <= 0:
        total = len(instructions) or 1

    num_params = getattr(program, "num_params", 0) or 0
    metadata = getattr(program, "metadata", {}) or {}
    param_aliases = []
    params_meta = metadata.get("parameters")
    if isinstance(params_meta, Sequence):
        for entry in params_meta:
            if isinstance(entry, str):
                param_aliases.append(entry)

    register_names: Dict[int, str] = {}
    used: Set[str] = set()

    def _pick_name(index: int) -> str:
        candidates = [
            rename_map.get(f"r{index}"),
            rename_map.get(f"R{index}"),
            rename_map.get(f"reg{index}"),
            rename_map.get(f"var_{index}"),
        ]
        if index < num_params:
            if index < len(param_aliases):
                candidates.insert(0, param_aliases[index])
            candidates.extend([
                rename_map.get(f"arg{index}"),
                rename_map.get(f"param{index}"),
            ])
            default_name = f"arg{index}"
        else:
            default_name = f"t{index}"
        for candidate in candidates:
            if isinstance(candidate, str) and candidate:
                sanitized = _sanitize_identifier(candidate, default_name)
                if sanitized not in used:
                    return sanitized
        return _sanitize_identifier(default_name, default_name)

    for idx in range(total):
        name = _pick_name(idx)
        original = name
        counter = 1
        while name in used:
            name = f"{original}_{counter}"
            counter += 1
        register_names[idx] = name
        used.add(name)

    return register_names


def _load_mapping_file(mapping_path: str | Path) -> Dict[str, str]:
    data = json.loads(Path(mapping_path).read_text(encoding="utf-8"))
    rename_map: Dict[str, str] = {}

    def _add_entry(source: object, target: object) -> None:
        if not isinstance(source, str) or not isinstance(target, str):
            return
        if not source or not target:
            return
        rename_map[source] = target

    if isinstance(data, dict):
        simple = all(isinstance(value, str) for value in data.values())
        if simple:
            for name, target in data.items():
                _add_entry(name, target)
        else:
            for key in ("renames", "mapping", "items", "rows"):
                entries = data.get(key)
                if isinstance(entries, dict):
                    for name, target in entries.items():
                        _add_entry(name, target)
                elif isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, Mapping):
                            continue
                        source = entry.get("name") or entry.get("source") or entry.get("identifier")
                        target = entry.get("recommended_name") or entry.get("target") or entry.get("rename")
                        _add_entry(source, target)
    elif isinstance(data, list):
        for entry in data:
            if not isinstance(entry, Mapping):
                continue
            source = entry.get("name") or entry.get("source") or entry.get("identifier")
            target = entry.get("recommended_name") or entry.get("target") or entry.get("rename")
            _add_entry(source, target)

    if not rename_map:
        raise ValueError("mapping file did not contain any rename entries")

    # Canonicalise the mapping order so downstream pretty-printing runs always
    # see the same rename ranking regardless of input JSON ordering or Python's
    # hash randomisation.
    return {
        source: target
        for source, target in _sorted_rename_items(rename_map)
    }


def _sorted_rename_items(rename_map: Mapping[str, str]) -> List[Tuple[str, str]]:
    """Return ``rename_map`` entries in a deterministic order."""

    def _sort_key(item: Tuple[str, str]) -> Tuple[str, str, str, str]:
        source, target = item
        return (
            target.lower(),
            target,
            source.lower(),
            source,
        )

    return sorted(rename_map.items(), key=_sort_key)


def _apply_renames_preserving_comments(text: str, rename_map: Mapping[str, str]) -> str:
    """Rewrite identifier occurrences while leaving comments untouched."""

    if not rename_map:
        return text

    try:
        from luaparser import ast
        from luaparser import astnodes
    except ImportError as exc:  # pragma: no cover - import guarded by tests
        raise RuntimeError(
            "pretty_print_with_mapping requires luaparser to be installed"
        ) from exc

    line_offsets = _compute_line_offsets(text)
    replacements: List[Tuple[int, int, str]] = []
    seen_spans: Set[Tuple[int, int]] = set()

    class _RenameCollector(ast.ASTRecursiveVisitor):
        def __init__(self) -> None:
            super().__init__()
            self._stack: List[object] = []
            self.found: Set[str] = set()

        def visit(self, node):  # type: ignore[override]
            if isinstance(node, list):
                for child in node:
                    self.visit(child)
                return node
            if node is None:
                return node
            self._stack.append(node)
            result = super().visit(node)
            self._stack.pop()
            return result

        # pylint: disable=unused-argument
        def enter_Name(self, node):  # type: ignore[override]
            identifier = getattr(node, "id", None)
            if not identifier or identifier not in rename_map:
                return

            if self._is_dot_property(node):
                return

            lineno = getattr(node, "lineno", None)
            col = getattr(node, "col_offset", None)
            if not isinstance(lineno, int) or not isinstance(col, int):
                return
            if lineno <= 0 or col < 0 or lineno - 1 >= len(line_offsets):
                return

            start = line_offsets[lineno - 1] + col
            end = start + len(identifier)
            if start < 0 or end > len(text):
                return

            span = (start, end)
            if span in seen_spans:
                return
            seen_spans.add(span)
            replacements.append((start, end, rename_map[identifier]))
            self.found.add(identifier)

        def _is_dot_property(self, node: object) -> bool:
            if len(self._stack) < 2:
                return False
            parent = self._stack[-2]
            if isinstance(parent, astnodes.Index):
                notation = getattr(parent, "notation", None)
                if notation == astnodes.IndexNotation.DOT and parent.idx is node:
                    return True
            return False

    tree = ast.parse(text)
    collector = _RenameCollector()
    collector.visit(tree)

    missing = [
        name
        for name, _ in _sorted_rename_items(rename_map)
        if name not in collector.found
    ]
    if missing:
        protected = _collect_protected_ranges(text)

        def _prev_non_space(index: int) -> Optional[str]:
            j = index - 1
            while j >= 0:
                ch = text[j]
                if not ch.isspace():
                    return ch
                j -= 1
            return None

        for name in missing:
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            for match in pattern.finditer(text):
                start, end = match.span()
                if _position_in_ranges(start, protected) or _position_in_ranges(end - 1, protected):
                    continue
                prev = _prev_non_space(start)
                if prev in {".", ":"}:
                    continue
                span = (start, end)
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                replacements.append((start, end, rename_map[name]))

    updated = text
    for start, end, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        updated = updated[:start] + replacement + updated[end:]

    return updated


def _propagate_comment_headers(text: str, rename_map: Mapping[str, str]) -> str:
    """Update comment headers and inline notes that reference renamed functions."""

    if not text or not rename_map:
        return text

    comment_patterns: Dict[str, re.Pattern[str]] = {}
    for original, target in _sorted_rename_items(rename_map):
        if not original or original == target:
            continue
        comment_patterns[original] = re.compile(rf"\b{re.escape(original)}\b")

    if not comment_patterns:
        return text

    lines = text.splitlines()
    trailing_newline = text.endswith("\n")
    updated_lines = list(lines)

    def _line_mentions_function(line: str, new_name: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return False
        def_pattern = _propagate_comment_headers._definition_patterns.setdefault(
            new_name,
            re.compile(rf"(?:^|;)\s*(?:local\s+)?function\s+{re.escape(new_name)}\b"),
        )
        if def_pattern.search(stripped):
            return True
        assign_pattern = _propagate_comment_headers._assignment_patterns.setdefault(
            new_name,
            re.compile(rf"\b{re.escape(new_name)}\s*=\s*function\b"),
        )
        if assign_pattern.search(stripped):
            return True
        call_pattern = _propagate_comment_headers._call_patterns.setdefault(
            new_name,
            re.compile(rf"\b{re.escape(new_name)}\s*\("),
        )
        return bool(call_pattern.search(stripped))

    def _comment_precedes_target(idx: int, new_name: str) -> bool:
        for offset in range(1, 6):
            pos = idx + offset
            if pos >= len(updated_lines):
                break
            candidate = updated_lines[pos].strip()
            if not candidate:
                continue
            if candidate.startswith("--"):
                continue
            return _line_mentions_function(candidate, new_name)
        return False

    for idx, line in enumerate(lines):
        comment_index = line.find("--")
        if comment_index == -1:
            continue
        prefix = line[:comment_index]
        comment = line[comment_index:]
        replaced = comment
        for original, pattern in sorted(comment_patterns.items()):
            if not pattern.search(replaced):
                continue
            new_name = rename_map.get(original)
            if not new_name:
                continue
            if comment_index == 0:
                if not _comment_precedes_target(idx, new_name):
                    continue
            else:
                if not _line_mentions_function(prefix, new_name):
                    continue
            new_comment = pattern.sub(new_name, replaced)
            if new_comment != replaced:
                replaced = new_comment
        if replaced != comment:
            updated_lines[idx] = prefix + replaced

    rebuilt = "\n".join(updated_lines)
    if trailing_newline:
        rebuilt += "\n"
    return rebuilt


_propagate_comment_headers._definition_patterns = {}  # type: ignore[attr-defined]
_propagate_comment_headers._assignment_patterns = {}  # type: ignore[attr-defined]
_propagate_comment_headers._call_patterns = {}  # type: ignore[attr-defined]


def _build_rename_preview(original: str, renamed: str) -> List[Dict[str, object]]:
    """Return a structured preview of line-level changes caused by renaming."""

    if original == renamed:
        return []

    original_lines = original.splitlines()
    renamed_lines = renamed.splitlines()
    preview: List[Dict[str, object]] = []

    matcher = difflib.SequenceMatcher(None, original_lines, renamed_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        length = max(i2 - i1, j2 - j1, 1)
        for offset in range(length):
            orig_index = i1 + offset
            new_index = j1 + offset
            original_line = original_lines[orig_index] if orig_index < i2 else ""
            updated_line = renamed_lines[new_index] if new_index < j2 else ""
            if not original_line and not updated_line:
                continue
            if orig_index < len(original_lines):
                line_number: Optional[int] = orig_index + 1
            elif new_index < len(renamed_lines):
                line_number = new_index + 1
            else:
                line_number = None
            preview.append(
                {
                    "line": line_number,
                    "original": original_line,
                    "updated": updated_line,
                }
            )

    return preview

def _compute_line_offsets(text: str) -> List[int]:
    offsets = [0]
    for index, char in enumerate(text):
        if char == "\n":
            offsets.append(index + 1)
    if offsets[-1] != len(text):
        offsets.append(len(text))
    return offsets


def _extract_returned_table(text: str) -> Optional[str]:
    located = _extract_returned_table_with_span(text)
    if located is None:
        return None
    _, _, table_src = located
    return table_src


def _extract_returned_table_with_span(text: str) -> Optional[Tuple[int, int, str]]:
    candidates = [re.search(r"return\s*\(\s*\{", text), re.search(r"return\s*\{", text)]
    start = None
    for match in candidates:
        if match:
            start = text.find("{", match.start())
            break
    if start is None:
        return None

    depth = 0
    i = start
    n = len(text)
    in_short: Optional[str] = None
    in_long: Optional[int] = None
    in_comment: Optional[object] = None

    while i < n:
        ch = text[i]
        if in_short:
            if ch == "\\" and in_short in {'"', "'"}:
                i += 2
                continue
            if ch == in_short:
                in_short = None
            i += 1
            continue

        if in_long is not None:
            closing = "]" + "=" * in_long + "]"
            if text.startswith(closing, i):
                i += len(closing)
                in_long = None
                continue
            i += 1
            continue

        if in_comment == "line":
            if ch in "\r\n":
                in_comment = None
            i += 1
            continue
        if isinstance(in_comment, int):
            closing = "]" + "=" * in_comment + "]"
            if text.startswith(closing, i):
                i += len(closing)
                in_comment = None
                continue
            i += 1
            continue

        if ch == "-" and text.startswith("--", i):
            i += 2
            long_eq = _match_long_bracket(text, i)
            if long_eq is not None:
                i += 1 + long_eq + 1
                in_comment = long_eq
            else:
                in_comment = "line"
            continue

        if ch in {'"', "'"}:
            in_short = ch
            i += 1
            continue

        if ch == "[":
            long_eq = _match_long_bracket(text, i)
            if long_eq is not None:
                i += 1 + long_eq + 1
                in_long = long_eq
                continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                return start, end, text[start:end]
        i += 1
    return None


def _extract_top_level_keys(table_src: str) -> List[str]:
    inner = table_src[1:-1]
    keys: List[str] = []

    for match in _IDENT_KEY_RE.finditer(inner):
        keys.append(match.group(1))

    for match in _BRACKET_STRING_KEY_RE.finditer(inner):
        keys.append(match.group(2))

    seen = set()
    deduped: List[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            deduped.append(key)
    return deduped


def introspect_top_level_table(
    path: str | Path, *, output_path: str | Path | None = None
) -> Dict[str, object]:
    """Inspect a reconstructed Lua payload for exported table members."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")

    located = _extract_returned_table_with_span(text)
    entries: Dict[str, Dict[str, object]] = {}

    if located is not None:
        table_start, _, table_src = located
        entries = _parse_return_table(table_src, table_start, text)

    if not entries:
        boundary_meta = Path(str(file_path) + ".boundaries.json")
        if boundary_meta.exists():
            try:
                metadata = json.loads(boundary_meta.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                metadata = {}
            source_path = metadata.get("input")
            if isinstance(source_path, str) and source_path:
                original_path = Path(source_path)
                if original_path.exists():
                    original_text = original_path.read_text(encoding="utf-8", errors="ignore")
                    located = _extract_returned_table_with_span(original_text)
                    if located is not None:
                        table_start, _, table_src = located
                        entries = _parse_return_table(table_src, table_start, original_text)

    if output_path is None:
        output_path = file_path.with_name(file_path.name + ".top_level.json")

    output_path = Path(output_path)
    output_path.write_text(json.dumps(entries, indent=2, sort_keys=True), encoding="utf-8")

    return {"entries": entries, "output_path": str(output_path), "table_span": located[:2] if located else None}


def _parse_return_table(table_src: str, base_offset: int, full_text: str) -> Dict[str, Dict[str, object]]:
    entries: Dict[str, Dict[str, object]] = {}
    candidates: List[Tuple[int, str, int, str]] = []

    for match in _IDENT_KEY_RE.finditer(table_src):
        key = match.group(1)
        candidates.append((match.start(), key, match.end(), "ident"))

    for match in _BRACKET_STRING_KEY_RE.finditer(table_src):
        quote = match.group(1)
        inner = match.group(2)
        key = _decode_short_fragment(f"{quote}{inner}{quote}")
        candidates.append((match.start(), key, match.end(), "bracket"))

    candidates.sort(key=lambda item: item[0])

    for start, key, after_eq, _ in candidates:
        key_start = start
        while key_start < after_eq and table_src[key_start].isspace():
            key_start += 1

        key_offset = base_offset + key_start
        value_start = _skip_ws_and_comments(table_src, after_eq)
        value_type = "function" if _starts_with_keyword(table_src, value_start, "function") else "value"

        line, column = _offset_to_location(full_text, key_offset)
        if key not in entries:
            entries[key] = {
                "location": {"line": line, "column": column, "offset": key_offset},
                "type": value_type,
            }

    return entries


def _split_param_list(raw: str) -> List[str]:
    params: List[str] = []
    for piece in raw.split(","):
        name = piece.strip()
        if not name or name == "...":
            continue
        if _IDENTIFIER_RE.fullmatch(name):
            params.append(name)
    return params


def _gather_identifier_roles(text: str, ranges: List[Tuple[int, int]]) -> DefaultDict[str, Set[str]]:
    roles: DefaultDict[str, Set[str]] = defaultdict(set)

    def record(name: str, role: str) -> None:
        if not name:
            return
        roles[name].add(role)

    for match in _LOCAL_DECL_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        for name in match.group(1).split(","):
            candidate = name.strip()
            if _IDENTIFIER_RE.fullmatch(candidate):
                record(candidate, "local")

    for match in _LOCAL_FUNCTION_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        name = match.group(1)
        record(name, "local")
        record(name, "function")
        record(name, "definition")
        for param in _split_param_list(match.group(2)):
            record(param, "parameter")

    for match in _FUNCTION_DEF_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        prefix = text[max(0, match.start() - 6) : match.start()].strip()
        if prefix == "local":
            continue
        owner = match.group(1)
        member = match.group(2)
        params = match.group(3)
        target = member or owner
        record(target, "function")
        record(target, "definition")
        if member:
            record(owner, "receiver")
        for param in _split_param_list(params):
            record(param, "parameter")

    for match in _ASSIGN_FUNCTION_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        name = match.group(1)
        record(name, "function")
        record(name, "assignment")
        prefix = text[max(0, match.start() - 6) : match.start()].strip()
        if prefix == "local":
            record(name, "local")
        for param in _split_param_list(match.group(2)):
            record(param, "parameter")

    for match in _FOR_LOOP_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        for name in match.groups():
            if name:
                record(name, "loop")

    for match in _NUMERIC_FOR_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        record(match.group(1), "loop")

    return roles


def _classify_identifier_usage(
    name: str,
    count: int,
    roles: Set[str],
    exported_functions: Set[str],
    exported_values: Set[str],
) -> str:
    if name in exported_functions:
        return "core_runtime"
    if name in exported_values and len(name) <= 3:
        return "core_runtime"
    if count >= 20 and len(name) <= 3:
        return "core_runtime"
    if "receiver" in roles and count >= 10:
        return "core_runtime"
    if len(name) <= 2 and count >= 4:
        return "core_runtime"
    return "helper"


def analyze_identifier_frequencies(
    path: str | Path, *, output_path: str | Path | None = None
) -> Dict[str, object]:
    """Generate an identifier frequency report and rename suggestions."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")

    ranges = _collect_protected_ranges(text)
    counts: Counter[str] = Counter()

    for match in _IDENTIFIER_RE.finditer(text):
        if _position_in_ranges(match.start(), ranges):
            continue
        counts[match.group(0)] += 1

    roles = _gather_identifier_roles(text, ranges)

    exported_functions: Set[str] = set()
    exported_values: Set[str] = set()
    header_keys: Set[str] = set()

    located = _extract_returned_table_with_span(text)
    if located is not None:
        table_start, _, table_src = located
        entries = _parse_return_table(table_src, table_start, text)
        for key, metadata in entries.items():
            if metadata.get("type") == "function":
                exported_functions.add(key)
            else:
                exported_values.add(key)
            roles[key].add("exported")

    try:
        header = detect_luraph_header(file_path)
    except OSError:
        header = {}
    else:
        header_keys.update(header.get("top_keys", []))

    if not header_keys:
        metadata_path = Path(str(file_path) + ".boundaries.json")
        if metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                metadata = {}
            origin = metadata.get("input")
            if isinstance(origin, str) and origin:
                try:
                    header = detect_luraph_header(origin)
                except OSError:
                    header = {}
                else:
                    header_keys.update(header.get("top_keys", []))

    for key in header_keys:
        roles[key].add("exported")
    exported_functions.update(header_keys)

    if output_path is None:
        output_path = file_path.with_name(f"{file_path.stem}_identifier_plan.csv")

    rows: List[Dict[str, object]] = []
    rename_counters: DefaultDict[str, int] = defaultdict(int)

    candidate_names: Set[str] = set(counts)
    candidate_names.update(exported_functions)
    candidate_names.update(exported_values)

    def sort_key(name: str) -> Tuple[int, str]:
        return (-counts.get(name, 0), name)

    for name in sorted(candidate_names, key=sort_key):
        if name in _RESERVED_IDENTIFIERS:
            continue
        count = counts.get(name, 0)
        if count == 0 and name not in exported_functions and name not in exported_values:
            continue
        if count == 1 and len(name) > 3 and name not in exported_functions and name not in exported_values:
            continue
        usage = _classify_identifier_usage(
            name, count, roles.get(name, set()), exported_functions, exported_values
        )
        is_function = "function" in roles.get(name, set()) or name in exported_functions
        category = "runtime" if usage == "core_runtime" else "helper"
        kind = "func" if is_function else "sym"
        counter_key = f"{category}_{kind}"
        rename_counters[counter_key] += 1
        recommended = f"{category}_{kind}_{rename_counters[counter_key]:02d}"

        rows.append(
            {
                "name": name,
                "count": count,
                "usage_type": usage,
                "recommended_name": recommended,
            }
        )

    output_path = Path(output_path)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "count", "usage_type", "recommended_name"])
        for row in rows:
            writer.writerow([row["name"], row["count"], row["usage_type"], row["recommended_name"]])

    return {
        "output_path": str(output_path),
        "rows": rows,
        "exported_functions": sorted(exported_functions),
        "exported_values": sorted(exported_values),
    }


def _skip_ws_and_comments(text: str, index: int) -> int:
    length = len(text)
    while index < length:
        ch = text[index]
        if ch in {" ", "\t", "\r", "\n"}:
            index += 1
            continue
        if ch == "-" and text.startswith("--", index):
            index += 2
            if index < length and text[index] == "[":
                long_eq = _match_long_bracket(text, index)
                if long_eq is not None:
                    index = _consume_long_bracket(text, index, long_eq)
                    continue
            while index < length and text[index] not in "\r\n":
                index += 1
            continue
        break
    return index


def _starts_with_keyword(text: str, index: int, keyword: str) -> bool:
    end = index + len(keyword)
    if end > len(text):
        return False
    fragment = text[index:end].lower()
    if fragment != keyword:
        return False
    if index > 0 and (text[index - 1].isalnum() or text[index - 1] == "_"):
        return False
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return False
    return True


def _offset_to_location(text: str, offset: int) -> Tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    if last_newline == -1:
        column = offset + 1
    else:
        column = offset - last_newline
    return line, column

_BANNER_VERSION_MAP = {
    "14.4.3": "14.4.3",
    "14.4.2": "14.4.2",
    "14.4.1": "luraph_v14_4_initv4",
    "14.4": "luraph_v14_4_initv4",
    "14.3": "14.3",
    "14.2": "luraph_v14_2_json",
    "14.1": "v14.1",
    "14.0.2": "v14.0.2",
    "14.0": "v14.0.2",
}

@dataclass(frozen=True)
class VersionInfo:
    """Description of a detected Luraph VM version."""

    name: str
    major: int
    minor: int
    features: frozenset[str]
    confidence: float
    matched_categories: Tuple[str, ...] = ()

    @property
    def is_unknown(self) -> bool:
        return self.name == "unknown"


class VersionDetector:
    """Heuristic detector for Luraph versions using repository descriptors."""

    _CATEGORY_FEATURE_MAP = {
        "signatures": "banner",
        "loaders": "loader",
        "upvalues": "upvalues",
        "long_strings": "container",
        "constants": "constants",
        "prologues": "prologue",
    }

    def __init__(self, descriptors: Mapping[str, Mapping[str, object]] | None = None) -> None:
        if descriptors is None:
            descriptors = {name: desc for name, desc in iter_descriptors()}
        self._descriptors: Dict[str, Mapping[str, object]] = dict(descriptors)
        self._all_features: FrozenSet[str] = self._collect_all_features()

    def detect(self, content: str, *, from_json: bool = False) -> VersionInfo:
        banner_version = _resolve_banner_version(content)
        if banner_version:
            return self.info_for_name(banner_version)

        if from_json and _JSON_INIT_RE.search(content) and _JSON_SCRIPT_KEY_RE.search(content):
            return self.info_for_name("luraph_v14_2_json")

        if _looks_like_initv4(content):
            return self.info_for_name("luraph_v14_4_initv4")

        best = VersionInfo("unknown", 0, 0, frozenset(), 0.0, ())
        best_score = 0
        best_priority = -1
        for name, descriptor in self._descriptors.items():
            heuristics = descriptor.get("heuristics", {})
            if not isinstance(heuristics, Mapping):
                continue
            priority = 0
            raw_priority = descriptor.get("priority") if isinstance(descriptor, Mapping) else None
            if isinstance(raw_priority, (int, float)):
                priority = int(raw_priority)
            score = 0
            total = 0
            categories: list[str] = []
            features: set[str] = set()
            for category, patterns in heuristics.items():
                if not isinstance(patterns, Iterable):
                    continue
                category_hits = 0
                for pattern in patterns:
                    if not isinstance(pattern, str):
                        continue
                    total += 1
                    if re.search(pattern, content, re.IGNORECASE):
                        score += 1
                        category_hits += 1
                if category_hits:
                    categories.append(category)
                    feature = self._CATEGORY_FEATURE_MAP.get(category) or category
                    features.add(feature)
            if total == 0:
                continue
            confidence = score / total
            better_score = score > best_score
            better_conf = score == best_score and confidence > best.confidence
            better_priority = (
                score == best_score
                and abs(confidence - best.confidence) < 1e-9
                and priority > best_priority
            )
            if better_score or better_conf or better_priority:
                major, minor = _parse_version_numbers(name)
                best = VersionInfo(
                    name=name,
                    major=major,
                    minor=minor,
                    features=frozenset(features),
                    confidence=confidence,
                    matched_categories=tuple(categories),
                )
                best_score = score
                best_priority = priority
        return best

    def detect_version(self, content: str, *, from_json: bool = False) -> VersionInfo:
        return self.detect(content, from_json=from_json)

    @property
    def all_features(self) -> FrozenSet[str]:
        """Return the union of all feature flags known to the detector."""

        return self._all_features

    def info_for_name(self, name: str) -> VersionInfo:
        """Return a :class:`VersionInfo` for ``name`` based on stored descriptors."""

        descriptor = self._descriptors.get(name)
        features: set[str] = set()
        categories: list[str] = []
        if isinstance(descriptor, Mapping):
            heuristics = descriptor.get("heuristics", {})
            if isinstance(heuristics, Mapping):
                for category in heuristics.keys():
                    categories.append(category)
                    feature = self._CATEGORY_FEATURE_MAP.get(category) or category
                    features.add(feature)
        major, minor = _parse_version_numbers(name)
        return VersionInfo(
            name=name,
            major=major,
            minor=minor,
            features=frozenset(features),
            confidence=1.0 if descriptor else 0.0,
            matched_categories=tuple(categories),
        )

    def _collect_all_features(self) -> FrozenSet[str]:
        features: set[str] = set()
        for descriptor in self._descriptors.values():
            heuristics = descriptor.get("heuristics", {}) if isinstance(descriptor, Mapping) else {}
            if not isinstance(heuristics, Mapping):
                continue
            for category in heuristics.keys():
                feature = self._CATEGORY_FEATURE_MAP.get(category) or category
                features.add(feature)
        return frozenset(features)


def _parse_version_numbers(name: str) -> Tuple[int, int]:
    matches = re.findall(r"\d+", name)
    if not matches:
        return 0, 0
    major = int(matches[0])
    minor = int(matches[1]) if len(matches) > 1 else 0
    return major, minor


def _looks_like_initv4(content: str) -> bool:
    bootstrap = detect_bootstrapper_source_from_text(content)
    if bootstrap.get("mode") != "external" or bootstrap.get("bootstrapper") != "initv4":
        return False

    stripped = content.lstrip()
    if stripped and _DIRECT_RETURN_RE.match(stripped):
        return False

    if not _INITV4_INIT_RE.search(content):
        return False
    if not _INITV4_SCRIPT_KEY_RE.search(content):
        return False

    if _INITV4_ALPHABET_RE.search(content):
        return True

    if _INITV4_BLOB_RE.search(content):
        return True

    if _INITV4_JSON_BLOB_RE.search(content):
        return True

    if _INITV4_JSON_ARRAY_KEY_RE.search(content):
        return True

    chunk_match = _INITV4_QUOTED_CHUNK_RE.search(content)
    if chunk_match:
        inner = chunk_match.group(2)
        if any(char not in _BASE64_CHARSET for char in inner):
            return True
        if _INITV4_CHUNK_ASSIGN_RE.search(content) and _INITV4_CHUNK_CONCAT_RE.search(content):
            return True

    long_match = _INITV4_LONG_BLOB_RE.search(content)
    if long_match and any(char not in _BASE64_CHARSET for char in long_match.group(0)):
        return True

    if _INITV4_CHUNK_ASSIGN_RE.search(content) and _INITV4_CHUNK_CONCAT_RE.search(content):
        return True

    return False


def _resolve_banner_version(content: str) -> str | None:
    url_versions = _extract_versions_from_luraph_url(content)
    for raw in url_versions:
        mapped = _map_banner_version(raw)
        if mapped:
            return mapped

    matches = list(_VERSION_BANNER_RE.findall(content))
    if not matches:
        return None
    for raw in matches:
        mapped = _map_banner_version(raw)
        if mapped:
            return mapped
    return None


def _map_banner_version(raw: str) -> str | None:
    candidate = raw.strip()
    if not candidate:
        return None
    parts = candidate.split('.')
    while parts:
        key = '.'.join(parts)
        mapped = _BANNER_VERSION_MAP.get(key)
        if mapped:
            return mapped
        # drop trailing zero segments to allow 14.4.0 -> 14.4
        if parts[-1] == '0':
            parts = parts[:-1]
            continue
        parts = parts[:-1]
    return _BANNER_VERSION_MAP.get(candidate)


__all__ = [
    "VersionDetector",
    "VersionInfo",
    "detect_luraph_header",
    "extract_metadata_provenance",
    "detect_compressed_fragments",
    "detect_multistage",
    "detect_embedded_bytecode",
    "cluster_fragments_by_similarity",
    "infer_encoding_order",
    "extract_embedded_comments",
    "entropy_detector",
    "extract_fragments",
    "fingerprint_obfuscation_patterns",
    "reconstruct_text",
    "normalize_bracket_literals",
    "pipeline_static_rebuild",
    "generate_run_summary",
    "split_functions_from_payload",
    "divide_unit_of_work",
    "complete_deobfuscate",
    "lift_helper_tables_to_modules",
    "introspect_top_level_table",
    "analyze_identifier_frequencies",
    "evaluate_deobfuscation_checklist",
    "evaluate_quality_gate",
    "parity_test",
    "pretty_print_with_mapping",
    "ir_to_lua",
    "round_trip_test",
]
