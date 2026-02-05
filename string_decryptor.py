"""High level helpers for collapsing layered string obfuscation.

Luraph payloads routinely nest several simple ciphers: hex encoded blobs that
are base64 wrapped, XORed with rolling keys, finally executed via
``loadstring`` or hand written closures.  The :class:`StringDecryptor` class
walks a piece of Lua source code and gradually replaces those constructions
with plain literals so later passes can operate on the simplified program.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from pattern_analyzer import Constant, PrimitiveTableInfo, SerializedChunk
from lua_literal_parser import LuaTable, parse_lua_expression


@dataclass(frozen=True)
class StringDecoderDescriptor:
    """Description of a detected inline string decoder."""

    closure_variable: str
    invocation: str
    gsub_alias: str
    metatable_alias: str
    cache_table: str
    token_variable: str
    token_length: int
    local_variable_count: int
    caches_results: bool
    primitive_table_info: Optional[PrimitiveTableInfo] = field(
        default=None, compare=False
    )
    context: Dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable representation of the descriptor."""

        return {
            "closure_variable": self.closure_variable,
            "invocation": self.invocation,
            "gsub_alias": self.gsub_alias,
            "metatable_alias": self.metatable_alias,
            "cache_table": self.cache_table,
            "token_variable": self.token_variable,
            "token_length": self.token_length,
            "local_variable_count": self.local_variable_count,
            "caches_results": self.caches_results,
            "primitive_table_info": self.primitive_table_info.to_dict()
            if self.primitive_table_info is not None
            else None,
            "context": dict(self.context),
        }

    def attach_primitive_table_info(self, info: PrimitiveTableInfo) -> None:
        """Link primitive table metadata so downstream decoders can reuse it."""

        object.__setattr__(self, "primitive_table_info", info)
        context = dict(self.context)
        context.update(
            {
                "primitive_token_width": info.token_width,
                "primitive_base_offset": info.base_offset,
                "primitive_radix": info.radix,
            }
        )
        object.__setattr__(self, "context", context)


@dataclass
class StringTable:
    """Mapping of encoded tokens to their decoded plaintext."""

    entries: Dict[str, str] = field(default_factory=dict)

    def add(self, token: str, decoded: str) -> None:
        if token not in self.entries:
            self.entries[token] = decoded

    def lookup(self, token: str) -> Optional[tuple[str, str]]:
        """Return the canonical token plus decoded string if available."""

        if not token:
            return None

        if token in self.entries:
            return token, self.entries[token]

        normalised = _normalise_v14_3_token(token)
        if normalised and normalised in self.entries:
            return normalised, self.entries[normalised]

        return None

    def __len__(self) -> int:  # pragma: no cover - convenience wrapper
        return len(self.entries)

    def __contains__(self, token: object) -> bool:  # pragma: no cover - passthrough
        return token in self.entries

    def decoded_strings(self) -> List[str]:
        """Return decoded strings in insertion order."""

        return list(self.entries.values())

    def to_dict(self) -> Dict[str, str]:  # pragma: no cover - used for JSON emission
        return dict(self.entries)


def detect_v14_3_string_decoder(source: str) -> Optional[StringDecoderDescriptor]:
    """Return a descriptor for the standalone v14.3 string decoder when present."""

    for match in re.finditer(r"\(function\s*\(([A-Za-z_][A-Za-z0-9_]*)\)", source):
        closure_var = match.group(1)
        lhs_idx = match.start() - 1
        while lhs_idx >= 0 and source[lhs_idx].isspace():
            lhs_idx -= 1
        if lhs_idx < 0 or source[lhs_idx] != "=":
            continue
        func_start = match.start() + source[match.start():].find("function")
        if func_start == -1:
            continue
        function_block = _extract_function_block(source, func_start)
        if function_block is None:
            continue
        body_end, params, body = function_block
        params = [param.strip() for param in params.split(",") if param.strip()]
        if len(params) != 1 or params[0] != closure_var:
            continue

        invocation = _extract_invocation(source, body_end)
        if invocation is None or not invocation:
            continue

        statements = _split_top_level_statements(body)
        if len(statements) < 2:
            continue

        assign_call = _parse_assignment_call(statements[0])
        if assign_call is None:
            continue
        target, gsub_alias, gsub_args = assign_call
        if not target or target != closure_var:
            continue
        gsub_params = _split_args(gsub_args)
        if len(gsub_params) < 3:
            continue
        first_arg = gsub_params[0].strip()
        if first_arg not in {closure_var, target}:
            continue
        if not _is_string_literal(gsub_params[1]):
            continue

        return_call = _parse_return_call(statements[1])
        if return_call is None:
            continue
        return_alias, return_args = return_call
        if return_alias != gsub_alias:
            continue
        return_params = _split_args(return_args)
        if len(return_params) < 3:
            continue
        if return_params[0].strip() not in {closure_var, target}:
            continue

        metatable_expr = return_params[2].strip()
        metatable_call = _parse_call_expression(metatable_expr)
        if metatable_call is None:
            continue
        metatable_alias, metatable_args = metatable_call
        mt_params = _split_args(metatable_args)
        if len(mt_params) != 2:
            continue
        if mt_params[0].strip().replace(" ", "") != "{}":
            continue
        table_expr = mt_params[1].strip()
        index_descriptor = _parse_metatable_index(table_expr)
        if index_descriptor is None:
            continue

        cache_table, token_var, local_count, token_length, caches_results = index_descriptor
        descriptor = StringDecoderDescriptor(
            closure_variable=closure_var,
            invocation=invocation,
            gsub_alias=gsub_alias,
            metatable_alias=metatable_alias,
            cache_table=cache_table,
            token_variable=token_var,
            token_length=token_length,
            local_variable_count=local_count,
            caches_results=caches_results,
        )
        return descriptor

    return None


def decode_string_v14_3(
    token: str,
    *,
    descriptor: Optional[StringDecoderDescriptor] = None,
    primitive_table: Optional[PrimitiveTableInfo] = None,
) -> str:
    """Decode a v14.3 token using the captured loader metadata."""

    table_info, token_width, base_offset = _resolve_v14_3_decoder_inputs(
        descriptor,
        primitive_table,
    )

    token = _normalise_v14_3_token(token)
    if not token:
        return ""

    weights = _derive_v14_3_weights(table_info, token_width)
    packer, chunk_size = _build_v14_3_pack_function(table_info.alphabet_literal)
    if chunk_size <= 0:
        raise ValueError("invalid packer configuration recovered from metadata")

    pieces: List[str] = []
    stride = token_width
    for offset in range(0, len(token), stride):
        chunk = token[offset : offset + stride]
        if len(chunk) != stride:
            raise ValueError("token length is not a multiple of the decoder width")
        value = _compute_v14_3_chunk_index(
            chunk,
            base_offset=base_offset,
            weights=weights,
            radix=table_info.radix,
        )
        pieces.append(packer(value))

    return "".join(pieces)


def build_v14_3_string_table(
    chunk: SerializedChunk,
    descriptor: StringDecoderDescriptor,
    *,
    primitive_table: Optional[PrimitiveTableInfo] = None,
    debug_output_path: Optional[Path] = None,
) -> StringTable:
    """Collect and decode all tokens referenced by ``chunk``."""

    table_info, token_width, base_offset = _resolve_v14_3_decoder_inputs(
        descriptor,
        primitive_table,
    )

    encoded_tokens = _collect_v14_3_tokens_from_chunk(
        chunk,
        token_width=token_width,
        base_offset=base_offset,
        radix=table_info.radix,
    )

    string_table = StringTable()
    for token in encoded_tokens:
        decoded = decode_string_v14_3(
            token,
            descriptor=descriptor,
            primitive_table=table_info,
        )
        string_table.add(token, decoded)

    if debug_output_path is not None:
        _write_decoded_strings_debug(string_table, debug_output_path)

    return string_table


def _compute_v14_3_chunk_index(
    chunk: str,
    *,
    base_offset: int,
    weights: Sequence[int],
    radix: Optional[int],
) -> int:
    digits = [ord(ch) - base_offset for ch in chunk]
    if any(d < 0 for d in digits):
        raise ValueError("token contains characters below the allowed alphabet")
    if radix is not None and any(d >= radix for d in digits):
        raise ValueError("token contains digits outside the primitive table radix")

    if len(weights) < len(digits):
        raise ValueError("weight table shorter than token width")

    value = 0
    for weight, digit in zip(weights, reversed(digits)):
        value += weight * digit
    return value


def _resolve_v14_3_decoder_inputs(
    descriptor: Optional[StringDecoderDescriptor],
    primitive_table: Optional[PrimitiveTableInfo],
) -> tuple[PrimitiveTableInfo, int, int]:
    if descriptor is None:
        raise ValueError("descriptor must be provided for v14.3 decoding")

    table_info = primitive_table or descriptor.primitive_table_info
    if table_info is None:
        raise ValueError(
            "primitive_table metadata is required – attach PrimitiveTableInfo before decoding"
        )

    token_width = table_info.token_width or descriptor.token_length
    if not token_width or token_width <= 0:
        raise ValueError("token width is missing from descriptor metadata")

    base_offset = (
        table_info.base_offset
        or descriptor.context.get("primitive_base_offset")
        or _infer_base_offset_from_expression(table_info.accumulator_expression)
    )
    if base_offset is None:
        raise ValueError("primitive table base offset is not available")

    return table_info, token_width, base_offset


def _collect_v14_3_tokens_from_chunk(
    chunk: SerializedChunk,
    *,
    token_width: int,
    base_offset: int,
    radix: Optional[int],
) -> List[str]:
    ordered: Dict[str, None] = {}

    def visit_prototype(proto) -> None:
        for constant in getattr(proto, "constants", []) or []:
            _collect_v14_3_tokens_from_value(
                constant,
                ordered,
                token_width=token_width,
                base_offset=base_offset,
                radix=radix,
            )
        for child in getattr(proto, "prototypes", []) or []:
            visit_prototype(child)

    for prototype in getattr(chunk, "prototypes", []) or []:
        visit_prototype(prototype)

    return list(ordered.keys())


def _collect_v14_3_tokens_from_value(
    value: Any,
    registry: Dict[str, None],
    *,
    token_width: int,
    base_offset: int,
    radix: Optional[int],
) -> None:
    if isinstance(value, Constant):
        _collect_v14_3_tokens_from_value(
            value.value,
            registry,
            token_width=token_width,
            base_offset=base_offset,
            radix=radix,
        )
        return

    if isinstance(value, str):
        token = _normalise_v14_3_token(value)
        if token and _looks_like_v14_3_token(
            token,
            token_width=token_width,
            base_offset=base_offset,
            radix=radix,
        ):
            registry.setdefault(token, None)
        return

    if isinstance(value, Mapping):
        for key, nested in value.items():
            _collect_v14_3_tokens_from_value(
                key,
                registry,
                token_width=token_width,
                base_offset=base_offset,
                radix=radix,
            )
            _collect_v14_3_tokens_from_value(
                nested,
                registry,
                token_width=token_width,
                base_offset=base_offset,
                radix=radix,
            )
        return

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for entry in value:
            _collect_v14_3_tokens_from_value(
                entry,
                registry,
                token_width=token_width,
                base_offset=base_offset,
                radix=radix,
            )


def _looks_like_v14_3_token(
    token: str,
    *,
    token_width: int,
    base_offset: int,
    radix: Optional[int],
) -> bool:
    if len(token) < token_width or len(token) % token_width != 0:
        return False

    alpha_only = True
    for ch in token:
        digit = ord(ch) - base_offset
        if digit < 0:
            return False
        if radix is not None and digit >= radix:
            return False
        if not ch.isalpha():
            alpha_only = False

    if alpha_only and len(token) == token_width:
        return False

    return True


def _write_decoded_strings_debug(table: StringTable, target_path: Path) -> None:
    resolved_target = target_path.resolve()
    out_root = (Path("out")).resolve()
    try:
        resolved_target.relative_to(out_root)
    except ValueError as exc:
        raise ValueError("debug_output_path must be inside the out/ directory") from exc

    target_path.parent.mkdir(parents=True, exist_ok=True)
    ordered_strings = list(dict.fromkeys(table.decoded_strings()))
    payload = {"strings": ordered_strings}
    target_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _derive_v14_3_weights(
    info: PrimitiveTableInfo, token_width: int
) -> Sequence[int]:
    weights = list(info.weights)
    if len(weights) >= token_width:
        return weights[:token_width]

    radix = info.radix
    if radix is None or radix <= 1:
        raise ValueError("primitive table does not specify enough weights or a radix")

    if not weights:
        weights.append(1)

    while len(weights) < token_width:
        weights.append(weights[-1] * radix)

    return weights[:token_width]


def _infer_base_offset_from_expression(expression: str) -> Optional[int]:
    if not expression:
        return None

    candidates = re.findall(r"-\s*([A-Za-z0-9_xXoObB]+)", expression)
    for literal in candidates:
        value = _parse_int_literal(literal)
        if value is not None:
            return value
    return None


def _normalise_v14_3_token(token: str) -> str:
    if not token:
        return ""
    return "".join(ch for ch in token if not ch.isspace())


def _build_v14_3_pack_function(
    literal: Optional[str],
) -> tuple[Callable[[int], str], int]:
    if not literal:
        raise ValueError("pack format literal missing from primitive table metadata")

    pack_literal = _materialise_pack_literal(literal)
    fmt, byte_size = _parse_pack_literal(pack_literal)
    mask = (1 << (byte_size * 8)) - 1

    def packer(value: int) -> str:
        bounded = value & mask
        packed = struct.pack(fmt, bounded)
        return packed.decode("latin-1")

    return packer, byte_size


def _materialise_pack_literal(literal: str) -> str:
    literal = literal.strip()
    if literal and literal[0] in {'"', "'"}:
        parsed = parse_lua_expression(literal)
        if not isinstance(parsed, str):
            raise ValueError("alphabet literal does not evaluate to a string")
        literal = parsed

    def repl(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    return re.sub(r"\\u\{([0-9A-Fa-f]+)\}", repl, literal)


def _parse_pack_literal(literal: str) -> tuple[str, int]:
    if len(literal) < 3:
        raise ValueError("pack literal is too short")
    endian = literal[0]
    if endian not in {"<", ">", "="}:
        raise ValueError(f"unsupported endian specifier {endian!r}")
    type_char = literal[1]
    size_part = literal[2:]
    if not size_part.isdigit():
        raise ValueError("pack literal size is not numeric")
    size = int(size_part, 10)
    signed = type_char.islower()
    type_char = type_char.lower()
    code_map = {
        1: ("b" if signed else "B"),
        2: ("h" if signed else "H"),
        4: ("i" if signed else "I"),
        8: ("q" if signed else "Q"),
    }
    if size not in code_map:
        raise ValueError(f"unsupported pack literal size {size}")
    fmt = f"{endian}{code_map[size]}"
    return fmt, size


def _extract_function_block(
    text: str, start: int
) -> Optional[tuple[int, str, str]]:
    if not text.startswith("function", start):
        return None
    pos = start + len("function")
    pos = _skip_ws(text, pos)
    if pos >= len(text) or text[pos] != "(":
        return None
    param_end = _find_matching_paren(text, pos)
    if param_end is None:
        return None
    params = text[pos + 1 : param_end]
    body_start = param_end + 1
    depth = 1
    i = body_start
    while i < len(text):
        ch = text[i]
        if ch in "'\"":
            i = _skip_string_literal(text, i)
            continue
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        if _is_keyword(text, i, "function"):
            depth += 1
            i += len("function")
            continue
        if _is_keyword(text, i, "end"):
            depth -= 1
            end_pos = i
            i += len("end")
            if depth == 0:
                body = text[body_start:end_pos]
                return i, params, body
            continue
        i += 1
    return None


def _extract_invocation(text: str, end_pos: int) -> Optional[str]:
    pos = _skip_ws(text, end_pos)
    if pos < len(text) and text[pos] == ")":
        pos = _skip_ws(text, pos + 1)
    if pos >= len(text) or text[pos] != "(":
        return None
    close = _find_matching_paren(text, pos)
    if close is None:
        return None
    invocation = text[pos + 1 : close].strip()
    return invocation


def _split_top_level_statements(body: str) -> List[str]:
    statements: List[str] = []
    start = 0
    paren = brace = bracket = func_depth = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in "'\"":
            i = _skip_string_literal(body, i)
            continue
        if body.startswith("--", i):
            i = _skip_comment(body, i)
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif _is_keyword(body, i, "function"):
            func_depth += 1
            i += len("function")
            continue
        elif _is_keyword(body, i, "end"):
            func_depth = max(func_depth - 1, 0)
            i += len("end")
            continue
        if (
            ch == ";"
            and paren == 0
            and brace == 0
            and bracket == 0
            and func_depth == 0
        ):
            segment = body[start:i].strip()
            if segment:
                statements.append(segment)
            start = i + 1
        i += 1
    tail = body[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def _parse_assignment_call(statement: str) -> Optional[tuple[str, str, str]]:
    stmt = statement.strip()
    if stmt.startswith("local "):
        stmt = stmt[6:].strip()
    if "=" not in stmt:
        return None
    lhs, rhs = stmt.split("=", 1)
    target = lhs.strip()
    call = _parse_call_expression(rhs.strip())
    if call is None:
        return None
    name, args = call
    return target, name, args


def _parse_return_call(statement: str) -> Optional[tuple[str, str]]:
    stmt = statement.strip()
    if not stmt.startswith("return"):
        return None
    expr = stmt[len("return") :].strip()
    call = _parse_call_expression(expr)
    if call is None:
        return None
    return call


def _parse_call_expression(expr: str) -> Optional[tuple[str, str]]:
    stripped = expr.strip()
    if not stripped:
        return None
    idx = 0
    length = len(stripped)
    while idx < length and _is_identifier_char(stripped[idx]):
        idx += 1
    if idx == 0:
        return None
    name = stripped[:idx]
    idx = _skip_ws(stripped, idx)
    if idx >= length or stripped[idx] != "(":
        return None
    close = _find_matching_paren(stripped, idx)
    if close is None:
        return None
    args = stripped[idx + 1 : close]
    remainder = stripped[close + 1 :].strip()
    if remainder:
        return None
    return name, args


def _parse_metatable_index(
    expr: str,
) -> Optional[tuple[str, str, int, int, bool]]:
    match = re.search(r"__index\s*=\s*function", expr)
    if not match:
        return None
    func_start = match.start()
    func_pos = expr.find("function", func_start)
    if func_pos == -1:
        return None
    block = _extract_function_block(expr, func_pos)
    if block is None:
        return None
    _, params, body = block
    param_list = [param.strip() for param in params.split(",") if param.strip()]
    if len(param_list) != 2:
        return None
    cache_table, token_param = param_list
    local_match = re.search(
        r"local\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)",
        body,
    )
    if not local_match:
        return None
    local_vars = [part.strip() for part in local_match.group(1).split(",") if part.strip()]
    local_count = len(local_vars)
    args_str = local_match.group(3)
    args = _split_args(args_str)
    if len(args) < 2:
        return None
    if args[0].strip() != token_param:
        return None
    token_length = _parse_int_literal(args[-1])
    if token_length is None:
        return None
    if token_length != 5:
        return None
    if local_count < 5:
        return None
    cache_pattern = rf"\b{re.escape(cache_table)}\s*\[\s*{re.escape(token_param)}\s*\]"
    caches_results = bool(re.search(cache_pattern + r"\s*=", body))
    return cache_table, token_param, local_count, token_length, caches_results


def _is_string_literal(expr: str) -> bool:
    stripped = expr.strip()
    return bool(stripped) and stripped[0] in {'"', "'"} and stripped[-1] == stripped[0]


def _parse_int_literal(text: str) -> Optional[int]:
    candidate = text.strip().lower().replace("_", "")
    if not candidate:
        return None
    sign = 1
    if candidate.startswith("-"):
        sign = -1
        candidate = candidate[1:]
    base = 10
    if candidate.startswith("0x"):
        base = 16
        digits = candidate[2:]
    elif candidate.startswith("0b"):
        base = 2
        digits = candidate[2:]
    elif candidate.startswith("0o"):
        base = 8
        digits = candidate[2:]
    else:
        digits = candidate
    if not digits:
        return None
    try:
        return sign * int(digits, base)
    except ValueError:
        return None


def _skip_ws(text: str, pos: int) -> int:
    length = len(text)
    while pos < length:
        ch = text[pos]
        if ch in " \t\r\n":
            pos += 1
            continue
        if text.startswith("--", pos):
            pos = _skip_comment(text, pos)
            continue
        break
    return pos


def _skip_comment(text: str, pos: int) -> int:
    pos += 2
    while pos < len(text) and text[pos] not in "\r\n":
        pos += 1
    return pos


def _find_matching_paren(text: str, start: int) -> Optional[int]:
    if start >= len(text) or text[start] != "(":
        return None
    depth = 1
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch in "'\"":
            i = _skip_string_literal(text, i)
            continue
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _skip_string_literal(text: str, start: int) -> int:
    quote = text[start]
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(text)


def _is_identifier_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _is_keyword(text: str, pos: int, keyword: str) -> bool:
    if not text.startswith(keyword, pos):
        return False
    before = text[pos - 1] if pos > 0 else ""
    after_pos = pos + len(keyword)
    after = text[after_pos] if after_pos < len(text) else ""
    if before and _is_identifier_char(before):
        return False
    if after and _is_identifier_char(after):
        return False
    return True


def _looks_printable(value: str) -> bool:
    printable = sum(ch.isprintable() for ch in value)
    return printable / max(len(value), 1) > 0.85


def _split_args(arguments: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(arguments):
        ch = arguments[i]
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(arguments[start:i].strip())
            start = i + 1
        i += 1
    tail = arguments[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _split_concat(expr: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "." and i + 1 < len(expr) and expr[i + 1] == "." and depth == 0:
            segment = expr[start:i].strip()
            if segment:
                parts.append(segment)
            i += 2
            start = i
            continue
        i += 1
    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _unwrap_parentheses(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(expr) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            expr = expr[1:-1].strip()
        else:
            break
    return expr


def _decode_hex_literal(value: str) -> Optional[str]:
    if len(value) % 2:
        return None
    try:
        decoded = bytes.fromhex(value)
        text = decoded.decode("utf-8", errors="replace")
        return text if _looks_printable(text) else None
    except (ValueError, binascii.Error):
        return None


def _decode_base64_literal(value: str) -> Optional[str]:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return None
    return text if _looks_printable(text) else None


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _rotl(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) & 0xFF) | (value >> (8 - shift))


def _rotr(value: int, shift: int) -> int:
    shift &= 7
    return ((value >> shift) | ((value << (8 - shift)) & 0xFF)) & 0xFF


def _decode_stream(op: str, payload: str, key: str) -> Optional[str]:
    data = payload.encode("latin-1", errors="ignore")
    key_bytes = key.encode("latin-1", errors="ignore")
    if not data or not key_bytes:
        return None
    if "xor" in op:
        result = _xor_bytes(data, key_bytes)
    elif "add" in op:
        key_ints = [kb for kb in key_bytes]
        result = bytes((b - key_ints[i % len(key_ints)]) & 0xFF for i, b in enumerate(data))
    elif "rol" in op:
        shift = key_bytes[0]
        result = bytes(_rotr(b, shift) for b in data)
    elif "ror" in op:
        shift = key_bytes[0]
        result = bytes(_rotl(b, shift) for b in data)
    else:
        return None
    text = result.decode("utf-8", errors="replace")
    return text if _looks_printable(text) else None


def _evaluate_expression(expr: str) -> Optional[str]:
    expr = _unwrap_parentheses(expr)
    concat_parts = _split_concat(expr)
    if len(concat_parts) > 1:
        pieces: List[str] = []
        for part in concat_parts:
            evaluated = _evaluate_expression(part)
            if evaluated is None:
                return None
            pieces.append(evaluated)
        return "".join(pieces)

    if expr.startswith("string.char") and expr.endswith(")"):
        args = _split_args(expr[len("string.char(") : -1])
        chars: List[str] = []
        for arg in args:
            try:
                value = parse_lua_expression(arg)
            except ValueError:
                return None
            if not isinstance(value, (int, float)):
                return None
            chars.append(chr(int(value) & 0xFF))
        text = "".join(chars)
        return text if _looks_printable(text) else None

    if expr.startswith("table.concat") and expr.endswith(")"):
        args = _split_args(expr[len("table.concat(") : -1])
        if not args:
            return None
        try:
            table_value = parse_lua_expression(args[0])
        except ValueError:
            return None
        if not isinstance(table_value, LuaTable):
            return None
        sep = ""
        if len(args) > 1:
            sep_value = _evaluate_expression(args[1])
            if sep_value is not None:
                sep = sep_value
        strings: List[str] = []
        for idx in range(1, len(table_value.array) + 1):
            try:
                value = table_value.get(idx)
            except KeyError:
                continue
            literal = _evaluate_table_value(value)
            if literal is None:
                return None
            strings.append(literal)
        text = sep.join(strings)
        return text if _looks_printable(text) else None

    try:
        literal = parse_lua_expression(expr)
    except ValueError:
        return None
    if isinstance(literal, str):
        return literal
    return None


def _evaluate_table_value(value: object) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return chr(int(value) & 0xFF)
    if isinstance(value, LuaTable):
        joined = []
        for idx in range(1, len(value.array) + 1):
            try:
                joined.append(_evaluate_table_value(value.get(idx)) or "")
            except KeyError:
                continue
        candidate = "".join(joined)
        return candidate if candidate else None
    return None


class StringDecryptor:
    """Apply a series of heuristics to simplify encrypted string blobs."""

    def __init__(self) -> None:
        self._passes: Sequence[Callable[[str], str]] = (
            self._decode_hex_chunks,
            self._decode_base64_chunks,
            self._decode_stream_calls,
            self._decode_escape_sequences,
            self._fold_inline_closures,
            self._decode_load_wrappers,
        )

    def decrypt(self, code: str) -> str:
        previous = None
        current = code
        while previous != current:
            previous = current
            for func in self._passes:
                try:
                    updated = func(current)
                except Exception:
                    continue
                current = updated
        return current

    # Individual passes -------------------------------------------------
    def _decode_hex_chunks(self, code: str) -> str:
        pattern = re.compile(r'(\b[0-9A-Fa-f]{8,}\b)')

        def repl(match: re.Match[str]) -> str:
            candidate = match.group(1)
            decoded = _decode_hex_literal(candidate)
            return decoded if decoded is not None else candidate

        return pattern.sub(repl, code)

    def _decode_base64_chunks(self, code: str) -> str:
        literal_pattern = re.compile(r'(["\'])([A-Za-z0-9+/=_-]{12,})\1')

        def decode_literal(match: re.Match[str]) -> str:
            quote, payload = match.groups()
            decoded = _decode_base64_literal(payload)
            if decoded is None:
                return match.group(0)
            escaped = decoded.replace("\\", "\\\\").replace(quote, f"\\{quote}")
            return f"{quote}{escaped}{quote}"

        code = literal_pattern.sub(decode_literal, code)

        call_pattern = re.compile(
            r'(?:base64|b64)[._]?(?:decode|dec|Decode)\s*\(\s*(["\'])(.*?)\1\s*\)'
        )

        def decode_call(match: re.Match[str]) -> str:
            quote, payload = match.groups()
            decoded = _decode_base64_literal(payload)
            if decoded is None:
                return match.group(0)
            escaped = decoded.replace("\\", "\\\\").replace(quote, f"\\{quote}")
            return f"{quote}{escaped}{quote}"

        return call_pattern.sub(decode_call, code)

    def _decode_stream_calls(self, code: str) -> str:
        pattern = re.compile(
            r'([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(["\'])(.*?)\2\s*,\s*(["\'])(.*?)\4\s*\)'
        )

        def repl(match: re.Match[str]) -> str:
            func_name, _, payload, __, key = match.groups()
            lowered = func_name.lower()
            decoded = _decode_stream(lowered, payload, key)
            if decoded is None:
                return match.group(0)
            escaped = decoded.replace("\\", "\\\\").replace("\"", "\\\"")
            return f'"{escaped}"'

        return pattern.sub(repl, code)

    def _decode_escape_sequences(self, code: str) -> str:
        def replace_hex(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        def replace_octal(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 8))
            except ValueError:
                return match.group(0)

        def replace_unicode(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        code = re.sub(r'\\x([0-9A-Fa-f]{2})', replace_hex, code)
        code = re.sub(r'\\([0-7]{1,3})', replace_octal, code)
        code = re.sub(r'\\u\{([0-9A-Fa-f]+)\}', replace_unicode, code)
        return code

    def _fold_inline_closures(self, code: str) -> str:
        pattern = re.compile(r'\(function\s*\(\s*\)\s*(.*?)end\)\s*\(\s*\)', re.DOTALL)

        def repl(match: re.Match[str]) -> str:
            body = match.group(1)
            ret_idx = body.find("return")
            if ret_idx == -1:
                return match.group(0)
            expr_start = ret_idx + len("return")
            depth = 0
            i = expr_start
            expr_end = len(body)
            while i < len(body):
                ch = body[i]
                if ch in "({[":
                    depth += 1
                elif ch in ")}]":
                    depth -= 1
                elif depth == 0 and body.startswith("end", i):
                    expr_end = i
                    break
                elif depth == 0 and body[i] == ";":
                    expr_end = i
                    break
                i += 1
            expr = body[expr_start:expr_end].strip()
            evaluated = _evaluate_expression(expr)
            if evaluated is None:
                return match.group(0)
            escaped = evaluated.replace("\\", "\\\\").replace("\"", "\\\"")
            return f'"{escaped}"'

        return pattern.sub(repl, code)

    def _decode_load_wrappers(self, code: str) -> str:
        pattern = re.compile(
            r'(?:loadstring|load)\s*\(\s*(["\'])(.*?)\1\s*(?:,\s*[^)]*)?\)\s*\(\s*\)'
        )

        def repl(match: re.Match[str]) -> str:
            quote, payload = match.groups()
            try:
                inner = payload.encode("utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                inner = payload
            decrypted = self.decrypt(inner)
            escaped = decrypted.replace("\\", "\\\\").replace(quote, f"\\{quote}")
            return f"{quote}{escaped}{quote}"

        return pattern.sub(repl, code)


__all__ = [
    "StringDecryptor",
    "StringDecoderDescriptor",
    "detect_v14_3_string_decoder",
    "decode_string_v14_3",
    "StringTable",
    "build_v14_3_string_table",
]

