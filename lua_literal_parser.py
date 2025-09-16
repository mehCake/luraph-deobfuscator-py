"""Lightweight Lua literal parser used for constant recovery.

The real Luraph payloads only require a very small subset of Lua syntax to
decode constants: numeric literals, quoted or long strings, table constructors
and boolean/nil keywords.  Rather than rely on an external Lua runtime, this
module implements a tiny recursive descent parser that turns those fragments
into regular Python data structures.

It intentionally ignores executable statements and only accepts expressions.
The produced values are safe Python objects (``int``, ``float``, ``str``,
``bool`` or :class:`LuaTable`).  Strings are automatically interned to keep
deduplicated copies across large constant pools.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union


_WHITESPACE = {" ", "\t", "\r", "\n"}


def _is_identifier_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_identifier_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _unescape_short_string(body: str) -> str:
    """Decode Lua short string escapes.

    Lua shares the majority of its escapes with Python (``\n``, ``\r`` …) but
    additionally allows decimal escapes (``\123``).  We implement the minimal
    subset required by the fixtures which is enough to resolve obfuscated
    constants.
    """

    result: List[str] = []
    it = iter(range(len(body)))
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            result.append(ch)
            i += 1
            continue

        i += 1
        if i >= len(body):
            result.append("\\")
            break
        esc = body[i]
        i += 1
        if esc in "abfnrtv\\\"'":
            mapping = {
                "a": "\a",
                "b": "\b",
                "f": "\f",
                "n": "\n",
                "r": "\r",
                "t": "\t",
                "v": "\v",
                "\\": "\\",
                "\"": "\"",
                "'": "'",
            }
            result.append(mapping[esc])
        elif esc.isdigit():
            digits = esc
            while i < len(body) and len(digits) < 3 and body[i].isdigit():
                digits += body[i]
                i += 1
            result.append(chr(int(digits, 10)))
        elif esc == "x" and i + 1 < len(body):
            hex_digits = body[i : i + 2]
            if re.fullmatch(r"[0-9a-fA-F]{2}", hex_digits):
                result.append(chr(int(hex_digits, 16)))
                i += 2
            else:
                result.append("\\x")
        else:
            # Unknown escape – keep it verbatim so the caller can spot it.
            result.append("\\" + esc)
    return sys.intern("".join(result))


@dataclass(frozen=True)
class LuaTable:
    """Representation of a Lua table literal.

    ``array`` contains positional entries (``t[1]`` .. ``t[#t]``) and ``mapping``
    holds explicit key/value pairs.  The structure is immutable which makes it
    hashable and safe to cache when identical tables are encountered multiple
    times in the same payload.
    """

    array: Tuple[Any, ...]
    mapping: Tuple[Tuple[Any, Any], ...]

    def to_python(self) -> Dict[Any, Any]:
        mapping: Dict[Any, Any] = {k: v for k, v in self.mapping}
        for index, value in enumerate(self.array, start=1):
            mapping.setdefault(index, value)
        return mapping

    def get(self, key: Any) -> Any:
        if isinstance(key, (int, float)) and float(key).is_integer():
            idx = int(key)
            if 1 <= idx <= len(self.array):
                return self.array[idx - 1]
        for k, v in self.mapping:
            if k == key:
                return v
        raise KeyError(key)


class _LuaParser:
    def __init__(self, text: str):
        self.text = text
        self.length = len(text)
        self.pos = 0

    # Public API -------------------------------------------------------
    def parse(self) -> Any:
        value = self._parse_value()
        self._skip_ws()
        if self.pos != self.length:
            raise ValueError(f"Unexpected trailing data at position {self.pos}")
        return value

    # Parsing helpers --------------------------------------------------
    def _skip_ws(self) -> None:
        while self.pos < self.length:
            ch = self.text[self.pos]
            if ch in _WHITESPACE:
                self.pos += 1
                continue
            if ch == "-" and self.text.startswith("--", self.pos):
                self.pos += 2
                while self.pos < self.length and self.text[self.pos] not in "\r\n":
                    self.pos += 1
                continue
            break

    def _peek(self) -> Optional[str]:
        if self.pos >= self.length:
            return None
        return self.text[self.pos]

    def _consume(self, expected: str) -> None:
        if not self.text.startswith(expected, self.pos):
            raise ValueError(f"Expected '{expected}' at position {self.pos}")
        self.pos += len(expected)

    # Value parsing ----------------------------------------------------
    def _parse_value(self) -> Any:
        self._skip_ws()
        ch = self._peek()
        if ch is None:
            raise ValueError("Unexpected end of input")
        if ch == "{":
            return self._parse_table()
        if ch in {'"', "'"}:
            return self._parse_short_string()
        if ch == "[" and self.text.startswith("[[", self.pos):
            return self._parse_long_string()
        next_ch = self._peek_ahead(1)
        if ch.isdigit() or (ch == "-" and next_ch is not None and next_ch.isdigit()):
            return self._parse_number()
        if _is_identifier_start(ch):
            ident = self._parse_identifier()
            if ident == "true":
                return True
            if ident == "false":
                return False
            if ident == "nil":
                return None
            raise ValueError(f"Unsupported identifier '{ident}' at position {self.pos}")
        raise ValueError(f"Unsupported literal starting with '{ch}' at position {self.pos}")

    def _peek_ahead(self, offset: int) -> Optional[str]:
        idx = self.pos + offset
        if idx >= self.length:
            return None
        return self.text[idx]

    def _parse_number(self) -> Union[int, float]:
        start = self.pos
        if self.text[self.pos] == "-":
            self.pos += 1
        while (
            self.pos < self.length
            and (
                self.text[self.pos].isalnum()
                or self.text[self.pos] in {".", "x", "X", "p", "P", "+", "-"}
            )
        ):
            self.pos += 1
        literal = self.text[start:self.pos]
        try:
            if "x" in literal.lower() and "p" in literal.lower():
                return float.fromhex(literal)
            if literal.lower().startswith("0x"):
                return int(literal, 16)
            if any(ch in literal for ch in (".", "e", "E")):
                return float(literal)
            return int(literal, 10)
        except ValueError as exc:
            raise ValueError(f"Invalid numeric literal '{literal}'") from exc

    def _parse_identifier(self) -> str:
        start = self.pos
        self.pos += 1
        while self.pos < self.length and _is_identifier_char(self.text[self.pos]):
            self.pos += 1
        return self.text[start:self.pos]

    def _parse_short_string(self) -> str:
        quote = self.text[self.pos]
        self.pos += 1
        start = self.pos
        escaped = False
        while self.pos < self.length:
            ch = self.text[self.pos]
            if not escaped and ch == quote:
                body = self.text[start:self.pos]
                self.pos += 1
                return _unescape_short_string(body)
            escaped = (not escaped and ch == "\\")
            self.pos += 1
        raise ValueError("Unterminated string literal")

    def _parse_long_string(self) -> str:
        # Lua supports `[=[ ... ]=]` with arbitrary number of `=`.  We honour the
        # same syntax here.
        match = re.match(r"\[=*\[", self.text[self.pos :])
        if not match:
            raise ValueError("Invalid long string start")
        marker = match.group(0)
        equals = marker.count("=")
        closing = "]" + "=" * equals + "]"
        self.pos += len(marker)
        start = self.pos
        end = self.text.find(closing, self.pos)
        if end == -1:
            raise ValueError("Unterminated long string literal")
        body = self.text[start:end]
        self.pos = end + len(closing)
        return sys.intern(body)

    def _parse_table(self) -> LuaTable:
        self._consume("{")
        array: List[Any] = []
        mapping: Dict[Any, Any] = {}
        while True:
            self._skip_ws()
            if self._peek() == "}":
                self.pos += 1
                break
            key: Optional[Any] = None
            value: Any
            mark = self.pos

            peek = self._peek()
            if peek == "[":
                self.pos += 1
                key = self._parse_value()
                self._skip_ws()
                self._consume("]")
                self._skip_ws()
                self._consume("=")
                self._skip_ws()
                value = self._parse_value()
            elif peek is not None and _is_identifier_start(peek):
                ident = self._parse_identifier()
                self._skip_ws()
                if self._peek() == "=":
                    self.pos += 1
                    self._skip_ws()
                    key = ident
                    value = self._parse_value()
                else:
                    # Not actually a key – treat the identifier as a value.
                    self.pos = mark
                    value = self._parse_value()
            else:
                value = self._parse_value()

            if key is None:
                array.append(value)
            else:
                mapping[key] = value

            self._skip_ws()
            nxt = self._peek()
            if nxt in {",", ";"}:
                self.pos += 1
                continue
            if nxt == "}":
                self.pos += 1
                break
            if nxt is None:
                raise ValueError("Unterminated table constructor")
        return LuaTable(tuple(array), tuple((k, v) for k, v in mapping.items()))


def parse_lua_expression(text: str) -> Any:
    """Parse *text* as a Lua expression and return a Python representation."""

    parser = _LuaParser(text)
    return parser.parse()


def iter_table_entries(table: LuaTable) -> Iterable[Tuple[Any, Any]]:
    """Yield entries of a Lua table literal in a deterministic order."""

    for idx, value in enumerate(table.array, start=1):
        yield idx, value
    for key, value in table.mapping:
        yield key, value


def lua_literal_to_string(value: Any) -> str:
    """Serialize a Python value back into a Lua literal string."""

    if isinstance(value, LuaTable):
        parts: List[str] = []
        for key, item in iter_table_entries(value):
            if isinstance(key, int) and 1 <= key <= len(value.array):
                parts.append(lua_literal_to_string(item))
            else:
                parts.append(f"[{lua_literal_to_string(key)}]={lua_literal_to_string(item)}")
        return "{" + ",".join(parts) + "}"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
        return f'"{escaped}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "nil"
    return str(value)


__all__ = [
    "LuaTable",
    "iter_table_entries",
    "lua_literal_to_string",
    "parse_lua_expression",
]

