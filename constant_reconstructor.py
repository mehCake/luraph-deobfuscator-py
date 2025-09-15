"""Constant pool reconstruction for Luraph payloads."""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, Dict, List, Optional, Union

from lua_literal_parser import LuaTable, lua_literal_to_string, parse_lua_expression

LuaValue = Union[str, int, float, bool, None, LuaTable]


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


def _skip_short_string(text: str, index: int) -> int:
    quote = text[index]
    index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return len(text)


def _skip_long_string(text: str, index: int) -> int:
    match = re.match(r"\[=*\[", text[index:])
    if not match:
        return index + 1
    marker = match.group(0)
    equals = marker.count("=")
    closing = "]" + "=" * equals + "]"
    index += len(marker)
    end = text.find(closing, index)
    return len(text) if end == -1 else end + len(closing)


def _extract_braced_block(text: str, start: int) -> Tuple[str, int]:
    depth = 0
    index = start
    while index < len(text):
        ch = text[index]
        if ch == "{":
            depth += 1
            index += 1
            continue
        if ch == "}":
            depth -= 1
            index += 1
            if depth == 0:
                return text[start:index], index
            continue
        if ch in {'"', "'"}:
            index = _skip_short_string(text, index)
            continue
        if ch == "[" and text.startswith("[[", index):
            index = _skip_long_string(text, index)
            continue
        index += 1
    raise ValueError("Unbalanced braces in table literal")


class ConstantReconstructor:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self._string_cache: Dict[str, str] = {}
        self._table_cache: Dict[LuaTable, LuaTable] = {}

    # ------------------------------------------------------------------
    def decrypt_lph_encfunc(self, value: str, key: int) -> str:
        decoded_chars = [chr(ord(ch) ^ key) for ch in value]
        return self._intern("".join(decoded_chars))

    def decrypt_encrypted_pools(self, content: str) -> Dict[str, LuaValue]:
        pattern = re.compile(r'LPH_ENCFUNC\(([^,]+),\s*([^)]+)\)')
        constants: Dict[str, LuaValue] = {}
        for match in pattern.finditer(content):
            literal_text, key_text = match.groups()
            try:
                key_value = parse_lua_expression(key_text)
            except ValueError:
                continue
            if not isinstance(key_value, (int, float)):
                continue
            key = int(key_value)
            literal_text = literal_text.strip()
            try:
                literal = parse_lua_expression(literal_text)
            except ValueError:
                continue
            if isinstance(literal, str):
                constants[match.group(0)] = self.decrypt_lph_encfunc(literal, key)
            elif isinstance(literal, (int, float)):
                constants[match.group(0)] = int(literal) ^ key
        return constants

    # ------------------------------------------------------------------
    def _intern(self, value: str) -> str:
        return self._string_cache.setdefault(value, sys.intern(value))

    def _intern_value(self, value: LuaValue) -> LuaValue:
        if isinstance(value, str):
            return self._intern(value)
        if isinstance(value, LuaTable):
            array = tuple(self._intern_value(item) for item in value.array)
            mapping = tuple((self._intern_value(key) if isinstance(key, str) else key,
                             self._intern_value(item)) for key, item in value.mapping)
            table = LuaTable(array, mapping)
            return self._table_cache.setdefault(table, table)
        return value

    def _format_literal(self, value: LuaValue) -> str:
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "nil"
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        if isinstance(value, LuaTable):
            return lua_literal_to_string(value)
        return str(value)

    # ------------------------------------------------------------------
    def _collect_constant_tables(self, content: str) -> Dict[str, LuaTable]:
        tables: Dict[str, LuaTable] = {}
        pattern = re.compile(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{')
        for match in pattern.finditer(content):
            name = match.group(1)
            start = match.end() - 1
            try:
                literal, end = _extract_braced_block(content, start)
            except ValueError:
                continue
            try:
                parsed = parse_lua_expression(literal)
            except ValueError:
                continue
            if isinstance(parsed, LuaTable):
                tables[name] = self._intern_value(parsed)  # type: ignore[arg-type]
        return tables

    def _inline_table_lookups(
        self, content: str, tables: Dict[str, LuaTable], replacements: Dict[str, str]
    ) -> str:
        for name, table in tables.items():
            pattern = re.compile(rf'{re.escape(name)}((?:\s*\[\s*[^\]]+\s*\])+)', re.MULTILINE)

            def repl(match: re.Match[str]) -> str:
                suffix = match.group(1)
                indices = re.findall(r'\[\s*([^\]]+)\s*\]', suffix)
                value: LuaValue = table
                for index_text in indices:
                    try:
                        key = parse_lua_expression(index_text)
                    except ValueError:
                        return match.group(0)
                    if isinstance(key, float) and key.is_integer():
                        key = int(key)
                    if isinstance(value, LuaTable):
                        try:
                            value = value.get(key)
                        except KeyError:
                            return match.group(0)
                    else:
                        return match.group(0)
                if isinstance(value, LuaTable):
                    return match.group(0)
                literal = self._format_literal(value)
                replacements.setdefault(match.group(0), literal)
                return literal

            content = pattern.sub(repl, content)
        return content

    # ------------------------------------------------------------------
    def extract_string_constants(self, content: str) -> Dict[str, str]:
        constants: Dict[str, str] = {}

        char_pattern = re.compile(r'string\.char\(([^)]+)\)')

        for match in char_pattern.finditer(content):
            args = _split_args(match.group(1))
            try:
                chars = [chr(int(parse_lua_expression(arg))) for arg in args]
            except Exception:
                continue
            literal = self._intern("".join(chars))
            constants[match.group(0)] = self._format_literal(literal)

        concat_pattern = re.compile(r'table\.concat\((\{[^}]+\})\)')

        for match in concat_pattern.finditer(content):
            try:
                table_value = parse_lua_expression(match.group(1))
            except ValueError:
                continue
            if not isinstance(table_value, LuaTable):
                continue
            joined: List[str] = []
            for idx in range(1, len(table_value.array) + 1):
                try:
                    value = table_value.get(idx)
                except KeyError:
                    continue
                if isinstance(value, str):
                    joined.append(value)
            if not joined:
                continue
            literal = self._intern("".join(joined))
            constants[match.group(0)] = self._format_literal(literal)

        for source, value in self.decrypt_encrypted_pools(content).items():
            if isinstance(value, str):
                constants[source] = self._format_literal(value)

        return constants

    def extract_numeric_constants(self, content: str) -> Dict[str, Union[int, float]]:
        constants: Dict[str, Union[int, float]] = {}
        for match in re.finditer(r'0[xX][0-9a-fA-F]+', content):
            literal = match.group(0)
            try:
                constants[literal] = int(literal, 16)
            except ValueError:
                continue
        for source, value in self.decrypt_encrypted_pools(content).items():
            if isinstance(value, (int, float)):
                constants[source] = value
        return constants

    # ------------------------------------------------------------------
    def reconstruct(self, content: str, patterns: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        replacements: Dict[str, str] = {}
        updated = content

        pool_constants = self.decrypt_encrypted_pools(updated)
        if pool_constants:
            def repl(match: re.Match[str]) -> str:
                original = match.group(0)
                value = pool_constants.get(original)
                if value is None:
                    return original
                literal = self._format_literal(value)
                replacements.setdefault(original, literal)
                return literal

            pattern = re.compile(r'LPH_ENCFUNC\(([^,]+),\s*([^)]+)\)')
            updated = pattern.sub(repl, updated)

        tables = self._collect_constant_tables(updated)
        if tables:
            updated = self._inline_table_lookups(updated, tables, replacements)

        string_constants = self.extract_string_constants(content)
        numeric_constants = self.extract_numeric_constants(content)

        for src, literal in string_constants.items():
            updated = updated.replace(src, literal)
        for src, value in numeric_constants.items():
            replacement = str(value)
            updated = updated.replace(src, replacement)

        return {
            "content": updated,
            "constants": {
                "strings": string_constants,
                "numbers": numeric_constants,
                "tables": tables,
                "replacements": replacements,
            },
        }

    def reconstruct_all_constants(self, content: str) -> Dict[str, Any]:
        result = self.reconstruct(content, None)
        constants = result["constants"]
        summary = {
            "total_strings": len(constants["strings"]),
            "total_numbers": len(constants["numbers"]),
            "total_tables": len(constants["tables"]),
            "total_inlined": len(constants["replacements"]),
        }
        constants["summary"] = summary
        return constants

