from __future__ import annotations

"""Integration tests for the v14.3 standalone VM detection pipeline."""

from pathlib import Path
from typing import List

import re

from opcode_lifter import find_vm_loader_v14_3
from pattern_analyzer import PatternAnalyzer
from src.utils_pkg import ast as lua_ast
from src.detect_protections import scan_lua
from version_detector import VersionDetector, VersionFeature


HELPER_NAMES = ("o", "t3", "a3", "M", "r")


def _sanitize_numeric_literal(text: str) -> str:
    return text.replace("_", "")


def _parse_expression(expr: str) -> lua_ast.Expr:
    expr = expr.strip()
    if not expr:
        return lua_ast.Literal(None)
    if expr.endswith(")"):
        for helper in HELPER_NAMES:
            prefix = f"{helper}("
            if expr.startswith(prefix):
                args = _split_arguments(expr[len(prefix) : -1])
                return lua_ast.Call(
                    lua_ast.Name(helper),
                    [_parse_expression(arg) for arg in args],
                )
    table_match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\[(.+)\]", expr)
    if table_match:
        table = lua_ast.Name(table_match.group(1))
        key_expr = _parse_expression(table_match.group(2))
        return lua_ast.TableAccess(table, key_expr)
    literal = _sanitize_numeric_literal(expr)
    try:
        if literal.lower().startswith("0x") or literal.lower().startswith("0b"):
            return lua_ast.Literal(int(literal, 0))
        return lua_ast.Literal(int(literal, 10))
    except ValueError:
        pass
    return lua_ast.Name(expr.strip())


def _split_arguments(argument_text: str) -> List[str]:
    args: List[str] = []
    token: List[str] = []
    depth = 0
    for ch in argument_text:
        if ch in "({[":
            depth += 1
            token.append(ch)
        elif ch in ")}]":
            depth = max(0, depth - 1)
            token.append(ch)
        elif ch == "," and depth == 0:
            arg = "".join(token).strip()
            if arg:
                args.append(arg)
            token = []
        else:
            token.append(ch)
    tail = "".join(token).strip()
    if tail:
        args.append(tail)
    return args


FOR_HEADER_RE = re.compile(
    r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^,;]+?)\s*,\s*([^,;]+?)(?:\s*,\s*([^d;]+?))?\s*do",
    re.IGNORECASE,
)

TOKEN_RE = re.compile(r"\b(for|function|if|repeat|while|end|until)\b", re.IGNORECASE)


def _extract_block(text: str, start: int) -> tuple[str, int]:
    depth = 1
    position = start
    while True:
        match = TOKEN_RE.search(text, position)
        if match is None:
            raise ValueError("Unterminated block while parsing loader heuristics")
        keyword = match.group(1).lower()
        if keyword in {"for", "function", "if", "repeat", "while"}:
            depth += 1
        elif keyword in {"end", "until"}:
            depth -= 1
            if depth == 0:
                return text[start:match.start()], match.end()
        position = match.end()


def _split_statements(text: str) -> List[str]:
    statements: List[str] = []
    token: List[str] = []
    depth = 0
    for ch in text:
        if ch in "({[":
            depth += 1
            token.append(ch)
        elif ch in ")}]":
            depth = max(0, depth - 1)
            token.append(ch)
        elif ch == ";" and depth == 0:
            candidate = "".join(token).strip()
            if candidate:
                statements.append(candidate)
            token = []
        else:
            token.append(ch)
    tail = "".join(token).strip()
    if tail:
        statements.append(tail)
    return statements


def _find_call_end(text: str, start: int) -> int:
    depth = 0
    index = start
    while index < len(text):
        ch = text[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


def _clean_statement(statement: str) -> str:
    stmt = statement.strip()
    if not stmt:
        return stmt
    for keyword in ("then", "else", "elseif"):
        pattern = re.compile(rf"\b{keyword}\b", re.IGNORECASE)
        stmt = pattern.sub(";", stmt)
    stmt = stmt.replace("end", "")
    stmt = stmt.strip()
    return stmt


def _parse_statements(text: str) -> List[lua_ast.Stmt]:
    statements: List[lua_ast.Stmt] = []
    for raw in _split_statements(text):
        stmt = _clean_statement(raw)
        if not stmt:
            continue
        for helper in HELPER_NAMES:
            marker = f"{helper}("
            index = stmt.find(marker)
            if index == -1:
                continue
            paren = stmt.find("(", index)
            if paren == -1:
                continue
            end = _find_call_end(stmt, paren)
            call_text = stmt[index:end]
            call_expr = _parse_expression(call_text)
            prefix = stmt[:index].strip()
            if prefix.startswith("return"):
                statements.append(lua_ast.Return([call_expr]))
                break
            lhs, sep, _ = prefix.rpartition("=")
            if sep:
                target_text = lhs.strip()
                is_local = False
                if target_text.startswith("local "):
                    is_local = True
                    target_text = target_text[len("local ") :].strip()
                target_expr = _parse_expression(target_text)
                statements.append(
                    lua_ast.Assignment(
                        targets=[target_expr],
                        values=[call_expr],
                        is_local=is_local,
                    )
                )
            else:
                statements.append(lua_ast.CallStmt(call_expr))
            break
    return statements


def _parse_block(text: str) -> List[lua_ast.Stmt]:
    statements: List[lua_ast.Stmt] = []
    cursor = 0
    while cursor < len(text):
        match = FOR_HEADER_RE.search(text, cursor)
        if match is None:
            statements.extend(_parse_statements(text[cursor:]))
            break
        if match.start() > cursor:
            statements.extend(_parse_statements(text[cursor:match.start()]))
        body, end_index = _extract_block(text, match.end())
        start_expr = _parse_expression(match.group(2))
        stop_expr = _parse_expression(match.group(3))
        step_expr = _parse_expression(match.group(4) or "1")
        loop_body = _parse_block(body)
        if loop_body:
            statements.append(
                lua_ast.NumericFor(
                    var=match.group(1),
                    start=start_expr,
                    stop=stop_expr,
                    step=step_expr,
                    body=loop_body,
                )
            )
        cursor = end_index
    return statements


def _build_loader_ast(source: str) -> lua_ast.Chunk:
    region_start = source.find("P=(0X6c)")
    if region_start == -1:
        region_start = 0
    section = source[region_start:]
    statements = _parse_block(section)
    return lua_ast.Chunk(body=statements)


def test_v14_3_detection_pipeline() -> None:
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")

    detector = VersionDetector()
    version = detector.detect(source)
    assert version.name == VersionFeature.LURAPH_V14_3_VM.value

    protection = scan_lua(source, filename="Obfuscated4.lua")
    profile = protection.get("profile")
    assert profile is not None
    assert profile["vm_mode"] == "full"
    assert profile["string_encryption"] is True

    analyzer = PatternAnalyzer()
    chunk = analyzer.locate_serialized_chunk(source)
    assert chunk is not None

    loader_ast = _build_loader_ast(source)
    loader = find_vm_loader_v14_3(loader_ast)
    assert loader is not None
