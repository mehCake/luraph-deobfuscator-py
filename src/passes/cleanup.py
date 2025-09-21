"""Post-processing cleanup helpers for decoded Lua sources."""

from __future__ import annotations

import ast
import math
import operator
import re
from typing import Dict, Tuple, TYPE_CHECKING

from string_decryptor import StringDecryptor

from .. import utils

if TYPE_CHECKING:  # pragma: no cover - typing hook only
    from ..pipeline import Context


_IF_FALSE_ELSE_RE = re.compile(
    r"if\s+(?:false|0|nil)\s+then\s*(?P<if_body>.*?)\s*else\s*(?P<else_body>.*?)\s*end",
    re.IGNORECASE | re.DOTALL,
)

_IF_FALSE_RE = re.compile(
    r"if\s+(?:false|0|nil)\s+then\s*(?P<body>.*?)\s*end",
    re.IGNORECASE | re.DOTALL,
)

_IF_TRUE_RE = re.compile(
    r"if\s+true\s+then\s*(?P<body>.*?)\s*end",
    re.IGNORECASE | re.DOTALL,
)

_DOUBLE_LOADSTRING_RE = re.compile(
    r"(?:loadstring|load)\s*\(\s*(?:loadstring|load)\s*\(\s*([\"\'])"
    r"(?P<payload>.*?)\1\s*\)\s*\)\s*\(\s*\)",
    re.DOTALL,
)

_TRAMPOLINE_RE = re.compile(
    r"(?P<full>(?:local\s+)?function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*"
    r"return\s+(?P<target>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)\s*end)",
    re.DOTALL,
)

_DO_RETURN_RE = re.compile(r"\bdo\s+return\s+end\b", re.IGNORECASE)

_SCRIPT_KEY_ASSIGN_RE = re.compile(
    r"^\s*(?:local\s+)?script_key\s*=\s*script_key\b[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)

_INIT_FN_ASSIGN_RE = re.compile(
    r"^\s*local\s+init_fn\s*=\s*function\s*\([^)]*\)\s*(?:.|\n)*?\bend\b",
    re.IGNORECASE | re.MULTILINE,
)

_INIT_FN_DEF_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+init_fn\s*\([^)]*\)\s*(?:.|\n)*?\bend\b",
    re.IGNORECASE | re.MULTILINE,
)

_INIT_FN_CALL_RE = re.compile(
    r"^\s*return\s+init_fn\s*\([^\n]*\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_DUMMY_LOOP_RE = re.compile(
    r"while\s+true\s+do\s*(?:--[^\n]*\n|\s)*(?:break\s*;?\s*)+(?:--[^\n]*\n|\s)*end",
    re.IGNORECASE,
)

_IDLE_LOOP_RE = re.compile(
    r"while\s+true\s+do\s*(?:--[^\n]*\n|\s)*(?:(?:task\.)?wait\s*\([^)]*\)\s*;?\s*)*(?:--[^\n]*\n|\s)*end",
    re.IGNORECASE,
)

_REPEAT_FALSE_RE = re.compile(
    r"repeat\s*(?:--[^\n]*\n|\s)*until\s+false",
    re.IGNORECASE,
)

_ASSERT_FALSE_RE = re.compile(
    r"assert\s*\(\s*false\b[^)]*\)\s*;?",
    re.IGNORECASE,
)

_SIMPLE_DO_BLOCK_RE = re.compile(
    r"\bdo\s+(?P<body>[^\n]+?)\s+end\b",
    re.IGNORECASE,
)

_ALLOWED_EXPR_CHARS = set("0123456789+-*/%.() \t\r\n")

_CONST_EXPR_RE = re.compile(r"(?P<expr>(?:[-+*/%().0-9]+\s*){2,})")

_ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}

_ALLOWED_UNOPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _constant_fold(source: str) -> Tuple[str, bool]:
    decryptor = StringDecryptor()
    folded = decryptor.decrypt(source)
    return folded, folded != source


def _evaluate_constant_expression(expr: str) -> str | None:
    stripped = expr.strip()
    if not stripped or set(stripped) - _ALLOWED_EXPR_CHARS:
        return None

    try:
        tree = ast.parse(stripped, mode="eval")
    except SyntaxError:
        return None

    def _eval(node: ast.AST) -> float | int:
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNOPS:
            return _ALLOWED_UNOPS[type(node.op)](_eval(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINOPS:
            left = _eval(node.left)
            right = _eval(node.right)
            return _ALLOWED_BINOPS[type(node.op)](left, right)
        raise ValueError("Unsupported expression node")

    try:
        value = _eval(tree)
    except (ValueError, ZeroDivisionError, OverflowError):
        return None

    if isinstance(value, bool):  # bool is a subclass of int
        return None
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        if value.is_integer():
            value = int(value)
        else:
            return format(value, ".10g")
    return str(value)


def _fold_constant_expressions(source: str) -> Tuple[str, int]:
    folded = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal folded
        expr = match.group("expr")
        core = expr.strip()
        if not core or not any(op in core for op in "+-*/%"):
            return expr
        start, end = match.span()
        leading_ws = len(expr) - len(expr.lstrip())
        trailing_ws = len(expr) - len(expr.rstrip())
        if start > 0 and leading_ws == 0:
            before = match.string[start - 1]
            if not before.isspace() and (before.isalnum() or before == "_"):
                return expr
        if end < len(match.string) and trailing_ws == 0:
            after = match.string[end]
            if not after.isspace() and (after.isalnum() or after == "_"):
                return expr
        evaluated = _evaluate_constant_expression(core)
        if evaluated is None:
            return expr
        folded += 1
        prefix = expr[:leading_ws] if leading_ws else ""
        suffix = expr[len(expr) - trailing_ws :] if trailing_ws else ""
        return f"{prefix}{evaluated}{suffix}"

    updated = _CONST_EXPR_RE.sub(_replace, source)
    return updated, folded


def _simplify_conditionals(source: str) -> Tuple[str, int]:
    removed = 0

    def _replace_false_else(match: re.Match[str]) -> str:
        nonlocal removed
        if_body = match.group("if_body")
        else_body = match.group("else_body")
        if any(keyword in if_body for keyword in ("if ", "function", "while ", "repeat ", "for ")):
            return match.group(0)
        removed += 1
        return else_body

    def _replace_false(match: re.Match[str]) -> str:
        nonlocal removed
        body = match.group("body")
        if "else" in body:
            return match.group(0)
        if any(keyword in body for keyword in ("if ", "function", "while ", "repeat ", "for ")):
            return match.group(0)
        removed += 1
        return ""

    def _replace_true(match: re.Match[str]) -> str:
        nonlocal removed
        body = match.group("body")
        if "else" in body:
            return match.group(0)
        removed += 1
        return body

    updated = _IF_FALSE_ELSE_RE.sub(_replace_false_else, source)
    updated = _IF_FALSE_RE.sub(_replace_false, updated)
    updated = _IF_TRUE_RE.sub(_replace_true, updated)
    return updated, removed


def _unwrap_double_loadstrings(source: str) -> Tuple[str, int]:
    replaced = 0

    def _rewrite(match: re.Match[str]) -> str:
        nonlocal replaced
        quote = match.group(1)
        payload = match.group("payload")
        try:
            inner = bytes(payload, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            inner = payload
        escaped = inner.replace("\\", "\\\\").replace(quote, f"\\{quote}")
        replaced += 1
        return f"loadstring({quote}{escaped}{quote})()"

    rewritten, _ = _DOUBLE_LOADSTRING_RE.subn(_rewrite, source)
    return rewritten, replaced


def _strip_trampolines(source: str) -> Tuple[str, int]:
    removed = 0

    def _rewrite(match: re.Match[str]) -> str:
        nonlocal removed
        params = [p.strip() for p in match.group("params").split(",") if p.strip()]
        args = [a.strip() for a in match.group("args").split(",") if a.strip()]
        if params == args or (params == ["..."] and args == ["..."]):
            removed += 1
            return ""
        if not params and not args:
            removed += 1
            return ""
        return match.group("full")

    rewritten, _ = _TRAMPOLINE_RE.subn(_rewrite, source)
    return rewritten, removed


def _strip_do_return(source: str) -> Tuple[str, int]:
    rewritten, count = _DO_RETURN_RE.subn("return", source)
    return rewritten, count


def _strip_script_key(source: str) -> Tuple[str, int]:
    rewritten, count = _SCRIPT_KEY_ASSIGN_RE.subn("", source)
    return rewritten, count


def _strip_init_fn(source: str) -> Tuple[str, int]:
    removed = 0

    def _rewrite_assign(match: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return ""

    updated = _INIT_FN_ASSIGN_RE.sub(_rewrite_assign, source)

    def _rewrite_func(match: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return ""

    updated = _INIT_FN_DEF_RE.sub(_rewrite_func, updated)
    return updated, removed


def _strip_init_fn_calls(source: str) -> Tuple[str, int]:
    rewritten, count = _INIT_FN_CALL_RE.subn("", source)
    return rewritten, count


def _strip_dummy_loops(source: str) -> Tuple[str, int]:
    removed = 0

    def _rewrite(match: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return ""

    rewritten = _DUMMY_LOOP_RE.sub(_rewrite, source)
    rewritten = _IDLE_LOOP_RE.sub(_rewrite, rewritten)
    rewritten = _REPEAT_FALSE_RE.sub(_rewrite, rewritten)
    return rewritten, removed


def _strip_assert_traps(source: str) -> Tuple[str, int]:
    removed = 0

    def _rewrite(match: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return ""

    rewritten = _ASSERT_FALSE_RE.sub(_rewrite, source)
    return rewritten, removed


def _flatten_simple_do_blocks(source: str) -> Tuple[str, int]:
    flattened = 0

    def _rewrite(match: re.Match[str]) -> str:
        nonlocal flattened
        body = match.group("body").strip()
        if not body:
            flattened += 1
            return ""
        if re.search(r"\b(local|function|for|while|repeat|if|elseif|else|do)\b", body):
            return match.group(0)
        flattened += 1
        return body

    rewritten = _SIMPLE_DO_BLOCK_RE.sub(_rewrite, source)
    return rewritten, flattened


def run(ctx: "Context") -> Dict[str, object]:
    ctx.ensure_raw_input()
    text = ctx.stage_output or ctx.working_text or ctx.raw_input
    if not text:
        ctx.stage_output = ""
        return {"empty": True}

    metadata: Dict[str, object] = {"input_length": len(text)}

    folded, changed = _constant_fold(text)
    metadata["constant_folded"] = changed
    text = folded

    text, const_expr = _fold_constant_expressions(text)
    metadata["constant_expressions"] = const_expr

    text, removed_blocks = _simplify_conditionals(text)
    metadata["dead_code_blocks"] = removed_blocks

    text, do_return_removed = _strip_do_return(text)
    metadata["do_return_simplified"] = do_return_removed

    text, wrapper_removed = _unwrap_double_loadstrings(text)
    metadata["double_loadstrings"] = wrapper_removed

    text, trampolines_removed = _strip_trampolines(text)
    metadata["vm_trampolines"] = trampolines_removed

    text, script_key_removed = _strip_script_key(text)
    metadata["bootstrap_keys"] = script_key_removed

    text, init_fn_removed = _strip_init_fn(text)
    metadata["bootstrap_init_fn"] = init_fn_removed

    text, init_fn_calls_removed = _strip_init_fn_calls(text)
    metadata["bootstrap_init_call"] = init_fn_calls_removed

    text, assert_traps_removed = _strip_assert_traps(text)
    metadata["assert_traps"] = assert_traps_removed

    text, dummy_loops_removed = _strip_dummy_loops(text)
    metadata["dummy_loops"] = dummy_loops_removed

    text, flattened_blocks = _flatten_simple_do_blocks(text)
    metadata["flattened_blocks"] = flattened_blocks

    cleaned = utils.decode_simple_obfuscations(text)
    cleaned = utils.strip_non_printable(cleaned)

    metadata["output_length"] = len(cleaned)
    metadata["changed"] = cleaned != ctx.stage_output

    ctx.stage_output = cleaned
    return metadata


__all__ = ["run"]

