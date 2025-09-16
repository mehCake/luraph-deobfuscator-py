"""Post-processing cleanup helpers for decoded Lua sources."""

from __future__ import annotations

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


def _constant_fold(source: str) -> Tuple[str, bool]:
    decryptor = StringDecryptor()
    folded = decryptor.decrypt(source)
    return folded, folded != source


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

    text, removed_blocks = _simplify_conditionals(text)
    metadata["dead_code_blocks"] = removed_blocks

    text, do_return_removed = _strip_do_return(text)
    metadata["do_return_simplified"] = do_return_removed

    text, wrapper_removed = _unwrap_double_loadstrings(text)
    metadata["double_loadstrings"] = wrapper_removed

    text, trampolines_removed = _strip_trampolines(text)
    metadata["vm_trampolines"] = trampolines_removed

    cleaned = utils.decode_simple_obfuscations(text)
    cleaned = utils.strip_non_printable(cleaned)

    metadata["output_length"] = len(cleaned)
    metadata["changed"] = cleaned != ctx.stage_output

    ctx.stage_output = cleaned
    return metadata


__all__ = ["run"]

