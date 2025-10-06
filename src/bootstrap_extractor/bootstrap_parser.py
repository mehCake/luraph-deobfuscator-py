"""Structured parser for bootstrap dispatch handler tables."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Dict, Iterator, List, Optional, Tuple

from src.vm.opcode_utils import (
    normalize_mnemonic,
    normalize_operand_model,
    operand_model_from_handler,
)

__all__ = [
    "OpcodeHandler",
    "BootstrapParseResult",
    "BootstrapParser",
]


@dataclass
class OpcodeHandler:
    """Metadata describing a single opcode handler."""

    opcode: int
    mnemonic: str
    operands: str
    trust: str
    source_snippet: str
    offset: int
    keyword_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class BootstrapParseResult:
    """Result produced by :class:`BootstrapParser`."""

    opcode_table: Dict[int, OpcodeHandler] = field(default_factory=dict)
    dispatch_name: Optional[str] = None


@dataclass
class _HandlerCandidate:
    opcode: int
    table: str
    args: List[str]
    body: str
    comment: Optional[str]
    offset: int


class BootstrapParser:
    """Parse initv4 bootstrap dispatch handlers into canonical metadata."""

    _DISPATCH_LOOP_RE = re.compile(
        r"for\s+[A-Za-z0-9_,\s]+\s+in\s+pairs\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        re.MULTILINE,
    )
    _TABLE_ASSIGN_RE = re.compile(
        r"(?P<table>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<opcode>0x[0-9A-Fa-f]+|\d+)\s*\]\s*=\s*function\s*\((?P<args>[^)]*)\)",
        re.MULTILINE,
    )
    _FUNC_REF_RE = re.compile(
        r"(?P<table>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<opcode>0x[0-9A-Fa-f]+|\d+)\s*\]\s*=\s*(?P<ref>[A-Za-z_][A-Za-z0-9_:\.]*)",
        re.MULTILINE,
    )

    _MNEMONIC_KEYWORDS: Dict[str, Tuple[str, ...]] = {
        "MOVE": ("move",),
        "LOADK": ("loadk", "const", "constant"),
        "CALL": ("call", "invoke"),
        "RETURN": ("return", "ret"),
        "CONCAT": ("concat", ".."),
        "GETTABLE": ("gettable", "[", "index"),
        "SETTABLE": ("settable", "store", "index"),
        "CLOSURE": ("closure", "proto"),
        "ADD": (" + ", "add"),
        "SUB": (" - ", "sub"),
        "MUL": (" * ", "mul"),
        "DIV": (" / ", "div"),
        "EQ": ("==", "eq"),
        "LT": ("<", "lt"),
        "JMP": ("jump", "jmp"),
    }

    def parse(self, text: str, script_key: Optional[str] = None) -> BootstrapParseResult:
        """Return canonical handler metadata extracted from *text*."""

        dispatch_name = self._detect_dispatch_name(text)
        handlers: Dict[int, OpcodeHandler] = {}

        for candidate in self._iter_handlers(text, dispatch_name):
            info = self._build_handler_info(candidate)
            handlers.setdefault(candidate.opcode, info)

        # Resolve function references assigned without inline definitions.
        for ref_candidate in self._iter_function_references(text, dispatch_name):
            if ref_candidate.opcode in handlers:
                continue
            info = self._build_handler_info(ref_candidate)
            handlers.setdefault(ref_candidate.opcode, info)

        return BootstrapParseResult(opcode_table=handlers, dispatch_name=dispatch_name)

    # ------------------------------------------------------------------
    def _detect_dispatch_name(self, text: str) -> Optional[str]:
        match = self._DISPATCH_LOOP_RE.search(text)
        if match:
            return match.group(1)
        # Fallback: locate a table initialiser that contains opcode style keys.
        table_match = re.search(
            r"local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{[^}]*\[\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\]",
            text,
        )
        if table_match:
            return table_match.group(1)
        return None

    # ------------------------------------------------------------------
    def _iter_handlers(
        self, text: str, dispatch_name: Optional[str]
    ) -> Iterator[_HandlerCandidate]:
        for match in self._TABLE_ASSIGN_RE.finditer(text):
            table = match.group("table")
            if dispatch_name and table != dispatch_name:
                continue
            opcode = int(match.group("opcode"), 0)
            args = [part.strip() for part in match.group("args").split(",") if part.strip()]
            start = match.start()
            local_block = match.group(0)
            func_relative = local_block.find("function")
            if func_relative == -1:
                continue
            func_index = start + func_relative
            if func_index == -1:
                continue
            body, end = self._consume_function(text, func_index)
            comment = self._extract_comment(text, end)
            yield _HandlerCandidate(
                opcode=opcode,
                table=table,
                args=args,
                body=body,
                comment=comment,
                offset=start,
            )

    # ------------------------------------------------------------------
    def _iter_function_references(
        self, text: str, dispatch_name: Optional[str]
    ) -> Iterator[_HandlerCandidate]:
        for match in self._FUNC_REF_RE.finditer(text):
            table = match.group("table")
            if dispatch_name and table != dispatch_name:
                continue
            opcode = int(match.group("opcode"), 0)
            ref = match.group("ref")
            resolved = self._locate_function_definition(text, ref)
            if resolved is None:
                continue
            yield _HandlerCandidate(
                opcode=opcode,
                table=table,
                args=resolved.args,
                body=resolved.body,
                comment=resolved.comment,
                offset=resolved.offset,
            )

    # ------------------------------------------------------------------
    def _build_handler_info(self, candidate: _HandlerCandidate) -> OpcodeHandler:
        keyword_counts = self._keyword_counts(candidate.body)
        raw_mnemonic, trust = self._infer_mnemonic(candidate, keyword_counts)
        mnemonic = normalize_mnemonic(raw_mnemonic) or raw_mnemonic or f"OPCODE_0x{candidate.opcode:02X}"
        if isinstance(mnemonic, str):
            mnemonic = mnemonic.upper()
        operands = operand_model_from_handler(candidate.body)
        if not operands:
            operands = normalize_operand_model(self._infer_operands(candidate.args, candidate.body))
        snippet = candidate.body.strip()
        if len(snippet) > 400:
            snippet = snippet[:397] + "..."
        return OpcodeHandler(
            opcode=candidate.opcode,
            mnemonic=mnemonic,
            operands=operands,
            trust=trust,
            source_snippet=snippet,
            offset=candidate.offset,
            keyword_counts=keyword_counts,
        )

    # ------------------------------------------------------------------
    def _keyword_counts(self, body: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        lower = body.lower()
        for mnemonic, patterns in self._MNEMONIC_KEYWORDS.items():
            total = 0
            for pattern in patterns:
                token = pattern.strip().lower()
                if token in {"+", "-", "*", "/", "==", "<", ".."}:
                    total += lower.count(token)
                elif token == "return":
                    total += len(re.findall(r"\breturn\b", lower))
                else:
                    total += lower.count(token)
            if total:
                counts[mnemonic] = total
        return counts

    # ------------------------------------------------------------------
    def _infer_mnemonic(
        self,
        candidate: _HandlerCandidate,
        keyword_counts: Dict[str, int],
    ) -> Tuple[str, str]:
        comment = (candidate.comment or "").strip()
        if comment:
            mnemonic = comment.split()[0].upper()
            trust = "high"
            return mnemonic, trust

        if keyword_counts:
            mnemonic = max(keyword_counts.items(), key=lambda item: (item[1], item[0]))[0]
            trust = "high" if keyword_counts[mnemonic] >= 2 else "medium"
            return mnemonic, trust

        return f"OPCODE_0x{candidate.opcode:02X}", "low"

    # ------------------------------------------------------------------
    def _infer_operands(self, args: List[str], body: str) -> str:
        if len(args) <= 1:
            return ""
        operand_args = [arg for arg in args[1:]]
        lowered = [arg.lower() for arg in operand_args]
        if any("sbx" in arg for arg in lowered):
            return "A sBx"
        if any("bx" in arg for arg in lowered):
            return "A Bx"
        rk_body = body.lower()
        if any(key in rk_body for key in ("rk", "isrk", "is_rk")) and len(operand_args) >= 3:
            return "A B C (RK)"
        if len(operand_args) >= 3:
            return "A B C"
        if len(operand_args) == 2:
            return "A B"
        return "A"

    # ------------------------------------------------------------------
    def _consume_function(self, text: str, start: int) -> Tuple[str, int]:
        depth = 0
        i = start
        limit = len(text)
        snippet_start = None
        while i < limit:
            if text[i] in {'"', "'"}:
                i = self._skip_string(text, i)
                continue
            if text.startswith("--", i):
                i = self._skip_comment_block(text, i)
                continue
            if self._is_word(text, i, "function"):
                if snippet_start is None:
                    snippet_start = i
                depth += 1
                i += len("function")
                continue
            if self._is_word(text, i, "end"):
                depth -= 1
                i += len("end")
                if depth <= 0:
                    end_index = i
                    start_index = snippet_start if snippet_start is not None else start
                    return text[start_index:end_index], end_index
                continue
            i += 1
        end_index = limit
        start_index = snippet_start if snippet_start is not None else start
        return text[start_index:end_index], end_index

    # ------------------------------------------------------------------
    def _skip_string(self, text: str, index: int) -> int:
        quote = text[index]
        i = index + 1
        limit = len(text)
        while i < limit:
            ch = text[i]
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                return i + 1
            i += 1
        return limit

    # ------------------------------------------------------------------
    def _skip_comment_block(self, text: str, index: int) -> int:
        # Handles both single-line and long comments best-effort.
        if text.startswith("--[[", index):
            end = text.find("]]", index + 4)
            if end == -1:
                return len(text)
            return end + 2
        end = text.find("\n", index)
        if end == -1:
            return len(text)
        return end + 1

    # ------------------------------------------------------------------
    def _is_word(self, text: str, index: int, word: str) -> bool:
        if not text.startswith(word, index):
            return False
        before = text[index - 1] if index > 0 else ""
        after = text[index + len(word)] if index + len(word) < len(text) else ""
        return (not before.isalnum() and before != "_") and (not after.isalnum() and after != "_")

    # ------------------------------------------------------------------
    def _extract_comment(self, text: str, index: int) -> Optional[str]:
        limit = len(text)
        i = index
        while i < limit and text[i] in {" ", "\t"}:
            i += 1
        if i < limit and text.startswith("--", i):
            end = text.find("\n", i)
            if end == -1:
                end = limit
            return text[i + 2 : end].strip()
        return None

    # ------------------------------------------------------------------
    def _locate_function_definition(
        self, text: str, name: str
    ) -> Optional[_HandlerCandidate]:
        pattern = re.compile(
            rf"(?:(?:local\s+)?function\s+{re.escape(name)}\s*\(([^)]*)\))",
        )
        match = pattern.search(text)
        if not match:
            return None
        args = [part.strip() for part in match.group(1).split(",") if part.strip()]
        body, end = self._consume_function(text, match.start())
        comment = self._extract_comment(text, end)
        return _HandlerCandidate(
            opcode=-1,
            table=name,
            args=args,
            body=body,
            comment=comment,
            offset=match.start(),
        )

