"""Utilities for locating ``LPH`` payload blocks inside bootstrap sources."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Tuple

__all__ = ["LPHBlock", "scan_lph_blocks"]


@dataclass(frozen=True)
class LPHBlock:
    """Description of an ``LPH`` block discovered in a source file."""

    header: str
    text: str
    source: str
    span: Tuple[int, int]


_LONG_STRING_RE = re.compile(r"\[(?P<eq>=*)\[(?P<body>LPH[!~][\s\S]*?)\]\1\]", re.MULTILINE)
_INLINE_DOUBLE_RE = re.compile(r'"(?P<body>LPH[!~][^"\n\r]{80,})"')
_INLINE_SINGLE_RE = re.compile(r"'(?P<body>LPH[!~][^'\n\r]{80,})'")


def _iter_matches(pattern: re.Pattern[str], text: str) -> Iterable[Tuple[str, Tuple[int, int]]]:
    for match in pattern.finditer(text):
        body = match.group("body")
        if not body:
            continue
        span = match.span("body")
        yield body, span


def scan_lph_blocks(text: str, source: str = "unknown") -> List[LPHBlock]:
    """Return a list of ``LPH`` payload blocks discovered within *text*."""

    if not text:
        return []

    results: List[LPHBlock] = []
    seen: set[Tuple[int, int]] = set()

    for body, span in _iter_matches(_LONG_STRING_RE, text):
        if span in seen:
            continue
        seen.add(span)
        header = body[:4]
        results.append(LPHBlock(header=header, text=body, source=source, span=span))

    for pattern in (_INLINE_DOUBLE_RE, _INLINE_SINGLE_RE):
        for body, span in _iter_matches(pattern, text):
            if span in seen:
                continue
            seen.add(span)
            header = body[:4]
            results.append(LPHBlock(header=header, text=body, source=source, span=span))

    return sorted(results, key=lambda block: block.span[0])
