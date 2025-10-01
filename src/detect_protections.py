"""Static detection heuristics for common Luraph protection techniques."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

# Regular expression patterns for each protection type. Patterns are compiled lazily at
# module import so unit tests pay a fixed cost.
_XOR_PATTERNS: Sequence[tuple[str, str]] = (
    (r"\bbit32\.bxor\b", "bit32_bxor"),
    (r"\bbxor\s*\(", "bxor_call"),
    (r"[\w\[\]]+\s*=\s*[\w\[\]]+\s*\^\s*\w+", "caret_xor"),
    (r"\w+\s*=\s*\w+\s*~\s*\w+", "tilde_xor"),
)

_COMPRESSION_PATTERNS: Sequence[tuple[str, str]] = (
    (r"zlib", "zlib"),
    (r"inflate", "inflate"),
    (r"uncompress", "uncompress"),
    (r"string\.unpack", "string_unpack"),
    (r"string\.pack", "string_pack"),
)

_GENERATION_PATTERNS: Sequence[tuple[str, str]] = (
    (r"string\.char", "string_char"),
    (r"load(string|buffer|file|string)", "load_call"),
    (r"table\.concat", "table_concat"),
)

_RANDOMNESS_PATTERNS: Sequence[tuple[str, str]] = (
    (r"math\.randomseed", "math_randomseed"),
    (r"os\.time", "os_time"),
    (r"crypto\.random", "crypto_random"),
    (r"script_key", "script_key_usage"),
)

_FRAGMENT_PATTERNS: Sequence[tuple[str, str]] = (
    (r"segments", "segments"),
    (r"chunks", "chunks"),
    (r"parts", "parts"),
    (r"for\s+\w+\s*=\s*1,\s*#\w+\s+do", "reassembly_loop"),
)

_JUNK_PATTERNS: Sequence[tuple[str, str]] = (
    (r"OP_?NOP", "explicit_nop"),
    (r"handlers?\s*\[[^\]]+\]\s*=\s*function\s*\([^)]*\)\s*return", "return_handler"),
    (r"\{\s*\[(\d+)\]\s*=\s*nil", "nil_table"),
)

_ANTITRACE_PATTERNS: Sequence[tuple[str, str]] = (
    (r"debug\.getinfo", "debug_getinfo"),
    (r"debug\.sethook", "debug_sethook"),
    (r"jit\.status", "jit_status"),
    (r"os\.execute", "os_execute"),
)

# Each protection category is mapped to the set of pattern groups tested above.
_CATEGORY_PATTERNS = {
    "xor": _XOR_PATTERNS,
    "compression": _COMPRESSION_PATTERNS,
    "dynamic_generation": _GENERATION_PATTERNS,
    "randomisation": _RANDOMNESS_PATTERNS,
    "fragmentation": _FRAGMENT_PATTERNS,
    "junk_ops": _JUNK_PATTERNS,
    "anti_trace": _ANTITRACE_PATTERNS,
}


@dataclass(frozen=True)
class DetectionEvidence:
    """A single detection result."""

    category: str
    pattern_id: str
    snippet: str
    filename: str

    def to_json(self) -> dict:
        return {
            "category": self.category,
            "pattern": self.pattern_id,
            "snippet": self.snippet,
            "filename": self.filename,
        }


def _find_matches(source: str, filename: str, patterns: Sequence[tuple[str, str]], category: str) -> List[DetectionEvidence]:
    evidence: List[DetectionEvidence] = []
    for pattern, pattern_id in patterns:
        regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        for match in regex.finditer(source):
            snippet = match.group(0)
            if len(snippet) > 160:
                snippet = snippet[:160] + "…"
            evidence.append(DetectionEvidence(category, pattern_id, snippet, filename))
    return evidence


def scan_lua(source: str, *, filename: str = "<memory>") -> dict:
    """Scan a Lua script and return structured protection evidence."""

    findings: List[DetectionEvidence] = []
    for category, patterns in _CATEGORY_PATTERNS.items():
        findings.extend(_find_matches(source, filename, patterns, category))

    categories = sorted({item.category for item in findings})
    result = {
        "protection_detected": bool(categories),
        "types": categories,
        "evidence": [item.to_json() for item in findings],
    }
    return result


def scan_files(paths: Iterable[Path]) -> dict:
    """Scan a list of Lua files and aggregate evidence."""

    combined: List[DetectionEvidence] = []
    for path in paths:
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        per_file = scan_lua(data, filename=path.as_posix())
        for item in per_file["evidence"]:
            combined.append(
                DetectionEvidence(
                    item["category"],
                    item["pattern"],
                    item["snippet"],
                    item["filename"],
                )
            )

    categories = sorted({item.category for item in combined})
    return {
        "protection_detected": bool(categories),
        "types": categories,
        "evidence": [item.to_json() for item in combined],
    }


def dump_report(paths: Iterable[Path], output: Path) -> None:
    """Write detection results to ``output`` as JSON."""

    report = scan_files(paths)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


__all__ = ["scan_lua", "scan_files", "dump_report"]
