"""Static handler comparison and signature heuristics for Luraph VMs."""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from math import log2
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

LOGGER = logging.getLogger(__name__)

__all__ = [
    "HandlerPattern",
    "HandlerComparison",
    "HandlerFingerprint",
    "HandlerCandidate",
    "HandlerSuggestion",
    "DEFAULT_PATTERNS",
    "fingerprint_bytes",
    "compare_handler_bytes",
    "analyse_handler_source",
    "analyse_handler_map",
    "emit_handler_suggestions",
    "extract_function_bodies",
    "main",
]


@dataclass(frozen=True)
class HandlerPattern:
    """Describe the expected characteristics of a known handler implementation."""

    mnemonic: str
    min_length: int = 0
    max_length: int | None = None
    unique_range: tuple[int, int] | None = None
    entropy_range: tuple[float, float] | None = None
    prefix: bytes = b""
    suffix: bytes = b""
    notes: str = ""


@dataclass(frozen=True)
class HandlerFingerprint:
    """Simple statistical view over a handler byte sequence."""

    length: int
    unique_bytes: int
    entropy: float
    prefix: bytes
    suffix: bytes


@dataclass(frozen=True)
class HandlerComparison:
    """Outcome of comparing a handler fingerprint against a known pattern."""

    mnemonic: str
    score: float
    reasons: Sequence[str]


@dataclass(frozen=True)
class HandlerCandidate:
    """Represents a mnemonic guess along with scoring evidence."""

    mnemonic: str
    confidence: float
    reasons: Sequence[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "mnemonic": self.mnemonic,
            "confidence": round(self.confidence, 3),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class HandlerSuggestion:
    """Suggestion bundle for a handler discovered in bootstrap code."""

    name: str
    opcode: Optional[int]
    candidates: Sequence[HandlerCandidate]
    resolvable: bool
    reasons: Sequence[str] = ()

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "name": self.name,
            "resolvable": self.resolvable,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }
        if self.opcode is not None:
            payload["opcode"] = self.opcode
        if self.reasons:
            payload["notes"] = list(self.reasons)
        return payload


def _shannon_entropy(counter: Counter[int], length: int) -> float:
    if length == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * log2(probability)
    return entropy


def fingerprint_bytes(blob: bytes) -> HandlerFingerprint:
    """Return a :class:`HandlerFingerprint` describing the *blob* byte statistics."""

    counter = Counter(blob)
    length = len(blob)
    entropy = _shannon_entropy(counter, length)
    prefix = blob[:8]
    suffix = blob[-8:] if blob else b""
    return HandlerFingerprint(
        length=length,
        unique_bytes=len(counter),
        entropy=entropy,
        prefix=prefix,
        suffix=suffix,
    )


DEFAULT_PATTERNS: Sequence[HandlerPattern] = (
    HandlerPattern(
        mnemonic="LOADK",
        min_length=12,
        max_length=96,
        unique_range=(4, 48),
        entropy_range=(1.5, 5.5),
        notes="Loads a constant into a stack slot; typically short with moderate entropy.",
    ),
    HandlerPattern(
        mnemonic="CALL",
        min_length=64,
        unique_range=(8, 192),
        entropy_range=(2.4, 6.8),
        notes="Function call handler tends to be long with varied byte usage.",
    ),
    HandlerPattern(
        mnemonic="RETURN",
        min_length=8,
        max_length=72,
        unique_range=(4, 80),
        entropy_range=(1.2, 5.0),
        notes="Return handler copies stack slots back to the caller.",
    ),
    HandlerPattern(
        mnemonic="JMP",
        min_length=4,
        max_length=48,
        unique_range=(2, 48),
        entropy_range=(0.8, 4.5),
        notes="Jump handler adjusts the program counter; usually tiny.",
    ),
    HandlerPattern(
        mnemonic="EQ",
        min_length=24,
        max_length=80,
        unique_range=(6, 64),
        entropy_range=(1.8, 6.2),
        notes="Equality handler compares two stack slots and branches.",
    ),
)


def _score_pattern(fingerprint: HandlerFingerprint, pattern: HandlerPattern, blob: bytes) -> HandlerComparison:
    score = 0.0
    reasons: List[str] = []

    length = fingerprint.length
    if length >= pattern.min_length:
        score += 0.25
        reasons.append(f"length≥{pattern.min_length}")
    else:
        reasons.append(f"length<{pattern.min_length}")
    if pattern.max_length is not None:
        if length <= pattern.max_length:
            score += 0.2
            reasons.append(f"length≤{pattern.max_length}")
        else:
            reasons.append(f"length>{pattern.max_length}")

    unique = fingerprint.unique_bytes
    if pattern.unique_range is not None:
        low, high = pattern.unique_range
        if low <= unique <= high:
            score += 0.2
            reasons.append(f"unique[{unique}] in {low}..{high}")
        else:
            reasons.append(f"unique[{unique}] outside {low}..{high}")

    if pattern.entropy_range is not None:
        low, high = pattern.entropy_range
        entropy = fingerprint.entropy
        if low <= entropy <= high:
            score += 0.2
            reasons.append(f"entropy {entropy:.2f} in {low:.1f}..{high:.1f}")
        else:
            reasons.append(f"entropy {entropy:.2f} outside {low:.1f}..{high:.1f}")

    if pattern.prefix and blob.startswith(pattern.prefix):
        score += 0.1
        reasons.append("prefix match")
    if pattern.suffix and blob.endswith(pattern.suffix):
        score += 0.05
        reasons.append("suffix match")

    score = min(score, 1.0)
    return HandlerComparison(mnemonic=pattern.mnemonic, score=score, reasons=tuple(reasons))


def compare_handler_bytes(
    blob: bytes,
    patterns: Sequence[HandlerPattern] = DEFAULT_PATTERNS,
    *,
    min_score: float = 0.3,
) -> List[HandlerComparison]:
    """Return a sorted list of pattern comparisons for the given *blob*.

    The resulting list is sorted by descending score.  Only comparisons whose
    score meets or exceeds *min_score* are returned.  The comparison is purely
    heuristic and should be used to guide manual analysis rather than replace it.
    """

    fingerprint = fingerprint_bytes(blob)
    results: List[HandlerComparison] = []
    for pattern in patterns:
        comparison = _score_pattern(fingerprint, pattern, blob)
        if comparison.score >= min_score:
            results.append(comparison)
    results.sort(key=lambda item: item.score, reverse=True)
    return results


_FUNCTION_PATTERN = re.compile(
    r"(?:\blocal\s+)?function\s+(?P<name>[A-Za-z_][\w\.]*)\s*\("
    r"|(?:\blocal\s+)?(?P<assign>[A-Za-z_][\w\.]*)\s*=\s*function\s*\(",
    re.IGNORECASE,
)

_TOKEN_PATTERN = re.compile(r"\b(function|end)\b")
_STACK_ASSIGN_PATTERN = re.compile(r"stack\s*\[[^\]]+\]\s*=", re.IGNORECASE)
_STACK_CALL_PATTERN = re.compile(r"stack\s*\[[^\]]+\]\s*\(", re.IGNORECASE)
_CONST_PATTERN = re.compile(r"const(?:ants)?\s*\[[^\]]+\]", re.IGNORECASE)
_PC_UPDATE_PATTERN = re.compile(r"pc\s*=\s*pc\s*[+\-]", re.IGNORECASE)
_PC_SET_PATTERN = re.compile(r"pc\s*=\s*[^\n;]+", re.IGNORECASE)
_RETURN_PATTERN = re.compile(r"\breturn\b", re.IGNORECASE)
_EQ_PATTERN = re.compile(r"==|~=", re.IGNORECASE)
_IF_PATTERN = re.compile(r"\bif\b", re.IGNORECASE)
_BIT32_PATTERN = re.compile(r"\bbit32\.", re.IGNORECASE)
_MATH_PATTERN = re.compile(r"\bmath\.", re.IGNORECASE)
_TOP_PATTERN = re.compile(r"\btop\s*=", re.IGNORECASE)
_TABLE_MOVE_PATTERN = re.compile(r"table\.move", re.IGNORECASE)


def extract_function_bodies(text: str) -> MutableMapping[str, str]:
    """Extract named function bodies from ``text``.

    The parser is intentionally lightweight: it tokenises ``function``/``end``
    keywords and keeps track of nesting to recover the body for each named
    handler definition.  It ignores anonymous or immediately invoked functions
    because Luraph handler dispatchers typically rely on named helpers.
    """

    functions: MutableMapping[str, str] = {}
    for match in _FUNCTION_PATTERN.finditer(text):
        name = match.group("name") or match.group("assign")
        if not name:
            continue
        body_start = match.end()
        end_index = _locate_matching_end(text, body_start)
        if end_index is None:
            LOGGER.debug("Could not locate end for function %s", name)
            continue
        body = text[body_start:end_index]
        functions[name] = body.strip()
    return functions


def _locate_matching_end(text: str, index: int) -> Optional[int]:
    depth = 1
    for token in _TOKEN_PATTERN.finditer(text, index):
        value = token.group(1)
        if value.lower() == "function":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return token.start()
    return None


def _extract_features(body: str) -> set[str]:
    features: set[str] = set()
    lowered = body.lower()
    if _STACK_ASSIGN_PATTERN.search(body):
        features.add("stack_store")
    if _STACK_CALL_PATTERN.search(body):
        features.add("stack_call")
    if _CONST_PATTERN.search(lowered):
        features.add("constants")
    if _PC_UPDATE_PATTERN.search(lowered):
        features.add("pc_relative")
    if _PC_SET_PATTERN.search(lowered):
        features.add("pc_set")
    if _RETURN_PATTERN.search(lowered):
        features.add("return")
    if _EQ_PATTERN.search(body) and _IF_PATTERN.search(lowered):
        features.add("compare")
    if _BIT32_PATTERN.search(lowered):
        features.add("bit32")
    if _MATH_PATTERN.search(lowered):
        features.add("math")
    if _TOP_PATTERN.search(lowered):
        features.add("top_adjust")
    if _TABLE_MOVE_PATTERN.search(lowered):
        features.add("table_move")
    return features


def _score_candidates(
    name: str,
    body: str,
    *,
    version_hint: Optional[str],
) -> List[HandlerCandidate]:
    features = _extract_features(body)
    candidates: List[HandlerCandidate] = []
    base_reasons: Dict[str, List[str]] = {}
    scores: Dict[str, float] = {}

    def bump(candidate: str, amount: float, reason: str) -> None:
        scores.setdefault(candidate, 0.0)
        scores[candidate] += amount
        base_reasons.setdefault(candidate, []).append(reason)

    if "stack_store" in features and "constants" in features:
        bump("LOADK", 0.45, "stack writes constant pool value")
    if "table_move" in features and "constants" in features:
        bump("LOADK", 0.15, "table.move used with constants")
    if "stack_call" in features:
        bump("CALL", 0.4, "stack entry invoked as function")
    if "return" in features and "stack_call" in features:
        bump("CALL", 0.1, "call followed by return")
    if "return" in features:
        bump("RETURN", 0.35, "explicit return keyword present")
    if "top_adjust" in features:
        bump("RETURN", 0.2, "top adjusted in handler")
    if "pc_relative" in features or "pc_set" in features:
        bump("JMP", 0.45, "program counter modified")
    if "compare" in features:
        bump("EQ", 0.35, "equality comparison detected")
    if "compare" in features and ("pc_relative" in features or "pc_set" in features):
        bump("EQ", 0.15, "comparison influences program counter")
    if "bit32" in features:
        bump("EQ", 0.05, "bitwise operations typical of equality handler")
        bump("CALL", 0.05, "bit32 usage suggests argument preparation")
    if "math" in features:
        bump("CALL", 0.05, "math helper usage inside handler")

    if version_hint and "14.4.2" in version_hint:
        if "table_move" in features:
            bump("LOADK", 0.1, "table.move common in 14.4.2 constant loader")
        if "pc_relative" in features and "compare" not in features:
            bump("JMP", 0.1, "pc adjustment without compare matches 14.4.2 jump")

    blob = body.encode("latin-1", errors="ignore")
    if blob:
        byte_scores = compare_handler_bytes(blob)
        for comparison in byte_scores:
            if comparison.score >= 0.55:
                bump(
                    comparison.mnemonic,
                    comparison.score * 0.25,
                    f"byte fingerprint score {comparison.score:.2f}",
                )

    for mnemonic, score in list(scores.items()):
        capped = min(score, 1.0)
        scores[mnemonic] = capped
        candidates.append(
            HandlerCandidate(
                mnemonic=mnemonic,
                confidence=capped,
                reasons=tuple(base_reasons.get(mnemonic, [])),
            )
        )

    candidates.sort(key=lambda item: item.confidence, reverse=True)
    return candidates


def analyse_handler_source(
    name: str,
    body: Optional[str],
    *,
    opcode: Optional[int] = None,
    version_hint: Optional[str] = None,
) -> HandlerSuggestion:
    """Analyse a handler body and produce mnemonic suggestions."""

    if not body:
        return HandlerSuggestion(name=name, opcode=opcode, candidates=(), resolvable=False)

    candidates = _score_candidates(name, body, version_hint=version_hint)
    resolvable = bool(candidates)
    reasons: List[str] = []
    if not resolvable:
        reasons.append("no textual heuristics matched")
    else:
        top = candidates[0]
        reasons.append(f"top candidate {top.mnemonic} ({top.confidence:.2f})")
    return HandlerSuggestion(
        name=name,
        opcode=opcode,
        candidates=tuple(candidates),
        resolvable=resolvable,
        reasons=tuple(reasons),
    )


def analyse_handler_map(
    handlers: Mapping[str, str],
    *,
    opcodes: Optional[Mapping[str, int]] = None,
    version_hint: Optional[str] = None,
) -> List[HandlerSuggestion]:
    """Analyse ``handlers`` and return a list of :class:`HandlerSuggestion`."""

    suggestions: List[HandlerSuggestion] = []
    for name, body in handlers.items():
        opcode = opcodes.get(name) if opcodes else None
        suggestions.append(
            analyse_handler_source(
                name,
                body,
                opcode=opcode,
                version_hint=version_hint,
            )
        )
    suggestions.sort(key=lambda item: (item.opcode is None, item.name))
    return suggestions


def emit_handler_suggestions(
    handlers: Mapping[str, str],
    *,
    opcodes: Optional[Mapping[str, int]] = None,
    output_dir: Path,
    version_hint: Optional[str] = None,
) -> Path:
    """Write handler suggestions to ``output_dir`` and return the path."""

    suggestions = analyse_handler_map(
        handlers,
        opcodes=opcodes,
        version_hint=version_hint,
    )
    payload = {
        "version_hint": version_hint,
        "handlers": [suggestion.to_dict() for suggestion in suggestions],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "handler_suggestions.json"
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    LOGGER.info("Wrote handler suggestions to %s", target)
    return target


def _load_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _build_handler_map_from_paths(paths: Iterable[Path]) -> Dict[str, str]:
    handlers: Dict[str, str] = {}
    for path in paths:
        text = _load_source(path)
        extracted = extract_function_bodies(text)
        handlers.update(extracted)
        LOGGER.debug("Extracted %d functions from %s", len(extracted), path)
    return handlers


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Suggest mnemonics for VM handlers")
    parser.add_argument("sources", nargs="+", help="Lua source files containing handlers")
    parser.add_argument("--out-dir", default="out", help="Directory for JSON output")
    parser.add_argument("--version-hint", help="Optional Luraph version hint")
    parser.add_argument(
        "--opcode-map",
        help="Optional JSON mapping of handler names to opcode numbers",
    )
    args = parser.parse_args(argv)

    source_paths = [Path(item) for item in args.sources]
    handlers = _build_handler_map_from_paths(source_paths)
    if not handlers:
        LOGGER.warning("No functions extracted from provided sources")
    if args.opcode_map:
        opcodes_data = json.loads(Path(args.opcode_map).read_text(encoding="utf-8"))
        if not isinstance(opcodes_data, dict):
            raise ValueError("opcode map must be a JSON object")
        opcodes = {str(key): int(value) for key, value in opcodes_data.items()}
    else:
        opcodes = None

    emit_handler_suggestions(
        handlers,
        opcodes=opcodes,
        output_dir=Path(args.out_dir),
        version_hint=args.version_hint,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
