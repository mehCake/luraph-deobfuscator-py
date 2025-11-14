"""Heuristic helpers for recognising common bootstrap artefacts."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "ChecksumResult",
    "VMStyleScore",
    "HeuristicSignal",
    "classify_operation_markers",
    "detect_checksums",
    "detect_endianness",
    "detect_vm_style",
    "likely_lph_variant",
    "looks_like_perm_table",
    "looks_like_prga",
    "looks_like_vm_dispatch",
    "score_base64_string",
    "score_lph_header",
    "score_operation_sequence",
    "score_permutation_sequence",
]

_BASE64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_OPERATION_WEIGHTS: Tuple[Tuple[str, float], ...] = (
    ("loadstring", 0.22),
    ("load", 0.18),
    ("string.char", 0.2),
    ("string.byte", 0.05),
    ("string.gsub", 0.05),
    ("string.reverse", 0.05),
    ("bit32.bxor", 0.08),
    ("bit32.band", 0.05),
    ("bit32.bor", 0.05),
    ("bit32.lshift", 0.04),
    ("bit32.rshift", 0.04),
    ("method:decode", 0.14),
    ("method:decrypt", 0.14),
    ("method:permute", 0.12),
    ("method:prga", 0.12),
    ("method:unpack", 0.12),
)
_OPERATION_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("xor", "xor"),
    ("perm", "permute"),
    ("prga", "prga"),
    ("decrypt", "decrypt"),
    ("decode", "decode"),
)
_LPH_MAGIC = (b"LPH", b"LP5", b"LP4", b"LP3")
_SMALL_OPERAND_THRESHOLD = 4


@dataclass(frozen=True)
class ChecksumResult:
    """Description of a detected checksum or CRC trailer."""

    name: str
    valid: bool
    confidence: float
    offset: int
    length: int
    expected: bytes
    actual: bytes

    def status_hint(self) -> str:
        """Return a human readable status hint for reporting."""

        return f"checksum:{self.name}:{'valid' if self.valid else 'mismatch'}"


@dataclass(frozen=True)
class VMStyleScore:
    """Heuristic classification describing VM operand usage style."""

    style: str
    confidence: float
    register_score: float
    stack_score: float
    sample_size: int
    max_operand: int
    unique_operands: int
    small_operand_ratio: float
    sequential_ratio: float


@dataclass(frozen=True)
class HeuristicSignal:
    """Structured heuristic result describing a detected artefact.

    Attributes
    ----------
    name:
        Short identifier for the heuristic (e.g. ``"prga"``).
    confidence:
        Normalised confidence value between 0.0 and 1.0.
    reasons:
        Human-readable bullet points that justify why the heuristic fired.
    version_hint:
        Optional best-effort guess of the targeted Luraph version family.
    """

    name: str
    confidence: float
    reasons: Tuple[str, ...]
    version_hint: Optional[str] = None


def _normalise_operation(operation: str) -> str:
    text = operation.strip().lower()
    if not text:
        return ""
    if text.startswith("method:"):
        return "method:" + text.split(":", 1)[1]
    return text


def _dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        if value and value not in seen:
            ordered.append(value)
            seen.add(value)
    return ordered


def _operation_name(operation: object) -> str:
    if isinstance(operation, str):
        return operation
    if hasattr(operation, "type"):
        return str(getattr(operation, "type"))
    if isinstance(operation, Mapping):
        value = operation.get("type")
        if value is not None:
            return str(value)
    return str(operation)


def _operation_args(operation: object) -> Mapping[str, object]:
    if hasattr(operation, "args"):
        args = getattr(operation, "args")
        if isinstance(args, Mapping):
            return args
    if isinstance(operation, Mapping):
        args = operation.get("args")
        if isinstance(args, Mapping):
            return args
    return {}


def classify_operation_markers(operations: Sequence[str]) -> List[str]:
    """Return simplified markers describing the provided *operations*."""

    markers: List[str] = []
    for operation in operations:
        normalised = _normalise_operation(operation)
        if not normalised:
            continue
        for prefix, _weight in _OPERATION_WEIGHTS:
            if normalised.startswith(prefix):
                markers.append(prefix)
                break
        else:
            for keyword, marker in _OPERATION_KEYWORDS:
                if keyword in normalised:
                    markers.append(marker)
                    break
    return _dedupe(markers)


def score_operation_sequence(operations: Sequence[str]) -> float:
    """Estimate a confidence score for a sequence of bootstrap operations."""

    if not operations:
        return 0.0

    score = 0.0
    matched: set[str] = set()
    for operation in operations:
        normalised = _normalise_operation(operation)
        if not normalised:
            continue
        for prefix, weight in _OPERATION_WEIGHTS:
            if normalised.startswith(prefix) and prefix not in matched:
                score += weight
                matched.add(prefix)
                break
        else:
            for keyword, _marker in _OPERATION_KEYWORDS:
                if keyword in normalised:
                    score += 0.04
                    break
    return max(0.0, min(1.0, score))


def _extract_operand(value: object) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def looks_like_prga(operations: Sequence[object]) -> HeuristicSignal:
    """Detect whether ``operations`` resemble a PRGA transform sequence.

    The heuristic favours patterns observed in Luraph v14.4.1–v14.4.3
    bootstrappers where PRGA helpers tend to combine ``bit32.bxor`` with
    rotate/permute stages.  Confidence increases when the operation stream
    shows multiple rotate invocations (``bit32.lrotate``/``bit32.rrotate``)
    alongside XORs and optional permutation helpers.  For v14.4.2 payloads we
    additionally expect rotate counts of 11 or 13 bits and table based
    permutations over 0x100 or 0x200 entries.
    """

    if not operations:
        return HeuristicSignal("prga", 0.0, ("no operations provided",))

    notes: List[str] = []
    rotate_hits = 0
    xor_hits = 0
    perm_hits = 0
    mask_hits = 0
    rotate_amounts: List[int] = []

    for op in operations:
        name = _normalise_operation(_operation_name(op))
        if not name:
            continue
        lowered = name.lower()
        if "rotate" in lowered:
            rotate_hits += 1
            args = _operation_args(op)
            amount = _extract_operand(args.get("bits"))
            if amount is None:
                amount = _extract_operand(args.get("amount"))
            if amount is not None:
                rotate_amounts.append(amount % 32)
        elif "xor" in lowered or lowered.startswith("bit32.bxor"):
            xor_hits += 1
        elif "perm" in lowered:
            perm_hits += 1
        elif any(keyword in lowered for keyword in ("band", "bor", "mask")):
            mask_hits += 1

    confidence = 0.0
    if rotate_hits and xor_hits:
        confidence += 0.45
        notes.append(f"saw {rotate_hits} rotate and {xor_hits} xor operations")
    elif xor_hits >= 2:
        confidence += 0.2
        notes.append("repeated xor operations without rotate support")

    if perm_hits:
        confidence += 0.2
        notes.append(f"detected permutation helpers ({perm_hits} matches)")

    if mask_hits:
        confidence += 0.1
        notes.append("presence of masking helpers often surrounding PRGA state")

    version_hint: Optional[str] = None
    if rotate_amounts:
        unique = sorted(set(rotate_amounts))
        notes.append(f"rotate amounts: {', '.join(str(v) for v in unique)}")
        if any(value in (11, 13) for value in unique):
            confidence += 0.15
            version_hint = "v14.4.2"
            notes.append("matches common 11/13-bit rotate pattern from v14.4.2")
        elif any(value in (5, 7) for value in unique):
            confidence += 0.1
            version_hint = version_hint or "v14.4.1"
            notes.append("matches 5/7-bit rotate motif typical of v14.4.1")
        elif any(value in (8, 16, 24) for value in unique):
            confidence += 0.1
            version_hint = version_hint or "v14.4.3"
            notes.append("matches 8/16-bit rotate usage observed in v14.4.3")

    if not notes:
        notes.append("no PRGA-specific patterns detected")

    return HeuristicSignal(
        name="prga",
        confidence=max(0.0, min(1.0, confidence)),
        reasons=tuple(notes),
        version_hint=version_hint,
    )


def looks_like_perm_table(values: Sequence[int]) -> HeuristicSignal:
    """Determine whether ``values`` resembles a permutation table.

    The heuristic combines the generic permutation scoring with additional
    metadata about array length and coverage.  Confidence increases when the
    table spans 0x100 or 0x200 elements which are common in Luraph
    v14.4.1–v14.4.3 bootstrap payloads.
    """

    score = score_permutation_sequence(values)
    notes: List[str] = []
    version_hint: Optional[str] = None

    length = len(values)
    if not values:
        notes.append("empty table")
        return HeuristicSignal("perm-table", 0.0, tuple(notes))

    min_value = min(values)
    max_value = max(values)
    notes.append(f"length={length} span={min_value}-{max_value}")

    if length in (256, 512):
        score += 0.25
        version_hint = "v14.4.2" if length == 512 else "v14.4.1"
        notes.append("length matches common PRGA permutation table size")
    elif length % 64 == 0:
        score += 0.1
        notes.append("length divisible by 64, plausible block table")

    if min_value == 0 and max_value == length - 1:
        score += 0.1
        notes.append("covers contiguous range starting at zero")

    duplicates = length - len(set(values))
    if duplicates:
        score *= 0.6
        notes.append(f"contains {duplicates} duplicate entries")
    else:
        notes.append("all entries unique")

    return HeuristicSignal(
        name="perm-table",
        confidence=max(0.0, min(1.0, score)),
        reasons=tuple(notes),
        version_hint=version_hint,
    )


_DISPATCH_PATTERN = re.compile(
    r"if\s+[^\n]*\bopcode\b[^\n]*==[^\n]*then\s+([A-Za-z_][\w\.]*)",
    re.IGNORECASE,
)
_DISPATCH_TABLE_PATTERN = re.compile(r"handlers?\s*\[\s*opcode\s*\]", re.IGNORECASE)
_DISPATCH_LOOP_PATTERN = re.compile(r"while\s+true\s+do", re.IGNORECASE)


def looks_like_vm_dispatch(snippet: str) -> HeuristicSignal:
    """Heuristically identify VM dispatcher style code in ``snippet``.

    Luraph 14.4.x dispatchers are typically structured as a ``while true`` loop
    containing a dense chain of ``if opcode ==`` tests or a handler table
    lookup.  The heuristic counts both constructs and reports a confidence
    score together with human readable notes.
    """

    if not snippet:
        return HeuristicSignal("vm-dispatch", 0.0, ("empty snippet",))

    matches = _DISPATCH_PATTERN.findall(snippet)
    table_refs = len(_DISPATCH_TABLE_PATTERN.findall(snippet))
    loop_refs = len(_DISPATCH_LOOP_PATTERN.findall(snippet))

    notes: List[str] = []
    confidence = 0.0
    if matches:
        confidence += min(0.5, 0.15 * len(matches))
        notes.append(f"found {len(matches)} opcode equality branches")
    if table_refs:
        confidence += 0.25
        notes.append("detected handler table lookup")
    if loop_refs:
        confidence += 0.2
        notes.append("contains dispatcher loop")

    if not notes:
        notes.append("no dispatcher patterns detected")

    version_hint = None
    if len(matches) >= 3:
        version_hint = "v14.4.2"
        notes.append("density of handlers matches v14.4.2 bootstrap style")
    elif table_refs:
        version_hint = "v14.4.1"
        notes.append("table lookup without dense branches resembles early variants")

    return HeuristicSignal(
        name="vm-dispatch",
        confidence=max(0.0, min(1.0, confidence)),
        reasons=tuple(notes),
        version_hint=version_hint,
    )


def likely_lph_variant(observations: Mapping[str, object]) -> HeuristicSignal:
    """Estimate which LPH variant best matches the provided ``observations``.

    The function expects a dictionary containing optional keys such as
    ``rotate_amounts`` (sequence of integers), ``permute_block`` (integer) and
    ``endianness`` (``"big"``/``"little"``/``"unknown"``).  The heuristic is
    tuned against Luraph v14.4.1–v14.4.3 payloads and favours v14.4.2 when a
    0x200 permutation block or 11/13-bit rotate pair is encountered.
    """

    notes: List[str] = []
    confidence = 0.0
    version_hint = "unknown"

    rotate_amounts = observations.get("rotate_amounts")
    if isinstance(rotate_amounts, Sequence) and rotate_amounts:
        normalised = sorted({int(value) % 32 for value in rotate_amounts if isinstance(value, int)})
        notes.append(f"rotate amounts: {', '.join(str(v) for v in normalised)}")
        if any(amount in (11, 13) for amount in normalised):
            confidence += 0.4
            version_hint = "v14.4.2"
            notes.append("11/13-bit rotates align with v14.4.2 PRGA variant")
        elif any(amount in (5, 7) for amount in normalised):
            confidence += 0.25
            version_hint = "v14.4.1"
            notes.append("5/7-bit rotates observed in earlier 14.4.1 payloads")
        elif any(amount in (8, 16, 24) for amount in normalised):
            confidence += 0.25
            version_hint = "v14.4.3"
            notes.append("8/16/24-bit rotates match newer 14.4.3 samples")
    elif rotate_amounts:
        notes.append("rotate amounts unavailable for scoring")

    perm_block = observations.get("permute_block")
    if isinstance(perm_block, int) and perm_block > 0:
        notes.append(f"permute block size {perm_block}")
        if perm_block in (512, 0x200):
            confidence += 0.3
            version_hint = "v14.4.2"
            notes.append("block size 0x200 strongly hints at v14.4.2")
        elif perm_block in (256, 0x100):
            confidence += 0.25
            version_hint = version_hint if version_hint != "unknown" else "v14.4.1"
            notes.append("block size 0x100 aligns with v14.4.1 tables")
        elif perm_block >= 768:
            confidence += 0.2
            version_hint = "v14.4.3"
            notes.append("large permutation tables appear in v14.4.3")

    endianness = observations.get("endianness")
    if isinstance(endianness, str) and endianness in {"big", "little"}:
        notes.append(f"endianness hint: {endianness}")
        if endianness == "little" and version_hint == "unknown":
            version_hint = "v14.4.2"
            confidence += 0.05
        elif endianness == "big" and version_hint == "unknown":
            version_hint = "v14.4.1"
            confidence += 0.05

    xor_stride = observations.get("xor_stride")
    if isinstance(xor_stride, int) and xor_stride:
        notes.append(f"xor stride {xor_stride}")
        if xor_stride in (3, 5):
            confidence += 0.1
            version_hint = version_hint if version_hint != "unknown" else "v14.4.1"
        elif xor_stride in (11, 13):
            confidence += 0.15
            version_hint = "v14.4.2"

    if not notes:
        notes.append("no discriminating observations provided")

    if confidence == 0.0:
        version_hint = "unknown"

    return HeuristicSignal(
        name="lph-variant",
        confidence=max(0.0, min(1.0, confidence)),
        reasons=tuple(notes),
        version_hint=None if version_hint == "unknown" else version_hint,
    )


def _instruction_field(instruction: object, field: str) -> Optional[int]:
    if hasattr(instruction, field):
        attr = getattr(instruction, field)
        return _extract_operand(attr)
    if isinstance(instruction, Mapping):
        return _extract_operand(instruction.get(field))
    return None


def detect_vm_style(instructions: Sequence[object]) -> VMStyleScore:
    """Classify the VM style (stack vs register) using operand heuristics."""

    if not instructions:
        return VMStyleScore(
            style="unknown",
            confidence=0.0,
            register_score=0.0,
            stack_score=0.0,
            sample_size=0,
            max_operand=0,
            unique_operands=0,
            small_operand_ratio=0.0,
            sequential_ratio=0.0,
        )

    operand_values: List[int] = []
    small_operands = 0
    prev_a: Optional[int] = None
    sequential_steps = 0

    for instruction in instructions:
        a = _instruction_field(instruction, "a")
        b = _instruction_field(instruction, "b")
        c = _instruction_field(instruction, "c")
        for value in (a, b, c):
            if value is None:
                continue
            operand_values.append(value)
            if value < _SMALL_OPERAND_THRESHOLD:
                small_operands += 1
        if a is not None and prev_a is not None and abs(a - prev_a) <= 1:
            sequential_steps += 1
        if a is not None:
            prev_a = a

    if not operand_values:
        return VMStyleScore(
            style="unknown",
            confidence=0.0,
            register_score=0.0,
            stack_score=0.0,
            sample_size=len(instructions),
            max_operand=0,
            unique_operands=0,
            small_operand_ratio=0.0,
            sequential_ratio=0.0,
        )

    unique_operands = len(set(operand_values))
    max_operand = max(operand_values)
    min_operand = min(operand_values)
    span = max_operand - min_operand if operand_values else 0
    total_operands = len(operand_values)
    small_ratio = small_operands / total_operands
    sequential_ratio = sequential_steps / max(1, len(instructions) - 1)

    register_score = 0.0
    if unique_operands >= 16:
        register_score += 0.4
    elif unique_operands >= 10:
        register_score += 0.25
    if max_operand >= 32:
        register_score += 0.3
    elif max_operand >= 16:
        register_score += 0.2
    if span >= 24:
        register_score += 0.1
    if small_ratio < 0.35:
        register_score += 0.15
    if sequential_ratio < 0.2:
        register_score += 0.1

    stack_score = 0.0
    if small_ratio >= 0.6:
        stack_score += 0.4
    elif small_ratio >= 0.45:
        stack_score += 0.3
    if sequential_ratio >= 0.35:
        stack_score += 0.3
    elif sequential_ratio >= 0.2:
        stack_score += 0.2
    if max_operand <= 12:
        stack_score += 0.2
    elif max_operand <= 20:
        stack_score += 0.1
    if unique_operands <= 8:
        stack_score += 0.1

    style = "unknown"
    confidence = max(register_score, stack_score)
    if register_score - stack_score >= 0.15:
        style = "register"
    elif stack_score - register_score >= 0.15:
        style = "stack"
    else:
        confidence *= 0.6

    return VMStyleScore(
        style=style,
        confidence=min(1.0, confidence),
        register_score=register_score,
        stack_score=stack_score,
        sample_size=len(instructions),
        max_operand=max_operand,
        unique_operands=unique_operands,
        small_operand_ratio=small_ratio,
        sequential_ratio=sequential_ratio,
    )


def score_base64_string(text: str, *, min_length: int = 32) -> float:
    """Score how likely *text* is to be Base64 encoded data."""

    if not text:
        return 0.0
    compact = re.sub(r"\s+", "", text)
    if len(compact) < min_length:
        return 0.0
    if not _BASE64_PATTERN.fullmatch(compact):
        return 0.0

    valid = sum(1 for char in compact if char in _BASE64_ALPHABET)
    if not valid:
        return 0.0

    score = valid / len(compact)
    padding = compact.rstrip("=")
    padding_length = len(compact) - len(padding)
    if len(compact) % 4 != 0:
        score *= 0.5
    if padding_length > 2:
        score *= 0.75
    if padding_length and not compact.endswith("=" * padding_length):
        score *= 0.5
    return max(0.0, min(1.0, score))


def score_permutation_sequence(values: Sequence[int]) -> float:
    """Score how closely *values* resemble a permutation array."""

    if not values:
        return 0.0

    length = len(values)
    unique = len(set(values))
    uniqueness = unique / length

    min_value = min(values)
    max_value = max(values)
    span = max_value - min_value + 1
    coverage = min(length / span if span else 0.0, 1.0)

    expected_zero = list(range(0, length))
    expected_one = list(range(1, length + 1))
    sorted_values = sorted(values)
    alignment = 0.0
    if sorted_values == expected_zero or sorted_values == expected_one:
        alignment = 1.0
    else:
        matches = sum(1 for a, b in zip(values, expected_zero) if a == b)
        matches_one = sum(1 for a, b in zip(values, expected_one) if a == b)
        alignment = max(matches, matches_one) / length

    return max(0.0, min(1.0, (uniqueness * 0.5) + (coverage * 0.25) + (alignment * 0.25)))


def score_lph_header(data: bytes, *, window: int = 16) -> float:
    """Score whether *data* contains a plausible LPH header."""

    if not data:
        return 0.0
    head = data[:window]
    for magic in _LPH_MAGIC:
        if head.startswith(magic):
            return 1.0
        if magic in head:
            return 0.85
    ascii_ratio = sum(1 for byte in head if 0x20 <= byte <= 0x7E) / len(head)
    entropy = 0.0
    counts = {}
    for byte in head:
        counts[byte] = counts.get(byte, 0) + 1
    for count in counts.values():
        p = count / len(head)
        entropy -= p * math.log(p, 2)
    entropy_score = min(entropy / 4.0, 1.0)
    if ascii_ratio > 0.6 and entropy_score > 0.5:
        return 0.6
    if ascii_ratio > 0.4 and entropy_score > 0.4:
        return 0.4
    return 0.0


def detect_endianness(data: bytes, *, window: int = 256) -> Tuple[str, float]:
    """Return a heuristic guess of the byte-order contained in *data*.

    The heuristic scans the first ``window`` bytes of the payload for familiar
    marker sequences such as ``0x01 0x02 0x03 0x04`` (big-endian structures) or
    ``0x04 0x03 0x02 0x01`` (little-endian layouts).  The result is a tuple of
    ``(endianness, confidence)`` where endianness is one of ``"big"``,
    ``"little"`` or ``"unknown"``.
    """

    if not data:
        return "unknown", 0.0

    view = memoryview(data)[:window]
    if len(view) < 4:
        return "unknown", 0.0

    buffer = bytes(view)
    patterns_big = (
        b"\x00\x01\x02\x03",
        b"\x01\x02\x03\x04",
        b"\x10\x11\x12\x13",
        b"LPH!",  # LPH headers often appear in big-endian layouts
    )
    patterns_little = (
        b"\x03\x02\x01\x00",
        b"\x04\x03\x02\x01",
        b"\x13\x12\x11\x10",
        b"!HPL",  # reversed LPH marker
    )

    def _count(patterns: Sequence[bytes]) -> int:
        total = 0
        for pattern in patterns:
            start = 0
            while True:
                index = buffer.find(pattern, start)
                if index == -1:
                    break
                total += 1
                start = index + 1
        return total

    big_matches = _count(patterns_big)
    little_matches = _count(patterns_little)

    asc_sequences = 0
    desc_sequences = 0
    limit = len(buffer) - 3
    for index in range(limit):
        a0, a1, a2, a3 = buffer[index : index + 4]
        if a0 < a1 < a2 < a3 and a1 == a0 + 1 and a2 == a1 + 1 and a3 == a2 + 1:
            asc_sequences += 1
        if a0 > a1 > a2 > a3 and a0 == a1 + 1 and a1 == a2 + 1 and a2 == a3 + 1:
            desc_sequences += 1

    big_score = big_matches + asc_sequences
    little_score = little_matches + desc_sequences

    if big_score == 0 and little_score == 0:
        return "unknown", 0.0

    if big_score > little_score:
        dominant = "big"
        dominant_score = big_score
        opponent_score = little_score
    elif little_score > big_score:
        dominant = "little"
        dominant_score = little_score
        opponent_score = big_score
    else:
        return "unknown", 0.0

    ratio = dominant_score / max(dominant_score + opponent_score, 1)
    coverage = dominant_score / max(limit, 1)
    confidence = max(ratio * 0.8, coverage * 4.0)
    if dominant_score < 2:
        confidence *= 0.5
    confidence = max(0.0, min(1.0, confidence))

    return dominant, confidence


def detect_checksums(data: bytes) -> List[ChecksumResult]:
    """Detect common checksum or CRC trailers embedded in *data*.

    The validator returns structured results describing whether a recognised
    trailer matches the recomputed checksum.  The caller can then surface these
    results directly in reports or downgrade confidence when a mismatch is
    observed.
    """

    import binascii
    import zlib

    results: List[ChecksumResult] = []

    length = len(data)
    if length < 2:
        return results

    def _append_result(
        name: str,
        *,
        expected: bytes,
        actual: bytes,
        offset: int,
        confidence: float,
    ) -> None:
        valid = actual == expected
        adjusted_confidence = confidence if valid else confidence * 0.35
        results.append(
            ChecksumResult(
                name=name,
                valid=valid,
                confidence=max(0.0, min(1.0, adjusted_confidence)),
                offset=offset,
                length=len(actual),
                expected=expected,
                actual=actual,
            )
        )

    # CRC32 trailer detection (4 bytes, computed over preceding bytes)
    if length >= 8:
        body = data[:-4]
        offset = length - 4
        trailer = data[offset:]
        crc_value = zlib.crc32(body) & 0xFFFFFFFF
        expected_be = crc_value.to_bytes(4, "big")
        expected_le = crc_value.to_bytes(4, "little")
        if trailer == expected_be:
            _append_result("crc32-be", expected=expected_be, actual=trailer, offset=offset, confidence=0.95)
        elif trailer == expected_le:
            _append_result("crc32-le", expected=expected_le, actual=trailer, offset=offset, confidence=0.95)
        else:
            # Provide the closest orientation as a mismatch hint so that
            # reports can highlight suspect trailers for manual review.
            match_be = sum(1 for a, b in zip(trailer, expected_be) if a == b)
            match_le = sum(1 for a, b in zip(trailer, expected_le) if a == b)
            if match_be or match_le:
                if match_be >= match_le:
                    _append_result(
                        "crc32-be",
                        expected=expected_be,
                        actual=trailer,
                        offset=offset,
                        confidence=0.4 + (match_be / 4) * 0.2,
                    )
                else:
                    _append_result(
                        "crc32-le",
                        expected=expected_le,
                        actual=trailer,
                        offset=offset,
                        confidence=0.4 + (match_le / 4) * 0.2,
                    )

    # CRC16 (X.25/IBM) trailer detection
    if length >= 4:
        body = data[:-2]
        offset = length - 2
        trailer16 = data[offset:]
        crc16 = binascii.crc_hqx(body, 0)
        expected_be = crc16.to_bytes(2, "big")
        expected_le = crc16.to_bytes(2, "little")
        if trailer16 == expected_be:
            _append_result("crc16-be", expected=expected_be, actual=trailer16, offset=offset, confidence=0.85)
        elif trailer16 == expected_le:
            _append_result("crc16-le", expected=expected_le, actual=trailer16, offset=offset, confidence=0.85)
        else:
            match_be = sum(1 for a, b in zip(trailer16, expected_be) if a == b)
            match_le = sum(1 for a, b in zip(trailer16, expected_le) if a == b)
            if match_be or match_le:
                if match_be >= match_le:
                    _append_result(
                        "crc16-be",
                        expected=expected_be,
                        actual=trailer16,
                        offset=offset,
                        confidence=0.35 + (match_be / 2) * 0.2,
                    )
                else:
                    _append_result(
                        "crc16-le",
                        expected=expected_le,
                        actual=trailer16,
                        offset=offset,
                        confidence=0.35 + (match_le / 2) * 0.2,
                    )

    # Simple additive checksum (sum(body) % 256)
    if length >= 3:
        body = data[:-1]
        offset = length - 1
        expected_sum = bytes([sum(body) & 0xFF])
        actual_sum = data[offset:]
        if actual_sum == expected_sum:
            _append_result("sum8", expected=expected_sum, actual=actual_sum, offset=offset, confidence=0.65)

    # XOR checksum across the body
    if length >= 3:
        xor_value = 0
        for byte in data[:-1]:
            xor_value ^= byte
        expected_xor = bytes([xor_value & 0xFF])
        offset = length - 1
        actual_xor = data[offset:]
        if actual_xor == expected_xor:
            _append_result("xor8", expected=expected_xor, actual=actual_xor, offset=offset, confidence=0.6)

    return results
