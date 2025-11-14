"""Guided fuzzing for PRGA parameter discovery.

The helpers in this module brute-force plausible PRGA parameter combinations
observed in Luraph 14.4.x payloads.  Rather than blindly iterating every
possible permutation, the search orders candidates by heuristics (small rotation
adjustments first, followed by common block sizes and small XOR seeds) and
scores the resulting byte streams using lightweight textual analysis.  This
allows analysts to quickly zero-in on parameter sets that yield Lua-like output
without executing any untrusted code.

Keys are *never* persisted – they can only be provided at runtime via the CLI
or direct function arguments.  The CLI wipes key buffers after use to ensure the
session scoped key material does not linger in memory longer than necessary.
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, MutableSequence, Optional, Sequence, Tuple

from ..decoders.initv4_prga import apply_prga
from .heuristics import score_base64_string

LOGGER = logging.getLogger(__name__)

__all__ = [
    "FuzzyCandidate",
    "FuzzySearchResult",
    "guided_search",
    "score_payload",
    "main",
]

_LUA_TOKENS: Tuple[str, ...] = (
    "local",
    "function",
    "return",
    "end",
    "if",
    "then",
    "for",
    "while",
    "repeat",
    "until",
)

_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
_DEFAULT_VARIANTS: Tuple[str, ...] = ("initv4 default", "initv4 alt")
_DEFAULT_ROTATIONS: Tuple[int, ...] = tuple(range(0, 8))
_DEFAULT_BLOCK_SIZES: Tuple[int, ...] = (1, 4, 8, 16, 32)
_DEFAULT_BLOCK_SHIFTS: Tuple[int, ...] = (0, 1, 2, 3, 4)
_DEFAULT_MAX_TRIES = 256
_DEFAULT_TIMEOUT = 5.0
_DEFAULT_TOP = 10


@dataclass(frozen=True)
class FuzzyCandidate:
    """Parameter combination explored during the search."""

    variant: str
    rotation_adjust: int
    block_size: int
    block_shift: int
    xor_seed: int

    def to_serialisable(self) -> Mapping[str, object]:
        return {
            "variant": self.variant,
            "rotation_adjust": self.rotation_adjust,
            "block_size": self.block_size,
            "block_shift": self.block_shift,
            "xor_seed": self.xor_seed,
        }


@dataclass(frozen=True)
class FuzzySearchResult:
    """Result produced by :func:`guided_search`."""

    candidate: FuzzyCandidate
    score: float
    ascii_ratio: float
    token_ratio: float
    lua_density: float
    base64_score: float
    preview: str
    attempt: int = field(default=0)

    def to_serialisable(self) -> Mapping[str, object]:
        payload = dict(self.candidate.to_serialisable())
        payload.update(
            {
                "score": round(self.score, 4),
                "ascii_ratio": round(self.ascii_ratio, 4),
                "token_ratio": round(self.token_ratio, 4),
                "lua_density": round(self.lua_density, 4),
                "base64_score": round(self.base64_score, 4),
                "preview": self.preview,
                "attempt": self.attempt,
            }
        )
        return payload


def _rol8(value: int, rotation: int) -> int:
    rotation &= 7
    value &= 0xFF
    if rotation == 0:
        return value
    return ((value << rotation) | (value >> (8 - rotation))) & 0xFF


def _rotate_bytes(data: bytes, amount: int) -> bytes:
    if not data or (amount & 7) == 0:
        return bytes(data)
    return bytes(_rol8(byte, amount) for byte in data)


def _rotate_block(block: MutableSequence[int], shift: int) -> None:
    if not block:
        return
    shift = shift % len(block)
    if shift == 0:
        return
    snapshot = list(block)
    size = len(block)
    for index in range(size):
        block[index] = snapshot[(index + shift) % size]


def _permute_blocks(data: bytes, *, block_size: int, block_shift: int) -> bytes:
    if block_size <= 1 or len(data) < block_size:
        return bytes(data)
    output = bytearray(data)
    for offset in range(0, len(output), block_size):
        block = output[offset : offset + block_size]
        if len(block) < block_size:
            break
        _rotate_block(block, block_shift)
        output[offset : offset + block_size] = block
    return bytes(output)


def _xor_stream(data: bytes, seed: int) -> bytes:
    mask = seed & 0xFF
    if mask == 0:
        return bytes(data)
    output = bytearray(len(data))
    for index, value in enumerate(data):
        output[index] = value ^ ((mask + index) & 0xFF)
    return bytes(output)


def _preview_text(data: bytes, limit: int = 120) -> str:
    if not data:
        return ""
    snippet = data[:limit].decode("latin-1", errors="replace")
    snippet = snippet.replace("\n", "\\n").replace("\r", "\\r")
    return snippet


def score_payload(data: bytes) -> Tuple[float, float, float, float]:
    """Return ``(score, ascii_ratio, token_ratio, lua_density)`` for *data*."""

    if not data:
        return 0.0, 0.0, 0.0, 0.0

    sample = data[: min(4096, len(data))]
    printable = sum(1 for byte in sample if byte in _PRINTABLE)
    ascii_ratio = printable / len(sample)

    text = sample.decode("latin-1", errors="ignore")
    token_hits = sum(text.count(token) for token in _LUA_TOKENS)
    unique_tokens = sum(1 for token in _LUA_TOKENS if token in text)
    token_ratio = unique_tokens / len(_LUA_TOKENS)
    lua_density = token_hits / max(len(text), 1)

    base_score = ascii_ratio * 0.6 + min(1.0, token_hits / 12.0) * 0.25 + token_ratio * 0.15
    return base_score, ascii_ratio, token_ratio, lua_density


def _apply_candidate(
    payload: bytes,
    *,
    key: Optional[bytes],
    candidate: FuzzyCandidate,
) -> bytes:
    if key:
        output = apply_prga(payload, key, params={"variant": candidate.variant})
    else:
        output = bytes(payload)
    output = _rotate_bytes(output, candidate.rotation_adjust)
    output = _permute_blocks(output, block_size=candidate.block_size, block_shift=candidate.block_shift)
    output = _xor_stream(output, candidate.xor_seed)
    return output


def _iter_candidates(
    *,
    variants: Sequence[str],
    rotations: Sequence[int],
    block_sizes: Sequence[int],
    block_shifts: Sequence[int],
    xor_seeds: Sequence[int],
) -> Iterator[FuzzyCandidate]:
    for variant in variants:
        for rotation in rotations:
            for block_size in block_sizes:
                valid_shifts = [shift for shift in block_shifts if shift < block_size]
                if not valid_shifts:
                    valid_shifts = [0]
                for block_shift in valid_shifts:
                    for xor_seed in xor_seeds:
                        yield FuzzyCandidate(
                            variant=variant,
                            rotation_adjust=rotation,
                            block_size=block_size,
                            block_shift=block_shift,
                            xor_seed=xor_seed,
                        )


def guided_search(
    payload: bytes,
    *,
    key: Optional[bytes] = None,
    variants: Sequence[str] = _DEFAULT_VARIANTS,
    rotations: Sequence[int] = _DEFAULT_ROTATIONS,
    block_sizes: Sequence[int] = _DEFAULT_BLOCK_SIZES,
    block_shifts: Sequence[int] = _DEFAULT_BLOCK_SHIFTS,
    xor_seeds: Sequence[int] = tuple(range(0, 16)),
    max_tries: int = _DEFAULT_MAX_TRIES,
    timeout: float = _DEFAULT_TIMEOUT,
    top: int = _DEFAULT_TOP,
) -> List[FuzzySearchResult]:
    """Search for promising PRGA parameter candidates."""

    if max_tries <= 0:
        raise ValueError("max_tries must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    start_time = time.monotonic()
    attempts = 0
    best: List[FuzzySearchResult] = []
    seeds = list(xor_seeds)

    for candidate in _iter_candidates(
        variants=variants, rotations=rotations, block_sizes=block_sizes, block_shifts=block_shifts, xor_seeds=seeds
    ):
        if attempts >= max_tries:
            LOGGER.info("Stopping search after reaching max tries (%d)", max_tries)
            break
        if time.monotonic() - start_time >= timeout:
            LOGGER.info("Stopping search after timeout %.2fs", timeout)
            break

        attempts += 1
        output = _apply_candidate(payload, key=key, candidate=candidate)
        score, ascii_ratio, token_ratio, lua_density = score_payload(output)
        base64_score = score_base64_string(output.decode("latin-1", errors="ignore"))
        preview = _preview_text(output)

        result = FuzzySearchResult(
            candidate=candidate,
            score=score + base64_score * 0.05,
            ascii_ratio=ascii_ratio,
            token_ratio=token_ratio,
            lua_density=lua_density,
            base64_score=base64_score,
            preview=preview,
            attempt=attempts,
        )
        best.append(result)

    best.sort(key=lambda item: item.score, reverse=True)
    return best[:top]


def _zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _load_payload(path: Path) -> bytes:
    return path.read_bytes()


def _write_results(results: Sequence[FuzzySearchResult], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = [result.to_serialisable() for result in results]
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOGGER.info("Wrote %d candidates to %s", len(results), destination)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path, help="Path to the decoded LPH payload bytes")
    parser.add_argument("--key", dest="key", help="Session key to apply during PRGA (never persisted)")
    parser.add_argument("--variant", action="append", dest="variants", help="PRGA variant to explore")
    parser.add_argument("--rotate", type=int, action="append", dest="rotations", help="Rotation adjustments to try")
    parser.add_argument("--block-size", type=int, action="append", dest="block_sizes", help="Block sizes to permute")
    parser.add_argument(
        "--block-shift", type=int, action="append", dest="block_shifts", help="Block rotation offsets to try"
    )
    parser.add_argument(
        "--xor-bits",
        type=int,
        default=4,
        help="Generate XOR seeds in the range [0, 2^bits). Default: 4",
    )
    parser.add_argument("--max-tries", type=int, default=_DEFAULT_MAX_TRIES, help="Maximum parameter combinations to test")
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT, help="Maximum search time in seconds")
    parser.add_argument("--top", type=int, default=_DEFAULT_TOP, help="Number of candidates to keep")
    parser.add_argument("--output", type=Path, default=Path("out/fuzzy_candidates.json"), help="Destination JSON path")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    payload = _load_payload(args.payload)

    variants = tuple(args.variants) if args.variants else _DEFAULT_VARIANTS
    rotations = tuple(args.rotations) if args.rotations else _DEFAULT_ROTATIONS
    block_sizes = tuple(args.block_sizes) if args.block_sizes else _DEFAULT_BLOCK_SIZES
    block_shifts = tuple(args.block_shifts) if args.block_shifts else _DEFAULT_BLOCK_SHIFTS

    xor_bits = max(0, args.xor_bits)
    xor_limit = 1 << min(xor_bits, 12)  # guard to keep the range manageable
    xor_seeds = tuple(range(0, xor_limit))

    key_bytes: Optional[bytes] = None
    scrub_buffer: Optional[bytearray] = None
    if args.key:
        scrub_buffer = bytearray(args.key.encode("utf-8"))
        key_bytes = bytes(scrub_buffer)

    try:
        results = guided_search(
            payload,
            key=key_bytes,
            variants=variants,
            rotations=rotations,
            block_sizes=block_sizes,
            block_shifts=block_shifts,
            xor_seeds=xor_seeds,
            max_tries=args.max_tries,
            timeout=args.timeout,
            top=args.top,
        )
        _write_results(results, args.output)
    finally:
        if scrub_buffer is not None:
            _zeroize(scrub_buffer)

    for result in results:
        LOGGER.info(
            "score=%.3f ascii=%.2f tokens=%.2f variant=%s rot=%d block=%d/%d xor=%d",  # noqa: E501
            result.score,
            result.ascii_ratio,
            result.token_ratio,
            result.candidate.variant,
            result.candidate.rotation_adjust,
            result.candidate.block_size,
            result.candidate.block_shift,
            result.candidate.xor_seed,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
