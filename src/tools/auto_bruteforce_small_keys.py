"""Brute-force helper for discovering tiny PRGA keys.

This module intentionally limits itself to extremely small key spaces and
requires explicit user opt-in before any brute-force attempt is made.  It is
useful for parity tests and highly constrained research scenarios where a
payload is suspected to reuse short session keys.

The implementation never persists provided keys except in the optional JSON
report requested by the caller.  All ephemeral key buffers are scrubbed before
continuing to the next attempt and verbose logging avoids printing key material.
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableSequence, Optional, Sequence

from ..decoders.initv4_prga import apply_prga
from .fuzzy_param_search import score_payload
from .heuristics import score_base64_string

LOGGER = logging.getLogger(__name__)

__all__ = [
    "BruteforceAttempt",
    "BruteforceReport",
    "bruteforce_small_keys",
    "write_report",
    "main",
]

_DEFAULT_ALPHABET = "0123456789ABCDEF"
_DEFAULT_MAX_LENGTH = 6
_DEFAULT_MAX_TRIES = 4096
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_TOP = 20
_DEFAULT_VARIANT = "initv4 default"


@dataclass(frozen=True)
class BruteforceAttempt:
    """Record describing a single attempted key."""

    key: str
    score: float
    ascii_ratio: float
    token_ratio: float
    lua_density: float
    base64_score: float
    preview: str
    attempt: int
    length: int
    elapsed: float

    def to_serialisable(self) -> Mapping[str, object]:
        return {
            "key": self.key,
            "score": round(self.score, 6),
            "ascii_ratio": round(self.ascii_ratio, 6),
            "token_ratio": round(self.token_ratio, 6),
            "lua_density": round(self.lua_density, 6),
            "base64_score": round(self.base64_score, 6),
            "preview": self.preview,
            "attempt": self.attempt,
            "length": self.length,
            "elapsed": round(self.elapsed, 6),
        }


@dataclass
class BruteforceReport:
    """Summary returned by :func:`bruteforce_small_keys`."""

    attempts: List[BruteforceAttempt]
    total_attempts: int
    truncated: bool
    timed_out: bool
    elapsed: float
    alphabet: str
    max_length: int
    variant: str
    payload_size: int

    def to_serialisable(self) -> Mapping[str, object]:
        return {
            "metadata": {
                "total_attempts": self.total_attempts,
                "truncated": self.truncated,
                "timed_out": self.timed_out,
                "elapsed": round(self.elapsed, 6),
                "alphabet": self.alphabet,
                "max_length": self.max_length,
                "variant": self.variant,
                "payload_size": self.payload_size,
            },
            "attempts": [attempt.to_serialisable() for attempt in self.attempts],
        }


def _preview_text(data: bytes, limit: int = 96) -> str:
    if not data:
        return ""
    snippet = data[:limit].decode("latin-1", errors="replace")
    snippet = snippet.replace("\n", "\\n").replace("\r", "\\r")
    return snippet


def _zeroize(buffer: MutableSequence[int]) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _iter_keys(alphabet: str, max_length: int) -> Iterable[str]:
    for length in range(1, max_length + 1):
        for combo in itertools.product(alphabet, repeat=length):
            yield "".join(combo)


def bruteforce_small_keys(
    payload: bytes,
    *,
    allow_bruteforce: bool,
    alphabet: str = _DEFAULT_ALPHABET,
    max_length: int = _DEFAULT_MAX_LENGTH,
    max_tries: int = _DEFAULT_MAX_TRIES,
    timeout: float = _DEFAULT_TIMEOUT,
    variant: str = _DEFAULT_VARIANT,
    top: int = _DEFAULT_TOP,
) -> BruteforceReport:
    """Try short PRGA keys against *payload* and score the decoded bytes."""

    if not allow_bruteforce:
        raise PermissionError("explicit --allow-bruteforce opt-in is required")

    if not payload:
        raise ValueError("payload must be non-empty")

    if max_length <= 0:
        raise ValueError("max_length must be positive")

    start = time.perf_counter()
    attempts: List[BruteforceAttempt] = []
    total_attempts = 0
    truncated = False
    timed_out = False

    for key_str in _iter_keys(alphabet, max_length):
        if total_attempts >= max_tries:
            truncated = True
            break
        if time.perf_counter() - start > timeout:
            timed_out = True
            break

        key_buffer = bytearray(key_str, "latin-1")
        total_attempts += 1
        try:
            decoded = apply_prga(payload, bytes(key_buffer), params={"variant": variant})
        except Exception as exc:  # pragma: no cover - defensive guard
            LOGGER.debug("PRGA attempt %d failed: %s", total_attempts, exc)
            decoded = b""
        finally:
            _zeroize(key_buffer)

        score, ascii_ratio, token_ratio, lua_density = score_payload(decoded)
        base64_score = score_base64_string(decoded.decode("latin-1", errors="ignore"))
        attempt = BruteforceAttempt(
            key=key_str,
            score=score,
            ascii_ratio=ascii_ratio,
            token_ratio=token_ratio,
            lua_density=lua_density,
            base64_score=base64_score,
            preview=_preview_text(decoded),
            attempt=total_attempts,
            length=len(key_str),
            elapsed=time.perf_counter() - start,
        )
        attempts.append(attempt)

    elapsed = time.perf_counter() - start
    if top and len(attempts) > top:
        attempts.sort(key=lambda item: item.score, reverse=True)
        attempts = attempts[:top]
    else:
        attempts.sort(key=lambda item: item.score, reverse=True)

    report = BruteforceReport(
        attempts=attempts,
        total_attempts=total_attempts,
        truncated=truncated,
        timed_out=timed_out,
        elapsed=elapsed,
        alphabet=alphabet,
        max_length=max_length,
        variant=variant,
        payload_size=len(payload),
    )
    return report


def write_report(report: BruteforceReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report.to_serialisable(), handle, indent=2)
        handle.write("\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", help="Path to the PRGA payload to brute-force")
    parser.add_argument("--allow-bruteforce", action="store_true", help="Opt-in to key brute forcing")
    parser.add_argument("--alphabet", default=_DEFAULT_ALPHABET, help="Alphabet to use when generating keys")
    parser.add_argument("--max-length", type=int, default=_DEFAULT_MAX_LENGTH, help="Maximum key length to try")
    parser.add_argument("--max-tries", type=int, default=_DEFAULT_MAX_TRIES, help="Maximum number of attempts")
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT, help="Time budget in seconds")
    parser.add_argument("--variant", default=_DEFAULT_VARIANT, help="PRGA variant to emulate")
    parser.add_argument("--top", type=int, default=_DEFAULT_TOP, help="Number of top attempts to keep in the report")
    parser.add_argument("--output-dir", default="out/bruteforce", help="Directory for JSON reports")
    parser.add_argument("--candidate-name", help="Override output file stem")
    parser.add_argument("--min-score", type=float, default=0.0, help="Minimum score threshold for reporting")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.allow_bruteforce:
        parser.error("--allow-bruteforce flag is required before running this tool")

    payload_path = Path(args.payload)
    payload = payload_path.read_bytes()

    report = bruteforce_small_keys(
        payload,
        allow_bruteforce=True,
        alphabet=args.alphabet,
        max_length=args.max_length,
        max_tries=args.max_tries,
        timeout=args.timeout,
        variant=args.variant,
        top=args.top,
    )

    if args.min_score > 0.0:
        filtered = [attempt for attempt in report.attempts if attempt.score >= args.min_score]
    else:
        filtered = list(report.attempts)

    output_dir = Path(args.output_dir)
    candidate = args.candidate_name or payload_path.stem
    output_path = output_dir / f"{candidate}.json"

    filtered_report = BruteforceReport(
        attempts=filtered,
        total_attempts=report.total_attempts,
        truncated=report.truncated,
        timed_out=report.timed_out,
        elapsed=report.elapsed,
        alphabet=report.alphabet,
        max_length=report.max_length,
        variant=report.variant,
        payload_size=report.payload_size,
    )

    write_report(filtered_report, output_path)

    print(
        f"Bruteforce complete: attempts={report.total_attempts} "
        f"truncated={report.truncated} timed_out={report.timed_out} "
        f"top_score={(filtered[0].score if filtered else 0.0):.4f}"
    )

    # Best effort scrub of temporary structures containing keys.
    for attempt in filtered:
        _zeroize(bytearray(attempt.key, "latin-1"))
    for attempt in report.attempts:
        _zeroize(bytearray(attempt.key, "latin-1"))

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
