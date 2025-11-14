"""Hill-climbing parameter tuner for Luraph 14.4.x payloads.

This module provides a deterministic hill-climbing search that iteratively
adjusts the permutation block size and rotate offsets used when reversing
obfuscated payloads.  The search space is limited using the same Luraph
version heuristics employed by the rest of the toolkit so that analysts can
focus on realistic candidates (for example the 0x200 permutation block that is
common in v14.4.2 payloads).

The tuner avoids executing untrusted Lua code; it simply applies reversible
byte permutations and rotate adjustments before scoring the decoded payload
using lightweight textual heuristics.  The CLI requires the user to pass
``--confirm`` before running to avoid accidentally kicking off a heavy
analysis job and supports deterministic seeds to reproduce results.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Optional, Sequence, Tuple

from .fuzzy_param_search import score_payload
from .heuristics import score_base64_string

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ParamCandidate",
    "TuningStep",
    "TuningResult",
    "hill_climb_parameters",
    "main",
]

# Default bounds tuned to Luraph v14.4.x observations.
_VERSION_ROTATE_HINTS: Mapping[str, Tuple[int, ...]] = {
    "v14.4.1": (5, 7, 9),
    "v14.4.2": (11, 13, 15),
    "v14.4.3": (8, 16, 24),
    "unknown": (11, 13, 7, 9),
}

_VERSION_BLOCK_HINTS: Mapping[str, Tuple[int, ...]] = {
    "v14.4.1": (256, 384, 512),
    "v14.4.2": (512, 384, 256),
    "v14.4.3": (768, 896, 1024),
    "unknown": (256, 384, 512),
}

_DEFAULT_BLOCK_SHIFTS: Tuple[int, ...] = (0, 1, 2, 3, 4)
_DEFAULT_MAX_ITERATIONS = 48
_MIN_IMPROVEMENT = 5e-4
_PREVIEW_BYTES = 160
_DEFAULT_SEED = 1337


@dataclass(frozen=True)
class ParamCandidate:
    """Candidate parameter combination explored by the tuner."""

    rotate: int
    block_size: int
    block_shift: int

    def normalised(self) -> "ParamCandidate":
        block_size = max(1, int(self.block_size))
        block_shift = int(self.block_shift) % block_size
        rotate = int(self.rotate) % 32
        return ParamCandidate(rotate=rotate, block_size=block_size, block_shift=block_shift)

    def to_serialisable(self) -> Mapping[str, int]:
        candidate = self.normalised()
        return {
            "rotate": candidate.rotate,
            "block_size": candidate.block_size,
            "block_shift": candidate.block_shift,
        }


@dataclass(frozen=True)
class TuningStep:
    """A single evaluation performed during tuning."""

    candidate: ParamCandidate
    score: float
    ascii_ratio: float
    token_ratio: float
    lua_density: float
    base64_score: float
    preview: str
    iteration: int

    def to_serialisable(self) -> Mapping[str, object]:
        return {
            **self.candidate.to_serialisable(),
            "score": round(self.score, 4),
            "ascii_ratio": round(self.ascii_ratio, 4),
            "token_ratio": round(self.token_ratio, 4),
            "lua_density": round(self.lua_density, 4),
            "base64_score": round(self.base64_score, 4),
            "preview": self.preview,
            "iteration": self.iteration,
        }


@dataclass(frozen=True)
class TuningResult:
    """Outcome produced by :func:`hill_climb_parameters`."""

    best: TuningStep
    history: Tuple[TuningStep, ...]
    iterations: int
    elapsed: float
    seed: int

    def to_serialisable(self) -> Mapping[str, object]:
        return {
            "best": self.best.to_serialisable(),
            "history": [step.to_serialisable() for step in self.history],
            "iterations": self.iterations,
            "elapsed": round(self.elapsed, 4),
            "seed": self.seed,
        }


def _preview_text(data: bytes) -> str:
    if not data:
        return ""
    snippet = data[:_PREVIEW_BYTES].decode("latin-1", errors="ignore")
    snippet = snippet.replace("\n", "\\n").replace("\r", "\\r")
    return snippet


def _apply_candidate(payload: bytes, candidate: ParamCandidate) -> bytes:
    candidate = candidate.normalised()
    rotated = _rotate_bytes(payload, candidate.rotate)
    return _permute_blocks(rotated, candidate.block_size, candidate.block_shift)


def _rotate_bytes(data: bytes, amount: int) -> bytes:
    amount &= 7
    if amount == 0 or not data:
        return bytes(data)
    rotated = bytearray(len(data))
    for index, value in enumerate(data):
        rotated[index] = ((value << amount) | (value >> (8 - amount))) & 0xFF
    return bytes(rotated)


def _permute_blocks(data: bytes, block_size: int, block_shift: int) -> bytes:
    block_size = max(1, block_size)
    if block_size <= 1 or len(data) < block_size:
        return bytes(data)
    block_shift = block_shift % block_size
    if block_shift == 0:
        return bytes(data)
    buffer = bytearray(data)
    for offset in range(0, len(buffer), block_size):
        block = buffer[offset : offset + block_size]
        if len(block) < block_size:
            break
        snapshot = block[:]
        for index in range(block_size):
            block[index] = snapshot[(index + block_shift) % block_size]
        buffer[offset : offset + block_size] = block
    return bytes(buffer)


def _version_key(version_hint: Optional[str]) -> str:
    if not version_hint:
        return "unknown"
    version_hint = version_hint.lower()
    for key in ("v14.4.1", "v14.4.2", "v14.4.3"):
        if version_hint.startswith(key):
            return key
    return "unknown"


def _candidate_rotations(version_hint: str) -> Tuple[int, ...]:
    base = _VERSION_ROTATE_HINTS.get(version_hint, _VERSION_ROTATE_HINTS["unknown"])
    values = {0}
    for rotation in base:
        for delta in range(-2, 3):
            values.add((rotation + delta) % 32)
    return tuple(sorted(values))


def _candidate_block_sizes(version_hint: str) -> Tuple[int, ...]:
    base = _VERSION_BLOCK_HINTS.get(version_hint, _VERSION_BLOCK_HINTS["unknown"])
    return tuple(dict.fromkeys(size for size in base if size > 0))


def _iter_neighbours(
    candidate: ParamCandidate,
    *,
    rotations: Sequence[int],
    block_sizes: Sequence[int],
    block_shifts: Sequence[int],
    rng: random.Random,
) -> Iterator[ParamCandidate]:
    candidate = candidate.normalised()
    rotation_order = sorted(rotations, key=lambda value: (abs(value - candidate.rotate), value))
    block_size_order = [size for size in block_sizes if size != candidate.block_size]
    block_shift_order = [
        shift
        for shift in block_shifts
        if shift < candidate.block_size and shift != candidate.block_shift
    ]

    neighbours: list[ParamCandidate] = []
    for rotation in rotation_order:
        if rotation == candidate.rotate:
            continue
        neighbours.append(ParamCandidate(rotation, candidate.block_size, candidate.block_shift))
    for block_size in block_size_order:
        for shift in block_shifts:
            if shift >= block_size:
                continue
            neighbours.append(ParamCandidate(candidate.rotate, block_size, shift))
    for shift in block_shift_order:
        neighbours.append(ParamCandidate(candidate.rotate, candidate.block_size, shift))

    rng.shuffle(neighbours)
    for neighbour in neighbours:
        yield neighbour.normalised()


def _evaluate(payload: bytes, candidate: ParamCandidate, iteration: int) -> TuningStep:
    transformed = _apply_candidate(payload, candidate)
    score, ascii_ratio, token_ratio, lua_density = score_payload(transformed)
    base64_score = score_base64_string(transformed.decode("latin-1", errors="ignore"))
    total_score = score + base64_score * 0.05
    bias = -0.0005 * (candidate.block_size / 1024)
    if candidate.block_shift:
        bias += 0.001
    else:
        bias -= 0.0003
    total_with_bias = total_score + bias
    preview = _preview_text(transformed)
    return TuningStep(
        candidate=candidate.normalised(),
        score=total_with_bias,
        ascii_ratio=ascii_ratio,
        token_ratio=token_ratio,
        lua_density=lua_density,
        base64_score=base64_score,
        preview=preview,
        iteration=iteration,
    )


def hill_climb_parameters(
    payload: bytes,
    *,
    version_hint: Optional[str] = None,
    seed: int = _DEFAULT_SEED,
    max_iterations: int = _DEFAULT_MAX_ITERATIONS,
    block_shifts: Sequence[int] = _DEFAULT_BLOCK_SHIFTS,
) -> TuningResult:
    """Run a deterministic hill-climbing search across parameter candidates."""

    if max_iterations <= 0:
        raise ValueError("max_iterations must be positive")

    version_key = _version_key(version_hint)
    rotations = _candidate_rotations(version_key)
    block_sizes = _candidate_block_sizes(version_key)
    base_rotations = tuple(dict.fromkeys(_VERSION_ROTATE_HINTS.get(version_key, _VERSION_ROTATE_HINTS["unknown"]))) or (rotations[0],)
    base_blocks = tuple(dict.fromkeys(_VERSION_BLOCK_HINTS.get(version_key, _VERSION_BLOCK_HINTS["unknown"]))) or (block_sizes[0],)
    block_shifts = tuple(block_shifts) if block_shifts else _DEFAULT_BLOCK_SHIFTS

    rng = random.Random(seed)
    start = time.perf_counter()

    history: list[TuningStep] = []
    visited: set[Tuple[int, int, int]] = set()

    initial_candidates = [
        ParamCandidate(rotation, base_blocks[0], 0).normalised()
        for rotation in base_rotations[:4]
    ]
    initial_candidates.extend(
        ParamCandidate(base_rotations[0], size, 0).normalised()
        for size in base_blocks[1:4]
    )
    if not initial_candidates:
        initial_candidates = [ParamCandidate(rotations[0], block_sizes[0], 0).normalised()]

    best: Optional[TuningStep] = None
    iteration = 0
    for candidate in initial_candidates:
        key = (candidate.rotate, candidate.block_size, candidate.block_shift)
        if key in visited:
            continue
        visited.add(key)
        iteration += 1
        step = _evaluate(payload, candidate, iteration)
        history.append(step)
        if best is None or step.score > best.score:
            best = step

    if best is None:
        empty_candidate = ParamCandidate(0, 1, 0)
        step = _evaluate(payload, empty_candidate, 1)
        history.append(step)
        best = step

    iterations = iteration

    for _ in range(max_iterations):
        neighbours = list(
            _iter_neighbours(
                best.candidate,
                rotations=rotations,
                block_sizes=block_sizes,
                block_shifts=block_shifts,
                rng=rng,
            )
        )
        improved = False
        for neighbour in neighbours:
            key = (neighbour.rotate, neighbour.block_size, neighbour.block_shift)
            if key in visited:
                continue
            visited.add(key)
            iterations += 1
            step = _evaluate(payload, neighbour, iterations)
            history.append(step)
            if step.score > best.score + _MIN_IMPROVEMENT:
                best = step
                improved = True
                break
        if not improved:
            break

    elapsed = time.perf_counter() - start
    return TuningResult(best=best, history=tuple(history), iterations=iterations, elapsed=elapsed, seed=seed)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", help="Path to the payload bytes to tune against")
    parser.add_argument("--version-hint", default="v14.4.2", help="Version hint to restrict the search space")
    parser.add_argument("--seed", type=int, default=_DEFAULT_SEED, help="Deterministic seed controlling neighbour ordering")
    parser.add_argument("--max-iterations", type=int, default=_DEFAULT_MAX_ITERATIONS, help="Maximum hill-climb iterations")
    parser.add_argument("--block-shifts", type=int, nargs="*", help="Optional explicit block shift candidates")
    parser.add_argument("--output", help="Path to write JSON results")
    parser.add_argument("--confirm", action="store_true", help="Acknowledge that hill-climbing may take time")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.confirm:
        parser.error("--confirm flag is required to run the parameter tuner")

    payload_path = Path(args.payload)
    payload = payload_path.read_bytes()

    result = hill_climb_parameters(
        payload,
        version_hint=args.version_hint,
        seed=args.seed,
        max_iterations=args.max_iterations,
        block_shifts=args.block_shifts or _DEFAULT_BLOCK_SHIFTS,
    )

    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(result.to_serialisable(), handle, indent=2)
            handle.write("\n")
        LOGGER.info("Wrote tuning results to %s", output_path)
    else:
        print(json.dumps(result.to_serialisable(), indent=2))

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
