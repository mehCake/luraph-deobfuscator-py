"""Helpers for reversing Layered Payload Handler (LPH) transforms.

The bootstrap code populates a ``params`` mapping that describes the
transformations which were applied to the payload.  This module provides a
Python implementation that mirrors the reverse flow so that analysts can
recover the original byte payload without executing Lua code.

The reverse pipeline supports the LPH variations encountered in
:mod:`Luraph` versions 14.4.1 and 14.4.2.  Those variants typically combine
four reversible stages:

``mask``
    Undo byte masking operations such as XOR or addition based paddings.
``block_rotate``
    Reverse block level rotations where contiguous groups of bytes are shifted.
``permute`` / ``inblock_permute``
    Reconstruct the original order when payload bytes were permuted globally or
    within fixed-size blocks.
``rotate`` / ``xor_mix``
    Undo bitwise rotations and neighbour based XOR mixing that introduce local
    diffusion.

The ``params`` dictionary contains stub entries for these operations so that
bootstrap discovery code can fill in the values as they are recovered from the
obfuscated artefacts.  The expected layout is illustrated by
:const:`LPH_PARAM_STUB` which is exported for bootstrap code to clone and fill.

Each call records a trace of intermediate buffers so that tooling can present a
step-by-step breakdown without rerunning the algorithm.  The most recent trace
is available through :func:`last_reverse_trace`.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Callable, Iterable, List, Mapping, MutableSequence, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReverseTraceEntry:
    """Capture the payload after a pipeline step.

    Parameters
    ----------
    step:
        The pipeline step that produced ``data``.
    data:
        The payload snapshot immediately after the step.
    detail:
        Operation specific metadata that callers may surface to users.  The
        values are intentionally untyped so the bootstrapper can describe the
        recovered parameters verbatim.
    """

    step: str
    data: bytes
    detail: Mapping[str, Any]


LPH_PARAM_STUB: Mapping[str, Any] = {
    "steps": [
        "mask",
        "block_rotate",
        "permute",
        "inblock_permute",
        "rotate",
        "xor_mix",
    ],
    "mask": {
        "mode": "xor",  # xor, add, sub
        "value": None,  # integer mask or None when ``stream`` is used
        "stream": None,  # optional byte stream for position dependant masks
    },
    "block_rotate": {
        "size": None,  # block size used during obfuscation
        "shift": 0,  # rotation distance in bytes
        "direction": "left",  # direction applied during obfuscation
    },
    "permute": {
        "table": None,  # global permutation table discovered during bootstrap
    },
    "inblock_permute": {
        "block_size": None,  # per-block permutation size
        "table": None,  # permutation applied to each block
    },
    "rotate": {
        "amount": None,  # default rotation amount
        "amounts": None,  # optional per-byte rotation list or byte stream
        "direction": "left",  # direction applied during obfuscation
    },
    "xor_mix": {
        "mode": "stream",  # stream, rolling
        "stream": None,  # static xor stream (stream mode)
        "stride": 1,  # number of bytes to look back (rolling mode)
        "seed": None,  # optional seed bytes for the first ``stride`` entries
    },
}
"""Template describing the parameter structure expected by :func:`reverse_lph`."""


@dataclass(frozen=True)
class ReverseCandidate:
    """Result container returned by :func:`try_parameter_presets`.

    Attributes
    ----------
    name:
        Name of the preset that produced the candidate.
    params:
        Parameter mapping that was used to reverse the payload.
    output:
        Decoded payload.
    score:
        Heuristic score assigned by the caller supplied scoring function.
    trace:
        Pipeline trace captured during :func:`reverse_lph` execution.
    """

    name: str
    params: Mapping[str, Any]
    output: bytes
    score: float
    trace: List[ReverseTraceEntry]


_LAST_TRACE: List[ReverseTraceEntry] = []


COMMON_PARAMETER_PRESETS: Tuple[Tuple[str, Mapping[str, Any]], ...] = (
    (
        "v14.4.1-default",
        {
            "steps": ["mask", "permute", "rotate", "xor_mix"],
            "mask": {"mode": "xor", "value": 0xA5},
            "permute": {"table": None},
            "rotate": {"amount": 3, "direction": "left"},
            "xor_mix": {"mode": "rolling", "stride": 1, "seed": b"\x00"},
        },
    ),
    (
        "v14.4.2-default",
        {
            "steps": [
                "mask",
                "block_rotate",
                "inblock_permute",
                "rotate",
                "xor_mix",
            ],
            "mask": {"mode": "xor", "value": 0x5C},
            "block_rotate": {"size": 16, "shift": 4, "direction": "right"},
            "inblock_permute": {"block_size": 4, "table": None},
            "rotate": {"amount": 1, "direction": "left"},
            "xor_mix": {"mode": "stream", "stream": b"LPH"},
        },
    ),
)
"""Common LPH parameter presets observed across supported Luraph versions."""


def last_reverse_trace() -> List[ReverseTraceEntry]:
    """Return a copy of the trace captured by the last :func:`reverse_lph` call."""

    return list(_LAST_TRACE)


def _coerce_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin1")
    if isinstance(value, Iterable):
        try:
            return bytes(int(v) & 0xFF for v in value)
        except TypeError as exc:  # pragma: no cover - defensive
            raise TypeError("unable to coerce iterable to bytes") from exc
    if isinstance(value, int):
        return bytes([(value & 0xFF)])
    raise TypeError(f"unsupported mask stream type: {type(value)!r}")


def _apply_mask(buffer: MutableSequence[int], params: Mapping[str, Any]) -> Mapping[str, Any]:
    mode = (params.get("mode") or "xor").lower()
    mask_stream = _coerce_bytes(params.get("stream"))
    if mask_stream:
        stream = mask_stream
    else:
        value = params.get("value")
        if value is None:
            logger.debug("mask step skipped (no stream or value provided)")
            return {"mode": mode, "mask": None}
        stream = _coerce_bytes(value)
    if not stream:
        logger.debug("mask step skipped (empty mask stream)")
        return {"mode": mode, "mask": None}

    stream_len = len(stream)
    for index in range(len(buffer)):
        before = buffer[index]
        mask_byte = stream[index % stream_len]
        if mode == "xor":
            buffer[index] = before ^ mask_byte
        elif mode == "add":
            buffer[index] = (before - mask_byte) & 0xFF
        elif mode == "sub":
            buffer[index] = (before + mask_byte) & 0xFF
        else:  # pragma: no cover - new modes are injected by bootstrap
            raise ValueError(f"unsupported mask mode: {mode}")
        logger.debug(
            "mask index=%d before=0x%02x mask=0x%02x after=0x%02x mode=%s",
            index,
            before,
            mask_byte,
            buffer[index],
            mode,
        )
    return {"mode": mode, "mask_length": stream_len}


def _apply_permutation(buffer: MutableSequence[int], params: Mapping[str, Any]) -> Mapping[str, Any]:
    table = params.get("table")
    if not table:
        logger.debug("permute step skipped (no table provided)")
        return {"table_length": 0}

    table_sequence = list(int(v) for v in table)
    size = len(buffer)
    if len(table_sequence) != size:
        raise ValueError("permutation table length mismatch")

    inverse = [0] * size
    for idx, target in enumerate(table_sequence):
        if target < 0 or target >= size:
            raise ValueError("permutation target out of range")
        inverse[target] = idx

    snapshot = list(buffer)
    for idx, src in enumerate(inverse):
        before = buffer[idx]
        buffer[idx] = snapshot[src]
        logger.debug(
            "permute index=%d from=%d before=0x%02x after=0x%02x",
            idx,
            src,
            before,
            buffer[idx],
        )

    return {"table_length": size}


def _apply_block_rotation(buffer: MutableSequence[int], params: Mapping[str, Any]) -> Mapping[str, Any]:
    """Undo block level rotations.

    The bootstrapper records the direction of rotation that was applied during
    obfuscation.  To reverse it we rotate in the opposite direction.
    """

    block_size = int(params.get("size") or 0)
    shift = int(params.get("shift") or 0)
    direction = (params.get("direction") or "left").lower()

    if not block_size or block_size <= 0:
        logger.debug("block rotate skipped (invalid block size)")
        return {"block_size": 0, "shift": 0}
    if shift % block_size == 0:
        logger.debug("block rotate skipped (shift multiple of block size)")
        return {"block_size": block_size, "shift": 0}
    if direction not in {"left", "right"}:
        raise ValueError("unsupported block rotation direction")

    effective_shift = shift % block_size
    undo_direction = "right" if direction == "left" else "left"

    def rotate_block(chunk: Sequence[int]) -> List[int]:
        if not chunk:
            return list(chunk)
        if undo_direction == "left":
            pivot = effective_shift
        else:
            pivot = len(chunk) - effective_shift
        pivot %= len(chunk)
        return list(chunk[pivot:]) + list(chunk[:pivot])

    for start in range(0, len(buffer), block_size):
        end = min(start + block_size, len(buffer))
        rotated = rotate_block(buffer[start:end])
        buffer[start:end] = rotated
        logger.debug(
            "block rotate start=%d end=%d direction=%s shift=%d",
            start,
            end,
            undo_direction,
            effective_shift,
        )

    return {"block_size": block_size, "shift": effective_shift, "direction": undo_direction}


def _apply_inblock_permutation(buffer: MutableSequence[int], params: Mapping[str, Any]) -> Mapping[str, Any]:
    """Undo per-block permutations."""

    block_size = int(params.get("block_size") or 0)
    table = params.get("table")
    if not block_size or block_size <= 0 or not table:
        logger.debug("in-block permutation skipped (no table or block size)")
        return {"block_size": 0}

    table_sequence = [int(v) for v in table]
    if len(table_sequence) != block_size:
        raise ValueError("in-block permutation table length mismatch")

    inverse = [0] * block_size
    for idx, target in enumerate(table_sequence):
        if target < 0 or target >= block_size:
            raise ValueError("in-block permutation target out of range")
        inverse[target] = idx

    for start in range(0, len(buffer), block_size):
        end = min(start + block_size, len(buffer))
        chunk = list(buffer[start:end])
        for idx in range(end - start):
            buffer[start + idx] = chunk[inverse[idx]]
        logger.debug(
            "in-block permute start=%d end=%d table=%s",
            start,
            end,
            ",".join(str(v) for v in table_sequence),
        )

    return {"block_size": block_size, "table_length": len(table_sequence)}


def _rol8(value: int, rotation: int) -> int:
    rotation &= 7
    value &= 0xFF
    return ((value << rotation) | (value >> (8 - rotation))) & 0xFF


def _ror8(value: int, rotation: int) -> int:
    rotation &= 7
    value &= 0xFF
    return ((value >> rotation) | (value << (8 - rotation))) & 0xFF


def _apply_rotation(buffer: MutableSequence[int], params: Mapping[str, Any]) -> Mapping[str, Any]:
    amount = params.get("amount")
    amounts = params.get("amounts")
    amount_stream = _coerce_bytes(amounts) if amounts is not None else None

    if amount_stream:
        rotations = [b & 7 for b in amount_stream]
    elif isinstance(amount, Iterable) and not isinstance(amount, (bytes, bytearray, memoryview, str)):
        rotations = [int(v) & 7 for v in amount]
    elif amount is None:
        rotations = []
    else:
        rotations = [int(amount) & 7]

    if not rotations:
        logger.debug("rotate step skipped (no rotation amount provided)")
        return {"rotations": []}

    direction = (params.get("direction") or "left").lower()
    if direction not in {"left", "right"}:
        raise ValueError("unsupported rotation direction")

    undo = _ror8 if direction == "left" else _rol8

    size = len(buffer)
    for idx in range(size):
        rotation = rotations[idx % len(rotations)]
        before = buffer[idx]
        buffer[idx] = undo(before, rotation)
        logger.debug(
            "rotate index=%d before=0x%02x rotation=%d direction=%s after=0x%02x",
            idx,
            before,
            rotation,
            direction,
            buffer[idx],
        )

    return {"direction": direction, "rotation_count": len(rotations)}


def _apply_xor_mix(buffer: MutableSequence[int], params: Mapping[str, Any]) -> Mapping[str, Any]:
    """Undo XOR diffusion introduced during obfuscation."""

    mode = (params.get("mode") or "stream").lower()
    if mode == "stream":
        stream = _coerce_bytes(params.get("stream"))
        if not stream:
            logger.debug("xor mix skipped (no stream provided)")
            return {"mode": mode, "stream_length": 0}
        length = len(stream)
        for index in range(len(buffer)):
            before = buffer[index]
            buffer[index] = before ^ stream[index % length]
            logger.debug(
                "xor-mix(stream) index=%d before=0x%02x key=0x%02x after=0x%02x",
                index,
                before,
                stream[index % length],
                buffer[index],
            )
        return {"mode": mode, "stream_length": length}

    if mode == "rolling":
        stride = max(1, int(params.get("stride") or 1))
        seed_stream = _coerce_bytes(params.get("seed"))
        seeds = list(seed_stream or b"")

        for index in range(len(buffer)):
            if index < stride:
                mix = seeds[index % len(seeds)] if seeds else 0
            else:
                mix = buffer[index - stride]
            before = buffer[index]
            buffer[index] = before ^ (mix & 0xFF)
            logger.debug(
                "xor-mix(rolling) index=%d before=0x%02x mix=0x%02x after=0x%02x",
                index,
                before,
                mix,
                buffer[index],
            )
        return {"mode": mode, "stride": stride, "seed_length": len(seeds)}

    raise ValueError(f"unsupported xor_mix mode: {mode}")


def _dump_intermediate(snapshot: bytes, step: str, order: int, debug: bool, dump_dir: Optional[Path]) -> None:
    if not debug:
        return

    target_dir = Path(dump_dir) if dump_dir is not None else Path("out/intermediate")
    target_dir.mkdir(parents=True, exist_ok=True)
    stem = f"lph_{order:02d}_{step}"
    bin_path = target_dir / f"{stem}.bin"
    txt_path = target_dir / f"{stem}.txt"
    bin_path.write_bytes(snapshot)
    txt_path.write_text(" ".join(f"{byte:02x}" for byte in snapshot) + "\n")


def reverse_lph(
    data: bytes,
    params: Mapping[str, Any],
    *,
    debug: bool = False,
    dump_dir: Optional[Path] = None,
) -> bytes:
    """Reverse the LPH pipeline described by ``params``.

    Parameters
    ----------
    data:
        The payload data produced by the bootstrap sequence.
    params:
        Mapping describing the operations to undo.  Bootstrap discovery code is
        expected to start from :const:`LPH_PARAM_STUB` and fill in concrete
        values.
    debug:
        When ``True`` each pipeline step writes ``.bin`` and ``.txt`` hex dumps
        to ``dump_dir`` (defaults to ``out/intermediate``).
    dump_dir:
        Optional directory used when ``debug`` mode is enabled.
    """

    buffer = bytearray(data)
    dumps: List[ReverseTraceEntry] = []

    steps = list(params.get("steps") or []) if params else []
    if not steps:
        steps = ["mask", "permute", "rotate"]

    for index, step in enumerate(steps):
        detail: Mapping[str, Any]
        if step == "mask":
            detail = _apply_mask(buffer, params.get("mask", {}))
        elif step == "block_rotate":
            detail = _apply_block_rotation(buffer, params.get("block_rotate", {}))
        elif step == "permute":
            detail = _apply_permutation(buffer, params.get("permute", {}))
        elif step == "inblock_permute":
            detail = _apply_inblock_permutation(buffer, params.get("inblock_permute", {}))
        elif step == "rotate":
            detail = _apply_rotation(buffer, params.get("rotate", {}))
        elif step == "xor_mix":
            detail = _apply_xor_mix(buffer, params.get("xor_mix", {}))
        else:
            logger.debug("unknown step '%s' skipped", step)
            continue

        snapshot = bytes(buffer)
        _dump_intermediate(snapshot, step, index, debug, dump_dir)
        dumps.append(ReverseTraceEntry(step=step, data=snapshot, detail=dict(detail)))
        logger.debug("after %s step payload_len=%d", step, len(snapshot))

    global _LAST_TRACE
    _LAST_TRACE = dumps
    return bytes(buffer)


def _default_score(payload: bytes) -> float:
    if not payload:
        return 0.0
    printable = sum(
        1
        for byte in payload
        if 0x20 <= byte <= 0x7E or byte in {0x0A, 0x0D, 0x09}
    )
    return printable / len(payload)


def try_parameter_presets(
    data: bytes,
    presets: Optional[Sequence[Tuple[str, Mapping[str, Any]]]] = None,
    *,
    score_fn: Optional[Callable[[bytes], float]] = None,
    debug: bool = False,
    dump_dir: Optional[Path] = None,
) -> List[ReverseCandidate]:
    """Attempt multiple parameter sets and return sorted candidates.

    The helper is primarily used by automated tooling which only recovered a
    subset of bootstrap parameters.  ``presets`` defaults to
    :const:`COMMON_PARAMETER_PRESETS` and callers may supply a custom scoring
    function.  Higher scores indicate better matches.
    """

    selected_presets = tuple(presets or COMMON_PARAMETER_PRESETS)
    score_cb = score_fn or _default_score
    results: List[ReverseCandidate] = []

    for name, preset in selected_presets:
        try:
            output = reverse_lph(data, preset, debug=debug, dump_dir=dump_dir)
        except Exception:  # pragma: no cover - preset exploration should continue
            logger.exception("reverse_lph failed for preset %%s", name)
            continue

        trace = list(last_reverse_trace())
        score = float(score_cb(output))
        results.append(
            ReverseCandidate(
                name=name,
                params=preset,
                output=output,
                score=score,
                trace=trace,
            )
        )

    results.sort(key=lambda candidate: candidate.score, reverse=True)
    return results


__all__ = [
    "COMMON_PARAMETER_PRESETS",
    "LPH_PARAM_STUB",
    "ReverseCandidate",
    "ReverseTraceEntry",
    "last_reverse_trace",
    "reverse_lph",
    "try_parameter_presets",
]
