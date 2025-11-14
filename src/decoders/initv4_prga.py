"""Helpers for mirroring the initv4 PRGA keystream tweaks.

The implementation here exists *solely* for parity and regression tests.  Real
Luraph payloads typically ship with embedded bootstrappers, therefore callers
must not substitute this helper for that runtime logic.  Keys must be provided
at execution time and never loaded from configuration files persisted on disk.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import ByteString, Callable, Iterable, List, Mapping, NamedTuple, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PRGATraceEntry:
    """Detailed record for a single PRGA operation."""

    index: int
    input_byte: int
    key_byte: int
    rotation: int
    xored: int
    output_byte: int
    variant: str = "initv4 default"
    rotation_direction: str = "ror"
    effective_key_byte: Optional[int] = None


_LAST_TRACE: List[PRGATraceEntry] = []


def _hex_dump(data: Iterable[int]) -> str:
    """Return a space-separated hexadecimal representation of ``data``."""

    return " ".join(f"{byte:02x}" for byte in data)


def last_prga_trace() -> List[PRGATraceEntry]:
    """Return the trace collected during the most recent :func:`apply_prga` call."""

    return list(_LAST_TRACE)


def _ror8(value: int, rotation: int) -> int:
    """Rotate an eight-bit value right by ``rotation`` bits."""

    rotation &= 7
    value &= 0xFF
    if rotation == 0:
        return value
    return ((value >> rotation) | ((value << (8 - rotation)) & 0xFF)) & 0xFF


def _rol8(value: int, rotation: int) -> int:
    """Rotate an eight-bit value left by ``rotation`` bits."""

    rotation &= 7
    value &= 0xFF
    if rotation == 0:
        return value
    return ((value << rotation) | (value >> (8 - rotation))) & 0xFF


def _permute_index_default(index: int, key_byte: int, total: int) -> int:
    """Permutation matching the original initv4 observations."""

    if total <= 0:
        return index
    swap_index = (index + key_byte) % total
    logger.debug(
        "permute-default index=%d swap_index=%d key_byte=0x%02x",
        index,
        swap_index,
        key_byte,
    )
    return swap_index


def _permute_index_alt(index: int, key_byte: int, total: int) -> int:
    """Alternative permutation using XOR-based shuffling."""

    if total <= 0:
        return index
    mask = ((key_byte << 1) | (key_byte >> 7)) & 0xFF
    swap_index = (index ^ mask) % total
    logger.debug(
        "permute-alt index=%d swap_index=%d key_byte=0x%02x mask=0x%02x",
        index,
        swap_index,
        key_byte,
        mask,
    )
    return swap_index


def _effective_key_default(key_byte: int, _index: int) -> int:
    return key_byte & 0xFF


def _effective_key_alt(key_byte: int, _index: int) -> int:
    return ((key_byte << 1) | (key_byte >> 7)) & 0xFF


def _rotation_default(key_byte: int, _index: int) -> int:
    return key_byte & 7


def _rotation_alt(key_byte: int, index: int) -> int:
    return ((key_byte >> 1) ^ index) & 7


class _VariantSpec(NamedTuple):
    permute: Callable[[int, int, int], int]
    effective_key: Callable[[int, int], int]
    rotation: Callable[[int, int], int]
    rotate_func: Callable[[int, int], int]
    rotation_direction: str


_DEFAULT_VARIANT = "initv4 default"
_ALT_VARIANT = "initv4 alt"
_VARIANT_ALIASES = {
    "default": _DEFAULT_VARIANT,
    "initv4": _DEFAULT_VARIANT,
    "initv4 default": _DEFAULT_VARIANT,
    "initv4-default": _DEFAULT_VARIANT,
    "initv4_default": _DEFAULT_VARIANT,
    "alt": _ALT_VARIANT,
    "alternative": _ALT_VARIANT,
    "initv4 alt": _ALT_VARIANT,
    "initv4-alt": _ALT_VARIANT,
    "initv4_alt": _ALT_VARIANT,
}

_VARIANT_SPECS = {
    _DEFAULT_VARIANT: _VariantSpec(
        permute=_permute_index_default,
        effective_key=_effective_key_default,
        rotation=_rotation_default,
        rotate_func=_ror8,
        rotation_direction="ror",
    ),
    _ALT_VARIANT: _VariantSpec(
        permute=_permute_index_alt,
        effective_key=_effective_key_alt,
        rotation=_rotation_alt,
        rotate_func=_rol8,
        rotation_direction="rol",
    ),
}


def _resolve_variant(params: Optional[Mapping[str, object]]) -> str:
    if not params:
        return _DEFAULT_VARIANT

    for key in ("variant", "prga_variant", "mode"):
        value = params.get(key) if params else None
        if value is None:
            continue
        normalised = str(value).strip().lower().replace("_", " ").replace("-", " ")
        canonical = _VARIANT_ALIASES.get(normalised)
        if canonical:
            return canonical
        raise ValueError(f"unsupported PRGA variant: {value!r}")

    return _DEFAULT_VARIANT


def apply_prga(
    decoded_lph: ByteString,
    key: ByteString,
    *,
    params: Optional[Mapping[str, object]] = None,
) -> bytes:
    """Mirror the Lua PRGA helper using byte-wise XOR and rotates.

    The implementation keeps a detailed trace for debugging purposes.  Each
    iteration records the inputs, intermediate XOR result, rotation amount and
    the final byte that is emitted.  Alternative PRGA variants can be selected
    via ``params['variant']`` (e.g. ``"initv4 alt"``).
    """

    if not key:
        raise ValueError("key must be non-empty")

    if params:
        for forbidden in ("key_path", "key_file", "key_config", "load_key_from"):
            if forbidden in params:
                raise ValueError(
                    "initv4 parity helper refuses to read keys from configuration files"
                )

    decoded_view = memoryview(decoded_lph)
    key_bytes = memoryview(key)

    key_len = len(key_bytes)
    if key_len == 0:
        raise ValueError("key must be non-empty")
    if key_len > 512:
        raise ValueError("key length exceeds 512-byte safety limit")

    variant = _resolve_variant(params)
    spec = _VARIANT_SPECS.get(variant)
    if spec is None:  # pragma: no cover - defensive guard
        raise ValueError(f"unsupported PRGA variant: {variant}")

    output = bytearray(len(decoded_view))
    total = len(decoded_view)
    trace: List[PRGATraceEntry] = []

    debug_enabled = bool(params.get("debug")) if params else False
    debug_dir: Optional[Path] = None
    if debug_enabled:
        raw_dir = params.get("debug_dir") if params else None
        debug_dir = Path(raw_dir) if raw_dir else Path("out") / "intermediate"
        debug_dir = debug_dir / "initv4"
        debug_dir.mkdir(parents=True, exist_ok=True)

    log_enabled = logger.isEnabledFor(logging.DEBUG) or debug_enabled
    if log_enabled:
        raw_bytes = decoded_view.tobytes()
        logger.debug(
            "prga start variant=%s total=%d key_len=%d",
            variant,
            total,
            key_len,
        )
        logger.debug("prga stage permute before=%s", _hex_dump(raw_bytes))
        permuted_stage: List[int] = []
        xor_stage: List[int] = []
        rotated_stage: List[int] = []
        rotations: List[int] = []
    else:
        permuted_stage = xor_stage = rotated_stage = rotations = None  # type: ignore[assignment]

    for index in range(total):
        key_byte = key_bytes[index % key_len]
        permuted_index = spec.permute(index, key_byte, total)
        permuted_value = decoded_view[permuted_index]

        if log_enabled:
            permuted_stage.append(permuted_value)

        effective_key = spec.effective_key(key_byte, index)
        xored = permuted_value ^ effective_key
        rotation = spec.rotation(key_byte, index)
        if log_enabled:
            xor_stage.append(xored & 0xFF)
            rotations.append(rotation)
        result = spec.rotate_func(xored, rotation)
        if log_enabled:
            rotated_stage.append(result)

        output[index] = result
        entry = PRGATraceEntry(
            index=index,
            input_byte=permuted_value,
            key_byte=key_byte,
            rotation=rotation,
            xored=xored,
            output_byte=result,
            variant=variant,
            rotation_direction=spec.rotation_direction,
            effective_key_byte=effective_key,
        )
        trace.append(entry)
        logger.debug(
            (
                "prga index=%d variant=%s permuted_index=%d input=0x%02x "
                "key=0x%02x eff_key=0x%02x xor=0x%02x rotation=%d(%s) output=0x%02x"
            ),
            index,
            variant,
            permuted_index,
            permuted_value,
            key_byte,
            effective_key,
            xored,
            rotation,
            spec.rotation_direction,
            result,
        )

    global _LAST_TRACE
    _LAST_TRACE = trace

    if log_enabled:
        logger.debug("prga stage permute after=%s", _hex_dump(permuted_stage))
        logger.debug("prga stage xor before=%s", _hex_dump(permuted_stage))
        logger.debug("prga stage xor after=%s", _hex_dump(xor_stage))
        logger.debug("prga stage rotate before=%s", _hex_dump(xor_stage))
        logger.debug("prga stage rotate after=%s", _hex_dump(rotated_stage))
        logger.debug("prga rotations=%s", " ".join(str(r) for r in rotations))
        logger.debug("prga complete variant=%s length=%d", variant, len(output))
    else:
        logger.debug("prga complete variant=%s length=%d", variant, len(output))

    if debug_enabled and debug_dir is not None:
        stages = [
            decoded_view.tobytes(),
            bytes(permuted_stage or []),
            bytes(xor_stage or []),
            bytes(rotated_stage or []),
        ]
        for index, data in enumerate(stages):
            if not data:
                continue
            path = debug_dir / f"initv4_stage{index}.bin"
            path.write_bytes(data)
            logger.debug("wrote debug stage %d (%d bytes) -> %s", index, len(data), path)

    return bytes(output)


__all__ = ["PRGATraceEntry", "apply_prga", "last_prga_trace"]
