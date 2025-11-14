"""Parity harness comparing Python PRGA with Lua reference implementation.

This module orchestrates byte-level parity checks between the Python
``apply_prga`` helper and a Lua reference implementation.  It is intentionally
side-effect free – payloads are never executed and any session keys supplied via
CLI arguments are wiped from memory after the comparison completes.

Example usage::

    python -m src.tools.parity_test tests/parity/sample_lph.bin \
        --limit 64 --variant "initv4 default"

To verify an obfuscated bootstrapper that requires a session key, pass the key
interactively (the buffer is zeroed afterwards)::

    python -m src.tools.parity_test tests/parity/sample_lph.bin --key-stdin

    # type the session key when prompted and press Enter
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from lupa import LuaError, LuaRuntime

from src.decoders.initv4_prga import PRGATraceEntry, apply_prga, last_prga_trace

logger = logging.getLogger(__name__)


DEFAULT_COMPARE_LIMIT = 64
_CONTEXT_WINDOW = 16


@dataclass(frozen=True)
class ParitySample:
    """Container describing a parity validation sample."""

    decoded_payload: bytes
    key: bytes
    lua_source: str


class ParityMismatchError(RuntimeError):
    """Raised when the parity harness observes diverging outputs."""

    def __init__(
        self,
        *,
        index: int,
        python_value: int,
        lua_value: int,
        context_py: str,
        context_lua: str,
    ) -> None:
        self.index = index
        self.python_value = python_value
        self.lua_value = lua_value
        self.context_py = context_py
        self.context_lua = context_lua
        super().__init__(
            "PRGA parity mismatch at byte {idx}: py={py:02x} lua={lua:02x}".format(
                idx=index,
                py=python_value,
                lua=lua_value,
            )
        )


@dataclass
class BruteforceOutcome:
    """Result metadata for a brute-force parity attempt."""

    attempted: bool
    attempts: int = 0
    success: bool = False
    best_prefix: int = 0
    best_key_length: Optional[int] = None
    reason: Optional[str] = None


def _read_sample(path: Path) -> ParitySample:
    """Load a parity sample description from ``path``.

    The sample file is expected to contain JSON with ``decoded_payload_hex``,
    ``key_hex`` and a ``lua_source`` chunk that returns a table exposing the
    ``apply_prga_ref`` function.
    """

    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        payload_hex = data["decoded_payload_hex"]
        key_hex = data["key_hex"]
        lua_source = data["lua_source"]
    except KeyError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"missing required field in sample: {exc}") from exc

    decoded_payload = bytes.fromhex(payload_hex)
    key = bytes.fromhex(key_hex)
    if not lua_source.strip():
        raise ValueError("lua_source must not be empty")

    return ParitySample(decoded_payload=decoded_payload, key=key, lua_source=lua_source)


def _as_lua_string(data: bytes) -> str:
    """Return ``data`` interpreted as a Latin-1 Lua string."""

    return data.decode("latin1")


def _compare_prefix(py_bytes: bytes, lua_bytes: bytes, limit: int) -> None:
    """Compare the first ``limit`` bytes of both buffers, raising on mismatch."""

    prefix = min(limit, len(py_bytes), len(lua_bytes))
    for index in range(prefix):
        py_val = py_bytes[index]
        lua_val = lua_bytes[index]
        if py_val != lua_val:
            half = max(1, _CONTEXT_WINDOW // 2)
            start = max(0, index - half)
            end = min(len(py_bytes), index + half)
            context_py = py_bytes[start:end].hex()
            context_lua = lua_bytes[start:end].hex()
            logger.error(
                "Mismatch at index %d: py=%02x lua=%02x | py[%d:%d]=%s lua[%d:%d]=%s",
                index,
                py_val,
                lua_val,
                start,
                end,
                context_py,
                start,
                end,
                context_lua,
            )
            raise ParityMismatchError(
                index=index,
                python_value=py_val,
                lua_value=lua_val,
                context_py=context_py,
                context_lua=context_lua,
            )

    if len(py_bytes) < limit or len(lua_bytes) < limit:
        logger.warning(
            "Buffers shorter than requested limit (%d); compared %d bytes",
            limit,
            prefix,
        )


def _matching_prefix_length(py_bytes: bytes, lua_bytes: bytes, limit: int) -> int:
    """Return the number of matching prefix bytes between both buffers."""

    prefix = min(limit, len(py_bytes), len(lua_bytes))
    for index in range(prefix):
        if py_bytes[index] != lua_bytes[index]:
            return index
    return prefix


def _iter_small_keys(lengths: Sequence[int]) -> Iterable[bytes]:
    for length in lengths:
        if length <= 0:
            continue
        for combo in product(range(256), repeat=length):
            yield bytes(combo)


def _bruteforce_small_keys(
    decoded_payload: bytes,
    lua_payload: str,
    lua_apply,
    *,
    params: Optional[dict],
    limit: int,
    max_attempts: int,
    key_lengths: Sequence[int],
    skip_keys: Sequence[bytes] = (),
) -> BruteforceOutcome:
    """Attempt to brute-force short keys and return the best match observed."""

    if max_attempts <= 0:
        return BruteforceOutcome(attempted=False, reason="max_attempts <= 0")

    attempts = 0
    best_prefix = -1
    best_length: Optional[int] = None
    skipped = {key for key in skip_keys if key}

    for candidate in _iter_small_keys(key_lengths):
        if attempts >= max_attempts:
            logger.debug("Brute-force guard reached after %d attempts", attempts)
            break
        if not candidate or candidate in skipped:
            continue
        attempts += 1
        py_bytes = apply_prga(decoded_payload, candidate, params=params)
        lua_bytes = lua_apply(lua_payload, _as_lua_string(candidate))
        if isinstance(lua_bytes, str):
            lua_bytes = lua_bytes.encode("latin1")
        prefix = _matching_prefix_length(py_bytes, lua_bytes, limit)
        if prefix > best_prefix:
            best_prefix = prefix
            best_length = len(candidate)
        if prefix >= limit:
            logger.info(
                "Brute-force discovered matching key of length %d after %d attempts",
                len(candidate),
                attempts,
            )
            return BruteforceOutcome(
                attempted=True,
                attempts=attempts,
                success=True,
                best_prefix=prefix,
                best_key_length=len(candidate),
            )

    if attempts == 0:
        return BruteforceOutcome(
            attempted=False,
            reason="No candidate lengths satisfied brute-force constraints",
        )

    return BruteforceOutcome(
        attempted=True,
        attempts=attempts,
        success=False,
        best_prefix=max(0, best_prefix),
        best_key_length=best_length,
    )


def _write_parity_report(
    report_path: Path,
    *,
    sample_path: Path,
    variant: str,
    limit: int,
    success: bool,
    baseline_prefix: int,
    mismatch: Optional[ParityMismatchError],
    brute_force: BruteforceOutcome,
    redact_keys: bool,
) -> None:
    """Serialise the parity outcome to ``report_path``."""

    report_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = [
        "# PRGA Parity Report",
        "",
        f"* **Sample:** `{sample_path}`",
        f"* **Variant:** `{variant}`",
        f"* **Comparison limit:** {limit} bytes",
        f"* **Result:** {'SUCCESS' if success else 'FAILURE'}",
        f"* **Matching prefix:** {baseline_prefix}/{limit} bytes",
        "",
        "## Details",
    ]

    if mismatch is None:
        lines.append(
            "Parity succeeded; Python and Lua outputs matched within the configured window."
        )
    else:
        lines.extend(
            [
                "Parity mismatch detected during comparison.",
                "",
                f"* **Mismatch index:** {mismatch.index}",
                f"* **Python byte:** 0x{mismatch.python_value:02x}",
                f"* **Lua byte:** 0x{mismatch.lua_value:02x}",
                f"* **Python context:** `{mismatch.context_py}`",
                f"* **Lua context:** `{mismatch.context_lua}`",
            ]
        )

    lines.extend(["", "## Brute-force search"])

    if not brute_force.attempted and brute_force.reason:
        lines.append(f"Brute-force skipped: {brute_force.reason}.")
    elif not brute_force.attempted:
        lines.append("Brute-force skipped: constraints not satisfied.")
    else:
        lines.append(f"Attempts executed: {brute_force.attempts}")
        lines.append(f"Best prefix observed: {brute_force.best_prefix}/{limit} bytes")
        if brute_force.best_key_length is not None:
            descriptor = (
                "redacted" if redact_keys else f"length {brute_force.best_key_length} bytes"
            )
            lines.append(f"Best candidate key ({descriptor}) achieved the prefix above.")
        if brute_force.success:
            lines.append("Brute-force located a key achieving the requested prefix length.")
        else:
            lines.append(
                "No brute-force candidate matched the requested prefix length within constraints."
            )

    lines.extend(["", "## Recommendations"])

    recommendations: List[str] = []
    if success:
        recommendations.append("No parameter changes required; parity succeeded.")
    else:
        if brute_force.success and brute_force.best_key_length is not None:
            recommendations.append(
                "Test a key of length {length} bytes discovered during brute-force.".format(
                    length=brute_force.best_key_length
                )
            )
        elif (
            brute_force.best_key_length is not None
            and brute_force.best_prefix > baseline_prefix
        ):
            recommendations.append(
                "Investigate {length}-byte keys – they matched {prefix}/{limit} bytes.".format(
                    length=brute_force.best_key_length,
                    prefix=brute_force.best_prefix,
                    limit=limit,
                )
            )
        else:
            recommendations.append(
                "Review PRGA variant parameters and bootstrap metadata for inconsistencies."
            )

        if variant == "initv4 default":
            recommendations.append("Consider testing the `initv4 alt` PRGA variant for this payload.")
        elif variant == "initv4 alt":
            recommendations.append("Consider testing the `initv4 default` PRGA variant for this payload.")

    if not recommendations:
        recommendations.append("No additional recommendations available.")

    for recommendation in recommendations:
        lines.append(f"* {recommendation}")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _log_recommendations(recommendations: Sequence[str]) -> None:
    if not recommendations:
        return
    for entry in recommendations:
        logger.info("Suggestion: %s", entry)


def _zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _dump_intermediate_stages(
    *,
    decoded_payload: bytes,
    output_bytes: bytes,
    trace: Sequence[PRGATraceEntry],
    directory: Path,
) -> None:
    """Write intermediate PRGA stage buffers to ``directory``.

    The following stage files are generated:

    ``stage-0.bin``
        Raw decoded payload passed into :func:`apply_prga`.
    ``stage-1.bin``
        Permuted bytes as consumed by the PRGA loop.
    ``stage-2.bin``
        XOR results prior to rotation (masked to eight bits).
    ``stage-3.bin``
        Final PRGA output bytes.
    """

    directory.mkdir(parents=True, exist_ok=True)

    permuted = bytes(entry.input_byte & 0xFF for entry in trace)
    xored = bytes(entry.xored & 0xFF for entry in trace)

    stage_payloads = [
        decoded_payload,
        permuted,
        xored,
        output_bytes,
    ]

    for index, payload in enumerate(stage_payloads):
        path = directory / f"stage-{index}.bin"
        path.write_bytes(payload)
        logger.debug("Wrote intermediate stage %d (%d bytes) to %s", index, len(payload), path)

    logger.info("Intermediate PRGA stages written to %s", directory)


def run_prga_parity(
    sample_path: Path,
    limit: int = DEFAULT_COMPARE_LIMIT,
    *,
    variant: Optional[str] = None,
    enable_bruteforce: bool = False,
    max_bruteforce_attempts: int = 4096,
    report_path: Optional[Path] = Path("out/parity_report.md"),
    intermediate_dir: Optional[Path] = None,
    raise_on_mismatch: bool = True,
    key_override: Optional[bytes] = None,
    scrub_override: bool = False,
    redact_keys: bool = False,
) -> Tuple[bytes, bytes]:
    """Execute the parity harness for the provided sample file."""

    sample = _read_sample(sample_path)
    if not sample.key:
        raise ValueError("sample key must be non-empty")

    lua = LuaRuntime(unpack_returned_tuples=True)
    try:
        lua_module = lua.eval(sample.lua_source)
    except LuaError as exc:
        logger.debug("Falling back to executing sample source via LuaRuntime.execute")
        lua.execute(sample.lua_source)
        try:
            lua_module = lua.eval("initv4_prga_ref")
        except LuaError as nested_exc:  # pragma: no cover - unexpected failure
            raise RuntimeError("failed to evaluate Lua reference module") from nested_exc
        if lua_module is None:  # pragma: no cover - defensive guard
            raise RuntimeError("Lua reference module returned nil") from exc
    lua_apply = lua_module["apply_prga_ref"]

    decoded_payload = sample.decoded_payload

    if key_override is not None:
        if isinstance(key_override, bytearray):
            key_buffer = key_override
        else:
            key_buffer = bytearray(key_override)
        scrub_target = key_buffer if scrub_override else bytearray(key_buffer)
    else:
        key_buffer = bytearray(sample.key)
        scrub_target = key_buffer

    logger.info("Running Python PRGA implementation")
    params: dict[str, object] = {}
    if variant:
        params["variant"] = variant
    if enable_bruteforce:
        params["bruteforce"] = True  # marker for logging/debugging

    try:
        py_bytes = apply_prga(decoded_payload, key_buffer, params=params or None)
        trace = last_prga_trace()

        if intermediate_dir is not None:
            if len(trace) != len(py_bytes):
                logger.warning(
                    "Trace length (%d) does not match output length (%d); stage dump may be truncated.",
                    len(trace),
                    len(py_bytes),
                )
            _dump_intermediate_stages(
                decoded_payload=decoded_payload,
                output_bytes=py_bytes,
                trace=trace,
                directory=intermediate_dir,
            )

        logger.info("Running Lua reference implementation")
        lua_payload = _as_lua_string(decoded_payload)
        lua_key = _as_lua_string(bytes(key_buffer))
        lua_bytes = lua_apply(lua_payload, lua_key)
        if isinstance(lua_bytes, str):
            lua_bytes = lua_bytes.encode("latin1")

        mismatch: Optional[ParityMismatchError] = None
        brute_force = BruteforceOutcome(
            attempted=False,
            reason="parity succeeded; brute-force unnecessary",
        )

        try:
            _compare_prefix(py_bytes, lua_bytes, limit)
            success = True
            baseline_prefix = min(limit, len(py_bytes), len(lua_bytes))
            logger.info("Parity successful for first %d bytes", baseline_prefix)
        except ParityMismatchError as error:
            mismatch = error
            success = False
            baseline_prefix = error.index
            logger.info(
                "Parity mismatch detected at index %d; initiating diagnostics",
                error.index,
            )

            lengths = list(range(1, 7)) if enable_bruteforce else []
            if enable_bruteforce and lengths:
                brute_force = _bruteforce_small_keys(
                    decoded_payload,
                    lua_payload,
                    lua_apply,
                    params=params or None,
                    limit=limit,
                    max_attempts=max_bruteforce_attempts,
                    key_lengths=lengths,
                    skip_keys=(bytes(key_buffer),),
                )
            elif not enable_bruteforce:
                brute_force = BruteforceOutcome(
                    attempted=False,
                    reason="brute-force disabled by configuration",
                )

        recommendations: List[str] = []
        if success:
            recommendations.append("No parameter changes required; parity succeeded.")
        else:
            if brute_force.success and brute_force.best_key_length is not None:
                recommendations.append(
                    "Try {length}-byte keys discovered during brute-force.".format(
                        length=brute_force.best_key_length
                    )
                )
            elif (
                brute_force.best_key_length is not None
                and brute_force.best_prefix > baseline_prefix
            ):
                recommendations.append(
                    "Investigate {length}-byte keys ({prefix}/{limit} bytes matched).".format(
                        length=brute_force.best_key_length,
                        prefix=brute_force.best_prefix,
                        limit=limit,
                    )
                )
            else:
                recommendations.append(
                    "Check PRGA variant parameters (e.g. rotate/permute tables)."
                )
            if variant == "initv4 default":
                recommendations.append("Consider testing the 'initv4 alt' PRGA variant.")
            elif variant == "initv4 alt":
                recommendations.append("Consider testing the 'initv4 default' PRGA variant.")

        _log_recommendations(recommendations)

        if report_path is not None:
            report_variant = variant if variant else "initv4 default"
            _write_parity_report(
                Path(report_path),
                sample_path=sample_path,
                variant=report_variant,
                limit=limit,
                success=success,
                baseline_prefix=baseline_prefix,
                mismatch=mismatch,
                brute_force=brute_force,
                redact_keys=redact_keys or scrub_override,
            )

        if mismatch is not None and raise_on_mismatch:
            raise mismatch

        return py_bytes, lua_bytes
    finally:
        if scrub_target is not None:
            _zeroize(scrub_target)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run initv4 PRGA parity harness")
    parser.add_argument(
        "sample",
        type=Path,
        nargs="?",
        default=Path("tests/parity/sample_lph.bin"),
        help="Path to the parity sample description",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_COMPARE_LIMIT,
        help="Number of bytes to compare between Python and Lua outputs",
    )
    parser.add_argument(
        "--variant",
        default=None,
        help="PRGA variant to execute (e.g. 'initv4 default', 'initv4 alt')",
    )
    parser.add_argument(
        "--brute-force-small-keys",
        action="store_true",
        help="Attempt brute-force search for keys of length 1..6 (safety capped)",
    )
    parser.add_argument(
        "--max-bruteforce-attempts",
        type=int,
        default=4096,
        help="Maximum number of brute-force key attempts to perform when enabled",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("out/parity_report.md"),
        help="Destination path for the generated parity report",
    )
    parser.add_argument(
        "--dump-intermediate",
        type=Path,
        default=None,
        help="Directory to store intermediate PRGA stage dumps",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (e.g. INFO, DEBUG)",
    )
    parser.add_argument(
        "--key",
        default=None,
        help="Session key for Obfuscated3.lua (not persisted; optional)",
    )
    parser.add_argument(
        "--key-stdin",
        action="store_true",
        help="Read session key from stdin (stripped); buffer is wiped afterwards",
    )
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    if args.key and args.key_stdin:
        raise SystemExit("--key and --key-stdin are mutually exclusive")

    key_override: Optional[bytearray] = None
    if args.key:
        raw = args.key
        if raw.startswith("hex:"):
            key_bytes = bytes.fromhex(raw[4:])
        else:
            key_bytes = raw.encode("utf-8")
        key_override = bytearray(key_bytes)
    elif args.key_stdin:
        raw = sys.stdin.readline().strip()
        if not raw:
            raise SystemExit("stdin did not provide a key")
        if raw.startswith("hex:"):
            key_bytes = bytes.fromhex(raw[4:])
        else:
            key_bytes = raw.encode("utf-8")
        key_override = bytearray(key_bytes)

    try:
        run_prga_parity(
            args.sample,
            limit=args.limit,
            variant=args.variant,
            enable_bruteforce=args.brute_force_small_keys,
            max_bruteforce_attempts=args.max_bruteforce_attempts,
            report_path=args.report,
            intermediate_dir=args.dump_intermediate,
            key_override=key_override,
            scrub_override=bool(key_override),
        )
    except ParityMismatchError as exc:
        logger.error("Parity mismatch: %s", exc)
        raise SystemExit(1) from exc
    finally:
        if key_override is not None:
            _zeroize(key_override)


if __name__ == "__main__":
    main()
