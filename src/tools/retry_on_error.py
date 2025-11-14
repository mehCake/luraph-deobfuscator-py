"""Utility to retry transient operations with exponential backoff."""

from __future__ import annotations

import logging
import time
from typing import Callable, Iterable, Optional, Tuple, Type


LOGGER = logging.getLogger(__name__)

TransientExceptionTypes = Tuple[Type[BaseException], ...]

__all__ = ["retry_on_error", "TransientExceptionTypes"]


def _normalise_exceptions(
    exceptions: Optional[Iterable[Type[BaseException]]],
) -> TransientExceptionTypes:
    if not exceptions:
        return (Exception,)  # pragma: no cover - defensive fallback
    return tuple(exceptions)


def retry_on_error(
    func: Callable[[], object],
    *,
    retries: int = 3,
    base_delay: float = 0.25,
    max_delay: float = 2.0,
    exceptions: Optional[Iterable[Type[BaseException]]] = None,
    logger: Optional[logging.Logger] = None,
    operation: Optional[str] = None,
) -> object:
    """Execute ``func`` retrying transient failures with exponential backoff.

    Parameters
    ----------
    func:
        Zero-argument callable to execute.
    retries:
        Number of retry attempts after the first failure.  ``0`` disables
        retry behaviour.
    base_delay:
        Initial delay (seconds) applied before the first retry.
    max_delay:
        Upper bound for backoff delays.
    exceptions:
        Iterable of exception types that should trigger a retry.  Any other
        exception types are re-raised immediately.
    logger:
        Optional logger used for warning messages.  Defaults to this module's
        logger.
    operation:
        Human readable name for logging context.
    """

    allowed: TransientExceptionTypes = _normalise_exceptions(exceptions)
    attempts = 0
    delay = max(base_delay, 0)
    log = logger or LOGGER
    op = operation or getattr(func, "__name__", "operation")

    while True:
        try:
            return func()
        except allowed as exc:  # type: ignore[misc]
            if attempts >= retries:
                log.error(
                    "Operation %s failed after %s retries: %s", op, retries, exc
                )
                raise

            attempts += 1
            sleep_for = min(max(delay, 0.0), max_delay)
            log.warning(
                "Transient failure during %s (attempt %s/%s): %s", op, attempts, retries, exc
            )
            if sleep_for > 0:
                time.sleep(sleep_for)
            delay = min(delay * 2 or base_delay, max_delay if max_delay > 0 else delay)
        except Exception:
            raise

