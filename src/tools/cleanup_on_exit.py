"""Abnormal-exit cleanup helpers.

This module tracks temporary analysis artefacts and sensitive in-memory
buffers so that they can be scrubbed if the pipeline terminates unexpectedly.
It installs a small set of signal handlers as well as an ``atexit`` hook that
performs best-effort wiping of key material and optional secure removal of
debug artefacts.  The helpers are intentionally lightweight so that they can
be reused by command-line tools without pulling in heavy dependencies.

The cleanup manager is idempotent – running the cleanup logic multiple times
is safe – which makes it straightforward to use in ``try``/``finally`` blocks
while still guarding against abrupt exits (e.g. ``SIGTERM``).
"""

from __future__ import annotations

import atexit
import logging
import os
import signal
from pathlib import Path
from threading import RLock
from typing import Dict, Optional, Tuple

LOGGER = logging.getLogger(__name__)

_DEFAULT_SIGNALS: Tuple[signal.Signals, ...] = tuple(
    getattr(signal, name)
    for name in ("SIGTERM", "SIGINT", "SIGHUP")
    if hasattr(signal, name)
)


class CleanupManager:
    """Track temporary paths and sensitive buffers for abnormal cleanup."""

    __slots__ = (
        "_lock",
        "_temp_paths",
        "_key_buffers",
        "_finalised",
        "_successful_exit",
    )

    def __init__(self) -> None:
        self._lock = RLock()
        self._temp_paths: Dict[Path, bool] = {}
        self._key_buffers: Dict[str, bytearray] = {}
        self._finalised = False
        self._successful_exit = False
        atexit.register(self._handle_atexit)
        self._register_signal_handlers()

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------
    def register_temp_path(self, path: Path, secure_wipe: bool = True) -> None:
        """Register a temporary path for removal on abnormal termination."""

        path = Path(path)
        with self._lock:
            self._temp_paths[path] = secure_wipe
            self._finalised = False
            self._successful_exit = False

    def register_key_buffer(self, name: str, buffer: Optional[bytearray]) -> None:
        """Track a mutable key buffer so it can be zeroed on exit."""

        if buffer is None:
            return
        with self._lock:
            self._key_buffers[name] = buffer
            self._finalised = False
            self._successful_exit = False

    # ------------------------------------------------------------------
    # Finalisation helpers
    # ------------------------------------------------------------------
    def finalize(self, successful: bool) -> None:
        """Explicitly finalise the cleanup manager.

        ``successful`` indicates whether the pipeline completed without fatal
        errors.  Temporary files are removed only when ``successful`` is
        ``False`` or when cleanup is triggered by a signal/abnormal exit.
        Key buffers are always wiped.
        """

        self.cleanup(reason="finalize", forced=not successful, successful=successful)

    def cleanup(
        self,
        *,
        reason: str = "manual",
        forced: bool = False,
        successful: Optional[bool] = None,
    ) -> None:
        """Perform cleanup now.

        ``forced`` forces removal of registered paths even if the manager was
        marked as successful.  ``successful`` can be supplied to override the
        stored exit state.
        """

        with self._lock:
            if successful is not None:
                self._successful_exit = successful

            if self._finalised:
                return

            LOGGER.debug("cleanup_on_exit triggered (%s)", reason)
            self._wipe_key_buffers_locked()

            should_remove_paths = forced or not self._successful_exit
            if should_remove_paths:
                self._purge_paths_locked()
            else:
                self._temp_paths.clear()

            self._finalised = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _register_signal_handlers(self) -> None:
        for sig in _DEFAULT_SIGNALS:
            try:
                previous = signal.getsignal(sig)
            except Exception:  # pragma: no cover - platform dependent
                continue

            def handler(signum: int, frame, *, _sig=sig, _previous=previous) -> None:
                try:
                    self.cleanup(
                        reason=f"signal {_sig.name}", forced=True, successful=False
                    )
                finally:
                    if callable(_previous):
                        _previous(signum, frame)
                    elif _previous == signal.SIG_DFL:
                        signal.signal(_sig, signal.SIG_DFL)
                        try:
                            os.kill(os.getpid(), signum)
                        except Exception:  # pragma: no cover - platform dependent
                            pass

            try:
                signal.signal(sig, handler)
            except Exception:  # pragma: no cover - platform dependent
                continue

    def _handle_atexit(self) -> None:
        self.cleanup(reason="atexit")

    def _wipe_key_buffers_locked(self) -> None:
        for name, buffer in list(self._key_buffers.items()):
            if buffer is None:
                continue
            LOGGER.debug("Zeroing key buffer '%s' (%d bytes)", name, len(buffer))
            for index in range(len(buffer)):
                buffer[index] = 0
            self._key_buffers.pop(name, None)

    def _purge_paths_locked(self) -> None:
        for path, secure in list(self._temp_paths.items()):
            try:
                self._secure_remove(path, secure)
            except Exception as exc:  # pragma: no cover - best-effort logging
                LOGGER.warning("Failed to remove temporary artefact %s: %s", path, exc)
        self._temp_paths.clear()

    def _secure_remove(self, path: Path, secure: bool) -> None:
        if not path.exists() and not path.is_symlink():
            return

        if path.is_dir() and not path.is_symlink():
            for child in path.iterdir():
                self._secure_remove(child, secure)
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            return

        if secure and path.is_file():
            self._overwrite_file(path)

        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def _overwrite_file(self, path: Path) -> None:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return

        if size == 0:
            return

        chunk_size = 64 * 1024
        zero_block = b"\x00" * chunk_size

        with path.open("r+b", buffering=0) as handle:
            handle.seek(0)
            remaining = size
            while remaining > 0:
                to_write = zero_block if remaining >= chunk_size else zero_block[:remaining]
                handle.write(to_write)
                remaining -= len(to_write)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:  # pragma: no cover - files on virtual FS may not support fsync
                pass

    # ------------------------------------------------------------------
    # Test utilities
    # ------------------------------------------------------------------
    def reset_state_for_tests(self) -> None:
        """Reset tracked paths/buffers (intended for the test-suite)."""

        with self._lock:
            self._temp_paths.clear()
            self._key_buffers.clear()
            self._finalised = False
            self._successful_exit = False


_MANAGER: Optional[CleanupManager] = None


def get_cleanup_manager() -> CleanupManager:
    """Return the global cleanup manager instance."""

    global _MANAGER
    if _MANAGER is None:
        _MANAGER = CleanupManager()
    return _MANAGER


__all__ = ["CleanupManager", "get_cleanup_manager"]

