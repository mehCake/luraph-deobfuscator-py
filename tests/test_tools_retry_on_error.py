from __future__ import annotations

import logging
from typing import List

import pytest

from src.tools.retry_on_error import retry_on_error


def test_retry_on_error_eventually_succeeds(monkeypatch, caplog):
    attempts: List[int] = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise OSError("temporary failure")
        return "ok"

    sleeps: List[float] = []
    monkeypatch.setattr("time.sleep", lambda value: sleeps.append(value))

    with caplog.at_level(logging.WARNING):
        result = retry_on_error(
            flaky,
            retries=3,
            base_delay=0.1,
            exceptions=(OSError,),
            logger=logging.getLogger("test"),
            operation="flaky",
        )

    assert result == "ok"
    assert attempts == [1, 1, 1]
    assert sleeps == [0.1, 0.2]
    # ensure warning was emitted
    assert any("Transient failure" in record.message for record in caplog.records)


def test_retry_on_error_respects_exception_filter():
    def bad():
        raise ValueError("not transient")

    with pytest.raises(ValueError):
        retry_on_error(bad, retries=2, exceptions=(OSError,))


def test_retry_on_error_raises_after_retries(monkeypatch, caplog):
    attempts = 0

    def always_fail():
        nonlocal attempts
        attempts += 1
        raise OSError("still broken")

    monkeypatch.setattr("time.sleep", lambda _: None)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(OSError):
            retry_on_error(
                always_fail,
                retries=2,
                base_delay=0.05,
                exceptions=(OSError,),
                logger=logging.getLogger("test"),
                operation="always_fail",
            )

    assert attempts == 3
    assert any("failed" in record.message for record in caplog.records)

