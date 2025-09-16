import time
from typing import List

import pytest

from src import utils


def test_run_parallel_speed_and_results():
    items = list(range(8))

    def worker(value: int) -> int:
        time.sleep(0.01)
        return value * 2

    sequential_results, sequential = utils.run_parallel(items, worker, jobs=1)
    parallel_results, parallel = utils.run_parallel(items, worker, jobs=4)

    assert sequential_results == parallel_results
    assert sequential > 0
    assert parallel <= sequential * 2


def test_benchmark_parallel_enforces_ratio(monkeypatch):
    def fake_run_parallel(
        items: List[int],
        worker,
        *,
        jobs: int = 1,
        timer=None,
    ):
        return [], 5.0

    monkeypatch.setattr(utils, "run_parallel", fake_run_parallel)

    timeline = iter([0.0, 1.0])

    def fake_timer() -> float:
        return next(timeline)

    with pytest.raises(RuntimeError):
        utils.benchmark_parallel([1, 2], lambda _: None, jobs=2, timer=fake_timer)

