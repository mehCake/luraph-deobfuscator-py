"""Tests for the sandbox snapshotter utilities."""

from __future__ import annotations

import json
from datetime import datetime

from src.tools.snapshotter import (
    Snapshot,
    capture_bootstrap_snapshots,
    diff_snapshots,
    write_snapshot_run,
)


SNIPPET_EMIT = """
local constants = {"alpha", "beta"}
snapshot_emit("initial", constants)
constants[2] = "gamma"
snapshot_emit("updated", constants)
"""


SNIPPET_GLOBAL = """
constants = {}
constants['key'] = "SHOULD_NOT_PERSIST"
constants['greeting'] = "hello"
"""


def test_snapshotter_captures_emitted_tables(tmp_path):
    run = capture_bootstrap_snapshots(snippet=SNIPPET_EMIT, run_name="test")
    assert len(run.snapshots) == 2
    assert run.snapshots[0].label == "initial"
    assert run.snapshots[1].payload[1] == "gamma"

    destination = tmp_path / "snapshots"
    written = write_snapshot_run(
        run,
        destination=destination,
        timestamp=datetime(2024, 1, 2, 3, 4, 5),
    )

    manifest = json.loads((written / "manifest.json").read_text())
    assert manifest["snapshot_count"] == 2
    diff_path = next(written.glob("diff_*.json"))
    diff_payload = json.loads(diff_path.read_text())
    assert "[1]" in diff_payload["changed"]
    assert diff_payload["changed"]["[1]"]["current"] == "gamma"


def test_snapshotter_captures_requested_globals(tmp_path):
    run = capture_bootstrap_snapshots(
        snippet=SNIPPET_GLOBAL,
        run_name="globals",
        requested_globals=["constants"],
    )
    assert len(run.snapshots) == 1
    snapshot = run.snapshots[0]
    assert "key" not in snapshot.payload

    written = write_snapshot_run(
        run,
        destination=tmp_path,
        timestamp=datetime(2024, 2, 3, 4, 5, 6),
    )
    snapshot_payload = json.loads(next(written.glob("snapshot_*.json")).read_text())
    assert "key" not in snapshot_payload["payload"]


def test_diff_snapshots_highlights_changes():
    first = Snapshot(
        label="first",
        index=1,
        created_at=datetime.utcnow(),
        payload={"numbers": [1, 2, 3]},
    )
    second = Snapshot(
        label="second",
        index=2,
        created_at=datetime.utcnow(),
        payload={"numbers": [1, 2, 4], "extra": "value"},
    )

    diff = diff_snapshots(first, second)
    assert "numbers[2]" in diff.changed
    assert diff.changed["numbers[2]"]["current"] == 4
    assert diff.added == {"extra": "value"}

