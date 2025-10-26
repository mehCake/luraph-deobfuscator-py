from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Mapping
from urllib import request

import pytest

from src import review_ui


def _start_server(config: review_ui.ReviewConfig) -> tuple[ThreadingHTTPServerWrapper, int]:
    server = review_ui._create_server(config, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Wait briefly for the server to come online
    for _ in range(50):
        if server.server_address[1] != 0:
            break
        time.sleep(0.01)
    return ThreadingHTTPServerWrapper(server, thread), server.server_address[1]


class ThreadingHTTPServerWrapper:
    def __init__(self, server, thread) -> None:
        self._server = server
        self._thread = thread

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _post_json(base: str, route: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    req = request.Request(
        f"{base}{route}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))


@pytest.fixture()
def sample_workspace(tmp_path: Path) -> dict[str, Path]:
    source = tmp_path / "source.lua"
    reconstructed = tmp_path / "reconstructed.lua"
    candidates = tmp_path / "candidates"
    candidates.mkdir()
    mapping = tmp_path / "mapping.json"
    upcodes = tmp_path / "upcodes.json"
    votes = tmp_path / "votes.json"

    source.write_text(
        "return { [0] = 'hello', [[world]] .. '!', \"g\" }\n",
        encoding="utf-8",
    )
    reconstructed.write_text(
        "return { foo = 'bar', baz = function() return 1 end }\n",
        encoding="utf-8",
    )
    (candidates / "sample.lua").write_text(
        "-- candidate\nreturn true\n",
        encoding="utf-8",
    )

    upcodes.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "opcode": 15,
                        "mnemonic": "OP_15",
                        "semantic": "test-opcode",
                        "sample_usage": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    votes.write_text(json.dumps({"votes": {}, "locks": {}}), encoding="utf-8")

    return {
        "source": source,
        "reconstructed": reconstructed,
        "candidates": candidates,
        "mapping": mapping,
        "upcodes": upcodes,
        "votes": votes,
    }


def test_collect_fragments_and_candidates(sample_workspace: dict[str, Path]) -> None:
    fragments = review_ui._collect_fragments(sample_workspace["source"])
    assert fragments, "expected fragments to be extracted"
    candidates = review_ui._list_candidate_files(sample_workspace["candidates"])
    assert candidates and candidates[0]["name"].endswith("sample.lua")


def test_render_pretty_round_trip(sample_workspace: dict[str, Path]) -> None:
    mapping = review_ui._load_mapping(sample_workspace["mapping"])
    assert mapping == {}

    result = review_ui._render_pretty(
        sample_workspace["reconstructed"],
        sample_workspace["mapping"],
        rerender=True,
    )
    assert result["success"]
    assert "return" in result["output"]

    # Saving a mapping with non-empty data should still persist the JSON file.
    saved = review_ui._save_mapping(sample_workspace["mapping"], {"foo": "bar"})
    assert saved == {"foo": "bar"}


def test_http_endpoints(sample_workspace: dict[str, Path]) -> None:
    config = review_ui.ReviewConfig(
        source_path=sample_workspace["source"],
        reconstructed_path=sample_workspace["reconstructed"],
        mapping_path=sample_workspace["mapping"],
        candidates_dir=sample_workspace["candidates"],
        upcodes_path=sample_workspace["upcodes"],
        votes_path=sample_workspace["votes"],
    )

    server, port = _start_server(config)
    base = f"http://127.0.0.1:{port}"
    try:
        with request.urlopen(f"{base}/") as response:
            body = response.read().decode("utf-8")
        assert "Interactive Review UI" in body

        with request.urlopen(f"{base}/api/fragments") as response:
            data = json.loads(response.read().decode("utf-8"))
        assert data["fragments"], "expected fragments payload"

        with request.urlopen(f"{base}/api/candidates") as response:
            data = json.loads(response.read().decode("utf-8"))
        assert data["candidates"], "expected candidates listing"

        with request.urlopen(f"{base}/api/opcodes") as response:
            opcode_payload = json.loads(response.read().decode("utf-8"))
        assert opcode_payload["opcodes"], "expected opcode payload"

        with request.urlopen(f"{base}/api/candidate?name=sample.lua") as response:
            candidate = response.read().decode("utf-8")
        assert "return true" in candidate

        # Saving an empty mapping keeps pretty printing working even without luaparser.
        payload = json.dumps({"mapping": {}}).encode("utf-8")
        req = request.Request(
            f"{base}/api/mapping",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(req) as response:
            update = json.loads(response.read().decode("utf-8"))
        assert update["mapping"] == {}
    finally:
        server.close()


def test_vote_flow_reaches_consensus(sample_workspace: dict[str, Path]) -> None:
    config = review_ui.ReviewConfig(
        source_path=sample_workspace["source"],
        reconstructed_path=sample_workspace["reconstructed"],
        mapping_path=sample_workspace["mapping"],
        candidates_dir=sample_workspace["candidates"],
        upcodes_path=sample_workspace["upcodes"],
        votes_path=sample_workspace["votes"],
        consensus_threshold=2,
    )

    server, port = _start_server(config)
    base = f"http://127.0.0.1:{port}"
    try:
        first = _post_json(
            base,
            "/api/vote",
            {"opcode": 15, "analyst": "alice", "mnemonic": "double value"},
        )
        assert first["identifier"] == "OP_15"
        assert not first["locked"]

        second = _post_json(
            base,
            "/api/vote",
            {"opcode": 15, "analyst": "bob", "mnemonic": "double value"},
        )
        assert second["locked"], "consensus should lock the opcode"
        assert second["locked_name"] == "DOUBLE_VALUE"

        mapping_payload = json.loads(sample_workspace["mapping"].read_text(encoding="utf-8"))
        assert mapping_payload["OP_15"] == "DOUBLE_VALUE"
    finally:
        server.close()
