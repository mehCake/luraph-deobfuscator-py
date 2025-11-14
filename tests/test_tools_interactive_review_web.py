from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.tools.interactive_review_web import (
    InMemoryCommentStore,
    create_app,
)


@pytest.fixture()
def sample_files(tmp_path: Path) -> tuple[Path, Path]:
    deobf = tmp_path / "out.lua"
    deobf.write_text("print('hello world')\nreturn 1", encoding="utf-8")
    ir = tmp_path / "ir.json"
    ir.write_text(json.dumps({"blocks": []}), encoding="utf-8")
    return deobf, ir


def test_create_app_serves_document(sample_files: tuple[Path, Path]) -> None:
    deobf, ir = sample_files
    app = create_app(deobfuscated_path=deobf, ir_path=ir)
    client = app.test_client()

    resp = client.get("/api/document")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["deobfuscated_path"].endswith("out.lua")
    assert payload["ir_path"].endswith("ir.json")

    html = client.get("/")
    assert html.status_code == 200
    assert b"Interactive Review" in html.data


def test_comment_submission_with_auth(sample_files: tuple[Path, Path]) -> None:
    deobf, ir = sample_files
    store = InMemoryCommentStore()
    app = create_app(deobfuscated_path=deobf, ir_path=ir, comment_store=store, auth_token="local")
    client = app.test_client()

    denied = client.post("/api/comments", json={"line": 1, "text": "hi"})
    assert denied.status_code == 403

    allowed = client.post(
        "/api/comments",
        headers={"X-Review-Token": "local"},
        json={"line": 1, "text": "looks good", "author": "qa"},
    )
    assert allowed.status_code == 200
    stored = store.list_comments()
    assert stored and stored[0].text == "looks good"


def test_comment_rejects_restricted_terms(sample_files: tuple[Path, Path]) -> None:
    deobf, ir = sample_files
    app = create_app(deobfuscated_path=deobf, ir_path=ir)
    client = app.test_client()

    resp = client.post("/api/comments", json={"line": 2, "text": "contains key=secret"})
    assert resp.status_code == 400
