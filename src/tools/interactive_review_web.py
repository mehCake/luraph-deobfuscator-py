"""Small local web UI for reviewing deobfuscated output.

This module intentionally keeps state in-memory only and never persists secrets or
keys to disk. The server binds to localhost and can optionally require a caller
provided authentication token through a request header. Designed for analysts to
quickly inspect artefacts produced by the pipeline.
"""

from __future__ import annotations

import argparse
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:  # pragma: no cover - exercised in tests when Flask is available
    from flask import Flask, Response, abort, jsonify, make_response, request
    _HAS_FLASK = True
except ModuleNotFoundError:  # pragma: no cover
    Flask = None  # type: ignore[assignment]
    Response = object  # type: ignore[assignment]

    def abort(*_args, **_kwargs):  # type: ignore[override]
        raise RuntimeError("Flask is required to use the interactive review web UI.")

    def jsonify(*_args, **_kwargs):  # type: ignore[override]
        raise RuntimeError("Flask is required to use the interactive review web UI.")

    def make_response(*_args, **_kwargs):  # type: ignore[override]
        raise RuntimeError("Flask is required to use the interactive review web UI.")

    request = None  # type: ignore[assignment]
    _HAS_FLASK = False


def _ensure_flask_available() -> None:
    if not _HAS_FLASK:
        raise RuntimeError(
            "Flask is required to use the interactive review web UI. Install Flask and try again."
        )


LOGGER = logging.getLogger(__name__)
DEFAULT_PORT = 5080
COMMENT_LIMIT = 500


@dataclass(slots=True)
class ReviewComment:
    """Simple representation of a reviewer comment."""

    line: int
    text: str
    author: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, str]:
        payload = {
            "line": self.line,
            "text": self.text,
            "created_at": self.created_at.isoformat() + "Z",
        }
        if self.author:
            payload["author"] = self.author
        return payload


class InMemoryCommentStore:
    """Thread-safe, ephemeral comment store."""

    def __init__(self) -> None:
        self._comments: List[ReviewComment] = []
        self._lock = threading.Lock()

    def add_comment(self, comment: ReviewComment) -> None:
        with self._lock:
            self._comments.append(comment)

    def list_comments(self) -> List[ReviewComment]:
        with self._lock:
            return list(self._comments)

    def clear(self) -> None:
        with self._lock:
            self._comments.clear()


class AuthStub:
    """Authentication helper enforcing a caller provided token if configured."""

    def __init__(self, token: str | None) -> None:
        self._token = token.strip() if token else None

    def required(self) -> bool:
        return bool(self._token)

    def _check_token(self, header_token: Optional[str]) -> Optional[str]:
        if not self._token:
            return None
        candidate = (header_token or "").strip()
        if candidate != self._token:
            LOGGER.warning("Rejected request without a valid review token")
            return "unauthorised"
        return None

    def verify(self) -> Optional[Response]:
        _ensure_flask_available()
        error = self._check_token(request.headers.get("X-Review-Token", ""))  # type: ignore[union-attr]
        if error is None:
            return None
        return make_response(jsonify({"error": error}), 403)

    def verify_headers(self, headers: Optional[Dict[str, str]]) -> Optional[str]:
        token = headers.get("X-Review-Token") if headers else None
        return self._check_token(token)


def _load_text(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Could not read artefact at {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _load_json(path: Path) -> Dict[str, object]:
    return json.loads(_load_text(path))


INDEX_HTML = """<!doctype html>
<title>Interactive Review</title>
<meta charset=\"utf-8\">
<style>
body { font-family: sans-serif; margin: 0; display: flex; height: 100vh; }
main { display: flex; flex: 1; }
section { flex: 1; padding: 1rem; overflow: auto; border-right: 1px solid #ccc; }
section:last-child { border-right: none; }
pre { white-space: pre-wrap; font-family: monospace; }
.comments { max-width: 28rem; }
.comment { border-bottom: 1px solid #ddd; padding: 0.5rem 0; }
</style>
<main>
  <section>
    <h1>Deobfuscated Output</h1>
    <pre id=\"deobf\">Loading…</pre>
  </section>
  <section>
    <h1>IR Preview</h1>
    <pre id=\"ir\">Loading…</pre>
  </section>
  <section class=\"comments\">
    <h1>Comments</h1>
    <form id=\"comment-form\">
      <label>Line <input name=\"line\" type=\"number\" min=\"0\" required></label>
      <label>Author <input name=\"author\" type=\"text\" maxlength=\"80\"></label>
      <label>Comment <textarea name=\"text\" rows=\"3\" maxlength=\"500\" required></textarea></label>
      <button type=\"submit\">Submit</button>
      <p id=\"status\" style=\"color: #a00;\"></p>
    </form>
    <div id=\"comments\"></div>
  </section>
</main>
<script>
async function loadDocument() {
  const response = await fetch('/api/document');
  if (!response.ok) return;
  const data = await response.json();
  document.getElementById('deobf').textContent = data.deobfuscated;
  document.getElementById('ir').textContent = data.ir ? JSON.stringify(data.ir, null, 2) : 'No IR available';
}
async function loadComments() {
  const response = await fetch('/api/comments');
  if (!response.ok) return;
  const data = await response.json();
  const container = document.getElementById('comments');
  container.innerHTML = '';
  data.comments.forEach(entry => {
    const div = document.createElement('div');
    div.className = 'comment';
    const author = entry.author ? ` (${entry.author})` : '';
    div.innerHTML = `<strong>Line ${entry.line}</strong>${author}<br>${entry.text}<br><small>${entry.created_at}</small>`;
    container.appendChild(div);
  });
}
async function submitComment(evt) {
  evt.preventDefault();
  const form = evt.target;
  const payload = {
    line: Number.parseInt(form.line.value, 10),
    author: form.author.value,
    text: form.text.value,
  };
  const response = await fetch('/api/comments', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Review-Token': window.localStorage.getItem('reviewToken') || '',
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    document.getElementById('status').textContent = 'Failed to submit comment';
    return;
  }
  form.reset();
  document.getElementById('status').textContent = '';
  await loadComments();
}
document.getElementById('comment-form').addEventListener('submit', submitComment);
loadDocument();
loadComments();
setInterval(loadComments, 5000);
</script>
"""


def create_app(
    *,
    deobfuscated_path: Path,
    ir_path: Optional[Path] = None,
    comment_store: Optional[InMemoryCommentStore] = None,
    auth_token: str | None = None,
) -> object:
    """Instantiate the Flask application."""

    artefacts: Dict[str, object] = {
        "deobfuscated": _load_text(deobfuscated_path),
        "deobfuscated_path": str(deobfuscated_path),
    }
    if ir_path:
        artefacts["ir_path"] = str(ir_path)
        try:
            artefacts["ir"] = _load_json(ir_path)
        except json.JSONDecodeError:
            LOGGER.warning("Unable to parse IR JSON at %s", ir_path)
            artefacts["ir"] = None

    store = comment_store or InMemoryCommentStore()
    auth = AuthStub(auth_token)

    if not _HAS_FLASK:
        return _StubApp(artefacts=artefacts, store=store, auth=auth)

    app = Flask(__name__)  # pragma: no cover - flask instrumentation

    @app.before_request
    def restrict_host() -> Optional[Response]:  # pragma: no cover - exercised indirectly
        remote_addr = request.remote_addr or ""
        if remote_addr and remote_addr not in {"127.0.0.1", "::1"}:
            LOGGER.warning("Rejected connection from %s", remote_addr)
            return make_response(jsonify({"error": "local-only"}), 403)
        return auth.verify()

    @app.get("/api/document")
    def get_document() -> Response:
        payload = {
            "deobfuscated": artefacts["deobfuscated"],
            "deobfuscated_path": artefacts["deobfuscated_path"],
        }
        if "ir" in artefacts:
            payload["ir"] = artefacts["ir"]
            payload["ir_path"] = artefacts.get("ir_path")
        return jsonify(payload)

    @app.get("/api/comments")
    def list_comments() -> Response:
        return jsonify({"comments": [c.to_dict() for c in store.list_comments()]})

    @app.post("/api/comments")
    def post_comment() -> Response:
        if request.mimetype != "application/json":
            abort(415)
        try:
            data = request.get_json(force=True)
        except Exception as exc:  # pragma: no cover - handled by Flask normally
            LOGGER.debug("Failed to decode JSON payload: %s", exc)
            abort(400)
        if not isinstance(data, dict):
            abort(400)
        line = data.get("line")
        text = (data.get("text") or "").strip()
        author = (data.get("author") or "").strip() or None
        if not isinstance(line, int) or line < 0:
            abort(400)
        if not text or len(text) > COMMENT_LIMIT:
            abort(400)
        if any(keyword in text.lower() for keyword in ("key=", "secret", "token")):
            return make_response(jsonify({"error": "text contains restricted terms"}), 400)
        comment = ReviewComment(line=line, text=text, author=author)
        store.add_comment(comment)
        return jsonify(comment.to_dict())

    @app.get("/")
    def index() -> Response:
        return make_response(INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"})

    return app


class _StubResponse:
    def __init__(
        self,
        status_code: int,
        *,
        json_payload: Optional[object] = None,
        text: Optional[str] = None,
        mimetype: str = "application/json",
    ) -> None:
        self.status_code = status_code
        self._json = json_payload
        if text is not None:
            self.data = text.encode("utf-8")
            self.headers = {"Content-Type": mimetype or "text/html"}
        elif json_payload is not None:
            self.data = json.dumps(json_payload).encode("utf-8")
            self.headers = {"Content-Type": mimetype}
        else:
            self.data = b""
            self.headers = {"Content-Type": mimetype}

    def get_json(self) -> Optional[object]:
        return self._json


class _StubClient:
    def __init__(self, app: "_StubApp") -> None:
        self._app = app

    def get(self, path: str):
        return self._app._handle_request("GET", path, headers={}, payload=None)

    def post(
        self,
        path: str,
        json: Optional[object] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        return self._app._handle_request("POST", path, headers=headers or {}, payload=json)


class _StubApp:
    def __init__(
        self,
        *,
        artefacts: Dict[str, object],
        store: InMemoryCommentStore,
        auth: AuthStub,
    ) -> None:
        self._artefacts = artefacts
        self._store = store
        self._auth = auth

    def test_client(self) -> _StubClient:
        return _StubClient(self)

    def _handle_request(
        self,
        method: str,
        path: str,
        *,
        headers: Dict[str, str],
        payload: Optional[object],
    ) -> _StubResponse:
        if method == "GET" and path == "/api/document":
            body = {
                "deobfuscated": self._artefacts["deobfuscated"],
                "deobfuscated_path": self._artefacts["deobfuscated_path"],
            }
            if "ir" in self._artefacts:
                body["ir"] = self._artefacts["ir"]
                body["ir_path"] = self._artefacts.get("ir_path")
            return _StubResponse(200, json_payload=body)

        if method == "GET" and path == "/api/comments":
            return _StubResponse(
                200,
                json_payload={"comments": [c.to_dict() for c in self._store.list_comments()]},
            )

        if method == "POST" and path == "/api/comments":
            error = self._auth.verify_headers(headers)
            if error:
                return _StubResponse(403, json_payload={"error": error})
            if not isinstance(payload, dict):
                return _StubResponse(400, json_payload={"error": "invalid json"})
            line = payload.get("line")
            text = (payload.get("text") or "").strip()
            author = (payload.get("author") or "").strip() or None
            if not isinstance(line, int) or line < 0:
                return _StubResponse(400, json_payload={"error": "invalid line"})
            if not text or len(text) > COMMENT_LIMIT:
                return _StubResponse(400, json_payload={"error": "invalid text"})
            lowered = text.lower()
            if any(keyword in lowered for keyword in ("key=", "secret", "token")):
                return _StubResponse(400, json_payload={"error": "text contains restricted terms"})
            comment = ReviewComment(line=line, text=text, author=author)
            self._store.add_comment(comment)
            return _StubResponse(200, json_payload=comment.to_dict())

        if method == "GET" and path == "/":
            return _StubResponse(200, text=INDEX_HTML, mimetype="text/html; charset=utf-8")

        return _StubResponse(404, json_payload={"error": "not found"})


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the interactive review UI")
    parser.add_argument("deobfuscated", type=Path, help="Path to the prettified Lua output")
    parser.add_argument("--ir", type=Path, help="Optional path to the lifted IR JSON")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind (localhost only)")
    parser.add_argument(
        "--auth-token",
        type=str,
        help="Optional review token that clients must supply via X-Review-Token",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not attempt to open a browser automatically",
    )
    return parser


def _open_browser(port: int) -> None:
    try:  # pragma: no cover - optional convenience
        import webbrowser

        webbrowser.open_new_tab(f"http://127.0.0.1:{port}/")
    except Exception as exc:  # pragma: no cover
        LOGGER.debug("Failed to open browser automatically: %s", exc)


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    app = create_app(
        deobfuscated_path=args.deobfuscated,
        ir_path=args.ir,
        auth_token=args.auth_token,
    )

    if not args.no_browser:
        _open_browser(args.port)

    LOGGER.info("Starting review UI on http://127.0.0.1:%s", args.port)
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


__all__ = [
    "ReviewComment",
    "InMemoryCommentStore",
    "create_app",
    "build_arg_parser",
    "main",
]
