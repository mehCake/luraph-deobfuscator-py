"""Interactive fragment and rename review UI with collaborative voting."""

from __future__ import annotations

from collections import Counter
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional
from urllib.parse import parse_qs, urlparse

from src.beautifier import LuaBeautifier
from version_detector import extract_fragments, pretty_print_with_mapping

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ReviewConfig:
    """Runtime configuration for the interactive review UI."""

    source_path: Path
    reconstructed_path: Path
    mapping_path: Path
    candidates_dir: Path
    upcodes_path: Path
    votes_path: Path
    consensus_threshold: int = 2


def _canonicalize_identifier(opcode: Optional[int], mnemonic: Optional[str]) -> str:
    if isinstance(mnemonic, str) and mnemonic.strip():
        return mnemonic.strip()
    if opcode is None:
        return "UNKNOWN"
    return f"OP_{opcode}"


def _canonicalize_vote_name(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    canonical: List[str] = []
    last_was_underscore = False
    for char in candidate:
        if char.isalnum():
            canonical.append(char.upper())
            last_was_underscore = False
        else:
            if not last_was_underscore:
                canonical.append("_")
            last_was_underscore = True
    cleaned = "".join(canonical).strip("_")
    if not cleaned:
        return None
    if cleaned[0].isdigit():
        cleaned = f"OP_{cleaned}"
    return cleaned


def _ensure_directory(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # pragma: no cover - defensive parsing guard
        _LOGGER.debug("failed to load JSON from %s", path, exc_info=True)
        return None


def _load_mapping(mapping_path: Path) -> Dict[str, str]:
    if not mapping_path.exists():
        return {}
    data = _load_json(mapping_path)
    if data is None:
        _LOGGER.warning("invalid mapping.json - falling back to empty map")
        return {}
    if not isinstance(data, Mapping):
        return {}
    mapping: Dict[str, str] = {}
    for key, value in data.items():
        if isinstance(key, str) and isinstance(value, str):
            mapping[key] = value
    return mapping


def _save_mapping(mapping_path: Path, mapping: Mapping[str, str]) -> Dict[str, str]:
    normalised = {str(key): str(value) for key, value in mapping.items()}
    mapping_path.write_text(
        json.dumps(normalised, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return normalised


def _collect_fragments(source_path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    try:
        fragments = extract_fragments(source_path)
    except Exception:  # pragma: no cover - defensive fallback
        _LOGGER.exception("failed to extract fragments from %%s", source_path)
        return records

    for idx, fragment in enumerate(fragments):
        preview = str(fragment.get("text") or fragment.get("value") or "")
        preview = preview.replace("\n", " ").strip()
        if len(preview) > 120:
            preview = preview[:117] + "..."
        record = {
            "index": fragment.get("index", idx),
            "kind": fragment.get("kind") or fragment.get("type"),
            "start": fragment.get("start"),
            "end": fragment.get("end"),
            "length": fragment.get("length"),
            "preview": preview,
        }
        records.append(record)
    return records


def _load_upcode_entries(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if not isinstance(data, Mapping):
        return []
    entries: List[Dict[str, Any]] = []
    for entry in data.get("entries", []):
        if not isinstance(entry, Mapping):
            continue
        opcode = entry.get("opcode")
        if not isinstance(opcode, int):
            continue
        mnemonic = entry.get("mnemonic")
        identifier = _canonicalize_identifier(opcode, mnemonic if isinstance(mnemonic, str) else None)
        record = {
            "opcode": opcode,
            "mnemonic": identifier,
            "semantic": entry.get("semantic"),
            "sample_usage": entry.get("sample_usage", []),
            "handler_table": entry.get("handler_table"),
        }
        entries.append(record)
    return sorted(entries, key=lambda item: item.get("opcode", 0))


def _load_vote_state(path: Path) -> Dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, Mapping):
        payload = {}
    votes_raw = payload.get("votes")
    locks_raw = payload.get("locks")
    votes: Dict[str, Dict[str, str]] = {}
    if isinstance(votes_raw, Mapping):
        for identifier, analyst_votes in votes_raw.items():
            if not isinstance(identifier, str) or not isinstance(analyst_votes, Mapping):
                continue
            normalised: Dict[str, str] = {}
            for analyst, choice in analyst_votes.items():
                if isinstance(analyst, str) and isinstance(choice, str):
                    normalised[analyst] = choice
            if normalised:
                votes[identifier] = normalised
    locks: Dict[str, Dict[str, Any]] = {}
    if isinstance(locks_raw, Mapping):
        for identifier, lock_data in locks_raw.items():
            if not isinstance(identifier, str) or not isinstance(lock_data, Mapping):
                continue
            name = lock_data.get("name")
            if not isinstance(name, str):
                continue
            supporters = lock_data.get("supporters")
            if isinstance(supporters, Iterable):
                supporters_list = [
                    str(value) for value in supporters if isinstance(value, str)
                ]
            else:
                supporters_list = []
            locked_at = lock_data.get("locked_at")
            locks[identifier] = {
                "name": name,
                "supporters": supporters_list,
                "locked_at": locked_at if isinstance(locked_at, str) else "",
            }
    return {"votes": votes, "locks": locks}


def _save_vote_state(path: Path, state: Mapping[str, Any]) -> Dict[str, Any]:
    payload = {"votes": {}, "locks": {}}
    votes = state.get("votes") if isinstance(state, Mapping) else None
    if isinstance(votes, Mapping):
        payload["votes"] = {
            str(identifier): {
                str(analyst): str(choice)
                for analyst, choice in analyst_votes.items()
                if isinstance(analyst, str) and isinstance(choice, str)
            }
            for identifier, analyst_votes in votes.items()
            if isinstance(identifier, str) and isinstance(analyst_votes, Mapping)
        }
    locks = state.get("locks") if isinstance(state, Mapping) else None
    if isinstance(locks, Mapping):
        normalised: Dict[str, Dict[str, Any]] = {}
        for identifier, lock_data in locks.items():
            if not isinstance(identifier, str) or not isinstance(lock_data, Mapping):
                continue
            name = lock_data.get("name")
            if not isinstance(name, str):
                continue
            supporters = lock_data.get("supporters")
            if isinstance(supporters, Iterable):
                supporters_list = [
                    str(value) for value in supporters if isinstance(value, str)
                ]
            else:
                supporters_list = []
            locked_at = lock_data.get("locked_at")
            normalised[identifier] = {
                "name": name,
                "supporters": supporters_list,
                "locked_at": locked_at if isinstance(locked_at, str) else "",
            }
        payload["locks"] = normalised
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _summarise_votes(votes: Mapping[str, str]) -> List[Dict[str, Any]]:
    counter = Counter(votes.values())
    return [
        {"mnemonic": mnemonic, "count": count}
        for mnemonic, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def _opcode_identifier_from_payload(payload: Mapping[str, Any]) -> Optional[str]:
    identifier = payload.get("identifier")
    if isinstance(identifier, str) and identifier.strip():
        return identifier.strip()
    opcode_value = payload.get("opcode")
    if isinstance(opcode_value, int):
        return f"OP_{opcode_value}"
    if isinstance(opcode_value, str) and opcode_value.strip():
        try:
            value = int(opcode_value.strip(), 0)
        except ValueError:
            return None
        return f"OP_{value}"
    return None


def _parse_opcode_value(raw: Any) -> Optional[int]:
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return int(raw.strip(), 0)
        except ValueError:
            return None
    return None


def _record_vote(
    config: ReviewConfig,
    identifier: str,
    opcode: Optional[int],
    analyst: str,
    mnemonic: str,
) -> Dict[str, Any]:
    votes_path = _ensure_directory(config.votes_path)
    state = _load_vote_state(votes_path)
    votes: MutableMapping[str, Dict[str, str]] = state.setdefault("votes", {})  # type: ignore[assignment]
    locks: MutableMapping[str, Dict[str, Any]] = state.setdefault("locks", {})  # type: ignore[assignment]

    existing_lock = locks.get(identifier)
    if existing_lock and existing_lock.get("name") != mnemonic:
        return {
            "error": "identifier is already locked",
            "identifier": identifier,
            "locked_name": existing_lock.get("name"),
        }

    analyst_votes = votes.setdefault(identifier, {})
    analyst_votes[analyst] = mnemonic
    tallies = _summarise_votes(analyst_votes)

    supporters = [name for name, choice in analyst_votes.items() if choice == mnemonic]
    threshold = max(1, config.consensus_threshold)
    consensus_reached = len(set(supporters)) >= threshold

    mapping_updates: Optional[Dict[str, str]] = None
    pretty_result: Optional[Dict[str, Any]] = None
    if consensus_reached:
        locks[identifier] = {
            "name": mnemonic,
            "supporters": sorted(set(supporters)),
            "locked_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        mapping = _load_mapping(config.mapping_path)
        if mapping.get(identifier) != mnemonic:
            mapping[identifier] = mnemonic
            mapping_updates = _save_mapping(config.mapping_path, mapping)
        pretty_result = _render_pretty(
            config.reconstructed_path,
            config.mapping_path,
            rerender=True,
        )

    persisted = _save_vote_state(votes_path, state)
    response: Dict[str, Any] = {
        "identifier": identifier,
        "opcode": opcode,
        "mnemonic": mnemonic,
        "votes": [{"analyst": key, "mnemonic": value} for key, value in sorted(analyst_votes.items())],
        "tallies": tallies,
        "consensus": consensus_reached,
        "needed": threshold,
        "locked": consensus_reached,
        "vote_state": persisted,
    }
    if consensus_reached:
        response["locked_name"] = mnemonic
        if mapping_updates is not None:
            response["mapping"] = mapping_updates
        if pretty_result is not None:
            response["pretty"] = pretty_result
    elif existing_lock:
        response["locked"] = True
        response["locked_name"] = existing_lock.get("name")
    return response


def _collect_opcode_payload(config: ReviewConfig) -> List[Dict[str, Any]]:
    mapping = _load_mapping(config.mapping_path)
    state = _load_vote_state(_ensure_directory(config.votes_path))
    votes = state.get("votes", {}) if isinstance(state, Mapping) else {}
    locks = state.get("locks", {}) if isinstance(state, Mapping) else {}

    entries = _load_upcode_entries(config.upcodes_path)
    identifiers = {entry["mnemonic"] for entry in entries}
    for identifier in mapping:
        if identifier not in identifiers:
            entries.append(
                {
                    "opcode": None,
                    "mnemonic": identifier,
                    "semantic": None,
                    "sample_usage": [],
                    "handler_table": None,
                }
            )

    enriched: List[Dict[str, Any]] = []
    for entry in entries:
        identifier = entry.get("mnemonic")
        if not isinstance(identifier, str):
            continue
        opcode = entry.get("opcode")
        vote_listing = votes.get(identifier, {}) if isinstance(votes, Mapping) else {}
        tallies = _summarise_votes(vote_listing)
        lock_data = locks.get(identifier) if isinstance(locks, Mapping) else None
        locked_name = None
        if isinstance(lock_data, Mapping):
            locked_name = lock_data.get("name") if isinstance(lock_data.get("name"), str) else None
        current_name = mapping.get(identifier)
        enriched.append(
            {
                "opcode": opcode,
                "identifier": identifier,
                "current_name": current_name,
                "locked": bool(lock_data) or (current_name is not None and current_name != identifier),
                "locked_name": locked_name or current_name,
                "votes": [
                    {"analyst": analyst, "mnemonic": choice}
                    for analyst, choice in sorted(vote_listing.items())
                ],
                "tallies": tallies,
                "needed": max(1, config.consensus_threshold),
                "semantic": entry.get("semantic"),
                "handler_table": entry.get("handler_table"),
                "sample_usage": entry.get("sample_usage", []),
            }
        )

    enriched.sort(
        key=lambda item: (
            item.get("opcode") is None,
            item.get("opcode") if item.get("opcode") is not None else 0,
            item.get("identifier"),
        )
    )
    return enriched


def _list_candidate_files(candidates_dir: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not candidates_dir.exists():
        return records
    for path in sorted(candidates_dir.glob("*.lua")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        preview = text.splitlines()
        summary = preview[0] if preview else ""
        records.append(
            {
                "name": path.name,
                "size": path.stat().st_size,
                "summary": summary[:160],
            }
        )
    return records


def _read_candidate_file(candidates_dir: Path, name: str) -> Optional[str]:
    if not name or "/" in name or ".." in name:
        return None
    candidate_path = (candidates_dir / name).expanduser().resolve()
    try:
        base = candidates_dir.expanduser().resolve()
    except FileNotFoundError:
        return None
    if base not in candidate_path.parents and candidate_path != base:
        return None
    if not candidate_path.exists():
        return None
    try:
        return candidate_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _render_pretty(
    reconstructed_path: Path,
    mapping_path: Path,
    *,
    rerender: bool,
) -> Dict[str, Any]:
    output_path = reconstructed_path.with_name("deobfuscated_pretty.lua")
    if rerender:
        mapping_data = _load_mapping(mapping_path)
        try:
            if mapping_data:
                pretty_print_with_mapping(
                    reconstructed_path,
                    mapping_path,
                    output_path=output_path,
                )
            else:
                text = reconstructed_path.read_text(encoding="utf-8", errors="ignore")
                beautifier = LuaBeautifier()
                formatted = beautifier.beautify(text)
                header = "\n".join(["--[[", "-- Renamed identifiers:", "--]]", ""]) + formatted
                output_path.write_text(header, encoding="utf-8")
        except Exception as exc:  # pragma: no cover - runtime feedback surface
            _LOGGER.debug("pretty printer failed", exc_info=True)
            return {
                "success": False,
                "error": str(exc),
                "output_path": str(output_path),
            }

    if output_path.exists():
        text = output_path.read_text(encoding="utf-8", errors="ignore")
    else:
        text = ""
    return {
        "success": True,
        "output": text,
        "output_path": str(output_path),
    }


def _render_index_html(config: ReviewConfig) -> str:
    configuration = json.dumps(
        {
            "source": str(config.source_path),
            "reconstructed": str(config.reconstructed_path),
            "mapping": str(config.mapping_path),
            "candidates": str(config.candidates_dir),
            "upcodes": str(config.upcodes_path),
            "votes": str(config.votes_path),
            "threshold": config.consensus_threshold,
        }
    )
    return INDEX_HTML.replace("__CONFIG_PLACEHOLDER__", configuration)


def _json_response(handler: BaseHTTPRequestHandler, payload: Mapping[str, Any], *, status: int = 200) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _text_response(handler: BaseHTTPRequestHandler, text: str, *, status: int = 200) -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _html_response(handler: BaseHTTPRequestHandler, html: str) -> None:
    body = html.encode("utf-8")
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler) -> Any:
    length = int(handler.headers.get("Content-Length", "0"))
    data = handler.rfile.read(length) if length else b""
    if not data:
        return {}
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        return {}


def _make_handler(config: ReviewConfig):
    class ReviewRequestHandler(BaseHTTPRequestHandler):
        server_version = "LuraphReview/1.0"

        def log_message(self, format: str, *args: Any) -> None:  # pragma: no cover - delegated to logger
            _LOGGER.info("%s - %s", self.address_string(), format % args)

        # pylint: disable=too-many-return-statements
        def do_GET(self) -> None:  # noqa: D401 - http handler
            parsed = urlparse(self.path)
            route = parsed.path
            if route == "/":
                _html_response(self, _render_index_html(config))
                return
            if route == "/api/fragments":
                fragments = _collect_fragments(config.source_path)
                _json_response(self, {"fragments": fragments})
                return
            if route == "/api/candidates":
                records = _list_candidate_files(config.candidates_dir)
                _json_response(self, {"candidates": records})
                return
            if route == "/api/opcodes":
                opcodes = _collect_opcode_payload(config)
                _json_response(self, {"opcodes": opcodes})
                return
            if route == "/api/candidate":
                params = parse_qs(parsed.query)
                name = params.get("name", [""])[0]
                content = _read_candidate_file(config.candidates_dir, name)
                if content is None:
                    _json_response(self, {"error": "candidate not found"}, status=404)
                    return
                _text_response(self, content)
                return
            if route == "/api/mapping":
                mapping = _load_mapping(config.mapping_path)
                _json_response(self, {"mapping": mapping})
                return
            if route == "/api/pretty":
                params = parse_qs(parsed.query)
                rerender = params.get("rerender", ["0"])[0] in {"1", "true", "yes"}
                result = _render_pretty(
                    config.reconstructed_path,
                    config.mapping_path,
                    rerender=rerender,
                )
                _json_response(self, result)
                return
            _json_response(self, {"error": "not found"}, status=404)

        def do_POST(self) -> None:  # noqa: D401 - http handler
            parsed = urlparse(self.path)
            route = parsed.path
            if route == "/api/mapping":
                payload = _read_json(self)
                mapping = payload.get("mapping") if isinstance(payload, dict) else None
                if not isinstance(mapping, Mapping):
                    _json_response(self, {"error": "mapping must be an object"}, status=400)
                    return
                normalised = _save_mapping(config.mapping_path, mapping)
                result = _render_pretty(
                    config.reconstructed_path,
                    config.mapping_path,
                    rerender=True,
                )
                payload = {"mapping": normalised, "pretty": result}
                payload["opcodes"] = _collect_opcode_payload(config)
                _json_response(self, payload)
                return
            if route == "/api/vote":
                payload = _read_json(self)
                if not isinstance(payload, Mapping):
                    _json_response(self, {"error": "payload must be an object"}, status=400)
                    return
                analyst = payload.get("analyst")
                if not isinstance(analyst, str) or not analyst.strip():
                    _json_response(self, {"error": "analyst is required"}, status=400)
                    return
                vote_choice = payload.get("mnemonic")
                canonical_vote = _canonicalize_vote_name(vote_choice if isinstance(vote_choice, str) else None)
                if not canonical_vote:
                    _json_response(
                        self,
                        {"error": "mnemonic must contain letters, digits, or underscores"},
                        status=400,
                    )
                    return
                identifier = _opcode_identifier_from_payload(payload)
                if not identifier:
                    _json_response(self, {"error": "opcode or identifier required"}, status=400)
                    return
                opcode_value = _parse_opcode_value(payload.get("opcode"))
                result = _record_vote(
                    config,
                    identifier,
                    opcode_value,
                    analyst.strip(),
                    canonical_vote,
                )
                if "error" in result:
                    _json_response(self, result, status=409)
                    return
                _json_response(self, result)
                return
            if route == "/api/pretty":
                payload = _read_json(self)
                rerender = bool(payload.get("rerender", False)) if isinstance(payload, dict) else False
                result = _render_pretty(
                    config.reconstructed_path,
                    config.mapping_path,
                    rerender=rerender,
                )
                _json_response(self, result)
                return
            _json_response(self, {"error": "not found"}, status=404)

    return ReviewRequestHandler


def _create_server(config: ReviewConfig, host: str, port: int) -> ThreadingHTTPServer:
    handler = _make_handler(config)
    server = ThreadingHTTPServer((host, port), handler)
    return server


def run_review_ui(
    source_path: str | Path,
    reconstructed_path: str | Path,
    *,
    mapping_path: str | Path | None = None,
    candidates_dir: str | Path = "candidates",
    upcodes_path: str | Path | None = None,
    votes_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
    consensus_threshold: int = 2,
) -> None:
    """Start the interactive review UI server."""

    source = Path(source_path)
    reconstructed = Path(reconstructed_path)
    mapping = Path(mapping_path) if mapping_path is not None else Path("mapping.json")
    candidates = Path(candidates_dir)
    upcodes = Path(upcodes_path) if upcodes_path is not None else Path("upcodes.json")
    votes = Path(votes_path) if votes_path is not None else Path("opcode_votes.json")

    threshold = max(1, int(consensus_threshold)) if consensus_threshold else 1

    config = ReviewConfig(
        source_path=source.expanduser().resolve(),
        reconstructed_path=reconstructed.expanduser().resolve(),
        mapping_path=_ensure_directory(mapping),
        candidates_dir=candidates.expanduser().resolve(),
        upcodes_path=upcodes.expanduser().resolve(),
        votes_path=_ensure_directory(votes),
        consensus_threshold=threshold,
    )

    server = _create_server(config, host, port)
    actual_host, actual_port = server.server_address
    url = f"http://{actual_host}:{actual_port}/"
    _LOGGER.info("interactive review UI available at %s", url)

    if open_browser:
        try:  # pragma: no cover - optional convenience path
            import webbrowser

            webbrowser.open(url)
        except Exception:  # pragma: no cover - optional convenience path
            _LOGGER.debug("failed to open browser", exc_info=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - manual shutdown
        _LOGGER.info("shutting down review UI")
    finally:
        server.shutdown()
        server.server_close()


INDEX_HTML = """<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Luraph Interactive Review UI</title>
    <style>
      body { font-family: sans-serif; margin: 0; padding: 0; display: flex; min-height: 100vh; }
      header { background: #1f2933; color: #f8f9fa; padding: 1rem 1.5rem; }
      h1 { margin: 0; font-size: 1.4rem; }
      main { display: flex; flex: 1; }
      section { flex: 1; padding: 1rem; overflow-y: auto; border-right: 1px solid #e2e8f0; }
      section:last-child { border-right: none; }
      table { border-collapse: collapse; width: 100%; }
      th, td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid #e2e8f0; }
      pre { background: #0f172a; color: #e2e8f0; padding: 0.75rem; border-radius: 4px; white-space: pre-wrap; }
      textarea { width: 100%; min-height: 160px; font-family: monospace; }
      button { margin-top: 0.5rem; padding: 0.35rem 0.75rem; }
      ul { list-style: none; padding: 0; }
      li { margin: 0.25rem 0; }
      li button { width: 100%; text-align: left; background: #e2e8f0; border: none; padding: 0.5rem; border-radius: 4px; cursor: pointer; }
      li button:hover { background: #cbd5f5; }
      .status { margin-top: 0.5rem; font-size: 0.9rem; color: #2563eb; }
      .error { color: #b91c1c; }
      .success { color: #047857; }
      .vote-controls { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin: 0.5rem 0; }
      .vote-controls label { display: flex; flex-direction: column; font-size: 0.85rem; }
      .vote-controls input { margin-top: 0.25rem; padding: 0.25rem; font-size: 1rem; min-width: 200px; }
      .vote-controls button { margin-top: 0; }
      .opcode-locked { color: #047857; font-weight: 600; }
      .opcode-table-actions { white-space: nowrap; }
    </style>
  </head>
  <body>
    <header>
      <h1>Luraph Interactive Review UI</h1>
      <p id=\"paths\"></p>
    </header>
    <main>
      <section>
        <h2>Fragments</h2>
        <table id=\"fragment-table\">
          <thead>
            <tr><th>#</th><th>Kind</th><th>Start</th><th>End</th><th>Preview</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </section>
      <section>
        <h2>Candidates</h2>
        <ul id=\"candidate-list\"></ul>
        <pre id=\"candidate-preview\">Select a candidate to view its source.</pre>
      </section>
      <section>
        <h2>Rename Mapping</h2>
        <textarea id=\"mapping-editor\"></textarea>
        <div>
          <button id=\"save-mapping\">Save mapping</button>
          <button id=\"refresh-pretty\">Refresh pretty output</button>
        </div>
        <div id=\"mapping-status\" class=\"status\"></div>
        <h2>Opcode voting</h2>
        <div class=\"vote-controls\">
          <label>Analyst name
            <input type=\"text\" id=\"analyst-name\" placeholder=\"Your name\" />
          </label>
          <button id=\"reload-opcodes\">Reload opcode list</button>
          <span id=\"consensus-info\">Consensus threshold: <strong id=\"consensus-threshold\"></strong> votes</span>
        </div>
        <table id=\"opcode-table\">
          <thead>
            <tr><th>Opcode</th><th>Identifier</th><th>Current / Locked</th><th>Votes</th><th class=\"opcode-table-actions\">Actions</th></tr>
          </thead>
          <tbody></tbody>
        </table>
        <div id=\"vote-status\" class=\"status\"></div>
        <h2>Pretty printed output</h2>
        <pre id=\"pretty-output\">Loading…</pre>
      </section>
    </main>
    <script>
      const CONFIG = __CONFIG_PLACEHOLDER__;

      function setStatus(text, isError=false) {
        const target = document.getElementById('mapping-status');
        target.textContent = text;
        target.className = 'status ' + (isError ? 'error' : 'success');
      }

      function setVoteStatus(text, isError=false) {
        const target = document.getElementById('vote-status');
        target.textContent = text;
        target.className = 'status ' + (isError ? 'error' : 'success');
      }

      function loadFragments() {
        fetch('/api/fragments').then(r => r.json()).then(data => {
          const tbody = document.querySelector('#fragment-table tbody');
          tbody.innerHTML = '';
          (data.fragments || []).forEach(fragment => {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${fragment.index}</td><td>${fragment.kind || ''}</td><td>${fragment.start ?? ''}</td><td>${fragment.end ?? ''}</td><td>${fragment.preview || ''}</td>`;
            tbody.appendChild(row);
          });
        });
      }

      function loadCandidates() {
        fetch('/api/candidates').then(r => r.json()).then(data => {
          const list = document.getElementById('candidate-list');
          list.innerHTML = '';
          (data.candidates || []).forEach(candidate => {
            const item = document.createElement('li');
            const button = document.createElement('button');
            button.textContent = `${candidate.name} (${candidate.size} bytes)`;
            button.addEventListener('click', () => loadCandidate(candidate.name));
            item.appendChild(button);
            if (candidate.summary) {
              const summary = document.createElement('div');
              summary.textContent = candidate.summary;
              summary.style.fontSize = '0.8rem';
              summary.style.color = '#475569';
              item.appendChild(summary);
            }
            list.appendChild(item);
          });
        });
      }

      function loadCandidate(name) {
        fetch(`/api/candidate?name=${encodeURIComponent(name)}`).then(r => {
          if (!r.ok) {
            return r.json().then(data => { throw new Error(data.error || 'unable to load candidate'); });
          }
          return r.text();
        }).then(text => {
          document.getElementById('candidate-preview').textContent = text;
        }).catch(err => {
          document.getElementById('candidate-preview').textContent = err.message;
        });
      }

      function loadMapping() {
        fetch('/api/mapping').then(r => r.json()).then(data => {
          document.getElementById('mapping-editor').value = JSON.stringify(data.mapping || {}, null, 2);
        });
      }

      function loadPretty(rerender=false) {
        const url = rerender ? '/api/pretty?rerender=1' : '/api/pretty';
        fetch(url).then(r => r.json()).then(data => {
          if (data.success) {
            document.getElementById('pretty-output').textContent = data.output || '';
            setStatus(rerender ? 'Pretty output refreshed.' : 'Pretty output loaded.', false);
          } else {
            document.getElementById('pretty-output').textContent = data.error || 'Unable to render pretty output.';
            setStatus(data.error || 'Unable to render pretty output.', true);
          }
        }).catch(err => {
          document.getElementById('pretty-output').textContent = err.message;
          setStatus(err.message, true);
        });
      }

      function saveMapping() {
        let mapping;
        try {
          mapping = JSON.parse(document.getElementById('mapping-editor').value || '{}');
        } catch (err) {
          setStatus('Mapping must be valid JSON: ' + err.message, true);
          return;
        }
        fetch('/api/mapping', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({mapping})
        }).then(r => r.json()).then(data => {
          if (data.pretty && data.pretty.success) {
            document.getElementById('pretty-output').textContent = data.pretty.output || '';
            setStatus('Mapping saved and pretty output updated.', false);
          } else if (data.pretty) {
            setStatus(data.pretty.error || 'Pretty printer failed.', true);
          } else {
            setStatus('Mapping saved.', false);
          }
          loadOpcodes();
        }).catch(err => setStatus(err.message, true));
      }

      function formatTallies(entry) {
        if (!Array.isArray(entry.tallies) || !entry.tallies.length) {
          return 'No votes yet';
        }
        return entry.tallies.map(t => `${t.mnemonic} (${t.count})`).join(', ');
      }

      function loadOpcodes() {
        fetch('/api/opcodes').then(r => r.json()).then(data => {
          const tbody = document.querySelector('#opcode-table tbody');
          tbody.innerHTML = '';
          (data.opcodes || []).forEach(entry => {
            const row = document.createElement('tr');
            const lockedName = entry.locked_name || '';
            const lockLabel = lockedName ? `<span class="opcode-locked">${lockedName}</span>` : (entry.current_name || '—');
            const voteCell = formatTallies(entry);
            row.innerHTML = `
              <td>${entry.opcode ?? ''}</td>
              <td>${entry.identifier}</td>
              <td>${lockLabel}</td>
              <td>${voteCell}</td>
              <td class="opcode-table-actions"></td>
            `;
            const actionCell = row.querySelector('.opcode-table-actions');
            const button = document.createElement('button');
            button.textContent = entry.locked ? 'Locked' : 'Cast vote';
            button.disabled = !!entry.locked;
            button.addEventListener('click', () => voteForOpcode(entry));
            actionCell.appendChild(button);
            tbody.appendChild(row);
          });
        }).catch(err => setVoteStatus(err.message || 'Failed to load opcodes', true));
      }

      function getAnalystName() {
        return (document.getElementById('analyst-name').value || '').trim();
      }

      function voteForOpcode(entry) {
        const analyst = getAnalystName();
        if (!analyst) {
          setVoteStatus('Enter an analyst name before voting.', true);
          return;
        }
        const defaultName = entry.locked_name || (entry.current_name && entry.current_name !== entry.identifier ? entry.current_name : '');
        const response = prompt(`Vote for ${entry.identifier}`, defaultName || '');
        if (response === null) {
          return;
        }
        const vote = response.trim();
        if (!vote) {
          setVoteStatus('Vote must not be empty.', true);
          return;
        }
        submitVote(entry, analyst, vote);
      }

      function submitVote(entry, analyst, vote) {
        fetch('/api/vote', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            opcode: entry.opcode,
            identifier: entry.identifier,
            analyst,
            mnemonic: vote,
          })
        }).then(response => {
          if (!response.ok) {
            return response.json().then(data => Promise.reject(data));
          }
          return response.json();
        }).then(data => {
          if (data.pretty && data.pretty.success) {
            document.getElementById('pretty-output').textContent = data.pretty.output || '';
          }
          if (data.locked) {
            setVoteStatus(`Consensus reached for ${data.identifier}: ${data.locked_name}.`, false);
          } else {
            setVoteStatus(`Vote recorded for ${data.identifier}.`, false);
          }
          loadOpcodes();
        }).catch(err => {
          const message = err && err.error ? err.error : (err && err.message ? err.message : 'Failed to record vote');
          setVoteStatus(message, true);
        });
      }

      document.getElementById('paths').textContent = `Source: ${CONFIG.source} | Reconstructed: ${CONFIG.reconstructed} | Mapping: ${CONFIG.mapping} | Votes: ${CONFIG.votes}`;
      document.getElementById('consensus-threshold').textContent = CONFIG.threshold || 1;

      const analystInput = document.getElementById('analyst-name');
      const storedAnalyst = localStorage.getItem('luraph-analyst-name') || '';
      analystInput.value = storedAnalyst;
      analystInput.addEventListener('input', () => {
        localStorage.setItem('luraph-analyst-name', analystInput.value || '');
      });

      document.getElementById('save-mapping').addEventListener('click', saveMapping);
      document.getElementById('refresh-pretty').addEventListener('click', () => loadPretty(true));
      document.getElementById('reload-opcodes').addEventListener('click', loadOpcodes);

      loadFragments();
      loadCandidates();
      loadMapping();
      loadPretty(false);
      loadOpcodes();
    </script>
  </body>
</html>
"""


__all__ = [
    "ReviewConfig",
    "run_review_ui",
]

