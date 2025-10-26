"""Command line interface for running the deobfuscation pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import string
import sys
import textwrap
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import pipeline, utils
from .bootstrap import scan_lph_blocks
from .cli import reporting as cli_reporting
from .utils import write_json, write_text
from .usage_audit import UsageConfirmationError, require_usage_confirmation
from .deobfuscator import LuaDeobfuscator
from .lph_reader import read_lph_blob
from .passes.preprocess import flatten_json_to_lua
from .utils_pkg.ir import IRModule
from .utils.luraph_vm import canonicalise_opcode_name
from .utils.opcode_inference import DEFAULT_OPCODE_NAMES
from .vm.opcode_constants import MANDATORY_MNEMONICS
from version_detector import (
    VersionInfo,
    evaluate_deobfuscation_checklist,
    evaluate_quality_gate,
    generate_run_summary,
    pretty_print_with_mapping,
)

LOG_FILE = Path("deobfuscator.log")
DEFAULT_PAYLOAD_ITERATIONS = 5
CRASH_DIR = Path("out") / "crash_reports"

_SCRIPT_KEY_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"script_key\s*=\s*script_key\s*or\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"getgenv\(\)\.script_key\s*=\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"script_key\s*=\s*['\"]([^'\"]+)['\"]"),
)
_SCRIPT_KEY_REQUIRED_RE = re.compile(r"script_key\s*=\s*script_key\s*or", re.IGNORECASE)
_LPH_KEY_CANDIDATE_RE = re.compile(r"[a-z0-9]{18,24}")
_DEFAULT_TEST_KEYS = ("koqzpaexlygm9b227uy",)
_SCRIPT_KEY_ENV_VARS: Tuple[str, ...] = (
    "LURAPH_SESSION_KEY",
    "LURAPH_SCRIPT_KEY",
    "SCRIPT_KEY",
)


def _consume_env_script_key() -> tuple[Optional[str], Optional[str]]:
    """Return a script key sourced from the environment, removing it once read."""

    for variable in _SCRIPT_KEY_ENV_VARS:
        value = os.environ.get(variable)
        if value is None:
            continue
        # Remove the value immediately so it cannot leak into child processes.
        os.environ.pop(variable, None)
        stripped = value.strip()
        if stripped:
            return stripped, variable
    return None, None


def _detect_script_key(text: Optional[str]) -> Optional[str]:
    """Return an inline script key detected in ``text`` if present."""

    if not text:
        return None
    for pattern in _SCRIPT_KEY_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = match.group(1).strip()
            if candidate:
                return candidate

    try:
        payload = json.loads(text)
    except Exception:
        return None

    def _extract(value: Any) -> Optional[str]:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        if isinstance(value, Mapping):
            for key, sub_value in value.items():
                if isinstance(key, str) and key.lower() == "script_key":
                    if isinstance(sub_value, str) and sub_value.strip():
                        return sub_value.strip()
                nested = _extract(sub_value)
                if nested:
                    return nested
        if isinstance(value, list):
            for entry in value:
                nested = _extract(entry)
                if nested:
                    return nested
        return None

    return _extract(payload)


def _candidate_script_keys(text: Optional[str]) -> List[str]:
    """Return heuristic script-key candidates near discovered ``LPH`` blobs."""

    if not text:
        return []

    candidates: List[str] = []
    blocks = scan_lph_blocks(text, source="input")
    for block in blocks:
        start, end = block.span
        window = text[max(0, start - 256) : min(len(text), end + 256)]
        for match in _LPH_KEY_CANDIDATE_RE.finditer(window):
            token = match.group(0)
            if token not in candidates:
                candidates.append(token)
    return candidates


def _requires_script_key(text: Optional[str]) -> bool:
    """Return ``True`` when *text* likely needs a script key to decode."""

    if not text:
        return False
    if _SCRIPT_KEY_REQUIRED_RE.search(text):
        return True
    lowered = text.lower()
    if "initv4" in lowered and "payload =" in lowered:
        return True
    return False


class _ColourFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG: "blue",
        logging.INFO: "green",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "magenta",
    }

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - trivial wrapper
        message = super().format(record)
        colour = self.COLOURS.get(record.levelno, "green")
        return utils.colorize_text(message, colour)


@dataclass
class WorkItem:
    source: Path
    destination: Path
    lua_destination: Optional[Path] = None
    json_destination: Optional[Path] = None


_ALLOWED_OPTION_KEY_FIELDS = {"script_key_source", "script_key_source_detail"}


def _sanitise_crash_options(options: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a serialisable, key-free snapshot of CLI options."""

    sanitized: Dict[str, Any] = {}
    for key, value in options.items():
        key_lower = key.lower()
        if "key" in key_lower and key_lower not in _ALLOWED_OPTION_KEY_FIELDS:
            continue
        sanitized[key] = utils.serialise_metadata(value)
    return sanitized


def _normalise_crash_timings(
    timings: Sequence[Tuple[str, float]],
    failed_pass: Optional[str] = None,
    failed_duration: Optional[float] = None,
) -> List[Dict[str, Any]]:
    entries = [{"name": name, "duration": duration} for name, duration in timings]
    if failed_pass and failed_duration is not None:
        entries.append({"name": failed_pass, "duration": failed_duration, "failed": True})
    return entries


def _write_crash_report(
    *,
    item: WorkItem,
    ctx: Optional[pipeline.Context],
    iteration: int,
    failed_pass: Optional[str],
    timings: Sequence[Tuple[str, float]],
    failed_duration: Optional[float],
    exc: BaseException,
) -> Path:
    """Persist a safe-mode crash report without leaking key material."""

    utils.ensure_directory(CRASH_DIR)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    stem = item.source.stem or item.source.name or "input"
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)[:80] or "input"
    crash_path = CRASH_DIR / f"{safe_stem}_iter{iteration}_{timestamp}.json"
    base_payload: Dict[str, Any] = {
        "safe_mode": True,
        "timestamp": timestamp,
        "timestamp_epoch": time.time(),
        "input": str(item.source),
        "destination": str(item.destination) if item.destination else None,
        "iteration": iteration,
        "failed_pass": failed_pass,
        "timings": _normalise_crash_timings(timings, failed_pass, failed_duration),
        "error": {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exception(type(exc), exc, exc.__traceback__),
        },
    }
    if ctx is not None:
        base_payload["stage_output_length"] = len(ctx.stage_output or "")
        base_payload["has_output"] = bool(ctx.output)
        if ctx.detected_version:
            base_payload["detected_version"] = ctx.detected_version.name
        if isinstance(ctx.options, Mapping):
            base_payload["options"] = _sanitise_crash_options(ctx.options)
        else:
            base_payload["options"] = {}
        base_payload["pass_metadata"] = utils.serialise_metadata(ctx.pass_metadata)
        base_payload["vm_metadata"] = utils.serialise_metadata(ctx.vm_metadata)
        report_obj = getattr(ctx, "report", None)
        if report_obj is not None:
            base_payload["report"] = report_obj.to_json()
            base_payload["masked_script_key"] = report_obj.masked_script_key()
    else:
        base_payload["options"] = {}
        base_payload["pass_metadata"] = {}
        base_payload["vm_metadata"] = {}

    write_json(crash_path, base_payload, sort_keys=True)
    return crash_path


@dataclass
class WorkResult:
    item: WorkItem
    success: bool
    output_path: Optional[Path] = None
    summary: str = ""
    error: Optional[str] = None


def configure_logging(verbose: bool) -> None:
    """Configure root logging handlers."""

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    level = logging.DEBUG if verbose else logging.INFO
    root.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if verbose:
        stream = logging.StreamHandler()
        stream.setFormatter(_ColourFormatter("%(levelname)s: %(message)s"))
        root.addHandler(stream)


def _split_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _parse_opcode_argument(value: str) -> int:
    token = value.strip().lower()
    if not token:
        raise ValueError("opcode must be a non-empty string")
    base = 10
    if token.startswith("0x"):
        token = token[2:]
        base = 16
    elif token.startswith("0b"):
        token = token[2:]
        base = 2
    elif token.startswith("0o"):
        token = token[2:]
        base = 8
    return int(token, base)


def _load_mapping_payload(path: Path) -> tuple[Optional[object], Dict[str, str]]:
    if not path.exists():
        return None, {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        logging.getLogger(__name__).warning("failed to parse mapping file %s: %s", path, exc)
        return None, {}

    rename_map: Dict[str, str] = {}

    def _add_entry(source: object, target: object) -> None:
        if isinstance(source, str) and isinstance(target, str) and source and target:
            rename_map[source] = target

    if isinstance(raw, dict):
        if raw and all(isinstance(value, str) for value in raw.values()):
            for key, value in raw.items():
                _add_entry(key, value)
        else:
            for key in ("renames", "mapping", "items", "rows"):
                container = raw.get(key)
                if isinstance(container, dict):
                    for source, target in container.items():
                        _add_entry(source, target)
                elif isinstance(container, list):
                    for entry in container:
                        if isinstance(entry, Mapping):
                            source = (
                                entry.get("name")
                                or entry.get("source")
                                or entry.get("identifier")
                            )
                            target = (
                                entry.get("recommended_name")
                                or entry.get("target")
                                or entry.get("rename")
                            )
                            _add_entry(source, target)
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, Mapping):
                source = entry.get("name") or entry.get("source") or entry.get("identifier")
                target = entry.get("recommended_name") or entry.get("target") or entry.get("rename")
                _add_entry(source, target)

    return raw, rename_map


def _update_mapping_payload(raw: Optional[object], identifier: str, mnemonic: str) -> object:
    entry = {"name": identifier, "recommended_name": mnemonic}
    if raw is None:
        return {identifier: mnemonic}
    if isinstance(raw, dict):
        if raw and all(isinstance(value, str) for value in raw.values()):
            updated = dict(raw)
            updated[identifier] = mnemonic
            return updated
        updated = dict(raw)
        renames = updated.get("renames") if isinstance(updated, dict) else None
        if isinstance(renames, dict):
            new_renames = dict(renames)
            new_renames[identifier] = mnemonic
            updated["renames"] = new_renames
            return updated
        if isinstance(renames, list):
            new_list: List[object] = []
            found = False
            for item in renames:
                if isinstance(item, Mapping):
                    if (
                        item.get("name") == identifier
                        or item.get("source") == identifier
                        or item.get("identifier") == identifier
                    ):
                        updated_item = dict(item)
                        updated_item["name"] = identifier
                        updated_item["recommended_name"] = mnemonic
                        new_list.append(updated_item)
                        found = True
                    else:
                        new_list.append(dict(item))
                else:
                    new_list.append(item)
            if not found:
                new_list.append(entry)
            updated["renames"] = new_list
            return updated
        updated["renames"] = [entry]
        return updated
    if isinstance(raw, list):
        new_list: List[object] = []
        found = False
        for item in raw:
            if isinstance(item, Mapping):
                if (
                    item.get("name") == identifier
                    or item.get("source") == identifier
                    or item.get("identifier") == identifier
                ):
                    updated_item = dict(item)
                    updated_item["name"] = identifier
                    updated_item["recommended_name"] = mnemonic
                    new_list.append(updated_item)
                    found = True
                else:
                    new_list.append(dict(item))
            else:
                new_list.append(item)
        if not found:
            new_list.append(entry)
        return new_list
    return {identifier: mnemonic}


def _canonicalize_user_mnemonic(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    candidate = re.sub(r"[^0-9A-Za-z]+", "_", raw.strip())
    candidate = re.sub(r"_+", "_", candidate).strip("_")
    if not candidate:
        return None
    canonical = candidate.upper()
    if canonical[0].isdigit():
        canonical = f"OP_{canonical}"
    return canonical


def _format_snippet(snippet: str) -> str:
    normalised = " ".join(snippet.split())
    return textwrap.shorten(normalised, width=120, placeholder="…")


def _collect_opcode_context(
    opcode: int,
    upcodes_path: Path,
    guesses_path: Path,
) -> Dict[str, Any]:
    context: Dict[str, Any] = {"entries": [], "guess": None}

    if upcodes_path.exists():
        try:
            data = json.loads(upcodes_path.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover - diagnostics only
            data = {}
        entries = []
        for entry in data.get("entries", []):
            if isinstance(entry, Mapping) and entry.get("opcode") == opcode:
                entries.append(entry)
        if entries:
            context["entries"] = entries

    if guesses_path.exists():
        try:
            data = json.loads(guesses_path.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover - diagnostics only
            data = {}
        guesses = data.get("guesses")
        if isinstance(guesses, Mapping):
            guess = guesses.get(str(opcode))
            if isinstance(guess, Mapping):
                context["guess"] = guess

    return context


def _print_opcode_context(
    opcode: int,
    identifier: str,
    existing_name: Optional[str],
    context: Mapping[str, Any],
) -> None:
    print(f"=== Opcode 0x{opcode:02X} ({opcode}) → {identifier}")
    if existing_name:
        print(f"Current mapping: {existing_name}")
    guess = context.get("guess")
    if isinstance(guess, Mapping):
        guess_name = guess.get("guess")
        confidence = guess.get("confidence")
        if guess_name:
            if confidence is not None:
                print(f"Semantic guess: {guess_name} (confidence {confidence})")
            else:
                print(f"Semantic guess: {guess_name}")
        evidence = guess.get("evidence")
        if evidence:
            print(f"Evidence: {evidence}")
    entries = context.get("entries")
    if isinstance(entries, list) and entries:
        print("Sample usage:")
        for entry in entries[:3]:
            if not isinstance(entry, Mapping):
                continue
            mnemonic = entry.get("mnemonic")
            semantic = entry.get("semantic")
            freq = entry.get("frequency")
            table = entry.get("handler_table")
            print(
                "  - mnemonic={mnemonic} freq={freq} table={table} semantic={semantic}".format(
                    mnemonic=mnemonic,
                    freq=freq,
                    table=table,
                    semantic=semantic,
                )
            )
            samples = entry.get("sample_usage")
            if isinstance(samples, list):
                for sample in samples[:2]:
                    if isinstance(sample, Mapping):
                        snippet = sample.get("snippet")
                        if isinstance(snippet, str) and snippet.strip():
                            print(f"    snippet: {_format_snippet(snippet)}")
    else:
        print("No recorded usage samples; consider inspecting VM traces or lifter output.")


def _prompt_mnemonic(identifier: str, default: Optional[str]) -> Optional[str]:
    prompt_suffix = f" [{default}]" if default else ""
    while True:
        response = input(
            f"Enter mnemonic for {identifier}{prompt_suffix} (leave blank to keep current, 'q' to abort): "
        ).strip()
        if not response:
            if default:
                return default
            else:
                print("A mnemonic is required unless you abort with 'q'.")
                continue
        if response.lower() in {"q", "quit", "exit"}:
            return None
        canonical = _canonicalize_user_mnemonic(response)
        if not canonical:
            print("Invalid mnemonic. Use letters, digits, or underscores (e.g. LOADK, CALL_PROTO).")
            continue
        return canonical


def _handle_name_opcode(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="name_opcode",
        description=(
            "Interactively assign a mnemonic to an opcode and refresh reconstructed Lua output."
        ),
    )
    parser.add_argument("opcode", help="Numeric opcode value (decimal, hex, 0b/0o accepted)")
    parser.add_argument(
        "--name",
        dest="mnemonic",
        help="Provide the mnemonic non-interactively (skips the prompt)",
    )
    parser.add_argument(
        "--mapping",
        default="mapping.json",
        help="Path to mapping.json to update (created if missing)",
    )
    parser.add_argument(
        "--source",
        default="reconstructed.lua",
        help="Reconstructed Lua file to reformat after updating the mapping",
    )
    parser.add_argument(
        "--output",
        help="Optional override for the pretty-printed Lua output path",
    )
    parser.add_argument(
        "--upcodes",
        default="upcodes.json",
        help="Path to upcodes.json for context (optional)",
    )
    parser.add_argument(
        "--guesses",
        default="opcode_guesses.json",
        help="Path to opcode_guesses.json for semantic hints (optional)",
    )
    parser.add_argument(
        "--skip-pretty",
        action="store_true",
        help="Skip pretty-printing after updating mapping (only write mapping)",
    )

    args = parser.parse_args(list(argv))

    try:
        opcode_value = _parse_opcode_argument(args.opcode)
    except ValueError as exc:
        parser.error(str(exc))

    identifier = f"OP_{opcode_value}"
    mapping_path = Path(args.mapping)
    raw_mapping, rename_map = _load_mapping_payload(mapping_path)
    existing_name = rename_map.get(identifier)

    context = _collect_opcode_context(
        opcode_value, Path(args.upcodes), Path(args.guesses)
    )
    _print_opcode_context(opcode_value, identifier, existing_name, context)

    provided = args.mnemonic.strip() if args.mnemonic else None
    if provided:
        new_name = _canonicalize_user_mnemonic(provided)
        if not new_name:
            parser.error(
                "provided mnemonic could not be canonicalised; use letters, digits, or underscores"
            )
    else:
        default = _canonicalize_user_mnemonic(existing_name)
        if not default:
            guess = context.get("guess")
            if isinstance(guess, Mapping):
                guess_name = guess.get("guess")
                default_guess = _canonicalize_user_mnemonic(guess_name)
                if default_guess:
                    default = default_guess
        new_name = _prompt_mnemonic(identifier, default)
        if new_name is None:
            print("Aborted without changes.")
            return 1

    payload = _update_mapping_payload(raw_mapping, identifier, new_name)
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Updated {mapping_path} with {identifier} -> {new_name}")

    if args.skip_pretty:
        return 0

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"Source Lua not found: {source_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else None
    result = pretty_print_with_mapping(source_path, mapping_path, output_path=output_path)
    print(f"Regenerated Lua at {result['output_path']}")
    return 0


_LPH_SIGNATURES = (b"LPH!", b"lph!", b"LPH_", b"lph_")
_LPH_SIGNATURE_TEXT = tuple(sig.decode("ascii", errors="ignore") for sig in _LPH_SIGNATURES)
_LPH_SUFFIXES = {".lph", ".b64", ".bin", ".payload", ".dat"}
_LPH_NAME_HINTS = ("lph", "payload", "bootstrap", "blob")


def _looks_like_lph_blob(path: Path) -> bool:
    lower = path.name.lower()
    if any(lower.endswith(suffix) for suffix in _LPH_SUFFIXES):
        return True
    if any(hint in lower for hint in _LPH_NAME_HINTS):
        return True
    try:
        with path.open("rb") as fh:
            sample = fh.read(4096)
    except OSError:
        return False
    if any(signature in sample for signature in _LPH_SIGNATURES):
        return True
    text_preview = sample.decode("utf-8", errors="ignore")
    return any(signature in text_preview for signature in _LPH_SIGNATURE_TEXT)


def _discover_lph_blobs(base: Path) -> List[Path]:
    if base.is_file():
        return [base] if _looks_like_lph_blob(base) else []
    results: List[Path] = []
    seen: set[Path] = set()
    for candidate in base.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate in seen:
            continue
        if _looks_like_lph_blob(candidate):
            seen.add(candidate)
            results.append(candidate)
    return sorted(results)


def _gather_inputs(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if not target.exists():
        raise FileNotFoundError(target)
    files: List[Path] = []
    for candidate in target.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() in {".lua", ".txt", ".json"} or not candidate.suffix:
            files.append(candidate)
    return sorted(files)


def _default_output_paths(source: Path) -> Tuple[Path, Path]:
    base = source.with_name(f"{source.stem}_deob")
    return base.with_suffix(".lua"), base.with_suffix(".json")


def _normalise_output_paths(base: Path) -> Tuple[Path, Path]:
    if base.suffix:
        root = base.with_suffix("")
    else:
        root = base
    return root.with_suffix(".lua"), root.with_suffix(".json")


def _canonical_opcode_map(mapping: Mapping[Any, Any]) -> Dict[int, str]:
    result: Dict[int, str] = {}
    for key, name in mapping.items():
        opcode: Optional[int] = None
        if isinstance(key, int):
            opcode = key
        elif isinstance(key, str):
            try:
                opcode = int(key, 0)
            except (TypeError, ValueError):
                opcode = None
        if opcode is None:
            continue
        canonical = canonicalise_opcode_name(name)
        if not canonical:
            continue
        opcode &= 0x3F
        result.setdefault(opcode, canonical)
    return result


def _summarise_lph_reports(reports: List[Mapping[str, Any]]) -> Tuple[Dict[str, Any], Dict[int, str]]:
    if not reports:
        return {}, {}

    combined_meta: Dict[str, Any] = {"lph_blobs": [dict(entry) for entry in reports]}
    opcode_map: Dict[int, str] = {}
    alphabet_candidate: str = ""

    for entry in reports:
        mapping = entry.get("opcode_map")
        if isinstance(mapping, Mapping):
            opcode_map.update(_canonical_opcode_map(mapping))
        alphabet = entry.get("alphabet")
        if isinstance(alphabet, str) and len(alphabet) > len(alphabet_candidate):
            alphabet_candidate = alphabet

    if not opcode_map:
        opcode_map = dict(DEFAULT_OPCODE_NAMES)

    preview_entries: List[Dict[str, str]] = []
    for opcode, name in list(sorted(opcode_map.items()))[:10]:
        preview_entries.append({f"0x{opcode:02X}": name})

    combined_meta["opcode_map"] = {f"0x{opcode:02X}": name for opcode, name in sorted(opcode_map.items())}
    combined_meta["opcode_map_count"] = len(opcode_map)
    if preview_entries:
        combined_meta["opcode_map_sample"] = preview_entries
    combined_meta["opcode_source"] = "bootstrap"

    if not alphabet_candidate:
        alphabet_candidate = string.ascii_uppercase + string.ascii_lowercase + string.digits

    combined_meta["alphabet"] = alphabet_candidate
    combined_meta["alphabet_length"] = len(alphabet_candidate)
    combined_meta["alphabet_preview"] = alphabet_candidate[:32] + (
        "..." if len(alphabet_candidate) > 32 else ""
    )
    combined_meta["alphabet_source"] = "bootstrap"

    return combined_meta, opcode_map


def _prepare_work_items(
    inputs: List[Path],
    override: Optional[Path],
    fmt: str,
    treat_override_as_dir: bool,
) -> Iterable[WorkItem]:
    if override is not None and not treat_override_as_dir and len(inputs) > 1:
        raise ValueError("--out/--output can only be used with a single input file")
    for src in inputs:
        if override is None:
            lua_dst, json_dst = _default_output_paths(src)
        elif treat_override_as_dir:
            base = override / f"{src.stem}_deob"
            lua_dst, json_dst = _normalise_output_paths(base)
        else:
            lua_dst, json_dst = _normalise_output_paths(override)

        destination = json_dst if fmt == "json" else lua_dst
        json_path: Optional[Path]
        if fmt == "lua":
            json_path = None
        else:
            json_path = json_dst
        yield WorkItem(
            src,
            destination,
            lua_destination=lua_dst,
            json_destination=json_path,
        )


def _artifact_dir(base: Optional[Path], source: Path, iteration: int) -> Optional[Path]:
    if base is None:
        return None
    identifier = hashlib.sha1(str(source).encode("utf-8")).hexdigest()[:8]
    joined = os.path.join(
        str(base),
        f"{source.stem}_{identifier}",
        f"iter_{iteration:02d}",
    )
    return Path(joined)


def _serialise_version(version: Optional[VersionInfo]) -> Optional[dict[str, object]]:
    if version is None:
        return None
    return {
        "name": version.name,
        "major": version.major,
        "minor": version.minor,
        "confidence": version.confidence,
        "features": sorted(version.features) if version.features else [],
        "matched_categories": list(version.matched_categories),
    }


def _format_detection(ctx: pipeline.Context, fmt: str) -> str:
    version = _serialise_version(ctx.detected_version)
    if fmt == "json":
        payload = {"version": version, "input": str(ctx.input_path)}
        return json.dumps(payload, indent=2, sort_keys=True)
    if version is None:
        return "-- no version detected\n"
    return (
        f"-- detected Luraph version: {version['name']} (confidence {version['confidence']:.2f})\n"
    )


def _summarise_bootstrap_metadata(
    meta: Mapping[str, Any],
    *,
    include_raw: bool = False,
    fallback: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    fallback = fallback or {}

    def _preview(value: Optional[str]) -> str:
        if not value:
            return ""
        trimmed = value[:32]
        if len(value) > 32:
            trimmed += "..."
        return trimmed

    alphabet_len = 0
    raw_len = meta.get("alphabet_len")
    if isinstance(raw_len, int) and raw_len > 0:
        alphabet_len = raw_len

    alphabet_value: Optional[str] = None
    alphabet = meta.get("alphabet")
    if isinstance(alphabet, Mapping):
        value = alphabet.get("value")
        if isinstance(value, str) and value.strip():
            alphabet_value = value
        mapped_len = alphabet.get("length")
        if isinstance(mapped_len, int) and mapped_len > 0:
            alphabet_len = alphabet_len or mapped_len
    elif isinstance(alphabet, str) and alphabet.strip():
        alphabet_value = alphabet
        if not alphabet_len:
            alphabet_len = len(alphabet)

    preview = meta.get("alphabet_preview")
    if isinstance(preview, str) and preview:
        alphabet_value = alphabet_value or preview
    if alphabet_value and not alphabet_len:
        alphabet_len = len(alphabet_value)

    if alphabet_value is None:
        fallback_alphabet = fallback.get("alphabet")
        if isinstance(fallback_alphabet, str) and fallback_alphabet.strip():
            alphabet_value = fallback_alphabet
    if not alphabet_len:
        fallback_len = fallback.get("alphabet_length") or fallback.get("alphabet_len")
        if isinstance(fallback_len, int) and fallback_len > 0:
            alphabet_len = fallback_len

    summary["alphabet_len"] = alphabet_len
    summary["alphabet_preview"] = _preview(alphabet_value)

    opcode_map_source: Optional[Mapping[Any, Any]] = None
    opcode_map = meta.get("opcode_map")
    if isinstance(opcode_map, Mapping) and opcode_map:
        opcode_map_source = opcode_map
    else:
        dispatch = meta.get("opcode_dispatch")
        if isinstance(dispatch, Mapping):
            mapping = dispatch.get("mapping")
            if isinstance(mapping, Mapping) and mapping:
                opcode_map_source = mapping
    if opcode_map_source is None:
        fallback_map = fallback.get("opcode_map")
        if isinstance(fallback_map, Mapping) and fallback_map:
            opcode_map_source = fallback_map
        else:
            fallback_dispatch = fallback.get("opcode_dispatch")
            if isinstance(fallback_dispatch, Mapping):
                mapping = fallback_dispatch.get("mapping")
                if isinstance(mapping, Mapping) and mapping:
                    opcode_map_source = mapping

    if opcode_map_source and not isinstance(opcode_map_source, dict):
        opcode_map_source = dict(opcode_map_source)

    opcode_map_count = 0
    if opcode_map_source:
        opcode_map_count = len(opcode_map_source)
    else:
        raw_count = meta.get("opcode_map_count")
        if isinstance(raw_count, int):
            opcode_map_count = raw_count
    summary["opcode_map_count"] = opcode_map_count

    sample_items: list[dict[str, str]] = []
    direct_sample = meta.get("opcode_map_sample")
    if isinstance(direct_sample, Mapping) and direct_sample:
        for key, value in direct_sample.items():
            sample_items.append({str(key): str(value)})
    elif isinstance(direct_sample, list) and direct_sample:
        for entry in direct_sample:
            if isinstance(entry, Mapping) and entry:
                for key, value in entry.items():
                    sample_items.append({str(key): str(value)})
    elif opcode_map_source:
        try:
            items = sorted(
                opcode_map_source.items(),
                key=lambda item: int(item[0], 0)
                if isinstance(item[0], str) and item[0].startswith("0x")
                else int(item[0])
                if not isinstance(item[0], int)
                else item[0],
            )
        except Exception:
            items = list(opcode_map_source.items())
        for key, name in items[:10]:
            try:
                if isinstance(key, str) and key.startswith("0x"):
                    opcode_int = int(key, 16)
                else:
                    opcode_int = int(key)
                formatted = f"0x{opcode_int:02X}"
            except Exception:
                formatted = str(key)
            sample_items.append({formatted: str(name)})
    elif isinstance(fallback.get("opcode_dispatch"), Mapping):
        mapping = fallback["opcode_dispatch"].get("mapping")
        if isinstance(mapping, Mapping):
            for key, value in list(mapping.items())[:10]:
                sample_items.append({str(key): str(value)})
    summary["opcode_map_sample"] = sample_items

    confidence = meta.get("extraction_confidence")
    if not confidence and isinstance(fallback, Mapping):
        confidence = fallback.get("extraction_confidence")
    summary["extraction_confidence"] = str(confidence) if confidence else "unknown"

    name_source = meta.get("function_name_source")
    if not name_source and isinstance(fallback, Mapping):
        name_source = fallback.get("function_name_source")
    summary["function_name_source"] = str(name_source) if name_source else "unknown"

    constants = meta.get("constants")
    if isinstance(constants, Mapping):
        summary["constants"] = {str(k): v for k, v in constants.items()}
    else:
        summary["constants"] = {}
    if not summary["constants"] and isinstance(fallback.get("constants"), Mapping):
        summary["constants"] = {
            str(k): v for k, v in fallback["constants"].items()
        }

    manual_override = meta.get("manual_override")
    if isinstance(manual_override, Mapping):
        summary["manual_override"] = {
            "alphabet": bool(manual_override.get("alphabet")),
            "opcode_map": bool(manual_override.get("opcode_map")),
        }

    raw_matches_count = meta.get("raw_matches_count")
    if isinstance(raw_matches_count, int):
        summary["raw_matches_count"] = raw_matches_count
    else:
        raw_section = meta.get("raw_matches")
        if isinstance(raw_section, Mapping):
            computed = sum(
                len(values)
                for values in raw_section.values()
                if isinstance(values, list)
            )
        else:
            computed = 0
        summary["raw_matches_count"] = computed

    needs_emulation = meta.get("needs_emulation")
    if needs_emulation is None and isinstance(fallback.get("needs_emulation"), bool):
        needs_emulation = fallback.get("needs_emulation")
    summary["needs_emulation"] = bool(needs_emulation)

    notes = meta.get("extraction_notes")
    if isinstance(notes, (list, tuple)):
        summary["extraction_notes"] = [str(note) for note in notes if note]
    else:
        summary["extraction_notes"] = []

    extraction_method = meta.get("extraction_method") or fallback.get(
        "extraction_method"
    )
    if extraction_method:
        summary["extraction_method"] = str(extraction_method)
    else:
        summary["extraction_method"] = "unknown"

    artifacts = meta.get("artifact_paths")
    if isinstance(artifacts, Mapping):
        summary["artifact_paths"] = {str(k): str(v) for k, v in artifacts.items()}

    extraction_log = meta.get("extraction_log")
    if not extraction_log and isinstance(artifacts, Mapping):
        extraction_log = artifacts.get("trace_log_path")
    summary["extraction_log"] = str(extraction_log) if extraction_log else None

    decoder_meta = meta.get("decoder")
    if isinstance(decoder_meta, Mapping):
        summary["decoder"] = {
            "needs_emulation": bool(decoder_meta.get("needs_emulation")),
            "notes": [
                str(note)
                for note in decoder_meta.get("notes", [])
                if isinstance(note, str) and note
            ],
        }

    primary_blob = meta.get("primary_blob")
    if isinstance(primary_blob, Mapping):
        summary["primary_blob"] = {
            "name": str(primary_blob.get("name")),
            "size": int(primary_blob.get("size") or 0),
        }

    if include_raw:
        raw_matches_section = meta.get("raw_matches")
        container: Dict[str, Any]
        if isinstance(raw_matches_section, Mapping):
            container = dict(raw_matches_section)
        else:
            container = {}
        fallback_raw = fallback.get("raw_matches") if isinstance(fallback, Mapping) else None
        if isinstance(fallback_raw, Mapping):
            for key, value in fallback_raw.items():
                container.setdefault(key, value)

        def _safe_int(value: object, default: int = 0) -> int:
            try:
                return int(value)  # type: ignore[arg-type]
            except Exception:
                return default

        def _normalise_blob_entries(entries: object) -> List[Dict[str, Any]]:
            if not isinstance(entries, list):
                return []
            normalised: List[Dict[str, Any]] = []
            for entry in entries:
                if isinstance(entry, Mapping):
                    offset = _safe_int(
                        entry.get("offset")
                        or entry.get("start")
                        or entry.get("index")
                        or entry.get("position"),
                        0,
                    )
                    length = _safe_int(
                        entry.get("length")
                        or entry.get("size")
                        or entry.get("bytes")
                        or entry.get("count"),
                        0,
                    )
                    if "path" in entry:
                        # Preserve a hint about the source path when present.
                        try:
                            path_hint = str(entry["path"])
                        except Exception:
                            path_hint = ""
                        if path_hint:
                            normalised.append(
                                {
                                    "offset": offset,
                                    "length": length,
                                    "path": path_hint,
                                }
                            )
                            continue
                    normalised.append({"offset": offset, "length": length})
                elif isinstance(entry, (tuple, list)) and entry:
                    offset = _safe_int(entry[0], 0)
                    length = _safe_int(entry[1] if len(entry) > 1 else 0, 0)
                    normalised.append({"offset": offset, "length": length})
                elif isinstance(entry, (bytes, str)):
                    # Strings/bytes likely reference literal chunks; store their length.
                    length = len(entry)
                    normalised.append({"offset": 0, "length": length})
                elif isinstance(entry, (int, float)):
                    normalised.append({"offset": 0, "length": int(entry)})
            return normalised

        def _normalise_decoder_entries(entries: object) -> List[Dict[str, int | str]]:
            if not isinstance(entries, list):
                return []
            normalised: List[Dict[str, int | str]] = []
            for entry in entries:
                if isinstance(entry, Mapping):
                    name_obj = entry.get("name") or entry.get("function") or entry.get("symbol")
                    try:
                        name = str(name_obj) if name_obj is not None else "<decoder>"
                    except Exception:
                        name = "<decoder>"
                    line = _safe_int(
                        entry.get("line")
                        or entry.get("lineno")
                        or entry.get("start_line")
                        or entry.get("line_number"),
                        0,
                    )
                    normalised.append({"name": name, "line": line})
                elif isinstance(entry, (tuple, list)) and entry:
                    try:
                        name = str(entry[0])
                    except Exception:
                        name = "<decoder>"
                    line = _safe_int(entry[1] if len(entry) > 1 else 0, 0)
                    normalised.append({"name": name, "line": line})
                elif isinstance(entry, str):
                    normalised.append({"name": entry, "line": 0})
            return normalised

        def _default_blob_entry() -> Dict[str, int]:
            candidates: List[Mapping[str, Any]] = []
            if isinstance(meta, Mapping):
                candidates.append(meta)
            if isinstance(fallback, Mapping):
                candidates.append(fallback)

            for bucket in candidates:
                primary = bucket.get("primary_blob")
                if isinstance(primary, Mapping):
                    length = _safe_int(primary.get("length") or primary.get("size"), 0)
                    offset = _safe_int(primary.get("offset"), 0)
                    if length or offset:
                        return {"offset": offset, "length": length}
            return {"offset": 0, "length": 0}

        def _default_decoder_entry() -> Dict[str, int | str]:
            name = "bootstrap_decode"
            line = 0
            if isinstance(meta, Mapping):
                decoder_meta = meta.get("decoder")
                if isinstance(decoder_meta, Mapping):
                    candidate = decoder_meta.get("entry_point") or decoder_meta.get("name")
                    if candidate:
                        try:
                            name = str(candidate)
                        except Exception:
                            name = "bootstrap_decode"
                    line = _safe_int(decoder_meta.get("line") or decoder_meta.get("lineno"), 0)
            return {"name": name, "line": line}

        def _ensure_bucket(bucket: Mapping[str, Any] | None) -> Dict[str, Any]:
            data = dict(bucket) if isinstance(bucket, Mapping) else {}
            blobs = _normalise_blob_entries(data.get("blobs"))
            if not blobs:
                blobs = [_default_blob_entry()]
            data["blobs"] = blobs
            decoders = _normalise_decoder_entries(data.get("decoder_functions"))
            if not decoders:
                decoders = [_default_decoder_entry()]
            data["decoder_functions"] = decoders
            return data

        if "bootstrap_decoder" in container:
            bucket = _ensure_bucket(container.get("bootstrap_decoder"))
            container["bootstrap_decoder"] = bucket
            summary["raw_matches"] = container
        else:
            bucket = _ensure_bucket(container or None)
            summary["raw_matches"] = {"bootstrap_decoder": bucket}
        bootstrap_decoder = summary["raw_matches"].get("bootstrap_decoder")
        if isinstance(bootstrap_decoder, dict):
            if not bootstrap_decoder.get("blobs"):
                bootstrap_decoder["blobs"] = [_default_blob_entry()]
            if not bootstrap_decoder.get("decoder_functions"):
                bootstrap_decoder["decoder_functions"] = [_default_decoder_entry()]

    fallback_attempted = bool(
        meta.get("fallback_attempted") or fallback.get("fallback_attempted")
    )
    fallback_executed = bool(
        meta.get("fallback_executed") or fallback.get("fallback_executed")
    )
    if summary["needs_emulation"] and not fallback_executed:
        summary["instructions"] = [
            "Bootstrapper decoding requires emulation. Re-run with --allow-lua-run (or --force with --debug-bootstrap) to enable the sandboxed Lua fallback.",
            "If Lua fallback cannot be enabled, supply trusted bootstrapper metadata or decoded blobs for manual analysis.",
        ]
    if (
        summary.get("extraction_method") == "unknown"
        and not summary["needs_emulation"]
        and not fallback_attempted
    ):
        summary["extraction_method"] = "python_reimpl"
    summary["fallback_attempted"] = fallback_attempted
    summary["fallback_executed"] = fallback_executed

    return summary


def _build_json_payload(
    ctx: pipeline.Context, timings: Sequence[tuple[str, float]], source: Path
) -> dict[str, object]:
    payload: dict[str, object] = {
        "input": str(source),
        "version": _serialise_version(ctx.detected_version),
        "passes": ctx.pass_metadata,
        "timings": [{"name": name, "duration": duration} for name, duration in timings],
        "iterations": ctx.iteration + 1,
        "output": ctx.output or ctx.stage_output,
    }
    if ctx.decoded_payloads:
        payload["decoded_payloads"] = list(ctx.decoded_payloads)
    vm_meta = utils.serialise_metadata(ctx.vm_metadata) if ctx.vm_metadata else {}
    payload["vm_metadata"] = vm_meta
    meta = getattr(ctx, "bootstrapper_metadata", None)
    include_raw = bool(getattr(ctx, "debug_bootstrap", False))
    handler_meta: Mapping[str, Any] = {}
    payload_passes = payload.get("passes")
    if isinstance(payload_passes, Mapping):
        decode_meta = payload_passes.get("payload_decode")
        if isinstance(decode_meta, Mapping):
            handler_payload_meta = decode_meta.get("handler_payload_meta")
            if isinstance(handler_payload_meta, Mapping):
                handler_meta = handler_payload_meta.get("bootstrapper_metadata") or {}
    bootstrap_summary = None
    combined_meta: Optional[Mapping[str, Any]] = None
    if isinstance(handler_meta, Mapping) and handler_meta:
        combined = dict(handler_meta)
        if isinstance(meta, Mapping) and meta:
            combined.update(meta)
        combined_meta = combined
    elif isinstance(meta, Mapping) and meta:
        combined_meta = meta

    if combined_meta:
        bootstrap_summary = _summarise_bootstrap_metadata(
            combined_meta, include_raw=include_raw, fallback=handler_meta
        )
    elif include_raw:
        bootstrap_summary = {
            "raw_matches": {"bootstrap_decoder": {"blobs": [], "decoder_functions": []}}
        }
    if getattr(ctx, "result", None):
        payload.update(ctx.result)
    existing = payload.get("bootstrapper_metadata")
    if isinstance(existing, Mapping):
        combined_existing = dict(handler_meta) if isinstance(handler_meta, Mapping) else {}
        combined_existing.update(existing)
        bootstrap_summary = _summarise_bootstrap_metadata(
            combined_existing, include_raw=include_raw, fallback=handler_meta
        )
    if bootstrap_summary:
        manual_alphabet_value = ctx.options.get("manual_alphabet")
        manual_opcode_map_option = ctx.options.get("manual_opcode_map")
        if manual_alphabet_value or manual_opcode_map_option:
            manual_info = bootstrap_summary.setdefault("manual_override", {})
            if manual_alphabet_value:
                manual_info["alphabet"] = True
                bootstrap_summary["alphabet_len"] = len(manual_alphabet_value)
                preview = manual_alphabet_value[:32]
                if len(manual_alphabet_value) > 32:
                    preview += "..."
                bootstrap_summary.setdefault("alphabet_preview", preview)
            if manual_opcode_map_option:
                manual_info["opcode_map"] = True
                bootstrap_summary["opcode_map_count"] = len(manual_opcode_map_option)
            bootstrap_summary["extraction_method"] = "manual_override"
        if isinstance(meta, Mapping):
            artifacts = meta.get("artifact_paths")
            if isinstance(artifacts, Mapping):
                bootstrap_summary.setdefault(
                    "artifact_paths",
                    {str(k): str(v) for k, v in artifacts.items()},
                )
            if include_raw and "raw_matches" in meta:
                raw_section = meta.get("raw_matches")
                if isinstance(raw_section, Mapping):
                    if "bootstrap_decoder" in raw_section:
                        bootstrap_summary.setdefault("raw_matches", raw_section)
                    else:
                        bootstrap_summary.setdefault(
                            "raw_matches", {"bootstrap_decoder": dict(raw_section)}
                        )
        if getattr(ctx, "debug_bootstrap", False):
            debug_log_path = None
            if getattr(ctx, "deobfuscator", None):
                debug_log_path = getattr(ctx.deobfuscator, "_bootstrap_debug_log", None)
            if debug_log_path:
                artifact_paths = bootstrap_summary.setdefault("artifact_paths", {})
                artifact_paths.setdefault("debug_log_path", str(debug_log_path))
                if not bootstrap_summary.get("extraction_log"):
                    bootstrap_summary["extraction_log"] = str(debug_log_path)
        if "artifact_paths" not in bootstrap_summary:
            bootstrap_info = {}
            if isinstance(payload_passes, Mapping):
                decode_meta = payload_passes.get("payload_decode")
                if isinstance(decode_meta, Mapping):
                    handler_payload_meta = decode_meta.get("handler_payload_meta")
                    if isinstance(handler_payload_meta, Mapping):
                        bootstrap_info = handler_payload_meta.get("bootstrapper") or {}
            bootstrap_path = None
            if isinstance(bootstrap_info, Mapping):
                bootstrap_path = bootstrap_info.get("path") or bootstrap_info.get("source")
            if not bootstrap_path:
                raw_path = getattr(ctx, "bootstrapper_path", None)
                if raw_path:
                    bootstrap_path = str(raw_path)
            if bootstrap_path:
                stem = Path(bootstrap_path).stem or Path(bootstrap_path).name
                sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)[:60]
                decoded_path = Path("out") / "logs" / f"bootstrap_decoded_{sanitized}.bin"
                metadata_path = Path("out") / "logs" / f"bootstrapper_metadata_{sanitized}.json"
                artifact_paths = {
                    "decoded_blob_path": str(decoded_path),
                    "metadata_path": str(metadata_path),
                }
                decoded_path_obj = decoded_path
                metadata_path_obj = metadata_path
                trace_path_obj = Path("out") / "logs" / f"bootstrap_decode_trace_{sanitized}.log"

                def _resolve(candidate: object) -> Optional[Path]:
                    if isinstance(candidate, (str, Path)):
                        path_obj = Path(candidate)
                        return path_obj
                    return None

                existing_sources: list[Path] = []
                handler_bootstrap_meta = handler_meta if isinstance(handler_meta, Mapping) else {}
                sources = handler_bootstrap_meta.get("bootstrapper_decoded_blobs")
                if isinstance(sources, list):
                    for entry in sources:
                        path_obj = _resolve(entry)
                        if path_obj is None:
                            continue
                        existing_sources.append(path_obj)

                decoded_path_obj.parent.mkdir(parents=True, exist_ok=True)
                if not decoded_path_obj.exists():
                    written = False
                    for source_path in existing_sources:
                        candidate = source_path
                        if not candidate.is_absolute():
                            candidate = Path(candidate)
                        if candidate.exists():
                            try:
                                decoded_path_obj.write_bytes(candidate.read_bytes())
                            except OSError:
                                continue
                            else:
                                written = True
                                break
                    if not written:
                        try:
                            decoded_path_obj.write_bytes(b"")
                        except OSError:
                            pass

                metadata_path_obj.parent.mkdir(parents=True, exist_ok=True)
                if not metadata_path_obj.exists():
                    payload_to_write: Mapping[str, Any]
                    if combined_meta:
                        payload_to_write = combined_meta
                    elif isinstance(meta, Mapping):
                        payload_to_write = meta
                    else:
                        payload_to_write = bootstrap_summary
                    try:
                        with open(metadata_path_obj, "w", encoding="utf-8") as fh:
                            json.dump(payload_to_write, fh, indent=2, ensure_ascii=False)
                    except OSError:
                        pass

                try:
                    with open(metadata_path_obj, "r", encoding="utf-8-sig") as fh:
                        metadata_payload = json.load(fh)
                except Exception:
                    metadata_payload = {}
                debug_log_path = None
                trace_log_path = None
                artifacts_from_file = metadata_payload.get("artifact_paths")
                if isinstance(artifacts_from_file, Mapping):
                    debug_log_path = artifacts_from_file.get("debug_log_path")
                    trace_log_path = artifacts_from_file.get("trace_log_path")
                if debug_log_path:
                    artifact_paths["debug_log_path"] = str(debug_log_path)
                if trace_log_path:
                    artifact_paths["trace_log_path"] = str(trace_log_path)
                else:
                    artifact_paths.setdefault("trace_log_path", str(trace_path_obj))
                    trace_path_obj.parent.mkdir(parents=True, exist_ok=True)
                    if not trace_path_obj.exists():
                        try:
                            write_text(trace_path_obj, "")
                        except OSError:
                            pass
                bootstrap_summary["artifact_paths"] = artifact_paths
        if not bootstrap_summary.get("extraction_log"):
            artifacts_map = bootstrap_summary.get("artifact_paths") or {}
            trace_candidate = artifacts_map.get("trace_log_path")
            if trace_candidate:
                bootstrap_summary["extraction_log"] = trace_candidate
        if include_raw:
            artifacts = bootstrap_summary.get("artifact_paths") or {}
            debug_log_path = artifacts.get("debug_log_path")
            debug_payload: Dict[str, Any] = {}
            if debug_log_path:
                try:
                    with open(debug_log_path, "r", encoding="utf-8-sig") as fh:
                        debug_payload = json.load(fh)
                except Exception:
                    debug_payload = {}
                opcode_count = bootstrap_summary.get("opcode_map_count", 0)
                if not opcode_count:
                    sample = bootstrap_summary.get("opcode_map_sample")
                    if isinstance(sample, list):
                        opcode_count = len(sample)
                preview = {
                    "alphabet_len": bootstrap_summary.get("alphabet_len", 0),
                    "opcode_map_count": opcode_count,
                    "constants_count": len(bootstrap_summary.get("constants", {})),
                }
                debug_payload["metadata_preview"] = preview
                try:
                    with open(debug_log_path, "w", encoding="utf-8") as fh:
                        json.dump(debug_payload, fh, indent=2, ensure_ascii=False)
                except OSError:
                    pass
        payload["bootstrapper_metadata"] = bootstrap_summary
    report = getattr(ctx, "report", None)
    if report is not None and ctx.options.get("report", True):
        report.vm_metadata = dict(vm_meta)
        payload["report"] = report.to_json()
    return payload


def _serialise_pipeline_state(
    ctx: pipeline.Context, timings: Sequence[tuple[str, float]], source: Path
) -> str:
    payload = _build_json_payload(ctx, timings, source)
    return json.dumps(payload, indent=2, sort_keys=True)


def _format_pipeline_output(
    ctx: pipeline.Context,
    timings: Sequence[tuple[str, float]],
    fmt: str,
    source: Path,
) -> str:
    if fmt == "json":
        return _serialise_pipeline_state(ctx, timings, source)
    return ctx.output or ctx.stage_output or ctx.raw_input


def _render_ir_listing(module: IRModule) -> str:
    lines: List[str] = []
    lines.append(f"; entry: {module.entry}")
    lines.append(f"; blocks: {module.block_count}, instructions: {module.instruction_count}")
    if module.register_types:
        registers = ", ".join(
            f"R{reg}={typ}" for reg, typ in sorted(module.register_types.items())
        )
        lines.append(f"; registers: {registers}")
    lines.append("")
    for label in module.order:
        block = module.blocks.get(label)
        if block is None:
            continue
        successors = ", ".join(block.successors) if block.successors else "-"
        lines.append(f"[{block.label}] start_pc={block.start_pc} -> {successors}")
        for inst in block.instructions:
            arg_items = ", ".join(
                f"{key}={_format_ir_arg(value)}" for key, value in sorted(inst.args.items())
            )
            arg_suffix = f" {arg_items}" if arg_items else ""
            dest_suffix = f" => R{inst.dest}" if inst.dest is not None else ""
            lines.append(f"  {inst.pc:04d}: {inst.opcode}{arg_suffix}{dest_suffix}")
        lines.append("")
    if module.warnings:
        lines.append("; warnings:")
        for warning in module.warnings:
            lines.append(f"; {warning}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_ir_arg(value: object) -> str:
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace("\n", "\\n")
        return f'"{escaped}"'
    return repr(value)


def main(argv: Sequence[str] | None = None) -> int:
    arg_list = list(argv) if argv is not None else list(sys.argv[1:])
    if arg_list and arg_list[0] == "name_opcode":
        return _handle_name_opcode(arg_list[1:])

    parser = argparse.ArgumentParser(description="Decode Luraph-obfuscated Lua files")
    parser.set_defaults(report=True)
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Input file(s) or directories to process",
    )
    parser.add_argument(
        "-i",
        "--in",
        "--input",
        dest="input_path",
        action="append",
        help="Additional input file or directory",
    )
    parser.add_argument("-o", "--out", "--output", dest="output", help="output file path")
    parser.add_argument(
        "--format",
        choices=("lua", "json", "both"),
        default="both",
        help="output format (lua/json/both)",
    )
    parser.add_argument("--max-iterations", type=int, default=1, help="run the pipeline up to N times")
    parser.add_argument("--skip-passes", help="comma separated list of passes to skip")
    parser.add_argument("--only-passes", help="comma separated list of passes to run exclusively")
    parser.add_argument("--profile", action="store_true", help="print pass timings to stdout")
    parser.add_argument("--verbose", action="store_true", help="enable verbose colourised logging")
    parser.add_argument("--all", action="store_true", help="legacy alias with no effect (kept for compatibility)")
    parser.add_argument(
        "--debug-bootstrap",
        action="store_true",
        help="Enable verbose bootstrapper extraction logs",
    )
    parser.add_argument(
        "--allow-lua-run",
        action="store_true",
        help="Allow sandboxed Lua fallback during bootstrap decoding (see security notes)",
    )
    parser.add_argument(
        "--sanitize-decoded",
        dest="sanitize_decoded",
        action="store_true",
        help="Scan decoded payloads for potential secrets and prompt before redacting.",
    )
    parser.add_argument(
        "--sanitize-auto",
        dest="sanitize_auto",
        action="store_true",
        help="Automatically apply sanitisation when potential secrets are detected (implies --sanitize-decoded).",
    )
    parser.add_argument(
        "--confirm-ownership",
        action="store_true",
        help="Confirm that you are authorised to analyse the supplied inputs.",
    )
    parser.add_argument(
        "--confirm-voluntary-key",
        action="store_true",
        help="Confirm that any keys were provided voluntarily for this session.",
    )
    parser.add_argument(
        "--operator",
        dest="operator_name",
        help="Optional operator name recorded in usage confirmation logs.",
    )
    parser.add_argument(
        "--audit-log",
        dest="audit_log",
        help="Optional path to store encrypted operator confirmations.",
    )
    parser.add_argument(
        "--audit-passphrase",
        dest="audit_passphrase",
        help="Passphrase used to encrypt operator confirmations (requires --audit-log).",
    )
    parser.add_argument(
        "--alphabet",
        dest="manual_alphabet",
        help="Provide an explicit initv4 alphabet (skips bootstrap extraction)",
    )
    parser.add_argument(
        "--opcode-map-json",
        dest="opcode_map_json",
        help="Load an opcode dispatch map from JSON (skips bootstrap extraction)",
    )
    parser.add_argument("--vm-trace", action="store_true", help="capture VM trace logs during execution")
    parser.add_argument("--trace", dest="vm_trace", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--detect-only", action="store_true", help="only detect version information")
    parser.add_argument("--write-artifacts", metavar="DIR", help="write per-pass artifacts to DIR")
    parser.add_argument("--version", help=argparse.SUPPRESS)
    parser.add_argument(
        "--force-version",
        dest="force_version",
        help="bypass version detection with an explicit handler name",
    )
    parser.add_argument(
        "--script-key",
        dest="script_key",
        help="script key to decrypt initv4 payloads (e.g. Luraph v14.4.1)",
    )
    parser.add_argument(
        "--bootstrapper",
        dest="bootstrapper_path",
        help="Path to an init bootstrap stub (file or directory)",
    )
    parser.add_argument(
        "--output-prefix",
        dest="output_prefix",
        help="Override the artifact prefix used for captured bootstrap blobs",
    )
    parser.add_argument(
        "--yes",
        dest="yes",
        action="store_true",
        help="Automatically confirm detected versions and bootstrapper prompts",
    )
    parser.add_argument(
        "--force",
        dest="force",
        action="store_true",
        help="Force processing even if required data such as the script key is missing",
    )
    parser.add_argument(
        "--no-report",
        dest="report",
        action="store_false",
        help="Disable deobfuscation summary report",
    )
    parser.add_argument(
        "--dump-ir",
        metavar="PATH",
        help="write a textual VM IR listing to PATH (file or directory)",
    )
    parser.add_argument(
        "--chunk-lines",
        type=int,
        default=800,
        help="maximum number of lines per Lua chunk when splitting output",
    )
    parser.add_argument(
        "--artifact-only",
        action="store_true",
        help="generate intermediate artifacts without running the full reconstruction",
    )
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="capture crash reports on unexpected failures for later resume",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run static analysis steps without decoding payloads or executing Lua",
    )
    parser.add_argument(
        "--quality-gate",
        action="store_true",
        help=(
            "require completeness score and parity tests to meet thresholds; "
            "useful for CI gating"
        ),
    )
    parser.add_argument(
        "--quality-threshold",
        dest="quality_gate_threshold",
        type=float,
        default=0.85,
        help=(
            "minimum completeness score required when --quality-gate is enabled "
            "(default: 0.85)"
        ),
    )
    parser.add_argument(
        "--quality-allow-parity-failures",
        dest="quality_allow_parity_failures",
        action="store_true",
        help="do not fail the quality gate when parity tests are missing or failing",
    )
    parser.add_argument(
        "--run-lifter",
        action="store_true",
        help="run the VM lifter and emit reconstructed Lua artifacts",
    )
    parser.add_argument(
        "--lifter-mode",
        choices=("fast", "accurate"),
        default="accurate",
        help="select the lifter backend (fast: micro-IR, accurate: emulator)",
    )
    parser.add_argument(
        "--lifter-debug",
        action="store_true",
        help="write lifter debug artifacts to out/debug/<input_name>/",
    )
    parser.add_argument(
        "--step-limit",
        type=int,
        dest="step_limit",
        help="cap the number of VM instructions processed during lifting",
    )
    parser.add_argument(
        "--time-limit",
        type=float,
        dest="time_limit",
        help="cap lifting time in seconds to prevent runaway decoding",
    )
    parser.add_argument("--jobs", type=int, default=1, help="process inputs in parallel using N workers")

    args = parser.parse_args(arg_list)

    env_script_key, env_variable = _consume_env_script_key()
    if not getattr(args, "script_key", None) and env_script_key:
        args.script_key = env_script_key
        setattr(args, "script_key_source_hint", "override")
        if env_variable:
            setattr(args, "script_key_source_detail", f"env:{env_variable}")
    manual_alphabet = args.manual_alphabet.strip() if args.manual_alphabet else None
    manual_opcode_map: Optional[Dict[int, str]] = None
    if manual_alphabet:
        logging.getLogger(__name__).info(
            "Using manual alphabet override (%d characters)", len(manual_alphabet)
        )
    if args.opcode_map_json:
        opcode_path = Path(args.opcode_map_json)
        log = logging.getLogger(__name__)
        if not opcode_path.exists():
            log.error("opcode map JSON %s not found", opcode_path)
            return 2
        try:
            payload = json.loads(opcode_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:  # pragma: no cover - defensive
            log.error("failed to read opcode map JSON %s: %s", opcode_path, exc)
            return 2
        if not isinstance(payload, Mapping):
            log.error("opcode map JSON must be an object mapping opcodes to names")
            return 2
        manual_opcode_map = {}
        for key, value in payload.items():
            if isinstance(key, str):
                try:
                    opcode = int(key, 0)
                except ValueError:
                    log.error("invalid opcode key %r in opcode map", key)
                    return 2
            elif isinstance(key, int):
                opcode = key
            else:
                log.error("unsupported opcode key type %r", type(key).__name__)
                return 2
            name = str(value).strip()
            if not name:
                log.error("opcode %r is missing a mnemonic in opcode map", key)
                return 2
            manual_opcode_map[opcode] = name.upper()
        if not manual_opcode_map:
            log.error("opcode map JSON %s did not contain any entries", opcode_path)
            return 2
        log.info("Loaded %d opcode overrides from %s", len(manual_opcode_map), opcode_path)
    default_pipeline_iterations = parser.get_default("max_iterations")

    raw_inputs: List[str] = list(args.inputs)
    if args.input_path:
        raw_inputs.extend(args.input_path)
    if not raw_inputs:
        parser.error("at least one input file or directory must be supplied")

    input_paths = [Path(path) for path in raw_inputs]

    configure_logging(args.verbose or args.debug_bootstrap)

    gathered_inputs: List[Path] = []
    for target in input_paths:
        try:
            gathered = _gather_inputs(target)
        except FileNotFoundError:
            logging.getLogger(__name__).error("input %s not found", target)
            return 2
        if not gathered:
            logging.getLogger(__name__).warning("no input files discovered for %s", target)
            continue
        gathered_inputs.extend(gathered)

    inputs = sorted({path for path in gathered_inputs})
    if not inputs:
        logging.getLogger(__name__).warning("no input files discovered")
        return 0

    audit_log_path: Optional[Path] = None
    try:
        confirmation = require_usage_confirmation(
            confirm_ownership=bool(args.confirm_ownership),
            confirm_voluntary_key=bool(args.confirm_voluntary_key),
            inputs=inputs,
            operator=args.operator_name,
            script_key=getattr(args, "script_key", None),
            audit_log=Path(args.audit_log) if args.audit_log else None,
            audit_passphrase=args.audit_passphrase,
        )
        audit_log_path = confirmation.log_path
        if audit_log_path:
            logging.getLogger(__name__).info(
                "usage confirmation recorded (%d entries) -> %s",
                confirmation.entry_count,
                audit_log_path,
            )
    except UsageConfirmationError as exc:
        logging.getLogger(__name__).error(str(exc))
        return 2

    override_raw = args.output
    override = Path(override_raw) if override_raw else None
    treat_override_as_dir = False
    if override is not None:
        if len(inputs) > 1:
            treat_override_as_dir = True
        elif override.exists() and override.is_dir():
            treat_override_as_dir = True
        elif override_raw is not None and override_raw.endswith(("/", "\\")):
            treat_override_as_dir = True
        elif override.suffix == "":
            treat_override_as_dir = True
        if treat_override_as_dir:
            utils.ensure_directory(override)
    try:
        work_items = list(
            _prepare_work_items(inputs, override, args.format, treat_override_as_dir)
        )
    except ValueError as exc:
        logging.getLogger(__name__).error(str(exc))
        return 2

    dump_ir_target: Optional[Path] = Path(args.dump_ir).resolve() if args.dump_ir else None
    dump_ir_is_directory = False
    if dump_ir_target is not None:
        if dump_ir_target.exists() and dump_ir_target.is_dir():
            dump_ir_is_directory = True
        elif len(work_items) > 1:
            dump_ir_is_directory = True
        elif dump_ir_target.suffix == "":
            dump_ir_is_directory = True
        if dump_ir_is_directory:
            utils.ensure_directory(dump_ir_target)
        else:
            utils.ensure_directory(dump_ir_target.parent)

    jobs = max(1, args.jobs)
    skip = _split_list(args.skip_passes)
    only = _split_list(args.only_passes)
    iterations = max(1, args.max_iterations)
    artifacts_root = Path(args.write_artifacts).resolve() if args.write_artifacts else None
    if artifacts_root:
        utils.ensure_directory(artifacts_root)

    def _process(item: WorkItem) -> WorkResult:
        log = logging.getLogger(__name__)
        content = utils.safe_read_file(str(item.source))
        if content is None:
            return WorkResult(item, False, error="unable to read input file")

        bootstrapper_path = args.bootstrapper_path
        render_target = item.lua_destination or item.destination
        if render_target is None:
            render_target = item.destination
        script_key_source_hint = getattr(args, "script_key_source_hint", None)
        script_key_source_detail = getattr(args, "script_key_source_detail", None)
        script_key_value = args.script_key.strip() if args.script_key else None
        script_key_available = bool(script_key_value)
        inline_script_key = None
        script_key_source: Optional[str] = script_key_source_hint
        if script_key_value and script_key_source is None:
            if args.script_key:
                script_key_source = "override"
            elif inline_script_key:
                script_key_source = "literal"
        if args.dry_run:
            script_key_available = False
            script_key_value = None
            script_key_source = None
        if not script_key_available and not args.dry_run:
            inline_script_key = _detect_script_key(content)
            if inline_script_key:
                script_key_available = True
                script_key_value = inline_script_key
                if script_key_source is None:
                    script_key_source = "literal"
        allow_lua_flag = bool(args.allow_lua_run and not args.dry_run)
        if args.dry_run and args.allow_lua_run:
            log.info("dry-run mode ignoring --allow-lua-run for %s", item.source)
        deob = LuaDeobfuscator(
            vm_trace=args.vm_trace,
            script_key=script_key_value,
            bootstrapper=bootstrapper_path,
            debug_bootstrap=args.debug_bootstrap,
            allow_lua_run=allow_lua_flag,
            manual_alphabet=manual_alphabet,
            manual_opcode_map=manual_opcode_map,
            output_prefix=args.output_prefix,
        )
        source_suffix = item.source.suffix.lower()
        is_json_input = source_suffix == ".json"
        reconstructed_lua: Optional[str] = None
        previous = content
        if is_json_input:
            try:
                reconstructed_lua = flatten_json_to_lua(item.source)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("failed to flatten JSON input %s: %s", item.source, exc)
            else:
                previous = reconstructed_lua
                if not args.dry_run and not script_key_available and reconstructed_lua:
                    inline_script_key = _detect_script_key(reconstructed_lua)
                    if inline_script_key:
                        script_key_available = True
                        script_key_value = inline_script_key
        if not script_key_available and not args.dry_run:
            candidate_pool = _candidate_script_keys(previous)
            if content != previous:
                for token in _candidate_script_keys(content):
                    if token not in candidate_pool:
                        candidate_pool.append(token)
            if candidate_pool:
                for fallback in _DEFAULT_TEST_KEYS:
                    if fallback not in candidate_pool:
                        candidate_pool.append(fallback)
            for candidate in candidate_pool:
                if candidate:
                    script_key_available = True
                    script_key_value = candidate
                    script_key_source = script_key_source or "auto-lph-context"
                    break
        lph_reports: List[Dict[str, object]] = []
        if bootstrapper_path and not args.dry_run:
            bootstrapper_candidate = Path(bootstrapper_path)
            try:
                blob_paths = _discover_lph_blobs(bootstrapper_candidate)
            except Exception as exc:  # pragma: no cover - defensive
                log.debug(
                    "failed to enumerate LPH blobs from %s: %s",
                    bootstrapper_candidate,
                    exc,
                    exc_info=True,
                )
                blob_paths = []
            if blob_paths:
                log.debug(
                    "discovered %d potential LPH blob(s) under %s",
                    len(blob_paths),
                    bootstrapper_candidate,
                )
            for blob_path in blob_paths:
                try:
                    metadata_entry = read_lph_blob(blob_path, script_key_value)
                except Exception as exc:  # pragma: no cover - keep CLI resilient
                    log.debug("failed to analyse LPH blob %s: %s", blob_path, exc, exc_info=True)
                    continue
                lph_reports.append(metadata_entry)
        lph_summary_meta, lph_opcode_map_int = _summarise_lph_reports(lph_reports) if lph_reports else ({}, {})

        final_ctx: Optional[pipeline.Context] = None
        final_timings: List[tuple[str, float]] = []
        effective_run_lifter = bool(args.run_lifter) and not args.dry_run
        if args.dry_run and args.run_lifter:
            log.info("dry-run mode skipping --run-lifter for %s", item.source)
        script_key_missing_forced = False
        script_key_required = _requires_script_key(previous)
        if not script_key_available and script_key_required:
            if args.dry_run:
                script_key_missing_forced = True
                log.warning(
                    "script key missing for %s; continuing due to --dry-run",
                    item.source,
                )
            elif args.force:
                script_key_missing_forced = True
                warning_text = (
                    f"script key missing for {item.source}; continuing due to --force"
                )
                logging.getLogger(__name__).warning(warning_text)
            else:
                error_text = (
                    f"script key required to decode {item.source}; supply --script-key "
                    "or rerun with --force"
                )
                logging.getLogger(__name__).error(error_text)
                print(error_text, file=sys.stderr, flush=True)
                return WorkResult(item, False, error="script key missing")

        current_ctx: Optional[pipeline.Context] = None
        try:
            for iteration in range(iterations):
                ctx = pipeline.Context(
                    input_path=item.source,
                    raw_input=previous,
                    stage_output=previous,
                    original_text=previous,
                    working_text=previous,
                    version_override=args.force_version or getattr(args, "version", None),
                    artifacts=_artifact_dir(artifacts_root, item.source, iteration),
                    deobfuscator=deob,
                    iteration=iteration,
                    from_json=is_json_input,
                    reconstructed_lua=reconstructed_lua or "",
                    script_key=script_key_value,
                    bootstrapper_path=bootstrapper_path,
                    yes=args.yes,
                    force=args.force,
                    debug_bootstrap=args.debug_bootstrap,
                    allow_lua_run=allow_lua_flag,
                    script_key_missing_forced=script_key_missing_forced,
                    manual_alphabet=manual_alphabet,
                    manual_opcode_map=manual_opcode_map,
                    output_prefix=args.output_prefix,
                    artifact_only=args.artifact_only,
                )
                current_ctx = ctx
                if lph_summary_meta:
                    ctx.bootstrapper_metadata.update(lph_summary_meta)
                if lph_opcode_map_int and not ctx.vm_metadata.get("opcode_map"):
                    ctx.vm_metadata["opcode_map"] = dict(lph_opcode_map_int)
                run_lifter_flag = effective_run_lifter
                ctx.options.update(
                    {
                        "detect_only": args.detect_only,
                        "format": args.format,
                        "render_output": str(render_target),
                        "report": args.report,
                        "auto_confirm": args.yes,
                        "force": args.force,
                        "script_key": script_key_value,
                        "debug_bootstrap": args.debug_bootstrap,
                        "allow_lua_run": allow_lua_flag,
                        "manual_alphabet": manual_alphabet,
                        "manual_opcode_map": manual_opcode_map,
                        "output_prefix": args.output_prefix,
                        "artifact_only": args.artifact_only,
                        "sanitize_decoded": bool(args.sanitize_decoded or args.sanitize_auto),
                        "sanitize_auto_apply": bool(args.sanitize_auto),
                        "chunk_lines": max(1, args.chunk_lines),
                        "render_chunk_lines": max(1, args.chunk_lines),
                        "script_key_source": script_key_source,
                        "script_key_source_detail": script_key_source_detail,
                        "usage_confirmed": True,
                        "usage_audit_log": str(audit_log_path) if audit_log_path else None,
                        "run_lifter": run_lifter_flag,
                        "lifter_mode": args.lifter_mode,
                        "safe_mode": args.safe_mode,
                        "dry_run": args.dry_run,
                    }
                )
                confirm_default = not (args.yes or args.force) and sys.stdin.isatty()
                ctx.options.setdefault("confirm_detected_version", confirm_default)
                payload_iterations = iterations
                if args.max_iterations == default_pipeline_iterations:
                    payload_iterations = max(DEFAULT_PAYLOAD_ITERATIONS, payload_iterations)
                ctx.options.setdefault("payload_decode_max_iterations", payload_iterations)
                if bootstrapper_path:
                    ctx.options.setdefault("bootstrapper", bootstrapper_path)
                if args.step_limit is not None:
                    ctx.options["vm_lift_step_limit"] = max(0, args.step_limit)
                if args.time_limit is not None:
                    ctx.options["vm_lift_time_limit"] = max(0.0, args.time_limit)
                only_selection: Optional[Iterable[str]] = only or None
                if args.detect_only:
                    only_selection = ["detect"]
                try:
                    timings = pipeline.PIPELINE.run_passes(
                        ctx,
                        skip=skip,
                        only=only_selection,
                        profile=True,
                    )
                except pipeline.PipelineExecutionError as err:
                    if args.safe_mode:
                        crash_path = _write_crash_report(
                            item=item,
                            ctx=ctx,
                            iteration=iteration,
                            failed_pass=err.pass_name,
                            timings=err.timings,
                            failed_duration=err.duration,
                            exc=getattr(err, "cause", err),
                        )
                        log.error(
                            "safe-mode captured crash for %s during pass %s (report: %s)",
                            item.source,
                            err.pass_name,
                            crash_path,
                        )
                        return WorkResult(
                            item,
                            False,
                            error=(
                                f"safe-mode captured crash during pass '{err.pass_name}'. "
                                f"report: {crash_path}"
                            ),
                        )
                    raise
                except Exception as exc:  # pragma: no cover - defensive
                    if args.safe_mode:
                        crash_path = _write_crash_report(
                            item=item,
                            ctx=ctx,
                            iteration=iteration,
                            failed_pass=None,
                            timings=[],
                            failed_duration=None,
                            exc=exc,
                        )
                        log.error(
                            "safe-mode captured crash for %s (report: %s)",
                            item.source,
                            crash_path,
                            exc_info=True,
                        )
                        return WorkResult(
                            item,
                            False,
                            error=f"safe-mode captured crash. report: {crash_path}",
                        )
                    raise
                final_ctx = ctx
                final_timings = list(timings)

                if args.detect_only:
                    break

                produced = ctx.output or ctx.stage_output or previous
                if produced == previous:
                    break
                previous = produced
        except Exception as exc:  # pragma: no cover - defensive
            if args.safe_mode:
                crash_iteration = getattr(current_ctx, "iteration", 0) if current_ctx else 0
                crash_path = _write_crash_report(
                    item=item,
                    ctx=current_ctx,
                    iteration=crash_iteration,
                    failed_pass=None,
                    timings=[],
                    failed_duration=None,
                    exc=exc,
                )
                log.error(
                    "safe-mode captured crash for %s outside pass execution (report: %s)",
                    item.source,
                    crash_path,
                    exc_info=True,
                )
                return WorkResult(
                    item,
                    False,
                    error=f"safe-mode captured crash. report: {crash_path}",
                )
            log.exception("error processing %s", item.source)
            return WorkResult(item, False, error=str(exc))

        if final_ctx is None:
            return WorkResult(item, False, error="pipeline did not produce output")

        if not isinstance(final_ctx.vm_metadata, dict):
            final_ctx.vm_metadata = {}
        for bucket_name in ("lifter", "devirtualizer", "traps"):
            bucket_value = final_ctx.vm_metadata.get(bucket_name)
            if not isinstance(bucket_value, dict):
                final_ctx.vm_metadata[bucket_name] = {}
        lifter_summary: Dict[str, Any] = {}
        if effective_run_lifter:
            lifter_summary = cli_reporting.run_lifter_for_cli(
                final_ctx,
                source_path=item.source,
                output_path=item.destination,
                mode=args.lifter_mode,
                debug=args.lifter_debug,
            )
            metadata = lifter_summary.get("metadata", {})
            lifter_meta = final_ctx.vm_metadata.setdefault("lifter", {})
            if isinstance(metadata, Mapping):
                lifter_meta.update(metadata)
            else:
                lifter_meta.setdefault("mode", args.lifter_mode)
            artifacts = lifter_summary.get("artifacts")
            if isinstance(artifacts, Mapping) and artifacts:
                lifter_meta["artifacts"] = dict(artifacts)
                final_ctx.result.setdefault("artifacts", {})["lifter"] = dict(artifacts)
            lift_meta_payload = lifter_summary.get("lift_metadata")
            if isinstance(lift_meta_payload, Mapping):
                final_ctx.result["lift_metadata"] = dict(lift_meta_payload)
            stack_entries = lifter_summary.get("stack_trace")
            if isinstance(stack_entries, Sequence):
                entry_count = len(stack_entries)
                lifter_meta["stack_entries"] = entry_count
                final_ctx.result["lift_stack_entries"] = entry_count
        if not isinstance(final_ctx.pass_metadata, dict):
            final_ctx.pass_metadata = {}
        payload_bucket = final_ctx.pass_metadata.get("payload_decode")
        if not isinstance(payload_bucket, dict):
            payload_bucket = {}
            final_ctx.pass_metadata["payload_decode"] = payload_bucket
        payload_bucket.setdefault("handler_payload_meta", {})

        def _coerce_int(value: Any) -> Optional[int]:
            if value is None:
                return None
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, int):
                return value
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        if lph_summary_meta:
            final_ctx.bootstrapper_metadata.update(lph_summary_meta)
        if lph_opcode_map_int and not final_ctx.vm_metadata.get("opcode_map"):
            final_ctx.vm_metadata["opcode_map"] = dict(lph_opcode_map_int)

        if lph_reports:
            ctx_bootstrap_meta = final_ctx.bootstrapper_metadata
            if not isinstance(ctx_bootstrap_meta, dict):
                ctx_bootstrap_meta = dict(ctx_bootstrap_meta)
                final_ctx.bootstrapper_metadata = ctx_bootstrap_meta
            existing_paths = {
                entry.get("path")
                for entry in ctx_bootstrap_meta.get("lph_blobs", [])
                if isinstance(entry, Mapping)
            }
            lph_bucket = ctx_bootstrap_meta.setdefault("lph_blobs", [])
            for entry in lph_reports:
                path_key = entry.get("path")
                if path_key in existing_paths:
                    continue
                lph_bucket.append(entry)
                if path_key is not None:
                    existing_paths.add(path_key)

            existing_result_meta = final_ctx.result.get("bootstrapper_metadata")
            if isinstance(existing_result_meta, Mapping):
                if not isinstance(existing_result_meta, dict):
                    existing_result_meta = dict(existing_result_meta)
                    final_ctx.result["bootstrapper_metadata"] = existing_result_meta
            else:
                existing_result_meta = {}
                final_ctx.result["bootstrapper_metadata"] = existing_result_meta
            result_bucket = existing_result_meta.setdefault("lph_blobs", [])
            result_paths = {
                entry.get("path")
                for entry in result_bucket
                if isinstance(entry, Mapping)
            }
            for entry in lph_reports:
                path_key = entry.get("path")
                if path_key in result_paths:
                    continue
                result_bucket.append(entry)
                if path_key is not None:
                    result_paths.add(path_key)

        report = final_ctx.report if final_ctx else None
        if script_key_missing_forced and report is not None:
            warning_message = "script key missing (forced)"
            if not any(
                isinstance(entry, str) and "script key" in entry.lower()
                for entry in report.warnings
            ):
                report.warnings.append(warning_message)

        success = True
        error_message: Optional[str] = None

        lifter_metadata_raw = (
            lifter_summary.get("metadata") if effective_run_lifter else None
        )
        lifter_metadata = lifter_metadata_raw if isinstance(lifter_metadata_raw, Mapping) else None

        functions_lifted = None
        if lifter_metadata is not None:
            functions_lifted = _coerce_int(lifter_metadata.get("functions"))
            if functions_lifted is None:
                functions_lifted = _coerce_int(lifter_metadata.get("function_count"))

        placeholder_only_output = False
        if isinstance(payload_bucket, Mapping):
            placeholder_only_output = bool(payload_bucket.get("placeholder_output")) or bool(
                payload_bucket.get("placeholders_only")
            )
            handler_meta_summary = payload_bucket.get("handler_payload_meta")
            if isinstance(handler_meta_summary, Mapping):
                placeholder_only_output = placeholder_only_output or bool(
                    handler_meta_summary.get("placeholder_output")
                )
                placeholder_only_output = placeholder_only_output or bool(
                    handler_meta_summary.get("placeholders_only")
                )
            placeholder_source = payload_bucket.get("handler_placeholder_source")
            if (
                not placeholder_only_output
                and isinstance(placeholder_source, str)
                and placeholder_source.strip()
            ):
                placeholder_only_output = True

        placeholder_label = "placeholder-only output"
        if (
            args.run_lifter
            and placeholder_only_output
            and (functions_lifted is None or functions_lifted <= 0)
        ):
            print(utils.colorize_text(f"WARNING: {placeholder_label}", "red", bold=True))
            if report is not None and placeholder_label not in report.warnings:
                report.warnings.append(placeholder_label)

        mandatory_missing: set[str] = set()

        def _collect_missing_names(values: Any) -> None:
            if isinstance(values, str):
                cleaned = values.strip()
                if cleaned:
                    mandatory_missing.add(cleaned.upper())
            elif isinstance(values, Sequence) and not isinstance(
                values, (bytes, bytearray, str)
            ):
                for entry in values:
                    if isinstance(entry, str):
                        cleaned = entry.strip()
                        if cleaned:
                            mandatory_missing.add(cleaned.upper())

        for key in ("mandatory_missing_ops", "mandatory_missing"):
            _collect_missing_names(final_ctx.vm_metadata.get(key))

        vm_errors = final_ctx.vm_metadata.get("errors")
        if isinstance(vm_errors, Sequence):
            for entry in vm_errors:
                if isinstance(entry, str) and entry.startswith("missing/low-trust:"):
                    cleaned = entry.split(":", 1)[1].strip()
                    if cleaned:
                        mandatory_missing.add(cleaned.upper())

        related_containers: Tuple[Any, ...] = (
            final_ctx.vm_metadata.get("opcode_table"),
            final_ctx.vm_metadata.get("lifter"),
            final_ctx.bootstrapper_metadata
            if isinstance(final_ctx.bootstrapper_metadata, Mapping)
            else None,
            payload_bucket,
            payload_bucket.get("handler_payload_meta")
            if isinstance(payload_bucket.get("handler_payload_meta"), Mapping)
            else None,
        )

        for container in related_containers:
            if isinstance(container, Mapping):
                for key in ("mandatory_missing_ops", "mandatory_missing"):
                    _collect_missing_names(container.get(key))

        if lifter_metadata is not None:
            for key in ("mandatory_missing_ops", "mandatory_missing"):
                _collect_missing_names(lifter_metadata.get(key))
            meta_errors = lifter_metadata.get("errors")
            if isinstance(meta_errors, Sequence):
                for entry in meta_errors:
                    if (
                        isinstance(entry, str)
                        and entry.startswith("missing/low-trust:")
                    ):
                        cleaned = entry.split(":", 1)[1].strip()
                        if cleaned:
                            mandatory_missing.add(cleaned.upper())

        missing_recognized = {
            name for name in mandatory_missing if name in MANDATORY_MNEMONICS
        }
        required_mandatory = len(MANDATORY_MNEMONICS)
        trusted_count: Optional[int] = None
        if missing_recognized:
            trusted_count = max(0, required_mandatory - len(missing_recognized))

        coverage_failure = False
        if effective_run_lifter and args.lifter_mode == "accurate":
            coverage_failure = bool(missing_recognized)
            if lifter_metadata is not None:
                status_value = lifter_metadata.get("status")
                reason_value = lifter_metadata.get("reason")
                if isinstance(status_value, str) and status_value.lower() == "skipped":
                    reason_text = str(reason_value or "")
                    if "mandatory" in reason_text.lower():
                        coverage_failure = True
                if not coverage_failure:
                    errors_bucket = lifter_metadata.get("errors")
                    if isinstance(errors_bucket, Sequence):
                        if any(
                            isinstance(entry, str)
                            and entry.startswith("missing/low-trust:")
                            for entry in errors_bucket
                        ):
                            coverage_failure = True
            if coverage_failure and not missing_recognized:
                trusted_count = None

        if coverage_failure:
            detail_parts: List[str] = []
            if trusted_count is not None:
                detail_parts.append(f"{trusted_count}/{required_mandatory} trusted")
            if mandatory_missing:
                detail_parts.append(
                    "missing: " + ", ".join(sorted(mandatory_missing))
                )
            if detail_parts:
                invariant_message = (
                    "mandatory opcode coverage below threshold ("
                    + "; ".join(detail_parts)
                    + ")"
                )
            else:
                invariant_message = "mandatory opcode coverage below threshold"
            if args.force:
                if report is not None and invariant_message not in report.warnings:
                    report.warnings.append(invariant_message)
            else:
                success = False
                error_message = invariant_message
                if report is not None and invariant_message not in report.errors:
                    report.errors.append(invariant_message)

        wants_json_output = (
            not args.detect_only and item.json_destination is not None
        )
        if (
            wants_json_output
            and report is not None
            and final_ctx.options.get("report", True)
        ):
            vm_meta = (
                utils.serialise_metadata(final_ctx.vm_metadata)
                if final_ctx.vm_metadata
                else {}
            )
            report.vm_metadata = dict(vm_meta)
            final_ctx.result["report"] = report.to_json()
        else:
            final_ctx.result.pop("report", None)

        if args.detect_only:
            output_text = _format_detection(final_ctx, args.format)
        else:
            output_text = _format_pipeline_output(final_ctx, final_timings, args.format, item.source)

        if not utils.safe_write_file(str(item.destination), output_text):
            return WorkResult(item, False, error="failed to write output")

        if wants_json_output and item.json_destination is not None:
            json_path = item.json_destination
            json_text = _serialise_pipeline_state(final_ctx, final_timings, item.source)
            if json_path != item.destination:
                if not utils.safe_write_file(str(json_path), json_text):
                    return WorkResult(item, False, error="failed to write JSON report")

        if (
            not args.detect_only
            and report is not None
            and final_ctx.options.get("report", True)
        ):
            print("\n=== Deobfuscation Report ===")
            print(report.to_text())

        if not args.detect_only:
            decoded_count = 0
            fallback_count = 0

            payload_summary = final_ctx.pass_metadata.get("payload_decode")
            if isinstance(payload_summary, Mapping):
                handler_meta = payload_summary.get("handler_payload_meta")
                candidates = [handler_meta, payload_summary]
                for meta in candidates:
                    if not isinstance(meta, Mapping):
                        continue
                    success_value = meta.get("chunk_success_count")
                    if isinstance(success_value, int) and success_value >= 0:
                        decoded_count = max(decoded_count, success_value)
                    chunk_value = meta.get("chunk_count")
                    if isinstance(chunk_value, int) and chunk_value >= 0:
                        fallback_count = max(fallback_count, chunk_value)

            if decoded_count <= 0:
                if report is not None and isinstance(report.blob_count, int):
                    decoded_count = max(decoded_count, report.blob_count)
                decoded_count = max(decoded_count, fallback_count)

            if decoded_count <= 0 and final_ctx.decoded_payloads:
                decoded_count = len([entry for entry in final_ctx.decoded_payloads if entry])

            print(f"Decoded {decoded_count} blobs")

        if dump_ir_target and final_ctx:
            if dump_ir_is_directory:
                ir_path = dump_ir_target / f"{item.source.stem}.ir"
            else:
                ir_path = dump_ir_target
            ir_module = final_ctx.ir_module
            ir_text = _render_ir_listing(ir_module) if ir_module else "; no VM IR produced\n"
            if not utils.safe_write_file(str(ir_path), ir_text):
                logging.getLogger(__name__).warning(
                    "failed to write IR listing to %s", ir_path
                )

        summary_lines: List[str] = []
        if final_ctx.detected_version:
            summary_lines.append(f"Version: {final_ctx.detected_version.name}")
        if final_timings:
            summary_lines.append(utils.format_pass_summary(final_timings))

        checklist: Optional[Mapping[str, object]] = None
        quality_gate_info: Optional[Dict[str, object]] = None
        quality_gate_error: Optional[str] = None
        summary_path: Optional[Path] = None

        if not args.detect_only and not args.dry_run and render_target.exists():
            try:
                checklist = evaluate_deobfuscation_checklist(
                    item.source,
                    reconstructed_path=render_target,
                    write_lock_if_high_confidence=True,
                )
            except Exception:  # pragma: no cover - diagnostics only
                logging.getLogger(__name__).debug(
                    "failed to compute completeness score for %s",
                    item.source,
                    exc_info=True,
                )
                if args.quality_gate:
                    summary_lines.append("Quality gate: FAIL (checklist unavailable)")
                    quality_gate_error = (
                        "quality gate failed: unable to evaluate checklist"
                    )
            else:
                completeness = checklist.get("completeness")
                if isinstance(completeness, Mapping):
                    score = completeness.get("score")
                    if isinstance(score, (int, float)):
                        summary_lines.append(f"Completeness score: {score:.3f}")
                if args.quality_gate:
                    quality_gate_info = evaluate_quality_gate(
                        checklist,
                        threshold=args.quality_gate_threshold,
                        require_parity=not args.quality_allow_parity_failures,
                    )
                    gate_status = "PASS" if quality_gate_info["passed"] else "FAIL"
                    gate_score = quality_gate_info.get("score")
                    if isinstance(gate_score, float):
                        score_part = f"score {gate_score:.3f}"
                    else:
                        score_part = "score n/a"
                    threshold_raw = quality_gate_info.get("threshold")
                    if isinstance(threshold_raw, float):
                        threshold_part = f"threshold {threshold_raw:.3f}"
                    else:
                        threshold_part = "threshold n/a"
                    parity_meta = quality_gate_info.get("parity", {})
                    parity_total = parity_meta.get("total", 0)
                    parity_passed = parity_meta.get("passed", 0)
                    parity_desc = f", parity {parity_passed}/{parity_total}"
                    if args.quality_allow_parity_failures:
                        parity_desc += " (allow failures)"
                    summary_lines.append(
                        f"Quality gate: {gate_status} ({score_part}, {threshold_part}{parity_desc})"
                    )
                    if not quality_gate_info["passed"]:
                        failures = quality_gate_info.get("failures")
                        detail = "; ".join(
                            entry for entry in failures if isinstance(entry, str)
                        )
                        quality_gate_error = (
                            f"quality gate failed: {detail or 'requirements not met'}"
                        )

                extras_payload: Dict[str, object] = {}
                dangerous_meta = final_ctx.result.get("dangerous_calls")
                if isinstance(dangerous_meta, Mapping):
                    extras_payload["dangerous_calls"] = dict(dangerous_meta)
                try:
                    summary_target = render_target.parent / "SUMMARY.md"
                    summary_path = generate_run_summary(
                        summary_target,
                        source=item.source,
                        report=report,
                        checklist=checklist,
                        extras=extras_payload,
                    )
                except Exception:
                    logging.getLogger(__name__).debug(
                        "failed to generate SUMMARY.md for %s", item.source, exc_info=True
                    )
                else:
                    final_ctx.result["summary_path"] = str(summary_path)

        if args.quality_gate and quality_gate_info is None and quality_gate_error is None:
            summary_lines.append("Quality gate: SKIPPED (no output to evaluate)")

        summary = "\n".join(line for line in summary_lines if line)
        if quality_gate_error and success:
            success = False
            if error_message:
                error_message = f"{error_message}; {quality_gate_error}"
            else:
                error_message = quality_gate_error
        return WorkResult(
            item,
            success,
            output_path=item.destination,
            summary=(summary + (f"\nSummary: {summary_path}" if summary_path else "")).strip(),
            error=error_message,
        )

    try:
        results, duration = utils.run_parallel(work_items, _process, jobs=jobs)
    except Exception:  # pragma: no cover - catastrophic failure
        logging.getLogger(__name__).exception("unexpected error while processing inputs")
        return 1

    exit_code = 0
    for result in results:
        if result.summary:
            print(f"\n== {result.item.source} ==\n{result.summary}\n")
        if not result.success:
            exit_code = 1
            if result.error:
                logging.getLogger(__name__).error(
                    "failed processing %s: %s", result.item.source, result.error
                )
            else:
                logging.getLogger(__name__).error("failed processing %s", result.item.source)

    logging.getLogger(__name__).info(
        "processed %d file(s) in %.2fs with %d job(s)",
        len(work_items),
        duration,
        jobs,
    )

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
