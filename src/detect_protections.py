"""Static detection heuristics for common Luraph protection techniques."""

from __future__ import annotations

import json

import os
import re
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from lua_literal_parser import LuaTable, parse_lua_expression
from .luraph_api import LuraphAPI

# Regular expression patterns for each protection type. Patterns are compiled lazily at
# module import so unit tests pay a fixed cost.
_XOR_PATTERNS: Sequence[tuple[str, str]] = (
    (r"\bbit32\.bxor\b", "bit32_bxor"),
    (r"\bbxor\s*\(", "bxor_call"),
    (r"[\w\[\]]+\s*=\s*[\w\[\]]+\s*\^\s*\w+", "caret_xor"),
    (r"\w+\s*=\s*\w+\s*~\s*\w+", "tilde_xor"),
)

_COMPRESSION_PATTERNS: Sequence[tuple[str, str]] = (
    (r"\bzlib\b", "zlib"),
    (r"\binflate\b", "inflate"),
    (r"\buncompress\b", "uncompress"),
    (r"string\.unpack", "string_unpack"),
    (r"string\.pack", "string_pack"),
    (r"LPH_UnpackData", "lph_unpack"),
)

_GENERATION_PATTERNS: Sequence[tuple[str, str]] = (
    (r"string\.char", "string_char"),
    (r"load(string|buffer|file|string)", "load_call"),
    (r"table\.concat", "table_concat"),
    (r"setfenv", "setfenv"),
)

_RANDOMNESS_PATTERNS: Sequence[tuple[str, str]] = (
    (r"math\.randomseed", "math_randomseed"),
    (r"os\.time", "os_time"),
    (r"crypto\.random", "crypto_random"),
    (r"script_key", "script_key_usage"),
    (r"%s\s*\^\s*script_key" % r"[A-Za-z0-9_]+", "script_key_xor"),
)

_FRAGMENT_PATTERNS: Sequence[tuple[str, str]] = (
    (r"segments", "segments"),
    (r"chunks", "chunks"),
    (r"parts", "parts"),
    (r"for\s+\w+\s*=\s*1,\s*#\w+\s+do", "reassembly_loop"),
    (r"table\.insert\s*\(\s*\w+\s*,\s*\w+\s*\)", "table_insert"),
)

_JUNK_PATTERNS: Sequence[tuple[str, str]] = (
    (r"OP_?NOP", "explicit_nop"),
    (r"handlers?\s*\[[^\]]+\]\s*=\s*function\s*\([^)]*\)\s*return", "return_handler"),
    (r"\{\s*\[(\d+)\]\s*=\s*nil", "nil_table"),
)

_ANTITRACE_PATTERNS: Sequence[tuple[str, str]] = (
    (r"debug\.getinfo", "debug_getinfo"),
    (r"debug\.sethook", "debug_sethook"),
    (r"jit\.status", "jit_status"),
    (r"os\.execute", "os_execute"),
    (r"pcall\s*\(\s*debug\.traceback", "traceback_guard"),
)

# Each protection category is mapped to the set of pattern groups tested above.
_CATEGORY_PATTERNS = {
    "xor": _XOR_PATTERNS,
    "compression": _COMPRESSION_PATTERNS,
    "dynamic_generation": _GENERATION_PATTERNS,
    "randomisation": _RANDOMNESS_PATTERNS,
    "fragmentation": _FRAGMENT_PATTERNS,
    "junk_ops": _JUNK_PATTERNS,
    "anti_trace": _ANTITRACE_PATTERNS,
    "vm_bootstrap": (
        (r"virtual[%s_]*machine" % "\\s", "virtual_machine_label"),
        (r"L1", "helper_L1"),
        (r"Y1", "helper_Y1"),
        (r"LPH_UnpackData", "lph_unpack"),
    ),
}

_MACRO_REGEX = re.compile(r"\b(LPH_[A-Z0-9_]+)\b")
_MACRO_COMMENT_REGEX = re.compile(r"--\s*@?(lph[_-]?[a-z0-9_]+)")

_COMMENT_MACRO_CANONICAL = {
    "LPH_NOVIRTUALIZE": "LPH_NO_VIRTUALIZE",
    "LPH_NO_VIRT": "LPH_NO_VIRTUALIZE",
    "LPH_NOVIRT": "LPH_NO_VIRTUALIZE",
    "LPH_JITMAX": "LPH_JIT_MAX",
    "LPH_ENCFUNC": "LPH_ENCFUNC",
    "LPH_NOUPVALUES": "LPH_NO_UPVALUES",
}

_METADATA_VERSION_REGEX = re.compile(
    r"--\s*Luraph\s*v(?:ersion)?\s*([0-9][0-9A-Za-z.\-_]*)",
    re.IGNORECASE,
)
_METADATA_FLAG_REGEX = re.compile(r"--\s*Flags?\s*:?\s*(.+)", re.IGNORECASE)
_METADATA_NAME_REGEX = re.compile(r"--\s*Name\s*:?\s*(.+)", re.IGNORECASE)

_SETTINGS_ASSIGN_REGEX = re.compile(
    r"(?P<prefix>local\s+|global\s+|)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*{",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DetectionEvidence:
    """A single detection result."""

    category: str
    pattern_id: str
    snippet: str
    filename: str

    def to_json(self) -> dict:
        return {
            "category": self.category,
            "pattern": self.pattern_id,
            "snippet": self.snippet,
            "filename": self.filename,
        }


def _find_matches(source: str, filename: str, patterns: Sequence[tuple[str, str]], category: str) -> List[DetectionEvidence]:
    evidence: List[DetectionEvidence] = []
    for pattern, pattern_id in patterns:
        regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        for match in regex.finditer(source):
            snippet = match.group(0)
            if len(snippet) > 160:
                snippet = snippet[:160] + "…"
            evidence.append(DetectionEvidence(category, pattern_id, snippet, filename))
    return evidence


def _merge_unique(existing: List[str], new_items: Iterable[str]) -> List[str]:
    seen = OrderedDict((item, None) for item in existing)
    for item in new_items:
        if item not in seen:
            seen[item] = None
    return list(seen.keys())


def _normalise_key(key: Any) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, (int, float)) and float(key).is_integer():
        return str(int(key))
    return str(key)


def _lua_to_python(value: Any) -> Any:
    if isinstance(value, LuaTable):
        mapping: Dict[str, Any] = {}
        for key, val in value.mapping:
            mapping[_normalise_key(key)] = _lua_to_python(val)
        array_values = [_lua_to_python(item) for item in value.array]
        if mapping and array_values:
            mapping.setdefault("array", array_values)
            return mapping
        if mapping:
            return mapping
        return array_values
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_lua_to_python(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _lua_to_python(v) for k, v in value.items()}
    return str(value)


def _extract_table_literal(source: str, brace_index: int) -> str | None:
    if brace_index < 0 or brace_index >= len(source) or source[brace_index] != "{":
        return None
    depth = 0
    i = brace_index
    in_string: str | None = None
    length = len(source)

    while i < length:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < length else ""
        if in_string:
            if ch == "\\" and nxt:
                i += 2
                continue
            if ch == in_string:
                in_string = None
            else:
                i += 1
                continue
            i += 1
            continue
        if ch == "-" and nxt == "-":
            i += 2
            if i < length and source.startswith("[[", i):
                i += 2
                while i < length and not source.startswith("]]", i):
                    i += 1
                i = i + 2 if i < length else length
            else:
                while i < length and source[i] not in "\r\n":
                    i += 1
            continue
        if ch in {'"', "'"}:
            in_string = ch
            i += 1
            continue
        if ch == "[" and nxt == "[":
            i += 2
            while i < length and not source.startswith("]]", i):
                i += 1
            i = i + 2 if i < length else length
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[brace_index : i + 1]
        i += 1
    return None


def _assign_known(known: Dict[str, Any], key: str, value: Any) -> None:
    if key not in known:
        known[key] = value
        return
    existing = known[key]
    if existing == value:
        return
    if isinstance(existing, list):
        if value not in existing:
            existing.append(value)
        return
    known[key] = [existing, value] if value not in (existing,) else existing


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _ensure_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if "array" in value and isinstance(value["array"], list):
            return value["array"]
        return list(value.values())
    if value is None:
        return []
    return [value]


def _first_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        for item in value:
            result = _first_bool(item)
            if result is not None:
                return result
    if isinstance(value, dict):
        for item in value.values():
            result = _first_bool(item)
            if result is not None:
                return result
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _map_known_settings(known: Dict[str, Any], node: Any) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lower = key.lower()
            if lower in {"virtualize_all", "virtualise_all"}:
                bool_value = _coerce_bool(value)
                if bool_value is not None:
                    _assign_known(known, "virtualize_all", bool_value)
            elif lower in {"exclude_list", "exclude"}:
                _assign_known(known, "exclude_list", _ensure_list(value))
            elif lower in {"max_jit_kernels", "jit_max"}:
                if isinstance(value, (int, float)):
                    _assign_known(known, "max_jit_kernels", int(value))
                elif isinstance(value, str) and value.isdigit():
                    _assign_known(known, "max_jit_kernels", int(value))
            else:
                _map_known_settings(known, value)
    elif isinstance(node, list):
        for item in node:
            _map_known_settings(known, item)


def _extract_settings(source: str) -> Dict[str, Any]:
    tables: "OrderedDict[str, Any]" = OrderedDict()
    known: Dict[str, Any] = {}
    for match in _SETTINGS_ASSIGN_REGEX.finditer(source):
        name = match.group("name")
        if "setting" not in name.lower() and "config" not in name.lower():
            continue
        brace_index = source.find("{", match.start())
        if brace_index == -1:
            continue
        literal = _extract_table_literal(source, brace_index)
        if not literal:
            continue
        try:
            parsed = parse_lua_expression(literal)
        except ValueError:
            continue
        py_value = _lua_to_python(parsed)
        tables[name] = py_value
        _map_known_settings(known, py_value)
    return {"tables": dict(tables), "known": known}


def _canonical_macro(name: str) -> str:
    upper = name.upper()
    return _COMMENT_MACRO_CANONICAL.get(upper, upper)


def _detect_macros(source: str) -> List[str]:
    ordered: "OrderedDict[str, None]" = OrderedDict()
    for match in _MACRO_REGEX.finditer(source):
        macro = match.group(1).upper()
        ordered.setdefault(macro, None)
    for match in _MACRO_COMMENT_REGEX.finditer(source):
        comment_macro = match.group(1).upper()
        comment_macro = comment_macro.replace("-", "_")
        if not comment_macro.startswith("LPH_"):
            comment_macro = f"LPH_{comment_macro}" if not comment_macro.startswith("LURAPH") else comment_macro
        macro = _canonical_macro(comment_macro)
        ordered.setdefault(macro.upper(), None)
    return list(ordered.keys())


def _extract_metadata(source: str) -> tuple[Dict[str, Any], List[str]]:
    metadata: Dict[str, Any] = {}
    limitations: List[str] = []
    version_match = _METADATA_VERSION_REGEX.search(source)
    if version_match:
        metadata["luraph_version"] = version_match.group(1)
    name_match = _METADATA_NAME_REGEX.search(source)
    if name_match:
        metadata["script_name"] = name_match.group(1).strip()
    flag_matches = _METADATA_FLAG_REGEX.findall(source)
    if flag_matches:
        metadata["flags"] = [flag.strip() for flag in flag_matches if flag.strip()]
    return metadata, limitations


def _augment_metadata_from_api(metadata: Dict[str, Any], api_client: Optional[LuraphAPI]) -> tuple[Dict[str, Any], List[str]]:
    endpoint = os.environ.get("LURAPH_SIGNATURE_ENDPOINT")
    if api_client is None and not endpoint:
        return {}, []
    if "luraph_version" not in metadata:
        return {}, []
    version = metadata["luraph_version"]
    if api_client:
        try:
            payload = api_client.version_info(version)
        except RuntimeError as exc:
            return {}, [f"luraph_api_error: {exc}"]
        return {"signature_lookup": payload}, []
    url = endpoint.rstrip("/") + f"/{version}"
    try:
        with urllib.request.urlopen(url, timeout=3) as handle:
            payload = handle.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {}, [f"signature_lookup_failed: {exc}"]
    try:
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:  # pragma: no cover - defensive
        return {}, [f"signature_lookup_parse_error: {exc}"]
    return {"signature_lookup": data}, []


def _merge_settings(
    tables_accum: Dict[str, Any], known_accum: Dict[str, Any], new_settings: Dict[str, Any]
) -> None:
    tables = new_settings.get("tables", {}) if isinstance(new_settings, dict) else {}
    for name, value in tables.items():
        tables_accum.setdefault(name, value)
    known = new_settings.get("known", {}) if isinstance(new_settings, dict) else {}
    for key, value in known.items():
        if key not in known_accum:
            known_accum[key] = value
        else:
            existing = known_accum[key]
            if existing == value:
                continue
            if isinstance(existing, list):
                if isinstance(value, list):
                    for item in value:
                        if item not in existing:
                            existing.append(item)
                else:
                    if value not in existing:
                        existing.append(value)
            else:
                if isinstance(value, list):
                    merged = [existing]
                    for item in value:
                        if item not in merged:
                            merged.append(item)
                    known_accum[key] = merged
                elif value != existing:
                    known_accum[key] = [existing, value]


def _compute_recommendation(macros: Sequence[str], settings: Dict[str, Any], types: Sequence[str]) -> str:
    macro_set = {name.upper() for name in macros}
    prefer_frida = False
    if {"LPH_JIT", "LPH_JIT_MAX", "LPH_ENCFUNC"} & macro_set:
        prefer_frida = True
    if "compression" in types or "anti_trace" in types:
        prefer_frida = True
    if "LPH_ENCFUNC" in macro_set:
        prefer_frida = True
    virtualize_flag: bool | None = None
    if isinstance(settings, dict):
        known = settings.get("known") if isinstance(settings.get("known"), dict) else settings
        if isinstance(known, dict) and "virtualize_all" in known:
            virtualize_flag = _first_bool(known["virtualize_all"])
    if "LPH_NO_VIRTUALIZE" in macro_set or "LPH_SKIP" in macro_set or virtualize_flag is False:
        return "luajit"
    if prefer_frida:
        return "frida"
    return "luajit"


def scan_lua(source: str, *, filename: str = "<memory>", api_client: Optional[LuraphAPI] = None) -> dict:
    """Scan a Lua script and return structured protection evidence."""

    findings: List[DetectionEvidence] = []
    for category, patterns in _CATEGORY_PATTERNS.items():
        findings.extend(_find_matches(source, filename, patterns, category))

    categories = sorted({item.category for item in findings})
    macros = _detect_macros(source)
    settings = _extract_settings(source)
    metadata, metadata_limitations = _extract_metadata(source)
    metadata_augmented, augmentation_limitations = _augment_metadata_from_api(metadata, api_client)
    if metadata_augmented:
        metadata = {**metadata, **metadata_augmented}
    limitations = _merge_unique(list(metadata_limitations), augmentation_limitations)
    if "LPH_ENCFUNC" in macros:
        limitations = _merge_unique(limitations, ["encrypted functions present (LPH_ENCFUNC)"])

    recommendation = _compute_recommendation(macros, settings, categories)

    result = {
        "path": filename,
        "protection_detected": bool(categories),
        "types": categories,
        "evidence": [item.to_json() for item in findings],
        "macros": macros,
        "settings": settings,
        "metadata": metadata,
        "limitations": limitations,
        "recommendation": recommendation,
    }
    return result


def scan_files(paths: Iterable[Path], *, api_key: str | None = None) -> dict:
    """Scan a list of Lua files and aggregate evidence."""

    combined: List[DetectionEvidence] = []
    macros: List[str] = []
    settings_tables: Dict[str, Any] = {}
    known_settings: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    limitations: List[str] = []
    path_list: List[str] = []

    api_client: Optional[LuraphAPI] = None
    if api_key:
        api_client = LuraphAPI(api_key=api_key)

    for path in paths:
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        path_list.append(path.as_posix())
        per_file = scan_lua(data, filename=path.as_posix(), api_client=api_client)
        for item in per_file["evidence"]:
            combined.append(
                DetectionEvidence(
                    item["category"],
                    item["pattern"],
                    item["snippet"],
                    item["filename"],
                )
            )
        macros = _merge_unique(macros, per_file.get("macros", []))
        _merge_settings(settings_tables, known_settings, per_file.get("settings", {}))
        metadata = {**metadata, **per_file.get("metadata", {})}
        limitations = _merge_unique(limitations, per_file.get("limitations", []))

    categories = sorted({item.category for item in combined})
    recommendation = _compute_recommendation(macros, {"known": known_settings}, categories)
    return {
        "path": path_list[0] if path_list else "<memory>",
        "protection_detected": bool(categories),
        "types": categories,
        "evidence": [item.to_json() for item in combined],
        "macros": macros,
        "settings": {"tables": settings_tables, "known": known_settings},
        "metadata": metadata,
        "limitations": limitations,
        "recommendation": recommendation,
        "scanned": path_list,
    }


def dump_report(paths: Iterable[Path], output: Path, *, api_key: str | None = None) -> None:
    """Write detection results to ``output`` as JSON."""

    report = scan_files(paths, api_key=api_key)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Detect Luraph protection features")
    parser.add_argument("init", nargs="?", default="initv4.lua", help="Bootstrap file to analyse")
    parser.add_argument("--output", "-o", default=None, help="Optional JSON output path")
    parser.add_argument("--api-key", default=None, help="Optional Luraph API key for metadata lookups")
    parser.add_argument("--extra", nargs="*", default=(), help="Additional Lua files to include")
    args = parser.parse_args(list(argv) if argv is not None else None)

    paths = [Path(args.init)] + [Path(item) for item in args.extra]
    report = scan_files(paths, api_key=args.api_key)
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    raise SystemExit(main())


__all__ = ["scan_lua", "scan_files", "dump_report", "main"]
