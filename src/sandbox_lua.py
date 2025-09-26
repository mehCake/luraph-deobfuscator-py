"""Sandboxed Lua bootstrapper helpers for initv4 decoding."""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # pragma: no cover - optional dependency
    from lupa import LuaError, LuaRuntime
except Exception:  # pragma: no cover - fallback when lupa missing
    LuaRuntime = None  # type: ignore[assignment]
    LuaError = Exception  # type: ignore[assignment]

LOG = logging.getLogger(__name__)

_ALPHABET_RE = re.compile(r"^[!-~]{80,}$")
_HEX_KEY_RE = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass
class SandboxResult:
    """Holds the structured data extracted from the sandboxed bootstrap run."""

    alphabet: Optional[str]
    opcode_map: Dict[int, str]
    constants: Dict[str, int]
    log: str
    report: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "alphabet": self.alphabet,
            "opcode_map": dict(self.opcode_map),
            "constants": dict(self.constants),
            "log": self.log,
            "report": dict(self.report),
        }


def _looks_like_alphabet(candidate: str) -> bool:
    if not candidate or len(candidate) < 80:
        return False
    if not _ALPHABET_RE.match(candidate):
        return False
    unique = {ch for ch in candidate}
    return len(unique) >= 60


def _is_lua_available() -> bool:
    return LuaRuntime is not None


def _lua_type(runtime: "LuaRuntime"):
    return runtime.eval("return function(value) return type(value) end")


def _lua_tostring(runtime: "LuaRuntime"):
    return runtime.eval("return function(value) return tostring(value) end")


class SandboxViolation(RuntimeError):
    """Raised when the sandbox attempts to access a forbidden primitive."""


def _forbidden(name: str):
    def _raise(*_args: object, **_kwargs: object) -> None:
        raise SandboxViolation(f"sandboxed bootstrapper attempted to access {name}")

    return _raise


def make_safe_env(runtime: "LuaRuntime", *, log_buffer: Optional[List[str]] = None) -> Tuple[Any, Dict[str, Any]]:
    """Create a constrained Lua environment for executing the bootstrapper."""

    base_globals = runtime.globals()
    env = runtime.table_from({})
    modules: Dict[str, Any] = {}
    log_lines: List[str] = log_buffer if log_buffer is not None else []

    def _copy_module(name: str, allowed: Iterable[str]) -> Optional[Any]:
        source = base_globals.get(name)
        if source is None:
            return None
        table = runtime.table_from({})
        for attr in allowed:
            try:
                table[attr] = source[attr]
            except Exception:
                continue
        env[name] = table
        modules[name] = table
        modules[f"__orig_{name}"] = source
        return table

    string_table = _copy_module(
        "string",
        (
            "byte",
            "char",
            "find",
            "format",
            "gsub",
            "len",
            "lower",
            "upper",
            "sub",
            "rep",
        ),
    )
    _copy_module(
        "table",
        (
            "insert",
            "remove",
            "unpack",
            "pack",
            "concat",
        ),
    )
    _copy_module(
        "math",
        (
            "abs",
            "ceil",
            "floor",
            "max",
            "min",
            "sqrt",
            "modf",
            "random",
            "randomseed",
        ),
    )
    _copy_module(
        "bit32",
        ("band", "bor", "bxor", "bnot", "lshift", "rshift", "arshift"),
    )
    _copy_module("bit", ("band", "bor", "bxor", "bnot", "lshift", "rshift"))

    for name in (
        "assert",
        "error",
        "next",
        "pairs",
        "ipairs",
        "pcall",
        "xpcall",
        "select",
        "tonumber",
        "tostring",
        "type",
        "math",
        "string",
        "table",
    ):
        value = base_globals.get(name)
        if value is not None:
            env[name] = value

    # Ensure commonly used helpers remain available
    for builtin in ("rawset", "rawget", "rawequal", "setmetatable", "getmetatable"):
        value = base_globals.get(builtin)
        if value is not None:
            env[builtin] = value
            modules[builtin] = value

    # Provide limited versions of loadstring/load
    for loader in ("load", "loadstring"):
        value = base_globals.get(loader)
        if value is not None:
            env[loader] = value

    def _logger(*args: Any) -> None:
        message = " ".join(str(arg) for arg in args)
        log_lines.append(message)

    env["print"] = _logger
    modules["__log"] = log_lines

    # Disable unsafe primitives
    env["os"] = _forbidden("os")
    env["io"] = _forbidden("io")
    env["package"] = _forbidden("package")
    env["debug"] = _forbidden("debug")
    env["require"] = _forbidden("require")
    env["dofile"] = _forbidden("dofile")
    env["loadfile"] = _forbidden("loadfile")

    env["_G"] = env
    return env, modules


def _normalise_numeric_key(raw_key: Any) -> Optional[int]:
    if isinstance(raw_key, (int, float)):
        try:
            if isinstance(raw_key, float):
                if not raw_key.is_integer():
                    return None
                return int(raw_key)
            return int(raw_key)
        except Exception:
            return None
    if isinstance(raw_key, str):
        if raw_key.isdigit():
            try:
                return int(raw_key, 10)
            except Exception:
                return None
        if _HEX_KEY_RE.match(raw_key):
            try:
                return int(raw_key, 16)
            except Exception:
                return None
    return None


def _analyse_table(
    lua_type_func,
    tostring_func,
    table_obj: Any,
) -> Tuple[int, Dict[int, str], Dict[str, Any]]:
    mapping: Dict[int, str] = {}
    callable_entries = 0
    total_numeric = 0
    inferred_names = 0
    direct_names = 0
    try:
        iterator = table_obj.items()
    except Exception:
        return callable_entries, mapping, {
            "total_numeric": total_numeric,
            "inferred": inferred_names,
            "direct": direct_names,
        }

    for raw_key, raw_value in list(iterator):
        key = _normalise_numeric_key(raw_key)
        if key is None:
            continue

        try:
            lua_type = lua_type_func(raw_value)
        except Exception:
            lua_type = None

        callable_candidate: Optional[Any] = None
        name: Optional[str] = None

        if lua_type == "function":
            callable_candidate = raw_value
            try:
                label = tostring_func(raw_value)
            except Exception:
                label = None
            if isinstance(label, str) and label and not label.lower().startswith("function:"):
                name = label.strip()
        elif lua_type == "string":
            name = str(raw_value).strip()
        elif lua_type == "table":
            candidate_name = None
            try:
                candidate_name = raw_value["name"]
            except Exception:
                pass
            if not isinstance(candidate_name, str):
                try:
                    candidate_name = raw_value[1]
                except Exception:
                    candidate_name = None
            if isinstance(candidate_name, str):
                name = candidate_name.strip()

            try:
                handler = raw_value[1]
            except Exception:
                handler = None
            if handler is not None and lua_type_func(handler) == "function":
                callable_candidate = handler

        if callable_candidate is not None:
            callable_entries += 1
        total_numeric += 1

        if name:
            direct_names += 1
            mapping[key] = name.upper()
        else:
            inferred_names += 1
            mapping[key] = f"OP_{key:02X}"

    return callable_entries, mapping, {
        "total_numeric": total_numeric,
        "inferred": inferred_names,
        "direct": direct_names,
    }


def _collect_tables(lua_type_func, root: Any, limit: int = 2048) -> List[Any]:
    visited: set[int] = set()
    queue: List[Any] = [root]
    tables: List[Any] = []
    while queue and len(visited) < limit:
        candidate = queue.pop()
        try:
            lua_type = lua_type_func(candidate)
        except Exception:
            continue
        if lua_type != "table":
            continue
        ident = id(candidate)
        if ident in visited:
            continue
        visited.add(ident)
        tables.append(candidate)
        try:
            items = list(candidate.items())
        except Exception:
            continue
        for _, value in items:
            try:
                if lua_type_func(value) == "table":
                    queue.append(value)
            except Exception:
                continue
    return tables


def run_bootstrapper(
    bootstrap_src: str,
    script_key: str,
    *,
    timeout_s: int = 5,
) -> Dict[str, Any]:
    """Execute the initv4 bootstrapper within a sandboxed Lua runtime."""

    if not _is_lua_available():
        raise RuntimeError("lupa is not available; install lupa>=1.8 to enable sandbox execution")
    runtime = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    lua_type_func = _lua_type(runtime)
    tostring_func = _lua_tostring(runtime)
    log_lines: List[str] = []
    env, modules = make_safe_env(runtime, log_buffer=log_lines)
    rawset = modules.get("rawset") or runtime.globals().get("rawset")
    setmetatable = modules.get("setmetatable") or runtime.globals().get("setmetatable")
    string_table = modules.get("string")
    table_table = modules.get("table")
    orig_string = modules.get("__orig_string")
    orig_table = modules.get("__orig_table")

    alphabet_candidates: List[str] = []
    seen_alphabets: set[str] = set()
    table_candidates: Dict[int, Any] = {}
    table_metadata: Dict[int, Dict[str, Any]] = {}
    table_mappings: Dict[int, Dict[int, str]] = {}

    def _record_alphabet(candidate: Any) -> None:
        if isinstance(candidate, str) and _looks_like_alphabet(candidate):
            if candidate not in seen_alphabets:
                seen_alphabets.add(candidate)
                alphabet_candidates.append(candidate)

    def _capture_dispatch_from(table_obj: Any, *, eager: bool = False) -> None:
        if table_obj is None:
            return
        ident = id(table_obj)
        if not eager and ident in table_candidates:
            return
        callables, mapping, stats = _analyse_table(lua_type_func, tostring_func, table_obj)
        if not mapping:
            return
        if callables == 0 and not eager:
            return
        table_candidates[ident] = table_obj
        stats = dict(stats)
        stats["callable"] = callables
        table_metadata[ident] = stats
        table_mappings[ident] = mapping

    if string_table is not None and orig_string is not None:
        try:
            orig_char = orig_string["char"]
        except Exception:
            orig_char = None
        try:
            orig_find = orig_string["find"]
        except Exception:
            orig_find = None

        def _wrap_char(*args: Any) -> Any:
            result = orig_char(*args) if orig_char else None
            if isinstance(result, str):
                _record_alphabet(result)
            return result

        def _wrap_find(*args: Any) -> Any:
            if args:
                first = args[0]
                if isinstance(first, str):
                    _record_alphabet(first)
            return orig_find(*args) if orig_find else None

        if orig_char is not None:
            string_table["char"] = _wrap_char
        if orig_find is not None:
            string_table["find"] = _wrap_find

    if table_table is not None and orig_table is not None:
        try:
            orig_insert = orig_table["insert"]
        except Exception:
            orig_insert = None

        def _wrap_insert(tbl: Any, *args: Any) -> Any:
            value = args[-1] if args else None
            if isinstance(value, str):
                _record_alphabet(value)
            if orig_insert is not None:
                result = orig_insert(tbl, *args)
            else:
                result = None
            _capture_dispatch_from(tbl, eager=True)
            return result

        if orig_insert is not None:
            table_table["insert"] = _wrap_insert

    def _newindex(tbl: Any, key: Any, value: Any) -> None:
        if isinstance(value, str):
            _record_alphabet(value)
        if rawset is not None:
            rawset(tbl, key, value)
        else:  # pragma: no cover - safety fallback
            runtime.globals()["rawset"](tbl, key, value)
        if value is not None:
            try:
                if lua_type_func(value) == "table":
                    _capture_dispatch_from(value)
            except Exception:
                pass

    if setmetatable is not None:
        mt = runtime.table_from({})
        mt["__newindex"] = _newindex
        setmetatable(env, mt)

    finalize_func = runtime.eval(
        "return function(root)\n"
        "  local results = { alphabets = {}, tables = {} }\n"
        "  local seen = setmetatable({}, { __mode = 'k' })\n"
        "  local function is_printable(s)\n"
        "    return type(s) == 'string' and #s >= 80 and s:match('^[!-~]+$') ~= nil\n"
        "  end\n"
        "  local function consider_table(tbl)\n"
        "    if seen[tbl] then return end\n"
        "    seen[tbl] = true\n"
        "    local numeric = 0\n"
        "    local callable = 0\n"
        "    for k, v in pairs(tbl) do\n"
        "      if type(k) == 'number' or (type(k) == 'string' and k:match('^0x[0-9A-Fa-f]+$')) then\n"
        "        numeric = numeric + 1\n"
        "        if type(v) == 'function' then\n"
        "          callable = callable + 1\n"
        "        elseif type(v) == 'table' then\n"
        "          local first = rawget(v, 1)\n"
        "          if type(first) == 'function' then\n"
        "            callable = callable + 1\n"
        "          end\n"
        "        end\n"
        "      end\n"
        "      if type(v) == 'table' then\n"
        "        consider_table(v)\n"
        "      elseif is_printable(v) then\n"
        "        results.alphabets[#results.alphabets + 1] = v\n"
        "      end\n"
        "    end\n"
        "    if callable >= 4 and numeric >= callable then\n"
        "      results.tables[#results.tables + 1] = tbl\n"
        "    end\n"
        "  end\n"
        "  local function scan(value)\n"
        "    if type(value) == 'string' then\n"
        "      if is_printable(value) then\n"
        "        results.alphabets[#results.alphabets + 1] = value\n"
        "      end\n"
        "    elseif type(value) == 'table' then\n"
        "      consider_table(value)\n"
        "    end\n"
        "  end\n"
        "  scan(root)\n"
        "  for k, v in pairs(root) do\n"
        "    scan(v)\n"
        "  end\n"
        "  return results\n"
        "end"
    )

    env["finalize"] = finalize_func
    env["SCRIPT_KEY"] = script_key or ""

    loader = runtime.eval(
        "return function(src, env) local chunk, err = load(src, 'sandbox', 't', env) if not chunk then error(err) end return chunk end"
    )
    chunk = loader(bootstrap_src, env)

    result_holder: Dict[str, Any] = {}

    def _run_chunk() -> None:
        try:
            value = chunk()
            result_holder["value"] = value
            try:
                if value is not None and lua_type_func(value) == "function":
                    try:
                        value(script_key or "")
                    except LuaError:
                        value()
                    except TypeError:
                        value()
            except Exception:
                pass
        except LuaError as exc:  # pragma: no cover - depends on runtime
            result_holder["error"] = exc
        except SandboxViolation as exc:
            result_holder["error"] = exc
        except Exception as exc:  # pragma: no cover - defensive
            result_holder["error"] = exc

    thread = threading.Thread(target=_run_chunk, daemon=True)
    start_time = time.time()
    thread.start()
    thread.join(timeout=timeout_s)
    if thread.is_alive():
        raise TimeoutError("Lua sandbox execution timed out")
    if "error" in result_holder:
        raise result_holder["error"]

    elapsed = time.time() - start_time
    log_lines.append(f"sandbox execution completed in {elapsed:.3f}s")

    finalize_alphabets: List[Any] = []
    finalize_tables: List[Any] = []
    try:
        finalize_payload = finalize_func(env)
    except Exception:
        finalize_payload = None

    if finalize_payload is not None:
        try:
            alph_table = finalize_payload["alphabets"]
        except Exception:
            alph_table = None
        if alph_table is not None:
            try:
                for _, value in list(alph_table.items()):
                    finalize_alphabets.append(value)
            except Exception:
                pass

        try:
            tbl_table = finalize_payload["tables"]
        except Exception:
            tbl_table = None
        if tbl_table is not None:
            try:
                for _, value in list(tbl_table.items()):
                    finalize_tables.append(value)
            except Exception:
                pass

    for value in finalize_alphabets:
        if isinstance(value, str):
            _record_alphabet(value)

    for table_obj in finalize_tables:
        _capture_dispatch_from(table_obj, eager=True)

    if not table_candidates:
        tables = _collect_tables(lua_type_func, env)
        for table_obj in tables:
            _capture_dispatch_from(table_obj)

    def _select_alphabet() -> Optional[str]:
        if not alphabet_candidates:
            return None
        best: Optional[str] = None
        best_score = -1
        for candidate in alphabet_candidates:
            length = len(candidate)
            if length < 80:
                continue
            score = 0
            if 80 <= length <= 120:
                score = 2
            elif length > 120:
                score = 1
            if score > best_score or (score == best_score and best is not None and length > len(best)):
                best = candidate
                best_score = score
        return best or alphabet_candidates[0]

    def _select_opcode_table() -> Tuple[Dict[int, str], Dict[str, Any]]:
        best_mapping: Dict[int, str] = {}
        best_stats: Dict[str, Any] = {}
        best_rank = -1
        for ident, mapping in table_mappings.items():
            stats = table_metadata.get(ident, {})
            callable_entries = stats.get("callable", 0)
            total_numeric = stats.get("total_numeric", 0)
            if callable_entries >= 32 and callable_entries == total_numeric and callable_entries > 0:
                rank = 2
            elif callable_entries >= 16:
                rank = 1
            elif callable_entries:
                rank = 0
            else:
                rank = -1
            if rank > best_rank or (
                rank == best_rank
                and callable_entries > best_stats.get("callable", 0)
            ):
                best_rank = rank
                best_mapping = mapping
                best_stats = dict(stats)
                best_stats["rank"] = rank
        return best_mapping, best_stats

    alphabet = _select_alphabet()
    opcode_map, opcode_stats = _select_opcode_table()

    log_lines.append(
        f"alphabet candidates collected: {len(alphabet_candidates)}; selected={'yes' if alphabet else 'no'}"
    )
    log_lines.append(
        "dispatch tables analysed: "
        f"{len(table_mappings)}; selected_rank={opcode_stats.get('rank', -1)}"
    )

    constants: Dict[str, int] = {}
    try:
        for key, value in env.items():
            if isinstance(key, str) and key.isupper():
                if isinstance(value, (int, float)):
                    constants[key] = int(value)
    except Exception:
        pass

    opcode_count = len(opcode_map)
    opcode_sample: List[Dict[str, Any]] = []
    for key in sorted(opcode_map.keys())[:10]:
        opcode_sample.append({"id": key, "name": opcode_map[key]})

    alphabet_preview = None
    alphabet_len = len(alphabet) if isinstance(alphabet, str) else 0
    if alphabet_len:
        alphabet_preview = alphabet[:64]
        if alphabet_len > 64:
            alphabet_preview += "..."

    rank = opcode_stats.get("rank", -1)
    if rank >= 2 and alphabet_len >= 80:
        extraction_confidence = "high"
    elif rank >= 1 and alphabet_len >= 80:
        extraction_confidence = "medium"
    else:
        extraction_confidence = "low"

    inferred_count = opcode_stats.get("inferred", 0)
    direct_count = opcode_stats.get("direct", 0)
    if direct_count and not inferred_count:
        name_source = "read"
    elif direct_count and inferred_count:
        name_source = "mixed"
    else:
        name_source = "inferred"

    report = {
        "opcode_map_count": opcode_count,
        "opcode_sample": opcode_sample,
        "alphabet_len": alphabet_len,
        "alphabet_preview": alphabet_preview,
        "extraction_confidence": extraction_confidence,
        "function_name_source": name_source,
    }

    if opcode_map:
        log_lines.append(
            f"selected opcode table with {opcode_count} entries (callable={opcode_stats.get('callable', 0)})"
        )
    else:
        log_lines.append("no opcode table selected")

    result = SandboxResult(alphabet, opcode_map, constants, "\n".join(log_lines), report)
    return result.as_dict()
