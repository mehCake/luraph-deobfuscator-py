"""Symbolic key-usage scanning utilities and probe helpers."""

from __future__ import annotations

import hashlib
import itertools
import hmac
import json
import logging
import os
import queue
import re
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

try:  # pragma: no cover - optional dependency
    from Crypto.Cipher import ARC4 as _ARC4_MODULE  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    _ARC4_MODULE = None

from lua_vm_simulator import LuaVMSimulator
from src.ir import VMFunction, VMInstruction
from snapshot_manager import SnapshotManager
from utils import benchmark, benchmark_recorder, byte_diff
from src.utils import write_json
from version_detector import detect_luraph_header, entropy_detector


_CANDIDATE_TOKEN_RE = re.compile(r"\b(?:function|local)\s+[A-Za-z_]", re.IGNORECASE)


_LOGGER = logging.getLogger(__name__)


_TARGET_FUNCTIONS = {"prga", "initv4", "apply_prga"}
_BIT32_CALL_RE = re.compile(
    r"\b(?:bit32|bit)\s*\.\s*(bxor|bor|band|bnot)\s*\(([^\)]*)\)",
    re.IGNORECASE,
)
_BIT32_SYMBOL_RE = re.compile(r"\b(?:bit32|bit)\s*\.\s*(bxor|bor|band|bnot)\b", re.IGNORECASE)
_GENERIC_CALL_RE = re.compile(r"\b([A-Za-z_][\w]*)\s*\(([^\)]*)\)")
_FUNC_DEF_RE = re.compile(r"function\s+([A-Za-z_][\w]*)\s*\(([^\)]*)\)", re.IGNORECASE)
_ASSIGNED_FUNC_RE = re.compile(
    r"([A-Za-z_][\w]*)\s*=\s*function\s*\(([^\)]*)\)",
    re.IGNORECASE,
)
_BIT32_FUNCTION_ASSIGN_RE = re.compile(
    r"\s*,?\s*([A-Za-z_][\w]*)\s*=\s*function\s*\(([^\)]*)\)",
    re.IGNORECASE,
)
_TILDE_XOR_RE = re.compile(r"([A-Za-z0-9_\.\[\]\(\)]+)\s*~\s*([A-Za-z0-9_\.\[\]\(\)]+)")


_NATIVE_CRYPTO_ENV_VAR = "LURAPH_NATIVE_CRYPTO"
_CONFIG_PATH = Path(__file__).with_name("config.json")

if _ARC4_MODULE is not None:  # pragma: no branch - simple attribute lookup
    _NATIVE_RC4_BACKEND = getattr(_ARC4_MODULE, "__name__", "Crypto.Cipher.ARC4")
else:  # pragma: no cover - exercised implicitly when dependency missing
    _NATIVE_RC4_BACKEND = None


def _parse_bool_flag(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


@lru_cache(maxsize=1)
def _load_native_crypto_default() -> bool:
    """Return the default native-crypto flag from config/env."""

    env_value = os.environ.get(_NATIVE_CRYPTO_ENV_VAR)
    parsed = _parse_bool_flag(env_value) if env_value is not None else None
    if parsed is not None:
        return parsed

    try:
        text = _CONFIG_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    except OSError:  # pragma: no cover - defensive
        _LOGGER.debug("failed to read config.json for native crypto", exc_info=True)
        return False

    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # pragma: no cover - defensive
        _LOGGER.debug("invalid config.json while loading native crypto flag", exc_info=True)
        return False

    performance = data.get("performance")
    if isinstance(performance, Mapping):
        parsed = _parse_bool_flag(performance.get("use_native_crypto"))
        if parsed is not None:
            return parsed
    return False


def _native_crypto_backend() -> Optional[str]:
    return _NATIVE_RC4_BACKEND


def _should_use_native_crypto(enable_native: Optional[bool]) -> bool:
    if enable_native is not None:
        return bool(enable_native and _ARC4_MODULE is not None)
    return bool(_ARC4_MODULE is not None and _load_native_crypto_default())


def _build_arc4_cipher(key: bytes):
    if _ARC4_MODULE is None:
        return None
    factory = getattr(_ARC4_MODULE, "new", None)
    if not callable(factory):
        return None
    try:
        return factory(key)
    except Exception:  # pragma: no cover - defensive fallback
        _LOGGER.debug("failed to initialise native ARC4 cipher", exc_info=True)
        return None


def _current_git_commit() -> str:
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        )
    except Exception:  # pragma: no cover - git may be unavailable in tests
        return "unknown"
    return output.decode("utf-8", errors="ignore").strip() or "unknown"


def _compute_key_hmac(salt: bytes, key: bytes) -> str:
    return hmac.new(salt, key, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class KeyCandidate:
    """Description of a potential key usage site."""

    path: Path
    line: int
    kind: str
    name: str
    arguments: Sequence[str]
    snippet: str

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "line": self.line,
            "kind": self.kind,
            "name": self.name,
            "arguments": list(self.arguments),
            "snippet": self.snippet,
        }


def scan_key_usage(path: str | Path) -> List[KeyCandidate]:
    """Return all candidate sites where a key might be consumed."""

    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines() or [text]

    candidates: List[KeyCandidate] = []

    for index, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        for match in _FUNC_DEF_RE.finditer(raw_line):
            name = match.group(1)
            if name.lower() in _TARGET_FUNCTIONS:
                args = _split_arguments(match.group(2))
                candidates.append(
                    KeyCandidate(
                        path=file_path,
                        line=index,
                        kind="function_definition",
                        name=name,
                        arguments=args,
                        snippet=line[:160],
                    )
                )

        for match in _ASSIGNED_FUNC_RE.finditer(raw_line):
            name = match.group(1)
            lowered = name.lower()
            if lowered in _TARGET_FUNCTIONS or "permute" in lowered or "xor" in lowered:
                args = _split_arguments(match.group(2))
                candidates.append(
                    KeyCandidate(
                        path=file_path,
                        line=index,
                        kind="assigned_function",
                        name=name,
                        arguments=args,
                        snippet=line[:160],
                    )
                )

        for match in _GENERIC_CALL_RE.finditer(raw_line):
            name = match.group(1)
            lowered = name.lower()
            if lowered in _TARGET_FUNCTIONS or "permute" in lowered or "xor" in lowered:
                args = _split_arguments(match.group(2))
                candidates.append(
                    KeyCandidate(
                        path=file_path,
                        line=index,
                        kind="function_call",
                        name=name,
                        arguments=args,
                        snippet=line[:160],
                    )
                )

        seen_bit_spans = set()
        for match in _BIT32_CALL_RE.finditer(raw_line):
            op = match.group(1)
            args = _split_arguments(match.group(2))
            span = match.span()
            seen_bit_spans.add(span)
            candidates.append(
                KeyCandidate(
                    path=file_path,
                    line=index,
                    kind="bit32_call",
                    name=f"bit32.{op.lower()}",
                    arguments=args,
                    snippet=line[:160],
                )
            )

        for match in _BIT32_SYMBOL_RE.finditer(raw_line):
            span = match.span()
            if span in seen_bit_spans:
                continue
            tail = raw_line[match.end():]
            args: List[str] = []
            assign_match = _BIT32_FUNCTION_ASSIGN_RE.match(tail)
            if assign_match:
                args = _split_arguments(assign_match.group(2))
            candidates.append(
                KeyCandidate(
                    path=file_path,
                    line=index,
                    kind="bit32_symbol",
                    name=f"bit32.{match.group(1).lower()}",
                    arguments=args,
                    snippet=line[:160],
                )
            )

        for match in _TILDE_XOR_RE.finditer(raw_line):
            left, right = match.groups()
            candidates.append(
                KeyCandidate(
                    path=file_path,
                    line=index,
                    kind="bitwise_xor_operator",
                    name="~",
                    arguments=[left.strip(), right.strip()],
                    snippet=line[:160],
                )
            )

    return candidates


_SAMPLE_VERSION_HINTS = {
    "Obfuscated.json": "14.4.1",
    "Obfuscated2.lua": "14.4.2",
    "Obfuscated3.lua": "14.4.2",
    "Obfuscated5.lua": "14.4.2",
    "Obfuscated4.lua": "14.3",
    "Obfuscated6.lua": "14.3",
}


def build_key_candidate_report(
    paths: Iterable[str | Path],
    output_path: str | Path = "key_candidates.json",
) -> List[dict]:
    """Scan ``paths`` and write a JSON report describing key candidates."""

    all_candidates: List[dict] = []
    for raw_path in paths:
        file_path = Path(raw_path)
        detected_version = detect_luraph_header(file_path).get("version")
        if not detected_version:
            detected_version = _SAMPLE_VERSION_HINTS.get(file_path.name)
        for candidate in scan_key_usage(file_path):
            entry = candidate.to_dict()
            if detected_version:
                entry.setdefault("version", detected_version)
            all_candidates.append(entry)

    output = Path(output_path)
    output.write_text(json.dumps(all_candidates, indent=2), encoding="utf-8")
    return all_candidates


def _split_arguments(arg_src: str) -> List[str]:
    cleaned = arg_src.strip()
    if not cleaned:
        return []

    args: List[str] = []
    current: List[str] = []
    depth = 0
    in_string: str | None = None
    i = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if in_string:
            current.append(ch)
            if ch == "\\" and i + 1 < len(cleaned):
                current.append(cleaned[i + 1])
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in {'"', "'"}:
            in_string = ch
            current.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
        if ch == "," and depth == 0:
            arg = "".join(current).strip()
            if arg:
                args.append(arg)
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1

    if current:
        arg = "".join(current).strip()
        if arg:
            args.append(arg)
    return args


__all__ = [
    "KeyCandidate",
    "scan_key_usage",
    "build_key_candidate_report",
    "diff_candidates",
    "prga_candidates",
    "probe_prga",
    "derive_symbolic_key_constraints",
    "SymbolicKeyConstraints",
    "discover_transform_order",
    "ParityMismatchError",
    "ExactUpcodeParityReport",
    "BruteforceResult",
    "bruteforce_key_variants",
    "run_probe_harness",
    "clear_transform_cache",
]


@dataclass(frozen=True)
class BruteforceResult:
    """Successful PRGA decode emitted by :func:`bruteforce_key_variants`."""

    key_variant: str
    method: str
    key: bytes
    payload: bytes
    text: str
    emulator_status: str

    def to_dict(self) -> dict:
        return {
            "key_variant": self.key_variant,
            "method": self.method,
            "key_hex": self.key.hex(),
            "payload_preview": self.payload[:64].hex(),
            "text_preview": self.text[:160],
            "emulator_status": self.emulator_status,
        }


@dataclass(frozen=True)
class _ProbeJob:
    """Description of a decoding job to be executed by the worker pool."""

    index: int
    source_label: str
    payload: bytes
    metadata: Optional[Mapping[str, object]]
    key_token: str
    method: str
    transform: Callable[[str | bytes], bytes]
    fragment_sha: str
    key_sha: str
    transform_sha: str


@dataclass(frozen=True)
class _ProbeCandidate:
    """Successful decode result emitted by a worker."""

    job: _ProbeJob
    payload: bytes
    text: str
    sha256: str


@dataclass
class _CacheEntry:
    """Cached transform output reused across probe jobs."""

    payload: Optional[bytes]
    text: Optional[str]
    sha256: Optional[str]
    looks_like_lua: bool


class _TransformCache:
    """Thread-safe LRU cache for transform results."""

    def __init__(self, maxsize: int = 512) -> None:
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str, str], _CacheEntry] = OrderedDict()

    def get(self, key: tuple[str, str, str]) -> Optional[_CacheEntry]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                self._entries.move_to_end(key)
            return entry

    def set(self, key: tuple[str, str, str], value: _CacheEntry) -> None:
        with self._lock:
            self._entries[key] = value
            self._entries.move_to_end(key)
            while len(self._entries) > self._maxsize:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_TRANSFORM_CACHE = _TransformCache()


class _ProbeWorkerPool:
    """Run PRGA decode jobs in parallel while deduplicating by SHA-256."""

    _SENTINEL = object()

    def __init__(
        self,
        max_workers: Optional[int] = None,
        *,
        cache: Optional[_TransformCache] = None,
    ) -> None:
        if max_workers is None or max_workers <= 0:
            cpu_count = os.cpu_count() or 1
            max_workers = min(32, max(1, cpu_count * 2))
        self._jobs: queue.Queue[object] = queue.Queue()
        self._results: queue.Queue[
            tuple[int, _ProbeJob, Optional[_ProbeCandidate]]
        ] = queue.Queue()
        self._hashes: set[str] = set()
        self._hash_lock = threading.Lock()
        self._count_lock = threading.Lock()
        self._submitted = 0
        self._closed = False
        self._workers: List[threading.Thread] = []
        self._cache = cache or _TRANSFORM_CACHE
        for _ in range(max_workers):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self._workers.append(worker)

    def submit(
        self,
        source_label: str,
        payload: bytes,
        metadata: Optional[Mapping[str, object]],
        key_token: str,
        method: str,
        transform: Callable[[str | bytes], bytes],
        *,
        fragment_sha: str,
        key_sha: str,
        transform_sha: str,
    ) -> int:
        """Queue a new decoding job for execution and return its index."""

        with self._count_lock:
            if self._closed:
                raise RuntimeError("probe worker pool already closed")
            index = self._submitted
            self._submitted += 1
        job = _ProbeJob(
            index=index,
            source_label=source_label,
            payload=payload,
            metadata=metadata,
            key_token=key_token,
            method=method,
            transform=transform,
            fragment_sha=fragment_sha,
            key_sha=key_sha,
            transform_sha=transform_sha,
        )
        self._jobs.put(job)
        return index

    def close(self) -> None:
        """Prevent further submissions and signal workers to exit when idle."""

        with self._count_lock:
            self._closed = True
        for _ in self._workers:
            self._jobs.put(self._SENTINEL)

    def iter_results(self) -> Iterator[tuple[_ProbeJob, Optional[_ProbeCandidate]]]:
        """Yield job completions in submission order."""

        expected = 0
        pending: Dict[int, tuple[_ProbeJob, Optional[_ProbeCandidate]]] = {}
        total = self._submitted
        while expected < total:
            try:
                index, job, candidate = self._results.get(timeout=0.1)
            except queue.Empty:
                continue
            pending[index] = (job, candidate)
            while expected in pending:
                job_item, candidate_item = pending.pop(expected)
                yield job_item, candidate_item
                expected += 1

    def join(self) -> None:
        """Wait for all worker threads to terminate."""

        for worker in self._workers:
            worker.join()

    def _worker(self) -> None:  # pragma: no cover - concurrency is exercised via tests
        while True:
            job = self._jobs.get()
            if job is self._SENTINEL:
                self._jobs.task_done()
                break
            assert isinstance(job, _ProbeJob)
            candidate: Optional[_ProbeCandidate] = None
            start_time = time.perf_counter()
            try:
                cache_entry = None
                cache_key = (job.fragment_sha, job.transform_sha, job.key_sha)
                if self._cache:
                    cache_entry = self._cache.get(cache_key)

                if cache_entry is None:
                    with benchmark(
                        "prga_transform",
                        {
                            "method": job.method,
                            "fragment": job.source_label,
                        },
                    ):
                        raw = job.transform(job.payload)
                    text: Optional[str] = None
                    digest: Optional[str] = None
                    looks_like = False
                    if raw:
                        text_candidate = raw.decode("utf-8", errors="ignore")
                        if text_candidate and _looks_like_lua(text_candidate):
                            looks_like = True
                            text = text_candidate
                            digest = hashlib.sha256(raw).hexdigest()
                    cache_entry = _CacheEntry(
                        payload=raw,
                        text=text,
                        sha256=digest,
                        looks_like_lua=looks_like,
                    )
                    if self._cache:
                        self._cache.set(cache_key, cache_entry)

                raw = cache_entry.payload if cache_entry else None
                if raw and cache_entry.looks_like_lua:
                    text = cache_entry.text
                    if text is None:
                        text = raw.decode("utf-8", errors="ignore")
                    digest = cache_entry.sha256 or hashlib.sha256(raw).hexdigest()
                    emit = True
                    with self._hash_lock:
                        if digest in self._hashes:
                            emit = False
                        else:
                            self._hashes.add(digest)
                    if emit and text:
                        candidate = _ProbeCandidate(
                            job=job,
                            payload=raw,
                            text=text,
                            sha256=digest,
                        )
            except Exception:  # pragma: no cover - defensive logging
                _LOGGER.debug("probe worker failed", exc_info=True)
            finally:
                total_duration = time.perf_counter() - start_time
                benchmark_recorder().record(
                    "decode_attempt",
                    total_duration,
                    {
                        "method": job.method,
                        "fragment": job.source_label,
                        "key": job.key_token,
                    },
                )
                self._results.put((job.index, job, candidate))
                self._jobs.task_done()


def _ensure_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="ignore")


def _ensure_text(value: str | bytes | bytearray | memoryview) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("latin-1")
    return str(value)


def _format_diff_snippet(text: str, limit: int = 40) -> str:
    escaped = text.encode("unicode_escape", "replace").decode("ascii", "replace")
    if len(escaped) > limit:
        return escaped[:limit] + "…"
    return escaped


def _summarise_diff_operation(
    tag: str,
    i1: int,
    i2: int,
    j1: int,
    j2: int,
    a_text: str,
    b_text: str,
) -> Dict[str, Any]:
    snippet_a = _format_diff_snippet(a_text)
    snippet_b = _format_diff_snippet(b_text)
    if tag == "equal":
        summary = f"equal {i2 - i1} chars"
    elif tag == "replace":
        summary = f"replace a[{i1}:{i2}]→b[{j1}:{j2}] ({snippet_a!r}→{snippet_b!r})"
    elif tag == "delete":
        summary = f"delete a[{i1}:{i2}] ({snippet_a!r})"
    else:
        summary = f"insert b[{j1}:{j2}] ({snippet_b!r})"

    return {
        "tag": tag,
        "a": {
            "start": i1,
            "end": i2,
            "length": i2 - i1,
            "text": snippet_a,
        },
        "b": {
            "start": j1,
            "end": j2,
            "length": j2 - j1,
            "text": snippet_b,
        },
        "summary": summary,
    }


def _infer_diff_suggestions(
    text_a: str,
    text_b: str,
    operations: Sequence[Mapping[str, Any]],
) -> List[str]:
    non_equal = [op for op in operations if op.get("tag") != "equal"]
    if not non_equal:
        return ["identical outputs"]

    suggestions: List[str] = []

    stripped_a = text_a.strip()
    stripped_b = text_b.strip()
    if stripped_a == stripped_b and text_a != text_b:
        suggestions.append("whitespace-only differences (normalise whitespace)")

    lowered_a = text_a.lower()
    lowered_b = text_b.lower()
    if lowered_a == lowered_b and text_a != text_b:
        suggestions.append("case-only differences (normalise casing)")

    first = non_equal[0]
    last = non_equal[-1]
    len_a = len(text_a)
    len_b = len(text_b)

    if first["a"]["start"] == 0 and first["b"]["start"] == 0:
        if first["tag"] == "insert" and first["b"]["text"]:
            suggestions.append(f"candidate b adds prefix {first['b']['text']!r}")
        elif first["tag"] == "delete" and first["a"]["text"]:
            suggestions.append(f"candidate a prefix {first['a']['text']!r} removed in b")
        elif first["tag"] == "replace":
            suggestions.append("prefix differs; review initial transform order")

    if last["a"]["end"] == len_a or last["b"]["end"] == len_b:
        if last["tag"] == "insert" and last["b"]["end"] == len_b and last["b"]["text"]:
            suggestions.append(f"candidate b adds suffix {last['b']['text']!r}")
        elif last["tag"] == "delete" and last["a"]["end"] == len_a and last["a"]["text"]:
            suggestions.append(f"candidate a suffix {last['a']['text']!r} removed in b")
        elif last["tag"] == "replace":
            suggestions.append("suffix differs; inspect final transforms")

    if len_a == len_b and all(op["a"]["length"] == op["b"]["length"] for op in non_equal):
        suggestions.append("same-length replacements hint at XOR/permute transform ordering")

    deduped: List[str] = []
    seen: set[str] = set()
    for suggestion in suggestions:
        if suggestion in seen:
            continue
        seen.add(suggestion)
        deduped.append(suggestion)
    return deduped


def diff_candidates(
    a: str | bytes | bytearray | memoryview,
    b: str | bytes | bytearray | memoryview,
) -> Dict[str, Any]:
    """Return alignment metadata describing how to transform ``a`` into ``b``."""

    text_a = _ensure_text(a)
    text_b = _ensure_text(b)

    matcher = SequenceMatcher(None, text_a, text_b, autojunk=False)
    operations: List[Dict[str, Any]] = []
    distance = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        record = _summarise_diff_operation(tag, i1, i2, j1, j2, text_a[i1:i2], text_b[j1:j2])
        operations.append(record)
        if tag != "equal":
            distance += max(i2 - i1, j2 - j1)

    suggestions = _infer_diff_suggestions(text_a, text_b, operations)
    summary = suggestions[0] if suggestions else ""
    if not summary:
        for op in operations:
            if op["tag"] != "equal":
                summary = op.get("summary", "")
                if summary:
                    break
    if not summary:
        summary = "identical outputs" if text_a == text_b else "differences detected"

    return {
        "match": text_a == text_b,
        "ratio": matcher.ratio(),
        "distance": distance,
        "operations": operations,
        "suggestions": suggestions,
        "summary": summary,
        "a_length": len(text_a),
        "b_length": len(text_b),
    }


def _rc4_crypt_python(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out[idx] = byte ^ k
    return bytes(out)


def _rc4_crypt_native(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    cipher = _build_arc4_cipher(key)
    if cipher is None:
        return _rc4_crypt_python(data, key)
    encrypt = getattr(cipher, "encrypt", None)
    if callable(encrypt):
        try:
            return encrypt(data)
        except Exception:  # pragma: no cover - defensive fallback
            _LOGGER.debug("native ARC4 encrypt failed", exc_info=True)
            return _rc4_crypt_python(data, key)
    decrypt = getattr(cipher, "decrypt", None)
    if callable(decrypt):
        try:
            return decrypt(data)
        except Exception:  # pragma: no cover - defensive fallback
            _LOGGER.debug("native ARC4 decrypt failed", exc_info=True)
    return _rc4_crypt_python(data, key)


def _repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes((byte ^ key[index % key_len]) & 0xFF for index, byte in enumerate(data))


def _lfsr_transform(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    # Seed the register with a mix of the key bytes to stabilise small keys.
    state = 0xACE1
    for byte in key:
        state ^= byte
        state = ((state << 3) | (state >> 13)) & 0xFFFF

    out = bytearray(len(data))
    key_len = len(key)
    for index, byte in enumerate(data):
        tap = ((state >> 1) ^ state ^ (state >> 3) ^ (state >> 12)) & 0xFFFF
        state = ((tap << 1) | (tap >> 15)) & 0xFFFF
        state ^= key[index % key_len]
        out[index] = byte ^ (state & 0xFF)
    return bytes(out)


def _ror8(value: int, rotation: int) -> int:
    rotation &= 7
    value &= 0xFF
    if rotation == 0:
        return value
    return ((value >> rotation) | ((value << (8 - rotation)) & 0xFF)) & 0xFF


def _rol8(value: int, rotation: int) -> int:
    rotation &= 7
    value &= 0xFF
    if rotation == 0:
        return value
    return ((value << rotation) | (value >> (8 - rotation))) & 0xFF


def _rotating_permute_prga(data: bytes, key: bytes) -> bytes:
    """Permutation-style PRGA observed in newer Luraph payloads."""

    if not key:
        return data

    key_len = len(key)
    state = list(range(256))
    rot = 0
    mirror = 0

    for index in range(256):
        rot = (rot + key[index % key_len] + index) & 0xFF
        mirror = (mirror + state[rot] + key[(index + 1) % key_len]) & 0xFF
        swap_index = (rot + mirror + index) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]

    out = bytearray(len(data))
    for offset, byte in enumerate(data):
        rot = (rot + 1 + key[offset % key_len]) & 0xFF
        mirror = (mirror + state[rot] + offset) & 0xFF
        swap_index = (rot + mirror + key[(offset + rot) % key_len]) & 0xFF
        state[rot], state[swap_index] = state[swap_index], state[rot]
        key_byte = state[(state[rot] + state[mirror & 0xFF]) & 0xFF]
        out[offset] = byte ^ key_byte
    return bytes(out)


def _sieve_rotate_prga(data: bytes, key: bytes) -> bytes:
    """Hybrid sieve/rotation PRGA approximating v14.x handlers."""

    if not key:
        return data

    key_len = len(key)
    state = list(range(256))
    cursor = 0
    stride = sum(key) & 0xFF

    for round_index in range(2):
        for i in range(256):
            stride = (stride + state[i] + key[(i + round_index) % key_len]) & 0xFF
            cursor = (cursor + stride + i) & 0xFF
            state[i], state[cursor] = state[cursor], state[i]

    out = bytearray(len(data))
    for index, byte in enumerate(data):
        cursor = (cursor + 1) & 0xFF
        stride = (stride + state[cursor] + key[index % key_len] + index) & 0xFF
        jump = (stride | 1) & 0xFF
        target = (cursor + jump) & 0xFF
        state[cursor], state[target] = state[target], state[cursor]
        key_byte = (state[cursor] + state[target] + stride) & 0xFF
        out[index] = byte ^ key_byte
    return bytes(out)


def prga_candidates(
    key: str | bytes, *, enable_native: Optional[bool] = None
) -> Dict[str, Callable[[str | bytes], bytes]]:
    """Return PRGA candidate functions parameterised by ``key``.

    ``enable_native`` toggles optional native backends (pycryptodome) for
    RC4-like keystream generation.  When ``None`` the repository configuration
    and environment variables are consulted to determine the default.
    """

    key_bytes = _ensure_bytes(key)
    use_native = _should_use_native_crypto(enable_native)
    rc4_impl = _rc4_crypt_native if use_native else _rc4_crypt_python

    def _wrap(transform: Callable[[bytes, bytes], bytes]) -> Callable[[str | bytes], bytes]:
        def _apply(data: str | bytes) -> bytes:
            return transform(_ensure_bytes(data), key_bytes)

        return _apply

    return {
        "rc4_like": _wrap(rc4_impl),
        "rotate_permute": _wrap(_rotating_permute_prga),
        "sieve_rotate": _wrap(_sieve_rotate_prga),
        "repeating_xor": _wrap(_repeating_xor),
        "lfsr_mask": _wrap(_lfsr_transform),
    }


def probe_prga(
    key: str | bytes, data: str | bytes, *, enable_native: Optional[bool] = None
) -> Dict[str, bytes]:
    """Apply all PRGA candidates using ``key`` to ``data``."""

    data_bytes = _ensure_bytes(data)
    results: Dict[str, bytes] = {}
    for name, transform in prga_candidates(key, enable_native=enable_native).items():
        results[name] = transform(data_bytes)
    return results


def _initv4_xor_stage(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes((value ^ key[index % key_len]) & 0xFF for index, value in enumerate(data))


def _initv4_rotate_stage(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes(_ror8(value, key[index % key_len] & 7) for index, value in enumerate(data))


def _invert_rotate_stage(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes(_rol8(value, key[index % key_len] & 7) for index, value in enumerate(data))


@dataclass(frozen=True)
class TransformStageApplication:
    """Single stage application within a transform search attempt."""

    name: str
    output: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "length": len(self.output),
            "preview_hex": self.output[:32].hex(),
        }


_SUPPORTED_SYMBOLIC_PRIMITIVES = {"xor", "rotate", "rotate_left"}


@dataclass(frozen=True)
class SymbolicKeyConstraints:
    """Represents derived key-byte constraints for XOR/rotate pipelines."""

    order: Tuple[str, ...]
    allowed_values: Tuple[frozenset[int], ...]
    positions_checked: int
    supported: bool = True

    def satisfiable(self) -> bool:
        if not self.supported:
            return True
        return all(values for values in self.allowed_values)

    def is_key_compatible(self, key: bytes) -> bool:
        """Return ``True`` when ``key`` satisfies the derived constraints."""

        if not self.supported or not self.allowed_values:
            return True
        key_len = len(key)
        if key_len == 0:
            return False
        for index, allowed in enumerate(self.allowed_values):
            if not allowed:
                return False
            key_byte = key[index % key_len]
            if key_byte not in allowed:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "order": list(self.order),
            "positions_checked": self.positions_checked,
            "supported": self.supported,
            "allowed_counts": [len(values) for values in self.allowed_values],
            "sample_values": [sorted(values)[:8] for values in self.allowed_values],
        }


def _apply_symbolic_pipeline(value: int, key_byte: int, order: Sequence[str]) -> int:
    result = value & 0xFF
    key_val = key_byte & 0xFF
    for stage in order:
        if stage == "xor":
            result ^= key_val
        elif stage == "rotate":
            result = _ror8(result, key_val & 7)
        elif stage == "rotate_left":
            result = _rol8(result, key_val & 7)
        else:  # pragma: no cover - guarded by supported set checks
            raise ValueError(f"unsupported symbolic stage: {stage}")
    return result & 0xFF


def derive_symbolic_key_constraints(
    encoded: str | bytes,
    expected: str | bytes,
    order: Sequence[str],
    *,
    max_positions: int = 32,
) -> Optional[SymbolicKeyConstraints]:
    """Derive per-byte key constraints for XOR/rotate stage combinations."""

    order_tuple = tuple(order)
    if not order_tuple:
        return SymbolicKeyConstraints(order=order_tuple, allowed_values=tuple(), positions_checked=0)

    if any(stage not in _SUPPORTED_SYMBOLIC_PRIMITIVES for stage in order_tuple):
        return None

    encoded_bytes = _ensure_bytes(encoded)
    expected_bytes = _ensure_bytes(expected)
    limit = min(len(encoded_bytes), len(expected_bytes), max_positions)

    allowed_sets: List[frozenset[int]] = []
    for index in range(limit):
        byte_in = encoded_bytes[index]
        target = expected_bytes[index]
        matches = {
            candidate
            for candidate in range(256)
            if _apply_symbolic_pipeline(byte_in, candidate, order_tuple) == target
        }
        allowed_sets.append(frozenset(matches))

    return SymbolicKeyConstraints(
        order=order_tuple,
        allowed_values=tuple(allowed_sets),
        positions_checked=limit,
    )


@dataclass(frozen=True)
class TransformDiscoveryResult:
    """Outcome of the rotate/XOR/permute pipeline search."""

    success: bool
    order: tuple[str, ...]
    stages: tuple[TransformStageApplication, ...]
    diff: Optional[Dict[str, Any]] = None
    constraints: Optional[SymbolicKeyConstraints] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "order": list(self.order),
            "diff": self.diff,
            "stages": [stage.to_dict() for stage in self.stages],
            "constraints": self.constraints.to_dict() if self.constraints else None,
        }


_TRANSFORM_PRIMITIVES: "OrderedDict[str, Callable[[bytes, bytes], bytes]]" = OrderedDict(
    [
        ("permute", _rotating_permute_prga),
        ("xor", _initv4_xor_stage),
        ("rotate", _initv4_rotate_stage),
        ("rotate_left", _invert_rotate_stage),
    ]
)


def _score_transform_diff(diff: Optional[Dict[str, Any]], expected_len: int) -> int:
    """Return an ordering score for a diff result (higher is better)."""

    if not diff:
        return expected_len
    if diff.get("match"):
        return expected_len
    index = diff.get("index")
    if isinstance(index, int):
        return index
    return -1


def discover_transform_order(
    encoded: str | bytes,
    expected_decoded: str | bytes,
    key: str | bytes,
    *,
    primitives: Optional[Mapping[str, Callable[[bytes, bytes], bytes]]] = None,
    max_length: int = 4,
) -> TransformDiscoveryResult:
    """Search combinations of primitives to recover the decode pipeline order."""

    if max_length < 1:
        raise ValueError("max_length must be at least 1")

    key_bytes = _ensure_bytes(key)
    encoded_bytes = _ensure_bytes(encoded)
    expected_bytes = _ensure_bytes(expected_decoded)

    if primitives is None:
        primitive_items = tuple(_TRANSFORM_PRIMITIVES.items())
    else:
        primitive_items = tuple(OrderedDict(primitives).items())

    if not primitive_items:
        raise ValueError("no transform primitives provided")

    best_result: Optional[TransformDiscoveryResult] = None
    best_score = -1

    for length in range(1, max_length + 1):
        for combo in itertools.product(primitive_items, repeat=length):
            order_names = [name for name, _ in combo]
            constraints = derive_symbolic_key_constraints(
                encoded_bytes, expected_bytes, order_names
            )
            if constraints is not None and not constraints.satisfiable():
                continue
            data = encoded_bytes
            stage_results: List[TransformStageApplication] = []
            for name, func in combo:
                data = func(data, key_bytes)
                stage_results.append(TransformStageApplication(name=name, output=data))

            if data == expected_bytes:
                return TransformDiscoveryResult(
                    success=True,
                    order=tuple(order_names),
                    stages=tuple(stage_results),
                    diff=None,
                    constraints=constraints,
                )

            diff = byte_diff(data, expected_bytes)
            score = _score_transform_diff(diff, len(expected_bytes))
            if score > best_score:
                best_score = score
                best_result = TransformDiscoveryResult(
                    success=False,
                    order=tuple(order_names),
                    stages=tuple(stage_results),
                    diff=diff,
                    constraints=constraints,
                )

    if best_result is not None:
        return best_result

    return TransformDiscoveryResult(
        success=False,
        order=tuple(),
        stages=tuple(),
        diff=byte_diff(encoded_bytes, expected_bytes),
    )


@dataclass(frozen=True)
class ParityStageResult:
    """Result of comparing a single initv4 pipeline stage."""

    name: str
    actual: bytes
    expected: bytes
    match: bool
    diff: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ExactUpcodeParityReport:
    """Summary of an initv4 parity run across permutation/XOR/rotate stages."""

    success: bool
    stages: Mapping[str, ParityStageResult]
    expected: Mapping[str, bytes]
    failure_stage: Optional[str] = None
    failure_message: Optional[str] = None
    discovery: Optional[TransformDiscoveryResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "failure_stage": self.failure_stage,
            "failure_message": self.failure_message,
            "stages": {
                name: {
                    "match": stage.match,
                    "actual_hex": stage.actual.hex(),
                    "expected_hex": stage.expected.hex(),
                    "diff": stage.diff,
                }
                for name, stage in self.stages.items()
            },
            "discovery": self.discovery.to_dict() if self.discovery else None,
        }

    @property
    def discovered_order(self) -> Optional[tuple[str, ...]]:
        if self.discovery:
            return self.discovery.order
        return None


class ParityMismatchError(AssertionError):
    """Raised when the initv4 parity harness detects a mismatch."""

    def __init__(self, report: ExactUpcodeParityReport):
        message = report.failure_message or "initv4 parity mismatch"
        super().__init__(message)
        self.report = report


_PARITY_STAGE_ORDER = ("permute", "xor", "rotate")


def _derive_expected_stages(expected_final: bytes, key: bytes) -> Dict[str, bytes]:
    rotate_expected = expected_final
    xor_expected = _invert_rotate_stage(rotate_expected, key)
    permute_expected = _initv4_xor_stage(xor_expected, key)
    return {
        "permute": permute_expected,
        "xor": xor_expected,
        "rotate": rotate_expected,
    }


def _initv4_pipeline_steps(encoded: bytes, key: bytes) -> Dict[str, bytes]:
    permute_stage = _rotating_permute_prga(encoded, key)
    xor_stage = _initv4_xor_stage(permute_stage, key)
    rotate_stage = _initv4_rotate_stage(xor_stage, key)
    return {
        "permute": permute_stage,
        "xor": xor_stage,
        "rotate": rotate_stage,
    }


def _normalise_expected_stage_map(
    expected_final: bytes,
    key: bytes,
    overrides: Optional[Mapping[str, str | bytes]] = None,
) -> Dict[str, bytes]:
    expected_stages = _derive_expected_stages(expected_final, key)
    if not overrides:
        return expected_stages

    for name, value in overrides.items():
        if name not in _PARITY_STAGE_ORDER:
            raise ValueError(f"unknown parity stage override: {name}")
        expected_stages[name] = _ensure_bytes(value)
    return expected_stages


def exact_upcode_parity_test(
    encoded: str | bytes,
    expected_decoded: str | bytes,
    key: str | bytes,
    *,
    expected_stage_outputs: Optional[Mapping[str, str | bytes]] = None,
    strict: bool = True,
) -> ExactUpcodeParityReport:
    """Verify initv4 pipeline parity across permutation, XOR, and rotate stages."""

    if not key:
        raise ValueError("a non-empty key is required for parity testing")

    key_bytes = _ensure_bytes(key)
    encoded_bytes = _ensure_bytes(encoded)
    expected_bytes = _ensure_bytes(expected_decoded)

    discovery = discover_transform_order(
        encoded_bytes, expected_bytes, key_bytes, max_length=len(_PARITY_STAGE_ORDER)
    )

    stages = _initv4_pipeline_steps(encoded_bytes, key_bytes)
    expected_stages = _normalise_expected_stage_map(
        expected_bytes, key_bytes, expected_stage_outputs
    )

    stage_results: "OrderedDict[str, ParityStageResult]" = OrderedDict()
    failure_stage: Optional[str] = None
    failure_message: Optional[str] = None

    for stage_name in _PARITY_STAGE_ORDER:
        actual = stages[stage_name]
        expected_stage = expected_stages[stage_name]
        match = actual == expected_stage
        diff: Optional[Dict[str, Any]] = None
        if not match:
            diff = byte_diff(actual, expected_stage)
            if failure_stage is None:
                index = diff.get("index")
                a_byte = diff.get("a_byte")
                b_byte = diff.get("b_byte")
                failure_stage = stage_name
                failure_message = (
                    "Stage {stage} mismatch at index {idx}: actual={a:#04x} expected={b:#04x}\n"
                    "actual context: {a_ctx}\nexpected context: {b_ctx}\n"
                    "lengths: actual={a_len} expected={b_len}"
                ).format(
                    stage=stage_name,
                    idx=index if isinstance(index, int) else "?",
                    a=a_byte if isinstance(a_byte, int) else -1,
                    b=b_byte if isinstance(b_byte, int) else -1,
                    a_ctx=diff.get("a_context"),
                    b_ctx=diff.get("b_context"),
                    a_len=diff.get("a_len"),
                    b_len=diff.get("b_len"),
                )

        stage_results[stage_name] = ParityStageResult(
            name=stage_name,
            actual=actual,
            expected=expected_stage,
            match=match,
            diff=diff,
        )

    if failure_stage is not None:
        notes: List[str] = []
        if discovery.success:
            notes.append("discovered pipeline order: " + " -> ".join(discovery.order))
        elif discovery.order:
            idx = discovery.diff.get("index") if discovery.diff else None
            notes.append(
                "best pipeline guess {order} diverged at index {idx}".format(
                    order=" -> ".join(discovery.order),
                    idx=idx if isinstance(idx, int) else "?",
                )
            )
        if discovery.diff and discovery.diff.get("match") is False:
            notes.append(
                "transform diff context: {ctx}".format(
                    ctx=discovery.diff.get("a_context")
                )
            )
        if notes:
            extra = "; ".join(notes)
            failure_message = f"{failure_message}\n{extra}" if failure_message else extra

    report = ExactUpcodeParityReport(
        success=failure_stage is None,
        stages=stage_results,
        expected=expected_stages,
        failure_stage=failure_stage,
        failure_message=failure_message,
        discovery=discovery,
    )

    if not report.success and strict:
        raise ParityMismatchError(report)

    return report


def _iter_key_variants_from_base(key: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield unique small key variations derived from ``key``."""

    seen: set[bytes] = set()

    def _yield(name: str, candidate: bytes) -> Iterator[tuple[str, bytes]]:
        if candidate in seen:
            return
        seen.add(candidate)
        yield name, candidate

    yield from _yield("base", key)

    reversed_key = key[::-1]
    if reversed_key != key:
        yield from _yield("reversed", reversed_key)

    try:
        ascii_key = key.decode("ascii")
    except UnicodeDecodeError:
        ascii_key = None

    if ascii_key:
        upper_key = ascii_key.upper().encode("ascii")
        lower_key = ascii_key.lower().encode("ascii")
        if upper_key != key:
            yield from _yield("upper", upper_key)
        if lower_key != key and lower_key != upper_key:
            yield from _yield("lower", lower_key)

    suffix_null = key + b"\x00"
    yield from _yield("suffix_null", suffix_null)

    prefix_null = b"\x00" + key
    yield from _yield("prefix_null", prefix_null)


def bruteforce_key_variants(
    key: str | bytes,
    data: str | bytes,
    *,
    max_results: int | None = 100,
    enable_native: Optional[bool] = None,
    constraints: Optional[SymbolicKeyConstraints] = None,
) -> List[BruteforceResult]:
    """Try small manipulations of ``key`` to decode ``data`` into Lua.

    If ``constraints`` are provided, variants violating the symbolic
    conditions are skipped before attempting candidate transforms.
    """

    key_bytes = _ensure_bytes(key)
    data_bytes = _ensure_bytes(data)

    results: List[BruteforceResult] = []
    seen_fingerprints: set[tuple[str, str, str]] = set()

    for variant_name, variant_key in _iter_key_variants_from_base(key_bytes):
        if constraints is not None and not constraints.is_key_compatible(variant_key):
            continue
        for method, transform in prga_candidates(
            variant_key, enable_native=enable_native
        ).items():
            payload = transform(data_bytes)
            text = payload.decode("utf-8", errors="ignore")
            if not text or not _looks_like_lua(text):
                continue
            fingerprint = (variant_name, method, text[:160])
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            valid, detail = _validate_with_emulator(payload)
            result = BruteforceResult(
                key_variant=variant_name,
                method=method,
                key=variant_key,
                payload=payload,
                text=text,
                emulator_status="ok" if valid else detail,
            )
            results.append(result)
            if max_results is not None and len(results) >= max_results:
                return results
    return results


def _validate_with_emulator(candidate: bytes) -> tuple[bool, str]:
    """Round-trip ``candidate`` through the VM emulator and report status."""

    try:
        simulator = LuaVMSimulator(trace=False)
        program = VMFunction(
            constants=[candidate],
            instructions=[
                VMInstruction("LOADK", a=0, aux={"b_mode": "const", "const_b": candidate}),
                VMInstruction(
                    "RETURN",
                    a=0,
                    b=2,
                    aux={"b_mode": "immediate", "immediate_b": 2},
                ),
            ],
            register_count=1,
        )
        output = simulator.run(program, args=[])
    except Exception as exc:  # pragma: no cover - defensive
        _LOGGER.debug("emulator validation failed", exc_info=True)
        return False, f"exception: {exc}"

    if isinstance(output, (bytes, bytearray)):
        emulator_bytes = bytes(output)
    elif output is None:
        emulator_bytes = b""
    else:
        emulator_bytes = str(output).encode("utf-8", errors="ignore")

    if emulator_bytes == candidate:
        return True, "match"

    diff = byte_diff(candidate, emulator_bytes)
    detail = (
        f"mismatch@{diff['index']} (a={diff['a_byte']!r} b={diff['b_byte']!r})"
        if not diff.get("match")
        else "mismatch"
    )
    _LOGGER.debug("emulator diff: %s", diff)
    return False, detail


def _iter_probe_keys(extra_keys: Iterable[str | bytes] | None = None) -> Iterator[bytes]:
    yielded: set[bytes] = set()
    for value in range(256):
        key_bytes = bytes([value])
        yielded.add(key_bytes)
        yield key_bytes
    if not extra_keys:
        return
    for entry in extra_keys:
        key_bytes = _ensure_bytes(entry)
        if key_bytes in yielded:
            continue
        yielded.add(key_bytes)
        yield key_bytes


def _format_key_token(key: bytes) -> str:
    if len(key) == 1:
        return f"byte_{key[0]:02x}"
    digest = hashlib.sha1(key).hexdigest()[:10]
    return f"hash_{digest}"


def _compute_transform_spec_hash(
    method: str, transform: Callable[[str | bytes], bytes]
) -> str:
    """Return a stable hash describing the transform implementation."""

    base = transform
    closure = getattr(transform, "__closure__", None)
    if closure:
        for cell in closure:
            try:
                value = cell.cell_contents
            except ValueError:  # pragma: no cover - empty cell
                continue
            if callable(value) and hasattr(value, "__code__"):
                base = value
                break

    code = getattr(base, "__code__", None)
    hasher = hashlib.sha1()
    hasher.update(method.encode("utf-8", "ignore"))
    if code:
        hasher.update(code.co_code)
        hasher.update(str(code.co_consts).encode("utf-8", "ignore"))
        hasher.update(str(code.co_names).encode("utf-8", "ignore"))
    else:  # pragma: no cover - fallback for callables without __code__
        hasher.update(repr(base).encode("utf-8", "ignore"))
    return hasher.hexdigest()


def _looks_like_lua(text: str) -> bool:
    return bool(_CANDIDATE_TOKEN_RE.search(text))


def _summarise_fragment_metadata(
    metadata: Optional[Mapping[str, object]]
) -> Dict[str, object]:
    summary: Dict[str, object] = {}
    if not isinstance(metadata, Mapping):
        return summary
    if "fragment_index" in metadata and metadata["fragment_index"] is not None:
        summary["fragment_index"] = metadata["fragment_index"]
    if "entropy" in metadata and metadata["entropy"] is not None:
        summary["entropy"] = metadata["entropy"]
    if metadata.get("classification"):
        summary["classification"] = metadata["classification"]
    if "length" in metadata and metadata["length"] is not None:
        summary["length"] = metadata["length"]
    return summary


def run_probe_harness(
    path: str | Path,
    *,
    extra_keys: Iterable[str | bytes] | None = None,
    output_dir: str | Path = "candidates",
    max_results: int | None = 100,
    sample_bytes: int | None = None,
    max_workers: int | None = None,
    snapshot_path: str | Path | None = None,
    resume: bool = False,
    snapshot: SnapshotManager | None = None,
    enable_native_crypto: Optional[bool] = None,
) -> List[Path]:
    """Run ``probe_prga`` against a file and persist promising candidates.

    The harness inspects every single-byte key as well as any ``extra_keys``
    provided by the caller.  Detected fragments are ranked by entropy so that
    high-entropy payloads are probed before lower-entropy regions.  Outputs that
    contain common Lua tokens are written into ``output_dir`` for manual review.
    Use ``max_results`` to cap the total number of persisted artefacts and
    ``sample_bytes`` to work on a prefix of the input.  The function returns the
    list of saved paths in filesystem order.

    Provide ``snapshot_path`` (or an explicit :class:`SnapshotManager`) to
    persist progress, enabling long-running searches to be resumed by setting
    ``resume=True`` on subsequent invocations.  Snapshots only store hashed key
    metadata so raw keys are never written to disk.

    Each invocation writes ``run_manifest.json`` into ``output_dir`` capturing
    the run timestamp, git revision, salted key hashes, attempted transforms,
    and saved candidates for reproducibility.  Set ``enable_native_crypto`` to
    ``True`` to prefer accelerated PRGA candidates (when available) or ``False``
    to force the pure-Python implementations regardless of configuration.
    """

    file_path = Path(path)
    data = file_path.read_bytes()
    if sample_bytes is not None:
        data = data[:sample_bytes]
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    benchmarks = benchmark_recorder()
    benchmark_snapshot = benchmarks.take_snapshot()

    use_native_crypto = _should_use_native_crypto(enable_native_crypto)
    native_backend = _native_crypto_backend()

    manifest_path = output_root / "run_manifest.json"
    salt = os.urandom(16)
    manifest_attempts: List[Dict[str, object]] = []
    manifest_results: List[Dict[str, object]] = []
    manifest_keys: List[Dict[str, object]] = []
    manifest_data: Dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": _current_git_commit(),
        "target_file": str(file_path),
        "output_dir": str(output_root),
        "resume": resume,
        "salt": salt.hex(),
        "keys": manifest_keys,
        "transforms_attempted": manifest_attempts,
        "results_saved": manifest_results,
        "native_crypto": {
            "requested": enable_native_crypto,
            "enabled": use_native_crypto,
            "available": bool(native_backend),
            "backend": native_backend,
        },
    }
    key_ref_map: Dict[str, str] = {}
    attempt_entries: Dict[int, Dict[str, object]] = {}

    if snapshot is not None and snapshot_path is not None:
        raise ValueError("provide either snapshot or snapshot_path, not both")

    manager = snapshot
    if manager is None and snapshot_path is not None:
        manager = SnapshotManager(snapshot_path)

    saved: List[Path] = []
    diff_context: Dict[str, List[tuple[str, str]]] = {}

    fragment_sources: List[tuple[str, bytes, Dict[str, object] | None, str]] = []
    try:
        entropy_records = entropy_detector(file_path)
    except Exception:  # pragma: no cover - defensive best-effort
        _LOGGER.debug("entropy detection failed", exc_info=True)
        entropy_records = []

    for record in entropy_records:
        decoded = record.get("decoded")
        if not isinstance(decoded, str):
            continue
        try:
            payload = decoded.encode("latin-1")
        except UnicodeEncodeError:
            payload = decoded.encode("utf-8", errors="ignore")
        if not payload:
            continue
        index = record.get("fragment_index")
        if isinstance(index, int):
            source_label = f"fragment{index:04d}"
        else:
            source_label = "fragment"
        fragment_sha = hashlib.sha256(payload).hexdigest()
        fragment_sources.append((source_label, payload, record, fragment_sha))

    full_fragment_sha = hashlib.sha256(data).hexdigest()
    sources: List[tuple[str, bytes, Dict[str, object] | None, str]] = fragment_sources
    sources.append(("full", data, None, full_fragment_sha))

    if manager:
        if resume:
            manager.load()
        else:
            manager.reset()
        manager.update_metadata(
            target_file=str(file_path),
            output_dir=str(output_root),
            resume=resume,
            input_sha=full_fragment_sha,
        )
        manager.save()
        preexisting_saved = manager.saved_candidate_count()
    else:
        preexisting_saved = 0

    pool = _ProbeWorkerPool(max_workers=max_workers)
    for key_bytes in _iter_probe_keys(extra_keys):
        key_token = _format_key_token(key_bytes)
        key_sha = hashlib.sha256(key_bytes).hexdigest()
        key_ref = key_ref_map.get(key_sha)
        if key_ref is None:
            key_ref = f"k{len(key_ref_map):04d}"
            key_ref_map[key_sha] = key_ref
            manifest_keys.append(
                {
                    "ref": key_ref,
                    "hmac": _compute_key_hmac(salt, key_bytes),
                    "length": len(key_bytes),
                }
            )
        candidates = prga_candidates(key_bytes, enable_native=use_native_crypto)
        candidate_specs = {
            method: (transform, _compute_transform_spec_hash(method, transform))
            for method, transform in candidates.items()
        }
        for source_label, payload_bytes, metadata, fragment_sha in sources:
            if not payload_bytes:
                continue
            for method, (transform, transform_sha) in candidate_specs.items():
                if manager and manager.has_attempted(fragment_sha, transform_sha, key_sha):
                    continue
                job_index = pool.submit(
                    source_label,
                    payload_bytes,
                    metadata,
                    key_token,
                    method,
                    transform,
                    fragment_sha=fragment_sha,
                    key_sha=key_sha,
                    transform_sha=transform_sha,
                )
                attempt_entry: Dict[str, object] = {
                    "job_index": job_index,
                    "fragment_label": source_label,
                    "fragment_sha": fragment_sha,
                    "transform": method,
                    "transform_sha": transform_sha,
                    "key_ref": key_ref,
                    "status": "queued",
                }
                manifest_attempts.append(attempt_entry)
                attempt_entries[job_index] = attempt_entry

    pool.close()

    for job, candidate in pool.iter_results():
        metadata_summary = _summarise_fragment_metadata(job.metadata)
        diff_notes: List[str] = []
        saved_path: Optional[Path] = None
        candidate_sha: Optional[str] = None
        emulator_status = "no_candidate"
        status = "no-candidate"

        if candidate is not None:
            candidate_sha = candidate.sha256
            payload = candidate.payload
            text = candidate.text
            valid, detail = _validate_with_emulator(payload)
            emulator_status = "ok" if valid else detail
            status = "candidate"
            previous_entries = diff_context.setdefault(job.source_label, [])
            for prev_method, prev_text in previous_entries:
                diff_info = diff_candidates(prev_text, text)
                if diff_info.get("match"):
                    continue
                note = diff_info.get("summary") or ""
                if not note:
                    suggestions = diff_info.get("suggestions") or []
                    if suggestions:
                        note = suggestions[0]
                if not note:
                    ops = diff_info.get("operations") or []
                    for op in ops:
                        if op.get("tag") != "equal":
                            note = op.get("summary", "")
                            if note:
                                break
                if note:
                    diff_notes.append(f"vs {prev_method}: {note}")
            previous_entries.append((job.method, text))

            details: List[str] = []
            index = metadata_summary.get("fragment_index")
            if index is not None:
                details.append(f"index={index}")
            entropy = metadata_summary.get("entropy")
            if entropy is not None:
                details.append(f"entropy={entropy}")
            classification = metadata_summary.get("classification")
            if classification:
                details.append(f"class={classification}")
            length = metadata_summary.get("length")
            if length is not None:
                details.append(f"len={length}")

            extra = (
                f"-- fragment: {job.source_label} ({', '.join(details)})\n"
                if details
                else ""
            )
            can_save = max_results is None or (
                len(saved) + preexisting_saved < max_results
            )
            if can_save:
                output_path = (
                    output_root
                    / f"{file_path.name}.{job.source_label}.{job.method}.{job.key_token}.lua"
                )
                metadata_header = (
                    f"-- candidate generated by {job.method} with key token {job.key_token}\n"
                    f"-- source: {file_path}\n"
                    f"-- emulator validation: {emulator_status}\n"
                    f"{extra}"
                )
                if diff_notes:
                    metadata_header += "".join(
                        f"-- diff {note}\n" for note in diff_notes[:2]
                    )
                output_path.write_text(
                    metadata_header + text,
                    encoding="utf-8",
                    errors="ignore",
                )
                saved.append(output_path)
                saved_path = output_path
                status = "saved"
            else:
                status = "skipped_max_results"

        attempt_entry = attempt_entries.get(job.index)
        if attempt_entry is not None:
            attempt_entry["status"] = status
            attempt_entry["emulator_status"] = emulator_status
            if candidate_sha:
                attempt_entry["candidate_sha"] = candidate_sha
                attempt_entry["candidate_length"] = len(candidate.payload)

        if status == "saved" and saved_path and candidate_sha:
            manifest_results.append(
                {
                    "path": str(saved_path),
                    "sha256": candidate_sha,
                    "fragment_label": job.source_label,
                    "transform": job.method,
                    "key_ref": key_ref_map.get(job.key_sha),
                    "emulator_status": emulator_status,
                }
            )

        if manager:
            manager.record_prga_attempt(
                fragment_sha=job.fragment_sha,
                transform_sha=job.transform_sha,
                key_sha=job.key_sha,
                key_token=job.key_token,
                method=job.method,
                source_label=job.source_label,
                status=status,
                candidate_sha=candidate_sha,
                saved_path=str(saved_path) if saved_path else None,
                metadata=metadata_summary,
                diff_notes=diff_notes,
                emulator_status=emulator_status,
            )
            if saved_path and candidate_sha:
                manager.record_candidate(
                    path=str(saved_path),
                    sha256=candidate_sha,
                    method=job.method,
                    key_token=job.key_token,
                    source_label=job.source_label,
                    metadata=metadata_summary,
                    diff_notes=diff_notes,
                    emulator_status=emulator_status,
                )
            manager.save()

    pool.join()
    if manager:
        manager.save()
    hotspots = benchmarks.summarize(benchmark_snapshot)
    manifest_data["hotspots"] = [
        {
            "category": entry["category"],
            "total": entry["total"],
            "count": entry["count"],
            "average": entry["average"],
            "max": entry["max"],
            "samples": entry.get("samples", []),
        }
        for entry in hotspots
    ]
    manifest_data["hotspot_report"] = benchmarks.render_report(benchmark_snapshot)
    if hotspots:
        _LOGGER.info("Benchmark hotspots:\n%s", manifest_data["hotspot_report"])
    write_json(manifest_path, manifest_data, sort_keys=True)
    return saved


def clear_transform_cache() -> None:
    """Clear the shared transform cache (primarily for tests)."""

    _TRANSFORM_CACHE.clear()
