import os
import base64
import binascii
import json
import logging
import re
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, TypeVar, cast

from .exceptions import VMEmulationError
from .vm import LuraphVM

T = TypeVar("T")
R = TypeVar("R")


def setup_logging(level: int = logging.INFO) -> None:
    """Setup logging configuration"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug("Logging setup complete.")


def validate_file(filepath: str) -> bool:
    """Validate that a file exists and is readable"""
    path = Path(filepath)
    try:
        result = path.exists() and path.is_file() and os.access(path, os.R_OK)
        logging.debug(f"Validating file '{filepath}': {result}")
        return result
    except Exception as e:
        logging.error(f"Error validating file '{filepath}': {e}")
        return False


def create_output_path(input_path: str, suffix: str = "_deob.lua") -> str:
    """Return a deterministic output path next to ``input_path``."""

    path = Path(input_path)
    new_name = path.stem + suffix
    output_path = str(path.with_name(new_name))
    logging.debug("Created output path '%s' from input '%s'", output_path, input_path)
    return output_path


def safe_write_file(filepath: str, content: str, encoding: str = 'utf-8') -> bool:
    """Safely write content to file with logging"""
    path = Path(filepath)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding=encoding) as f:
            f.write(content)
        logging.debug(f"Successfully wrote to file '{filepath}'")
        return True
    except Exception as e:
        logging.error(f"Failed to write file '{filepath}': {e}")
        return False


def safe_read_file(filepath: str, encoding: str = 'utf-8') -> Optional[str]:
    """Safely read content from file with logging"""
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        logging.warning(f"File does not exist or is not a file: '{filepath}'")
        return None
    try:
        with open(path, 'r', encoding=encoding, errors='ignore') as f:
            content = f.read()
        logging.debug(f"Successfully read file '{filepath}' ({len(content)} bytes)")
        return content
    except Exception as e:
        logging.error(f"Failed to read file '{filepath}': {e}")
        return None


# Terminal helpers used by the interactive GUI

_COLOR_CODES = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


def colorize_text(text: str, color: str, bold: bool = False) -> str:
    """Return *text* wrapped in ANSI color codes."""
    code = _COLOR_CODES.get(color, "0")
    style = "1;" if bold else ""
    return f"\033[{style}{code}m{text}\033[0m"


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_user_input(prompt: str) -> str:
    """Wrapper around :func:`input` allowing easier testing."""
    try:
        return input(prompt)
    except EOFError:
        return ""


# Simple decoding helpers used across the deobfuscator


def _is_printable(s: str) -> bool:
    return all(32 <= ord(c) <= 126 or c in "\r\n\t" for c in s)


def strip_non_printable(text: str) -> str:
    """Return *text* with control characters removed."""

    allowed = {"\n", "\r", "\t", " "}
    return "".join(ch for ch in text if 32 <= ord(ch) <= 126 or ch in allowed)


def decrypt_lph_string(data: str, key: str = "hxsk0st7cyvjkicxnibhbm") -> str:
    """XOR-decrypt *data* using the provided *key*.

    The helper mirrors the simple LPH string encryption used by Luraph where a
    hard-coded key is XORed with each byte of the payload.  If decryption fails
    the original string is returned unchanged.
    """

    try:
        decoded_chars = [
            chr(ord(ch) ^ ord(key[i % len(key)])) for i, ch in enumerate(data)
        ]
        return "".join(decoded_chars)
    except Exception:
        return data


def decode_numeric_array(text: str) -> str:
    pattern = re.compile(r"\{(\s*\d+(?:\s*,\s*\d+)*)\s*\}")

    def repl(match: re.Match) -> str:
        nums = [int(n.strip()) for n in match.group(1).split(',')]
        try:
            result = ''.join(chr(n) for n in nums)
            if _is_printable(result):
                return f'"{result}"'
        except Exception:
            pass
        return match.group(0)

    return pattern.sub(repl, text)


def decode_base64_strings(text: str) -> str:
    pattern = re.compile(r'"([A-Za-z0-9+/=]{8,})"')

    def repl(match: re.Match) -> str:
        s = match.group(1)
        try:
            decoded = base64.b64decode(s).decode('utf-8')
            if _is_printable(decoded):
                return f'"{decoded}"'
        except Exception:
            pass
        return match.group(0)

    return pattern.sub(repl, text)


def decode_numeric_escapes(text: str) -> str:
    pattern = re.compile(r'"((?:\\\d{1,3})+)"')

    def repl(match: re.Match) -> str:
        nums = re.findall(r'\\(\d{1,3})', match.group(1))
        try:
            decoded = ''.join(chr(int(n)) for n in nums)
            if _is_printable(decoded):
                return f'"{decoded}"'
        except Exception:
            pass
        return match.group(0)

    return pattern.sub(repl, text)


def decode_simple_obfuscations(text: str) -> str:
    """Apply all lightweight decoders to *text*."""
    text = decode_numeric_array(text)
    text = decode_base64_strings(text)
    text = decode_numeric_escapes(text)
    return text


class LuaFormatter:
    """Lightweight Lua pretty printer with deterministic whitespace rules."""

    def __init__(self, indent: str = "    ") -> None:
        self.indent = indent

    def format_source(self, source: str) -> str:
        normalised = self._normalise_lines(source)
        if not normalised:
            return ""
        tables = self._format_tables(normalised)
        indented = self._apply_indentation(tables.split("\n"))
        cleaned = self._strip_trailing_blank_lines(indented)
        rendered = "\n".join(cleaned).rstrip()
        return rendered

    # -- Normalisation helpers -------------------------------------
    def _normalise_lines(self, text: str) -> str:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.rstrip() for line in text.split("\n")]
        compact: List[str] = []
        blank_run = 0
        for line in lines:
            if line.strip():
                compact.append(line)
                blank_run = 0
            else:
                blank_run += 1
                if blank_run == 1:
                    compact.append("")
        result = "\n".join(compact).strip("\n")
        return result

    def _strip_comment(self, line: str) -> str:
        if "--" not in line:
            return line
        in_single = False
        in_double = False
        i = 0
        length = len(line)
        while i < length:
            ch = line[i]
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double and line.startswith("--", i):
                return line[:i]
            if ch == "\\":
                i += 2
                continue
            i += 1
        return line

    def _apply_indentation(self, lines: List[str]) -> List[str]:
        indent_level = 0
        result: List[str] = []
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped:
                result.append("")
                continue
            code = self._strip_comment(stripped).strip()
            if self._dedent_before(code):
                indent_level = max(indent_level - 1, 0)
            result.append(f"{self.indent * indent_level}{stripped}")
            indent_level += self._indent_after(code)
        return result

    def _dedent_before(self, code: str) -> bool:
        return code.startswith(("end", "until", "elseif", "else"))

    def _indent_after(self, code: str) -> int:
        if not code:
            return 0
        if code.startswith("elseif") or code.startswith("else"):
            return 1
        if code.startswith("repeat"):
            return 1
        if code.startswith("function") or code.startswith("local function"):
            return 1
        if re.search(r"\bthen\b", code):
            return 1
        if re.search(r"\bdo\b", code) and not code.startswith("until"):
            return 1
        return 0

    def _strip_trailing_blank_lines(self, lines: List[str]) -> List[str]:
        trimmed = list(lines)
        while trimmed and not trimmed[-1].strip():
            trimmed.pop()
        return trimmed

    # -- Table formatting -------------------------------------------
    def _format_tables(self, text: str) -> str:
        table_re = re.compile(r"\{([^{}\n]*)\}")

        def repl(match: re.Match[str]) -> str:
            body = match.group(1)
            if not body.strip():
                return "{}"
            parts = [part.strip() for part in body.split(",") if part.strip()]
            formatted: List[str] = []
            for part in parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    formatted.append(f"{key.strip()} = {value.strip()}")
                else:
                    formatted.append(part.strip())
            return "{ " + ", ".join(formatted) + " }"

        return table_re.sub(repl, text)


def extract_embedded_json(content: str) -> Optional[str]:
    """Return the first JSON snippet found inside a Lua string.

    Some obfuscators store JSON-encoded payloads inside Lua long strings or
    quoted literals.  This helper scans the input for any string literal that
    looks like JSON and verifies it with :func:`json.loads`.
    """

    # Search Lua long bracket strings [[...]] first as they can span multiple
    # lines without escaping.  If that fails fall back to regular quoted
    # strings.
    patterns = [r"\[\[(.*?)\]\]", r'"(.*?)"', r"'(.*?)'"]
    for pat in patterns:
        for match in re.findall(pat, content, re.DOTALL):
            candidate = match.strip()
            if candidate.startswith("{") or candidate.startswith("["):
                try:
                    json.loads(candidate)
                    return candidate
                except Exception:
                    continue
    return None


def decode_json_format(content: str) -> Optional[str]:
    """Decode Luraph JSON-based payloads if present."""
    try:
        data = json.loads(content)
    except Exception:
        return None
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not (isinstance(first, list) and len(first) == 2):
        return None
    hex_key, stub = first
    try:
        key_bytes = binascii.unhexlify(hex_key)
    except Exception:
        return None

    decoded_segments: List[str] = []
    for seg in data[1:]:
        if not isinstance(seg, str):
            continue
        try:
            decoded = ''.join(chr(ord(ch) ^ key_bytes[i % len(key_bytes)]) for i, ch in enumerate(seg))
            if _is_printable(decoded):
                decoded_segments.append(decoded)
            else:
                decoded_segments.append(seg)
        except Exception:
            decoded_segments.append(seg)
    return stub + ''.join(decoded_segments)


def decode_superflow(content: str) -> Optional[str]:
    """Decode ``superflow_bytecode_ext0`` blobs if present."""
    match = re.search(r'superflow_bytecode_ext0\s*=\s*"([^"]+)"', content)
    if not match:
        return None
    data = bytes(int(n) for n in re.findall(r'\\(\d{1,3})', match.group(1)))
    for key in range(256):
        xored = bytes(b ^ key for b in data)
        try:
            out = zlib.decompress(xored)
            return out.decode('utf-8', errors='ignore')
        except Exception:
            continue
    return None


def decode_virtual_machine(content: Any, handler=None) -> Optional[str]:
    """Execute a minimal stack-based VM description if present.

    The function expects *content* to be a JSON object with two keys:
    ``constants`` (a list of constant values) and ``bytecode`` (a list of
    instructions).  Each instruction is itself a list whose first element is the
    opcode name followed by zero or more integer arguments.  A small but growing
    set of opcodes is supported by :class:`LuraphVM`, including arithmetic,
    comparisons, table manipulation, branching and simple function calls via a
    tiny global environment.

    ``handler`` may be a version specific module exposing a ``process`` function
    that can modify the VM before execution.
    """

    vm = LuraphVM()
    try:
        vm.load_bytecode(content)
    except VMEmulationError:
        return None
    if handler is not None:
        handler.process(vm)
    try:
        result = vm.run()
    except VMEmulationError:
        return None
    if isinstance(result, (str, int, float)):
        result_str = str(result)
        if _is_printable(result_str):
            return result_str
    return None


def run_parallel(
    items: Sequence[T],
    worker: Callable[[T], R],
    *,
    jobs: int = 1,
    timer: Callable[[], float] | None = None,
) -> Tuple[List[R], float]:
    """Process ``items`` with ``worker`` possibly using a thread pool.

    Returns a tuple ``(results, duration)`` where *duration* is measured in
    seconds using :func:`time.perf_counter` unless a custom ``timer`` callable is
    provided.  Results are ordered to match the input sequence.  Exceptions raised
    by ``worker`` propagate to the caller.
    """

    if not items:
        return [], 0.0

    timer = timer or time.perf_counter
    start = timer()

    if jobs <= 1 or len(items) == 1:
        results = [worker(item) for item in items]
        return results, timer() - start

    completed: List[Tuple[int, R]] = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(worker, item): idx for idx, item in enumerate(items)}
        for future in as_completed(futures):
            idx = futures[future]
            completed.append((idx, future.result()))

    completed.sort(key=lambda item: item[0])
    results = [value for _, value in completed]
    return results, timer() - start


def benchmark_parallel(
    items: Sequence[T],
    worker: Callable[[T], R],
    *,
    jobs: int = 2,
    timer: Callable[[], float] | None = None,
) -> dict[str, float]:
    """Benchmark ``worker`` sequentially and in parallel."""

    if jobs <= 1:
        raise ValueError("jobs must be greater than 1 for benchmarking")

    timer = timer or time.perf_counter

    start = timer()
    for item in items:
        worker(item)
    sequential = timer() - start

    _, parallel = run_parallel(items, worker, jobs=jobs, timer=timer)

    ratio = parallel / sequential if sequential > 0 else 0.0
    if ratio > 2.0:
        raise RuntimeError(
            f"parallel execution slower than baseline (ratio {ratio:.2f})"
        )

    return {
        "sequential": sequential,
        "parallel": parallel,
        "ratio": ratio,
        "jobs": float(jobs),
    }


def serialise_metadata(value: Any) -> Any:
    """Return a JSON-serialisable representation of ``value``."""

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
            if _is_printable(decoded):
                return decoded
        except Exception:
            return value.hex()
    if isinstance(value, (list, tuple, set)):
        return [serialise_metadata(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): serialise_metadata(item) for key, item in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        data = asdict(cast(Any, value))
        return {str(key): serialise_metadata(item) for key, item in data.items()}
    return repr(value)


def summarise_metadata(metadata: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a serialisable summary of ``metadata`` suitable for JSON dumps."""

    return {str(key): serialise_metadata(value) for key, value in metadata.items()}


def format_pass_summary(results: Sequence[Tuple[str, float]]) -> str:
    """Format ``results`` as a small table for console output."""

    if not results:
        return ""
    name_width = max(len(name) for name, _ in results)
    lines = [f"{'Pass'.ljust(name_width)}  Duration"]
    for name, duration in results:
        lines.append(f"{name.ljust(name_width)}  {duration:.3f}s")
    return "\n".join(lines)


def ensure_directory(path: Path) -> None:
    """Create *path* if it does not exist."""

    path.mkdir(parents=True, exist_ok=True)
