"""Runtime protection analysis helpers for Luraph captures."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Iterable, List, Sequence

import bz2
import lzma
import zlib

from .runtime_capture.trace_to_unpacked import LUA_BYTECODE_MAGIC, LUAJIT_MAGIC


@dataclass(slots=True)
class BufferObservation:
    """Container describing a decoded buffer or fragment."""

    data: bytes
    label: str = "capture"
    fragments: Sequence[bytes] | None = None


@dataclass(slots=True)
class ProtectionFinding:
    """Single detection entry produced by :class:`ProtectionsAnalyzer`."""

    type: str
    evidence: dict
    recommendation: str | None = None

    def to_json(self) -> dict:  # pragma: no cover - trivial serialiser
        payload = {"type": self.type, "evidence": self.evidence}
        if self.recommendation:
            payload["recommendation"] = self.recommendation
        return payload


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in {9, 10, 13})
    return printable / len(data)


def _looks_like_lua(data: bytes) -> bool:
    if not data:
        return False
    if data.startswith(LUA_BYTECODE_MAGIC) or data.startswith(LUAJIT_MAGIC):
        return True
    lower = data.lower()
    return any(token in lower for token in (b"function", b"return", b"local", b"script_key"))


class ProtectionsAnalyzer:
    """Detects protection techniques present in runtime captures."""

    def __init__(self, buffers: Sequence[BufferObservation]):
        self.buffers = list(buffers)

    # ------------------------------------------------------------------ XOR --
    def _detect_single_byte_xor(self, data: bytes, label: str) -> ProtectionFinding | None:
        best_ratio = 0.0
        best_key = None
        best_plain = None
        for key in range(1, 256):
            plain = bytes(byte ^ key for byte in data)
            ratio = _printable_ratio(plain)
            if ratio > best_ratio:
                best_ratio = ratio
                best_key = key
                best_plain = plain
        if best_key is not None and (best_ratio > 0.65 or _looks_like_lua(best_plain or b"")):
            evidence = {
                "label": label,
                "key": best_key,
                "score": round(best_ratio, 3),
            }
            if _looks_like_lua(best_plain or b""):
                evidence["lua_markers"] = True
            return ProtectionFinding("xor", evidence, recommendation="apply_single_byte_xor")
        return None

    def _detect_repeating_xor(self, data: bytes, label: str) -> ProtectionFinding | None:
        max_len = min(32, max(2, len(data) // 8))
        best = None
        for key_len in range(2, max_len + 1):
            key: List[int] = []
            slice_scores: List[float] = []
            for offset in range(key_len):
                slice_bytes = data[offset::key_len]
                if not slice_bytes:
                    break
                best_key = None
                best_score = 0.0
                for candidate in range(256):
                    plain = bytes(byte ^ candidate for byte in slice_bytes)
                    score = _printable_ratio(plain)
                    if score > best_score:
                        best_score = score
                        best_key = candidate
                if best_key is None or best_score < 0.55:
                    key = []
                    break
                key.append(best_key)
                slice_scores.append(best_score)
            if key and len(key) == key_len:
                if len(set(key)) == 1:
                    continue
                plain = bytes(byte ^ key[i % key_len] for i, byte in enumerate(data))
                ratio = _printable_ratio(plain)
                if ratio > 0.6 or _looks_like_lua(plain):
                    best = (
                        key,
                        ratio,
                        plain[: min(64, len(plain))],
                        statistics.mean(slice_scores) if slice_scores else ratio,
                    )
                    break
        if best:
            key_bytes, ratio, preview, avg_slice = best
            evidence = {
                "label": label,
                "key": [hex(k) for k in key_bytes],
                "score": round(ratio, 3),
                "slice_score": round(avg_slice, 3),
            }
            if _looks_like_lua(preview):
                evidence["lua_markers"] = True
            return ProtectionFinding("repeating_xor", evidence, recommendation="apply_repeating_xor")
        return None

    def _detect_rolling_xor(self, data: bytes, label: str) -> ProtectionFinding | None:
        if len(data) < 8:
            return None
        diffs = [data[i] ^ data[i - 1] for i in range(1, len(data))]
        unique = len(set(diffs))
        if unique <= max(4, len(data) // 16):
            evidence = {
                "label": label,
                "unique_deltas": unique,
                "entropy": round(_entropy(bytes(diffs)), 3),
            }
            return ProtectionFinding("rolling_xor", evidence, recommendation="trace_vm_writes")
        return None

    # ------------------------------------------------------------- Compression --
    def _detect_compression(self, data: bytes, label: str) -> ProtectionFinding | None:
        for name, decoder in (
            ("zlib", zlib.decompress),
            ("bz2", bz2.decompress),
            ("lzma", lzma.decompress),
        ):
            try:
                plain = decoder(data)
            except Exception:
                continue
            ratio = _printable_ratio(plain)
            if ratio > 0.5 or _looks_like_lua(plain):
                evidence = {
                    "label": label,
                    "method": name,
                    "size": len(plain),
                    "ratio": round(ratio, 3),
                }
                if _looks_like_lua(plain):
                    evidence["lua_markers"] = True
                return ProtectionFinding("compression", evidence, recommendation="decompress_then_unpack")
        return None

    # --------------------------------------------------------- Fragmentation --
    def _detect_fragmentation(self, fragments: Sequence[bytes], label: str) -> ProtectionFinding | None:
        if not fragments:
            return None
        lengths = [len(fragment) for fragment in fragments]
        if len(fragments) > 1 and max(lengths) - min(lengths) < max(4, sum(lengths) // 20):
            evidence = {
                "label": label,
                "fragments": len(fragments),
                "total": sum(lengths),
            }
            return ProtectionFinding("fragmentation", evidence, recommendation="concatenate_fragments")
        return None

    # ------------------------------------------------------------ Polymorphism --
    def _detect_polymorphic(self) -> ProtectionFinding | None:
        if len(self.buffers) < 2:
            return None
        lengths = {len(item.data) for item in self.buffers}
        if len(lengths) != 1:
            return None
        reference = self.buffers[0].data
        mismatch = any(buffer.data != reference for buffer in self.buffers[1:])
        if mismatch:
            evidence = {
                "captures": len(self.buffers),
                "length": len(reference),
            }
            return ProtectionFinding("polymorphic_encoding", evidence, recommendation="cluster_captures")
        return None

    # --------------------------------------------------------------- Junk ops --
    def _detect_junk(self, data: bytes, label: str) -> ProtectionFinding | None:
        if len(data) < 12:
            return None
        zero_runs = 0
        current = 0
        for byte in data:
            if byte == 0:
                current += 1
            else:
                if current >= 6:
                    zero_runs += 1
                current = 0
        if current >= 6:
            zero_runs += 1
        if zero_runs:
            evidence = {
                "label": label,
                "zero_runs": zero_runs,
            }
            return ProtectionFinding("junk_ops", evidence, recommendation="strip_zero_words")
        return None

    # --------------------------------------------------------- Anti-tracing --
    def _detect_anti_trace(self, data: bytes, label: str) -> ProtectionFinding | None:
        lower = data.lower()
        tokens = [b"debug", b"jit.status", b"os.execute", b"traceback"]
        if any(token in lower for token in tokens):
            evidence = {"label": label, "tokens": [token.decode() for token in tokens if token in lower]}
            return ProtectionFinding("anti_trace", evidence, recommendation="stub_debug_functions")
        return None

    # ------------------------------------------------------------ Entry point --
    def detect(self) -> List[ProtectionFinding]:
        results: List[ProtectionFinding] = []
        for buffer in self.buffers:
            data = buffer.data
            compression = self._detect_compression(data, buffer.label)
            if compression:
                results.append(compression)
                continue
            repeating = self._detect_repeating_xor(data, buffer.label)
            if repeating:
                results.append(repeating)
                continue
            single = self._detect_single_byte_xor(data, buffer.label)
            if single:
                results.append(single)
                continue
            rolling = self._detect_rolling_xor(data, buffer.label)
            if rolling:
                results.append(rolling)
            junk = self._detect_junk(data, buffer.label)
            if junk:
                results.append(junk)
            anti = self._detect_anti_trace(data, buffer.label)
            if anti:
                results.append(anti)
            if buffer.fragments:
                frag = self._detect_fragmentation(buffer.fragments, buffer.label)
                if frag:
                    results.append(frag)
        polymorphic = self._detect_polymorphic()
        if polymorphic:
            results.append(polymorphic)
        return results


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(byte) for byte in set(data)]
    total = float(len(data))
    return -sum((count / total) * math.log2(count / total) for count in counts)


def analyse_protections(buffers: Iterable[BufferObservation]) -> List[dict]:
    """Return JSON-serialisable protection findings for the given buffers."""

    analyzer = ProtectionsAnalyzer(list(buffers))
    return [finding.to_json() for finding in analyzer.detect()]


__all__ = ["BufferObservation", "ProtectionFinding", "ProtectionsAnalyzer", "analyse_protections"]
