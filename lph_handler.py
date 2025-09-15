from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

__all__ = ["LPHStringExtractor", "extract_payload", "extract_vm_ir"]


_JSON_PATTERNS = (
    re.compile(r"\[\[(.*?)\]\]", re.DOTALL),
    re.compile(r'"(.*?)"', re.DOTALL),
    re.compile(r"'(.*?)'", re.DOTALL),
)


@dataclass
class PayloadCandidate:
    raw: str
    data: Any


class LPHStringExtractor:
    """Compatibility shim used by the legacy CLI."""

    def extract_strings(self, code: str) -> str:
        return code


def extract_payload(content: str) -> Optional[Dict[str, Any]]:
    """Return a dictionary describing constants/bytecode if one is embedded."""

    for candidate in _iter_candidates(content):
        normalised = _normalise(candidate.data)
        if normalised is not None:
            return normalised
    return None


def extract_vm_ir(content: str) -> Optional[Dict[str, Any]]:
    """Alias for :func:`extract_payload` kept for readability."""

    return extract_payload(content)


def _iter_candidates(content: str) -> Iterator[PayloadCandidate]:
    trimmed = content.strip()
    if _looks_like_json(trimmed):
        data = _try_load_json(trimmed)
        if data is not None:
            yield PayloadCandidate(trimmed, data)
    for pattern in _JSON_PATTERNS:
        for match in pattern.finditer(content):
            candidate = match.group(1).strip()
            if not _looks_like_json(candidate):
                continue
            data = _try_load_json(candidate)
            if data is None:
                continue
            yield PayloadCandidate(candidate, data)
            if isinstance(data, str) and _looks_like_json(data):
                nested = _try_load_json(data)
                if nested is not None:
                    yield PayloadCandidate(data, nested)


def _looks_like_json(text: str) -> bool:
    return text.startswith("{") or text.startswith("[")


def _try_load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _normalise(data: Any) -> Optional[Dict[str, Any]]:
    if isinstance(data, dict):
        constants = data.get("constants") or data.get("const") or []
        bytecode = data.get("bytecode") or data.get("code") or []
        prototypes = data.get("prototypes") or data.get("functions") or []
        if isinstance(constants, list) and isinstance(bytecode, list):
            return {
                "constants": list(constants),
                "bytecode": list(bytecode),
                "code": list(bytecode),
                "prototypes": list(prototypes) if isinstance(prototypes, list) else [],
            }
    if isinstance(data, list):
        constants: List[Any] = []
        code: List[Any] = []
        if data and isinstance(data[0], list) and len(data[0]) == 2 and all(
            isinstance(part, str) for part in data[0]
        ):
            script = data[0][1]
            if script:
                constants.append(script)
            for element in data[1:]:
                if isinstance(element, str) and element.strip():
                    constants.append(element)
            return {
                "constants": constants,
                "bytecode": code,
                "code": code,
                "prototypes": [],
                "script": script,
            }
        if all(isinstance(item, list) for item in data):
            code = [list(instr) for instr in data]
            return {"constants": [], "bytecode": code, "code": code, "prototypes": []}
    return None
