"""Thin client for optional Luraph REST metadata lookups."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict
from urllib.error import URLError
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "https://api.luraph.com/v1"
CACHE_DIR = Path(os.environ.get("LURAPH_CACHE_DIR", Path.home() / ".cache" / "luraph"))


@dataclass(slots=True)
class LuraphAPI:
    """Simple REST client used to fetch version metadata when available."""

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    timeout: int = 5
    cache: Dict[str, Any] = field(default_factory=dict)

    def _cache_path(self, key: str) -> Path:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        safe = key.replace("/", "_")
        return CACHE_DIR / f"{safe}.json"

    def _request(self, endpoint: str) -> Dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        cache_path = self._cache_path(endpoint)
        if cache_path.exists():
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                cache_path.unlink(missing_ok=True)
        request = Request(url, headers={"Authorization": f"Bearer {self.api_key}"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
        except URLError as exc:
            raise RuntimeError(f"Luraph API request failed: {exc}") from exc
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise RuntimeError(f"invalid JSON from Luraph API: {exc}") from exc
        cache_path.write_text(payload, encoding="utf-8")
        return parsed

    def version_info(self, version: str) -> Dict[str, Any]:
        endpoint = f"versions/{version}" if not version.startswith("versions/") else version
        if endpoint in self.cache:
            return self.cache[endpoint]
        data = self._request(endpoint)
        self.cache[endpoint] = data
        return data

    def macro_info(self, macro: str) -> Dict[str, Any]:
        endpoint = f"macros/{macro}" if not macro.startswith("macros/") else macro
        if endpoint in self.cache:
            return self.cache[endpoint]
        data = self._request(endpoint)
        self.cache[endpoint] = data
        return data


__all__ = ["LuraphAPI", "DEFAULT_BASE_URL"]
