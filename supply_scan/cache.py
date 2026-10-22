"""Disk cache for OSV batch rows and full advisories.

A hit is reused for one day. After that the same package is asked again, so a
new advisory can still show up. Cache files live under LOCALAPPDATA on Windows
and under the XDG cache dir elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

TTL_SECONDS = 24 * 60 * 60
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def default_cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    if not base:
        base = str(Path.home() / ".cache")
    return Path(base) / "supply-scan"


class NullCache:
    """Used by --no-cache. Every lookup misses and nothing is written."""

    def get_query(self, ecosystem: str, name: str, version: str) -> dict | None:
        return None

    def put_query(self, ecosystem: str, name: str, version: str, result: dict) -> None:
        return None

    def get_advisory(self, osv_id: str) -> dict | None:
        return None

    def put_advisory(self, osv_id: str, body: dict) -> None:
        return None


class DiskCache:
    def __init__(self, root: Path, ttl_seconds: int = TTL_SECONDS, now=None):
        self.root = root
        self.ttl_seconds = ttl_seconds
        self._now = now or time.time

    def get_query(self, ecosystem: str, name: str, version: str) -> dict | None:
        return self._read(self._query_path(ecosystem, name, version))

    def put_query(self, ecosystem: str, name: str, version: str, result: dict) -> None:
        self._write(self._query_path(ecosystem, name, version), result)

    def get_advisory(self, osv_id: str) -> dict | None:
        return self._read(self._advisory_path(osv_id))

    def put_advisory(self, osv_id: str, body: dict) -> None:
        self._write(self._advisory_path(osv_id), body)

    def _query_path(self, ecosystem: str, name: str, version: str) -> Path:
        key = hashlib.sha256(f"{ecosystem}\n{name}\n{version}".encode()).hexdigest()
        return self.root / "queries" / key[:2] / f"{key}.json"

    def _advisory_path(self, osv_id: str) -> Path:
        safe = _SAFE_ID.sub("_", osv_id).strip("._") or "unknown"
        return self.root / "advisories" / f"{safe}.json"

    def _read(self, path: Path) -> dict | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            cached_at = float(payload["cached_at"])
            body = payload["body"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if self._now() - cached_at > self.ttl_seconds:
            return None
        if not isinstance(body, dict):
            return None
        return body

    def _write(self, path: Path, body: dict) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"cached_at": self._now(), "body": body}),
                encoding="utf-8",
            )
        except OSError:
            return
