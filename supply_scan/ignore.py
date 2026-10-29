"""Findings the user has accepted. This does not change the CLI exit code."""

from __future__ import annotations

import json
from pathlib import Path

from supply_scan.cache import default_cache_dir


def default_ignore_path() -> Path:
    return default_cache_dir() / "ignore.json"


def _entry(payload: dict) -> dict | None:
    ecosystem = payload.get("ecosystem")
    name = payload.get("name")
    osv_id = payload.get("id")
    version = payload.get("version")
    if version is None:
        version = ""
    if not isinstance(version, str):
        return None
    if not all(isinstance(value, str) and value.strip() for value in (ecosystem, name, osv_id)):
        return None
    return {
        "ecosystem": ecosystem.strip(),
        "name": name.strip(),
        "version": version.strip(),
        "id": osv_id.strip(),
    }


def _same(left: dict, right: dict) -> bool:
    return all(left[key] == right[key] for key in ("ecosystem", "name", "version", "id"))


def read_ignores(path: Path | None = None) -> list[dict]:
    path = default_ignore_path() if path is None else path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    found: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        entry = _entry(item)
        if entry is not None:
            found.append(entry)
    return found


def set_ignored(payload: dict, ignored: bool, path: Path | None = None) -> list[dict] | None:
    entry = _entry(payload)
    if entry is None:
        return None
    path = default_ignore_path() if path is None else path
    current = [item for item in read_ignores(path) if not _same(item, entry)]
    if ignored:
        current.append(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return current
