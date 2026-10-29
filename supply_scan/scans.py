"""Finished scans kept for comparison."""

from __future__ import annotations

import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from supply_scan.cache import default_cache_dir

_ID = re.compile(r"^[a-f0-9]{32}$")
_save_lock = threading.Lock()


def scans_dir() -> Path:
    return default_cache_dir() / "scans"


def _index_path(root: Path) -> Path:
    return root / "index.json"


def _read_index(root: Path) -> list[dict]:
    try:
        data = json.loads(_index_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict) and _ID.fullmatch(str(item.get("id") or ""))]


def _write_index(root: Path, entries: list[dict]) -> None:
    _index_path(root).write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")


def list_scans(root: Path | None = None) -> list[dict]:
    return _read_index(scans_dir() if root is None else root)


def load_scan(scan_id: str, root: Path | None = None) -> dict | None:
    if not _ID.fullmatch(scan_id or ""):
        return None
    root = scans_dir() if root is None else root
    try:
        data = json.loads((root / f"{scan_id}.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def save_scan(report: dict, root: Path | None = None) -> dict:
    root = scans_dir() if root is None else root
    with _save_lock:
        root.mkdir(parents=True, exist_ok=True)
        scan_id = uuid.uuid4().hex
        record = {
            "id": scan_id,
            "target": report.get("target") or "",
            "commit": report.get("commit"),
            "branch": report.get("branch"),
            "saved_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        }
        (root / f"{scan_id}.json").write_text(json.dumps(report) + "\n", encoding="utf-8")
        index = _read_index(root)
        index.insert(0, record)
        _write_index(root, index)
        return record
