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


def _counts(report: dict) -> dict:
    counts = report.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    return {"packages": counts.get("packages"), "vulnerable": counts.get("vulnerable")}


def list_scans(root: Path | None = None) -> list[dict]:
    root = scans_dir() if root is None else root
    entries = _read_index(root)
    stale = [entry for entry in entries if "packages" not in entry]
    if stale:
        with _save_lock:
            # re-read under the lock so a concurrent save_scan isn't overwritten
            entries = _read_index(root)
            for entry in entries:
                if "packages" not in entry:
                    entry.update(_counts(load_scan(entry["id"], root) or {}))
            _write_index(root, entries)
    return entries


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


def set_pinned(scan_id: str, pinned: bool, root: Path | None = None) -> bool:
    root = scans_dir() if root is None else root
    with _save_lock:
        entries = _read_index(root)
        entry = next((item for item in entries if item["id"] == scan_id), None)
        if entry is None:
            return False
        if pinned:
            entry["pinned"] = True
        else:
            entry.pop("pinned", None)
        _write_index(root, entries)
        return True


def delete_scan(scan_id: str, root: Path | None = None) -> bool:
    root = scans_dir() if root is None else root
    with _save_lock:
        entries = _read_index(root)
        kept = [item for item in entries if item["id"] != scan_id]
        if len(kept) == len(entries):
            return False
        _write_index(root, kept)
        (root / f"{scan_id}.json").unlink(missing_ok=True)
        return True


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
            **_counts(report),
        }
        (root / f"{scan_id}.json").write_text(json.dumps(report) + "\n", encoding="utf-8")
        index = _read_index(root)
        index.insert(0, record)
        _write_index(root, index)
        return record
