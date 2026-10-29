"""Load full advisories from OSV ecosystem all.zip exports (narrow hydration path)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from supply_scan.cache import DiskCache

OSV_VULNS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"


def _zip_path(cache: DiskCache, ecosystem: str) -> Path:
    safe = ecosystem.replace(":", "_").replace("/", "_")
    return cache.root / "osv-zips" / safe / "all.zip"


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "supply-scan"})
    with urllib.request.urlopen(request, timeout=300) as response:
        data = response.read()
    destination.write_bytes(data)


def ensure_ecosystem_zip(ecosystem: str, cache: DiskCache) -> Path:
    path = _zip_path(cache, ecosystem)
    if path.is_file() and path.stat().st_size > 0:
        return path
    segment = urllib.parse.quote(ecosystem, safe="")
    url = f"{OSV_VULNS_BASE}/{segment}/all.zip"
    try:
        _download(url, path)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OSError(f"OSV zip for {ecosystem} failed: {exc}") from exc
    return path


def read_advisory_from_zip(osv_id: str, ecosystem: str, cache: DiskCache) -> dict | None:
    """Return one advisory JSON from the cached export, or None if the id is not in the zip."""
    try:
        path = ensure_ecosystem_zip(ecosystem, cache)
    except OSError:
        return None
    member = f"{osv_id}.json"
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if member in names:
                raw = archive.read(member)
            else:
                match = next((name for name in names if name.endswith("/" + member)), None)
                if match is None:
                    return None
                raw = archive.read(match)
    except (OSError, zipfile.BadZipFile, KeyError):
        return None
    try:
        body = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return body if isinstance(body, dict) else None


def zip_hydration_enabled() -> bool:
    return os.environ.get("SUPPLY_SCAN_ZIP_ADVISORIES", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
