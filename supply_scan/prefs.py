"""Look-and-feel choices kept on disk so they follow the user to any address."""

from __future__ import annotations

import json
import re
from pathlib import Path

from supply_scan.cache import default_cache_dir

_THEME = re.compile(r"^[a-z]{1,24}$")
_ACCENT = re.compile(r"^#[0-9a-fA-F]{6}$")


def default_prefs_path() -> Path:
    return default_cache_dir() / "prefs.json"


def _clean(payload: object) -> dict:
    if not isinstance(payload, dict):
        return {}
    prefs = {}
    theme = payload.get("theme")
    if isinstance(theme, str) and _THEME.fullmatch(theme):
        prefs["theme"] = theme
    accent = payload.get("accent")
    if isinstance(accent, str) and _ACCENT.fullmatch(accent):
        prefs["accent"] = accent.lower()
    return prefs


def read_prefs(path: Path | None = None) -> dict:
    path = default_prefs_path() if path is None else path
    try:
        return _clean(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return {}


def update_prefs(payload: object, path: Path | None = None) -> dict:
    """Merge the valid keys of payload into the saved prefs and return them."""
    path = default_prefs_path() if path is None else path
    prefs = {**read_prefs(path), **_clean(payload)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prefs, indent=2) + "\n", encoding="utf-8")
    return prefs
