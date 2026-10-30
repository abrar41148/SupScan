"""Find where a folder the browser picked lives on this computer.

A page only learns the folder's name and its lockfiles, never its path. The
search looks for a folder with that name whose lockfiles have the same sizes.
"""

from __future__ import annotations

import os
import string
import time
from pathlib import Path

from supply_scan.inventory import SKIP_DIRS

MAX_DEPTH = 6
TIME_LIMIT_SECONDS = 8.0
_SKIP_NAMES = {name.lower() for name in SKIP_DIRS} | {
    "appdata", "windows", "program files", "program files (x86)", "programdata",
    "$recycle.bin", "system volume information", "node_modules",
}


def _roots() -> list[Path]:
    home = Path.home()
    roots = [home / "Desktop", home / "Documents", home / "Downloads", Path.cwd().parent, home]
    if os.name == "nt":
        roots += [Path(f"{letter}:/") for letter in string.ascii_uppercase if Path(f"{letter}:/").exists()]
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        try:
            key = root.resolve()
        except OSError:
            continue
        if key not in seen and key.is_dir():
            seen.add(key)
            out.append(key)
    return out


def _matches(candidate: Path, manifests: list[tuple[str, int]]) -> bool:
    for relative, size in manifests:
        try:
            if (candidate / relative).stat().st_size != size:
                return False
        except OSError:
            return False
    return True


def find_folder(
    name: str,
    manifests: list[tuple[str, int]],
    roots: list[Path] | None = None,
    time_limit: float = TIME_LIMIT_SECONDS,
) -> list[Path]:
    """Folders called `name` that hold every listed lockfile at the same size."""
    wanted = name.lower()
    deadline = time.monotonic() + time_limit
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots if roots is not None else _roots():
        queue = [(root, 0)]
        while queue:
            if time.monotonic() > deadline:
                return found
            directory, depth = queue.pop(0)
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                lower = entry.name.lower()
                if lower == wanted:
                    path = Path(entry.path)
                    if path not in seen and _matches(path, manifests):
                        seen.add(path)
                        found.append(path)
                if depth + 1 < MAX_DEPTH and lower not in _SKIP_NAMES and not entry.name.startswith("."):
                    queue.append((Path(entry.path), depth + 1))
        if found:
            return found
    return found
