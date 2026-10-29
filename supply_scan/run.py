"""One scan, shared by the CLI and the screen."""

from __future__ import annotations

import json
from pathlib import Path

from supply_scan.acquire import is_git_url, normalize_target, open_workspace
from supply_scan.cache import DiskCache, NullCache, default_cache_dir
from supply_scan.inventory import dedupe, scan_tree
from supply_scan.match import query_osv
from supply_scan.report import Snapshot, exit_code, render_json


def collect(target: str, branch: str | None = None, *, use_cache: bool = True, on_progress=None):
    """Run a scan. Returns the snapshot, its packages, and whether a clone was made."""
    if on_progress is not None and is_git_url(normalize_target(target)):
        on_progress({
            "phase": "clone",
            "files_done": 0,
            "files_total": 0,
            "bytes_done": 0,
            "bytes_total": 0,
        })
    with open_workspace(target, branch) as workspace:
        packages = dedupe(scan_tree(workspace.path, on_progress) if on_progress else scan_tree(workspace.path))
        packages.sort(key=lambda package: (package.manifest, package.name, package.version or ""))
        cache = DiskCache(default_cache_dir()) if use_cache else NullCache()
        if on_progress is None:
            query_osv(packages, cache=cache)
        else:
            query_osv(packages, cache=cache, on_progress=on_progress)
        snapshot = Snapshot(
            target=workspace.target,
            commit=workspace.commit,
            branch=workspace.branch,
            packages=packages,
        )
        cloned = workspace.cloned
    return snapshot, packages, cloned


def run_scan(
    target: str,
    branch: str | None = None,
    strict: bool = False,
    use_cache: bool = True,
    on_progress=None,
) -> dict:
    """Return the JSON report, plus exit_code from the same rules as the CLI."""
    snapshot, packages, _cloned = collect(target, branch, use_cache=use_cache, on_progress=on_progress)
    report = json.loads(render_json(snapshot))
    report["exit_code"] = exit_code(packages, strict)
    return report


def run_tree(
    root,
    target: str,
    branch: str | None,
    commit: str | None,
    strict: bool = False,
    use_cache: bool = True,
    on_progress=None,
) -> dict:
    """Scan a directory that is already on disk. The caller owns that directory."""
    packages = dedupe(scan_tree(Path(root), on_progress) if on_progress else scan_tree(Path(root)))
    packages.sort(key=lambda package: (package.manifest, package.name, package.version or ""))
    cache = DiskCache(default_cache_dir()) if use_cache else NullCache()
    if on_progress is None:
        query_osv(packages, cache=cache)
    else:
        query_osv(packages, cache=cache, on_progress=on_progress)
    snapshot = Snapshot(
        target=target,
        commit=commit,
        branch=branch,
        packages=packages,
    )
    report = json.loads(render_json(snapshot))
    report["exit_code"] = exit_code(packages, strict)
    return report
