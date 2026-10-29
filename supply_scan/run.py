"""One scan, shared by the CLI and the screen."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from supply_scan.acquire import AcquireError, is_git_url, normalize_target, open_workspace, short_acquire_error
from supply_scan.cache import DiskCache, NullCache, default_cache_dir
from supply_scan.inventory import Package, dedupe, scan_tree
from supply_scan.match import MatchError, query_osv
from supply_scan.report import Snapshot, exit_code, render_json, worst_exit_code

MAX_BATCH_TARGETS = 4


@dataclass
class TargetSpec:
    target: str
    branch: str | None = None
    git_token: str | None = None


@dataclass
class _TargetInventory:
    target: str
    commit: str | None
    branch: str | None
    cloned: bool
    packages: list[Package]
    error: str | None = None


def _osv_key(package: Package) -> tuple[str, str, str] | None:
    if package.unchecked_reason or not package.version:
        return None
    return (package.ecosystem, package.name, package.version)


def _copy_osv_fields(destination: Package, source: Package) -> None:
    destination.vulns = list(source.vulns)
    destination.recommend = source.recommend


def _inventory_target(
    spec: TargetSpec,
    *,
    on_progress=None,
    target_index: int = 0,
    target_total: int = 1,
) -> _TargetInventory:
    target = normalize_target(spec.target)
    branch = spec.branch
    try:
        def tagged(event: dict) -> None:
            if on_progress is None:
                return
            on_progress({
                **event,
                "target": target,
                "branch": branch,
                "target_index": target_index,
                "target_total": target_total,
            })

        if on_progress is not None and is_git_url(target):
            tagged({"phase": "clone"})
        with open_workspace(target, branch, spec.git_token) as workspace:
            if on_progress is not None:
                packages = dedupe(scan_tree(workspace.path, tagged))
            else:
                packages = dedupe(scan_tree(workspace.path))
            packages.sort(key=lambda package: (package.manifest, package.name, package.version or ""))
            return _TargetInventory(
                target=workspace.target,
                commit=workspace.commit,
                branch=workspace.branch,
                cloned=workspace.cloned,
                packages=packages,
            )
    except AcquireError as exc:
        return _TargetInventory(
            target=target,
            commit=None,
            branch=branch,
            cloned=False,
            packages=[],
            error=str(exc),
        )


def collect(
    target: str,
    branch: str | None = None,
    *,
    git_token: str | None = None,
    use_cache: bool = True,
    on_progress=None,
):
    """Run a scan. Returns the snapshot, its packages, and whether a clone was made."""
    cache = DiskCache(default_cache_dir()) if use_cache else NullCache()
    if on_progress is not None and is_git_url(normalize_target(target)):
        on_progress({
            "phase": "clone",
            "files_done": 0,
            "files_total": 0,
            "bytes_done": 0,
            "bytes_total": 0,
        })
    with open_workspace(target, branch, git_token) as workspace:
        packages = dedupe(scan_tree(workspace.path, on_progress) if on_progress else scan_tree(workspace.path))
        packages.sort(key=lambda package: (package.manifest, package.name, package.version or ""))
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


def run_batch(
    targets: list[TargetSpec],
    *,
    strict: bool = False,
    use_cache: bool = True,
    on_progress=None,
) -> tuple[int, list[dict], list[Snapshot]]:
    """Scan up to four targets with one shared OSV pass."""
    if not targets:
        raise ValueError("At least one target is required")
    if len(targets) > MAX_BATCH_TARGETS:
        raise ValueError(f"At most {MAX_BATCH_TARGETS} targets are allowed")

    total = len(targets)
    typed: list[_TargetInventory] = []
    for index, spec in enumerate(targets):
        typed.append(_inventory_target(
            spec,
            on_progress=on_progress,
            target_index=index,
            target_total=total,
        ))

    osv_error: str | None = None
    if any(not item.error for item in typed):
        cache = DiskCache(default_cache_dir()) if use_cache else NullCache()
        canonical: dict[tuple[str, str, str], Package] = {}
        query_list: list[Package] = []
        for inventory in typed:
            if inventory.error:
                continue
            for package in inventory.packages:
                key = _osv_key(package)
                if key is None:
                    continue
                if key not in canonical:
                    canonical[key] = package
                    query_list.append(package)
        if query_list:
            def tagged_osv(event: dict) -> None:
                if on_progress is None:
                    return
                on_progress({
                    **event,
                    "target_total": total,
                    "batch_osv": True,
                })

            try:
                if on_progress is None:
                    query_osv(query_list, cache=cache)
                else:
                    query_osv(query_list, cache=cache, on_progress=tagged_osv)
            except MatchError as exc:
                osv_error = str(exc)
            else:
                for inventory in typed:
                    if inventory.error:
                        continue
                    for package in inventory.packages:
                        key = _osv_key(package)
                        if key is None:
                            continue
                        leader = canonical.get(key)
                        if leader is not None and leader is not package:
                            _copy_osv_fields(package, leader)

    snapshots: list[Snapshot] = []
    reports: list[dict] = []
    for inventory in typed:
        if inventory.error:
            snapshot = Snapshot(
                target=inventory.target,
                commit=None,
                branch=inventory.branch,
                packages=[],
            )
            code = 2
        elif osv_error and any(_osv_key(package) for package in inventory.packages):
            snapshot = Snapshot(
                target=inventory.target,
                commit=inventory.commit,
                branch=inventory.branch,
                packages=inventory.packages,
            )
            code = 2
        else:
            snapshot = Snapshot(
                target=inventory.target,
                commit=inventory.commit,
                branch=inventory.branch,
                packages=inventory.packages,
            )
            code = exit_code(inventory.packages, strict)
        snapshots.append(snapshot)
        report = json.loads(render_json(snapshot))
        report["exit_code"] = code
        if inventory.error:
            raw = inventory.error
            report["error"] = short_acquire_error(raw)
            if report["error"] != raw.strip():
                report["error_detail"] = raw
        elif osv_error:
            report["error"] = osv_error
        reports.append(report)
    return worst_exit_code([report["exit_code"] for report in reports]), reports, snapshots


def run_scan(
    target: str,
    branch: str | None = None,
    strict: bool = False,
    git_token: str | None = None,
    use_cache: bool = True,
    on_progress=None,
) -> dict:
    """Return the JSON report, plus exit_code from the same rules as the CLI."""
    snapshot, packages, _cloned = collect(
        target,
        branch,
        git_token=git_token,
        use_cache=use_cache,
        on_progress=on_progress,
    )
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
