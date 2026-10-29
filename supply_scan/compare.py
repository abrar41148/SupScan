"""Compare two saved scans.

The same package is the ecosystem and the name. The version is what changed.
The page paints the two columns from `rows`.
"""

from __future__ import annotations

_SEVERITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


def _version(package: dict) -> str | None:
    value = package.get("version")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _recommend(package: dict) -> str | None:
    value = package.get("recommend")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _alias(package: dict) -> str | None:
    value = package.get("alias")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _findings(package: dict) -> list[dict]:
    vulns = package.get("vulns")
    if not isinstance(vulns, list):
        return []
    found = []
    for finding in vulns:
        if not isinstance(finding, dict):
            continue
        osv_id = finding.get("id")
        if not isinstance(osv_id, str) or not osv_id:
            continue
        related = finding.get("related_ids")
        if not isinstance(related, list):
            related = []
        entry = {
            "id": osv_id,
            "cve": finding.get("cve") if isinstance(finding.get("cve"), str) else None,
            "severity": finding.get("severity") if isinstance(finding.get("severity"), str) else None,
            "summary": finding.get("summary") if isinstance(finding.get("summary"), str) else None,
            "fixed_in": finding.get("fixed_in") if isinstance(finding.get("fixed_in"), str) else None,
            "kind": finding.get("kind") if isinstance(finding.get("kind"), str) else None,
            "related_ids": [str(item) for item in related if isinstance(item, str) and item],
        }
        found.append(entry)
    return found


def _finding_key(finding: dict) -> tuple:
    kind = finding.get("kind")
    if kind == "malware":
        rank = 0
    elif kind == "vulnerability":
        rank = 1
    else:
        rank = 2
    return (rank, _SEVERITY.get(finding.get("severity"), 5), finding.get("id") or "")


def _fold(rows: list[dict]) -> dict:
    base = rows[0]
    seen: dict[str, dict] = {}
    for row in rows:
        for finding in _findings(row):
            keys = [finding["id"], *finding.get("related_ids", [])]
            for key in keys:
                seen.setdefault(key, finding)
    manifest = base.get("manifest")
    reason = base.get("unchecked_reason")
    return {
        "ecosystem": base["ecosystem"],
        "name": base["name"],
        "version": _version(base),
        "direct": any(bool(row.get("direct")) for row in rows),
        "dev": all(bool(row.get("dev")) for row in rows),
        "manifest": manifest if isinstance(manifest, str) else "",
        "unchecked_reason": reason if isinstance(reason, str) else None,
        "recommend": _recommend(base),
        "alias": _alias(base),
        "vulns": list(seen.values()),
    }


def _groups(report: dict) -> dict[tuple[str, str], dict[str | None, dict]]:
    buckets: dict[tuple[str, str], dict[str | None, list]] = {}
    packages = report.get("packages")
    if not isinstance(packages, list):
        return {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not ecosystem or not isinstance(name, str) or not name:
            continue
        version = _version(package)
        buckets.setdefault((ecosystem, name), {}).setdefault(version, []).append(package)
    return {
        key: {version: _fold(rows) for version, rows in versions.items()}
        for key, versions in buckets.items()
    }


def _ids(versions: dict[str | None, dict]) -> set[str]:
    return {finding["id"] for row in versions.values() for finding in row["vulns"]}


def _public(row: dict) -> dict:
    return {
        "ecosystem": row["ecosystem"],
        "name": row["name"],
        "version": row["version"],
        "direct": row["direct"],
        "dev": row["dev"],
        "manifest": row["manifest"],
        "unchecked_reason": row["unchecked_reason"],
        "recommend": row["recommend"],
        "alias": row["alias"],
        "vulns": sorted(row["vulns"], key=_finding_key),
    }


def _version_key(row: dict) -> tuple:
    version = row.get("version")
    return (version is not None, version or "")


def _worst(versions: dict[str | None, dict]) -> int:
    rank = 99
    for row in versions.values():
        for finding in row["vulns"]:
            if finding.get("kind") == "malware":
                score = -1
            else:
                score = _SEVERITY.get(finding.get("severity"), 5)
            rank = min(rank, score)
    return rank


def _note(previous: dict[str | None, dict], current: dict[str | None, dict]) -> str | None:
    if not previous or not current:
        return None
    prev_rows = list(previous.values())
    curr_rows = list(current.values())
    notes = []
    prev_dev = all(row["dev"] for row in prev_rows)
    curr_dev = all(row["dev"] for row in curr_rows)
    if prev_dev != curr_dev:
        notes.append("Now dev" if curr_dev else "Now prod")
    prev_direct = any(row["direct"] for row in prev_rows)
    curr_direct = any(row["direct"] for row in curr_rows)
    if prev_direct != curr_direct:
        notes.append("Now direct" if curr_direct else "Now transitive")
    return ", ".join(notes) or None


def _advisories(previous: dict[str | None, dict], current: dict[str | None, dict]) -> list[dict]:
    before: dict[str, tuple] = {}
    after: dict[str, tuple] = {}
    for row in previous.values():
        for finding in row["vulns"]:
            before.setdefault(finding["id"], (row["version"], finding))
    for row in current.values():
        for finding in row["vulns"]:
            after.setdefault(finding["id"], (row["version"], finding))
    listed = []
    for osv_id in set(before) | set(after):
        if osv_id in after and osv_id in before:
            status = "still"
            version, finding = after[osv_id]
        elif osv_id in after:
            status = "appeared"
            version, finding = after[osv_id]
        else:
            status = "cleared"
            version, finding = before[osv_id]
        listed.append({
            "id": finding["id"],
            "status": status,
            "version": version,
            "cve": finding["cve"],
            "severity": finding["severity"],
            "summary": finding["summary"],
            "fixed_in": finding["fixed_in"],
            "kind": finding["kind"],
        })
    listed.sort(key=_finding_key)
    return listed


def _change(previous: dict[str | None, dict], current: dict[str | None, dict]) -> str | None:
    if not previous:
        return "added"
    if not current:
        return "removed"
    if set(previous) != set(current):
        return "version_changed"
    before = _ids(previous)
    after = _ids(current)
    if before != after:
        return "advisory_changed"
    if before:
        return "unchanged"
    return None


def compare_reports(current: dict, previous: dict) -> dict:
    if not isinstance(current, dict) or not isinstance(previous, dict):
        raise TypeError("compare_reports expects two report dicts")
    before = _groups(previous)
    after = _groups(current)
    rows = []
    for key in set(before) | set(after):
        prev_versions = before.get(key, {})
        curr_versions = after.get(key, {})
        kind = _change(prev_versions, curr_versions)
        if kind is None:
            continue
        ecosystem, name = key
        rows.append({
            "change": kind,
            "ecosystem": ecosystem,
            "name": name,
            "note": _note(prev_versions, curr_versions),
            "current": [_public(row) for row in sorted(curr_versions.values(), key=_version_key)],
            "previous": [_public(row) for row in sorted(prev_versions.values(), key=_version_key)],
            "advisories": _advisories(prev_versions, curr_versions),
            "_rank": min(_worst(curr_versions), _worst(prev_versions)),
        })
    rows.sort(key=lambda row: (row["_rank"], row["ecosystem"], row["name"]))
    for row in rows:
        del row["_rank"]
    return {"rows": rows}
