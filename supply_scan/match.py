"""Ask OSV which resolved versions are affected, and which release fixes them."""

from __future__ import annotations

import json
import sys
import threading
from functools import cmp_to_key
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING

from supply_scan.cache import DiskCache, NullCache, default_cache_dir
from supply_scan.inventory import Package
from supply_scan.osv_zip import read_advisory_from_zip, zip_hydration_enabled
from supply_scan.versions import version_key

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 1000

_AV = {"N": Decimal("0.85"), "A": Decimal("0.62"), "L": Decimal("0.55"), "P": Decimal("0.2")}
_AC = {"L": Decimal("0.77"), "H": Decimal("0.44")}
_UI = {"N": Decimal("0.85"), "R": Decimal("0.62")}
_CIA = {"H": Decimal("0.56"), "L": Decimal("0.22"), "N": Decimal("0")}
_PR_SAME = {"N": Decimal("0.85"), "L": Decimal("0.62"), "H": Decimal("0.27")}
_PR_CHANGED = {"N": Decimal("0.85"), "L": Decimal("0.68"), "H": Decimal("0.5")}
_WORDS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


class MatchError(Exception):
    pass


@dataclass
class Finding:
    osv_id: str
    cve: str | None
    severity: str
    summary: str
    fixed_in: str | None
    kind: str
    precise: bool
    related_ids: tuple[str, ...] = ()


def version_tuple(value: str | None, ecosystem: str | None = None):
    """A comparable version, or None when this ecosystem cannot order it."""
    return version_key(value, ecosystem)


def _cmp(left: str, right: str, ecosystem: str | None = None) -> int | None:
    left_key = version_tuple(left, ecosystem)
    right_key = version_tuple(right, ecosystem)
    if left_key is None or right_key is None:
        return None
    return (left_key > right_key) - (left_key < right_key)


def _event_version(event: dict) -> str:
    for field in ("introduced", "fixed", "limit", "last_affected"):
        if field in event:
            return str(event[field])
    return ""


def _sort_range_events(events: list[dict], ecosystem: str | None) -> list[dict]:
    """Order range events before walking them (same idea as osv-scalibr vulns.rangeContainsVersion)."""
    if len(events) < 2:
        return events

    def compare(left: dict, right: dict) -> int:
        if str(left.get("introduced")) == "0":
            return -1
        if str(right.get("introduced")) == "0":
            return 1
        order = _cmp(_event_version(left), _event_version(right), ecosystem)
        if order is None:
            return 0
        return order

    return sorted(events, key=cmp_to_key(compare))


def _matching_interval(
    installed: str,
    events: list[dict],
    ecosystem: str | None = None,
) -> tuple[bool | None, str | None]:
    """Walk introduced/fixed pairs. Returns (contained, fixed_version).

    contained is None when a bound does not parse. A matching interval with no
    fixed event means there is no patched release.
    """
    events = _sort_range_events(events, ecosystem)
    index = 0
    contained = False
    while index < len(events):
        event = events[index]
        if "introduced" not in event:
            index += 1
            continue
        introduced = str(event["introduced"])
        index += 1
        limit_kind = None
        limit_value = None
        if index < len(events):
            nxt = events[index]
            if "fixed" in nxt:
                limit_kind = "fixed"
                limit_value = str(nxt["fixed"])
                index += 1
            elif "last_affected" in nxt:
                limit_kind = "last_affected"
                limit_value = str(nxt["last_affected"])
                index += 1
        intro_order = _cmp(introduced, installed, ecosystem)
        if intro_order is None:
            return None, None
        if intro_order > 0:
            continue
        if limit_kind is None:
            contained = True
            continue
        limit_order = _cmp(installed, limit_value or "", ecosystem)
        if limit_order is None:
            return None, None
        if limit_kind == "fixed" and limit_order < 0:
            return True, limit_value
        if limit_kind == "last_affected" and limit_order <= 0:
            return True, None
    return contained, None


def range_contains(installed: str, events: list[dict], ecosystem: str | None = None) -> bool | None:
    contained, _fixed = _matching_interval(installed, events, ecosystem)
    return contained


def _segment_fix(installed: str, events: list[dict], ecosystem: str | None = None) -> str | None:
    _contained, fixed = _matching_interval(installed, events, ecosystem)
    return fixed


def _affected_ranges(vuln: dict, ecosystem: str, name: str) -> list[list[dict]]:
    ranges: list[list[dict]] = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != ecosystem:
            continue
        their_name = str(package.get("name") or "")
        if ecosystem == "PyPI":
            same = their_name.lower().replace("_", "-").replace(".", "-") == name
        else:
            same = their_name == name
        if not same:
            continue
        for item in affected.get("ranges") or []:
            ranges.append(item.get("events") or [])
    return ranges


def _roundup(value: Decimal) -> Decimal:
    scaled = value * 10
    if scaled == scaled.to_integral_value():
        return value.quantize(Decimal("0.1"))
    ceiling = scaled.to_integral_value(rounding=ROUND_CEILING)
    return (ceiling / Decimal(10)).quantize(Decimal("0.1"))


def cvss_v3_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3."):
        return None
    metrics = {}
    for piece in vector.split("/")[1:]:
        if ":" in piece:
            key, val = piece.split(":", 1)
            metrics[key] = val
    try:
        changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if changed else _PR_SAME
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = pr_table[metrics["PR"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
    except KeyError:
        return None
    one = Decimal(1)
    iss = one - ((one - conf) * (one - integ) * (one - avail))
    if changed:
        impact = Decimal("7.52") * (iss - Decimal("0.029")) - Decimal("3.25") * ((iss - Decimal("0.02")) ** 15)
    else:
        impact = Decimal("6.42") * iss
    exploitability = Decimal("8.22") * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if changed:
        raw = Decimal("1.08") * raw
    if raw > 10:
        raw = Decimal(10)
    return float(_roundup(raw))


def _band(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def severity_of(vuln: dict) -> str:
    for item in vuln.get("severity") or []:
        score = str(item.get("score") or "")
        if score.startswith("CVSS:3."):
            numeric = cvss_v3_score(score)
            if numeric is not None:
                return _band(numeric)
        try:
            return _band(float(score))
        except ValueError:
            continue
    for source in (vuln.get("database_specific"), vuln.get("ecosystem_specific")):
        if isinstance(source, dict):
            word = _WORDS.get(str(source.get("severity") or "").upper())
            if word:
                return word
    return "unknown"


def _finding(vuln: dict, package: Package) -> Finding | None:
    osv_id = str(vuln.get("id") or "unknown")
    aliases = vuln.get("aliases") or []
    cve = next((str(alias) for alias in aliases if str(alias).startswith("CVE-")), None)
    summary = str(vuln.get("summary") or vuln.get("details") or "").strip().replace("\n", " ")
    if len(summary) > 200:
        summary = summary[:197] + "..."
    events_list = _affected_ranges(vuln, package.ecosystem, package.name)
    precise_fixes: list[str | None] = []
    imprecise = False
    if not events_list:
        imprecise = True
    contained_any = False
    for events in events_list:
        contained = range_contains(package.version or "", events, package.ecosystem)
        if contained is None:
            imprecise = True
            continue
        if contained:
            contained_any = True
            precise_fixes.append(_segment_fix(package.version or "", events, package.ecosystem))
    if events_list and not imprecise and not contained_any:
        return None
    if imprecise:
        collected = []
        for events in events_list:
            collected.extend(str(event["fixed"]) for event in events if "fixed" in event)
        fixed_in = ", ".join(dict.fromkeys(collected)) or None
        precise = False
    else:
        concrete = [fix for fix in precise_fixes if fix]
        if not concrete:
            fixed_in = None
            precise = True
        elif all(version_tuple(fix, package.ecosystem) for fix in concrete):
            fixed_in = max(concrete, key=lambda item: version_tuple(item, package.ecosystem) or ())
            precise = True
        else:
            fixed_in = ", ".join(dict.fromkeys(concrete))
            precise = False
    return Finding(
        osv_id=osv_id,
        cve=cve,
        severity=severity_of(vuln),
        summary=summary,
        fixed_in=fixed_in,
        kind="malware" if osv_id.startswith("MAL-") else "vulnerability",
        precise=precise,
    )


def _vuln_ids(vuln: dict) -> set[str]:
    found = {str(vuln.get("id") or "")}
    found.discard("")
    for alias in vuln.get("aliases") or []:
        text = str(alias)
        if text:
            found.add(text)
    return found


def _primary_osv_id(ids: set[str]) -> str:
    for prefix in ("GHSA-", "CVE-", "MAL-", "PYSEC-", "GO-"):
        matches = sorted(item for item in ids if item.startswith(prefix))
        if matches:
            return matches[0]
    return min(ids)


def _merge_findings(group: list[Finding], ecosystem: str | None) -> Finding:
    primary = _primary_osv_id({item.osv_id for item in group})
    best = min(
        group,
        key=lambda item: (
            0 if item.osv_id == primary else 1,
            _SEVERITY_RANK.get(item.severity, 9),
            item.osv_id,
        ),
    )
    related = tuple(sorted({item.osv_id for item in group} - {best.osv_id}))
    fixes = [item.fixed_in for item in group if item.fixed_in]
    fixed_in = best.fixed_in
    if fixes and all(version_tuple(fix, ecosystem) for fix in fixes):
        fixed_in = max(fixes, key=lambda item: version_tuple(item, ecosystem) or ())
    cve = best.cve or next((item.cve for item in group if item.cve), None)
    precise = all(item.precise for item in group)
    return Finding(
        osv_id=best.osv_id,
        cve=cve,
        severity=min(group, key=lambda item: _SEVERITY_RANK.get(item.severity, 9)).severity,
        summary=best.summary,
        fixed_in=fixed_in,
        kind="malware" if any(item.kind == "malware" for item in group) else "vulnerability",
        precise=precise,
        related_ids=related,
    )


def _group_findings(
    findings: list[Finding],
    vulns: list[dict],
    ecosystem: str | None = None,
) -> list[Finding]:
    if len(findings) < 2:
        return findings
    labels: list[set[str]] = []
    for finding, vuln in zip(findings, vulns):
        cluster = _vuln_ids(vuln)
        cluster.add(finding.osv_id)
        if finding.cve:
            cluster.add(finding.cve)
        labels.append(cluster)
    parent = list(range(len(findings)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for left in range(len(findings)):
        for right in range(left + 1, len(findings)):
            if labels[left] & labels[right]:
                union(left, right)

    buckets: dict[int, list[Finding]] = {}
    for index, finding in enumerate(findings):
        buckets.setdefault(find(index), []).append(finding)
    grouped: list[Finding] = []
    for bucket in buckets.values():
        grouped.append(
            _merge_findings(bucket, ecosystem) if len(bucket) > 1 else bucket[0],
        )
    grouped.sort(key=lambda item: (_SEVERITY_RANK.get(item.severity, 9), item.osv_id))
    return grouped


def _recommend(findings: list[Finding], ecosystem: str | None) -> str | None:
    if any(not finding.precise for finding in findings):
        return None
    fixes = [finding.fixed_in for finding in findings if finding.fixed_in]
    if not fixes or any(version_tuple(fix, ecosystem) is None for fix in fixes):
        return None
    return max(fixes, key=lambda item: version_tuple(item, ecosystem) or ())


def annotate(packages: list[Package], results: list[dict]) -> None:
    targets = [package for package in packages if not package.unchecked_reason and package.version]
    if len(results) != len(targets):
        raise MatchError(f"OSV returned {len(results)} results for {len(targets)} packages")
    for package, result in zip(targets, results):
        vulns = []
        findings = []
        for vuln in (result or {}).get("vulns") or []:
            if vuln.get("withdrawn"):
                continue
            finding = _finding(vuln, package)
            if finding is not None:
                vulns.append(vuln)
                findings.append(finding)
        package.vulns = _group_findings(findings, vulns, package.ecosystem)
        package.recommend = _recommend(package.vulns, package.ecosystem)


def _fetch_vuln(osv_id: str) -> dict:
    url = "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(osv_id, safe="")
    request = urllib.request.Request(url, headers={"User-Agent": "supply-scan"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise MatchError(f"OSV advisory {osv_id} failed: {exc}") from exc


def hydrate(results: list[dict], fetch=None) -> list[dict]:
    """OSV batch results often contain only an id. The fix and severity live on the full advisory."""
    fetch = fetch or _fetch_vuln
    needed: list[str] = []
    for result in results:
        for vuln in (result or {}).get("vulns") or []:
            if vuln.get("id") and not vuln.get("affected"):
                needed.append(str(vuln["id"]))
    details: dict[str, dict] = {}
    unique = list(dict.fromkeys(needed))
    if unique:
        if len(unique) > 1:
            with ThreadPoolExecutor(max_workers=8) as pool:
                for osv_id, full in zip(unique, pool.map(fetch, unique)):
                    details[osv_id] = full
        else:
            for osv_id in unique:
                details[osv_id] = fetch(osv_id)
    hydrated: list[dict] = []
    for result in results:
        vulns = []
        for vuln in (result or {}).get("vulns") or []:
            replacement = details.get(str(vuln.get("id") or ""))
            vulns.append(replacement or vuln)
        hydrated.append({"vulns": vulns})
    return hydrated


def _post_batch(chunk: list[Package]) -> list[dict]:
    payload = {
        "queries": [
            {
                "version": package.version,
                "package": {"name": package.name, "ecosystem": package.ecosystem},
            }
            for package in chunk
        ]
    }
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "supply-scan"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise MatchError(f"OSV query failed: {exc}") from exc
    batch = body.get("results")
    if not isinstance(batch, list) or len(batch) != len(chunk):
        raise MatchError("OSV returned an unexpected batch")
    return batch


def query_osv(
    packages: list[Package],
    cache: DiskCache | NullCache | None = None,
    on_progress=None,
) -> None:
    targets = [package for package in packages if not package.unchecked_reason and package.version]
    if not targets:
        return
    if cache is None:
        cache = DiskCache(default_cache_dir())
    total = len(targets)
    done = 0

    def emit_packages() -> None:
        if on_progress is None:
            return
        if done != total and done != 1 and done % 20 != 0:
            return
        on_progress({
            "phase": "osv",
            "packages_done": done,
            "packages_total": total,
        })

    if on_progress is not None:
        on_progress({"phase": "osv", "packages_done": 0, "packages_total": total})
    results: list[dict | None] = [None] * len(targets)
    missing: list[int] = []
    for index, package in enumerate(targets):
        hit = cache.get_query(package.ecosystem, package.name, package.version or "")
        if hit is None:
            missing.append(index)
        else:
            results[index] = hit
            done += 1
            emit_packages()
    for start in range(0, len(missing), BATCH_SIZE):
        indexes = missing[start:start + BATCH_SIZE]
        chunk = [targets[index] for index in indexes]
        for index, result in zip(indexes, _post_batch(chunk)):
            package = targets[index]
            cache.put_query(package.ecosystem, package.name, package.version or "", result)
            results[index] = result
            done += 1
            emit_packages()

    filled = [result or {"vulns": []} for result in results]
    needed: list[str] = []
    id_ecosystem: dict[str, str] = {}
    for package, result in zip(targets, filled):
        for vuln in (result or {}).get("vulns") or []:
            if vuln.get("id") and not vuln.get("affected"):
                osv_id = str(vuln["id"])
                needed.append(osv_id)
                id_ecosystem.setdefault(osv_id, package.ecosystem)
    advisory_total = len(list(dict.fromkeys(needed)))
    advisory_done = 0
    advisory_lock = threading.Lock()

    def fetch(osv_id: str) -> dict:
        nonlocal advisory_done
        cached = cache.get_advisory(osv_id)
        if cached is not None:
            body = cached
        else:
            body = None
            if zip_hydration_enabled() and isinstance(cache, DiskCache):
                ecosystem = id_ecosystem.get(osv_id)
                if ecosystem:
                    body = read_advisory_from_zip(osv_id, ecosystem, cache)
            if body is None:
                body = _fetch_vuln(osv_id)
            cache.put_advisory(osv_id, body)
        if on_progress is not None and advisory_total:
            with advisory_lock:
                advisory_done += 1
                current = advisory_done
                if current == advisory_total or current == 1 or current % 5 == 0:
                    on_progress({
                        "phase": "advisories",
                        "advisories_done": current,
                        "advisories_total": advisory_total,
                    })
        return body

    if on_progress is not None and advisory_total:
        on_progress({
            "phase": "advisories",
            "advisories_done": 0,
            "advisories_total": advisory_total,
        })
    print(
        f"osv: {len(targets) - len(missing)} cached, {len(missing)} fetched",
        file=sys.stderr,
    )
    annotate(packages, hydrate(filled, fetch))
