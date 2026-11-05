"""A short markdown report of one scan: verdict, failing packages, and every advisory behind them."""

from __future__ import annotations

from collections import defaultdict

from supply_scan.inventory import Package
from supply_scan.match import Finding
from supply_scan.report import (
    Snapshot,
    exit_code,
    fail_threshold,
    finding_fails,
)

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_OSV = "https://osv.dev/vulnerability/"


def _cell(text: object) -> str:
    return " ".join(str(text).split()).replace("|", "/")


def _link(vuln_id: str) -> str:
    return f"[{vuln_id}]({_OSV}{vuln_id})"


def _rank(finding: Finding) -> tuple:
    malware = 0 if finding.kind == "malware" else 1
    return (malware, _ORDER.get(finding.severity, 9), finding.osv_id)


def _ref(finding: Finding) -> str:
    ref = _link(finding.osv_id)
    if finding.cve:
        ref += f" / {_link(finding.cve)}"
    return ref


def _rule(strict: bool, fail_on: str | None) -> str:
    level = fail_threshold(strict, fail_on)
    if level == "none":
        what = "Malware is the only thing that fails the run"
    else:
        severity = {"critical": "any critical", "high": "any high or critical"}.get(level, f"any {level} or worse")
        scope = "any package (dev-only ones included)" if strict else "a non-dev package"
        what = f"Rule: {severity} finding in {scope} fails the run. Malware always fails"
    return f"{what}. Everything below is scan output and OSV advisory text; nothing is added by hand."


def _advisory_header(strict: bool, fail_on: str | None) -> str:
    level = fail_threshold(strict, fail_on)
    return {"high": "High+", "none": "Failing"}.get(level, f"{level.capitalize()}+" if level != "critical" else "Critical")


def render_markdown(snapshot: Snapshot, *, strict: bool = False, fail_on: str | None = None) -> str:
    packages = snapshot.packages
    status = exit_code(packages, strict, fail_on)

    failing: dict[str, list[Package]] = defaultdict(list)
    for package in packages:
        if any(finding_fails(package, finding, strict, fail_on) for finding in package.vulns):
            failing[package.name].append(package)

    rows = []
    for name, group in failing.items():
        hits: dict[str, Finding] = {}
        for package in group:
            for finding in package.vulns:
                if finding_fails(package, finding, strict, fail_on):
                    hits.setdefault(finding.osv_id, finding)
        worst = min(hits.values(), key=_rank)
        rows.append({
            "name": name,
            "group": sorted(group, key=lambda package: package.version or ""),
            "direct": any(package.direct for package in group),
            "versions": sorted({package.version or "-" for package in group}),
            "fix": sorted({package.recommend or "none" for package in group}),
            "worst": worst,
            "count": len(hits),
        })
    rows.sort(key=lambda row: (not row["direct"], _rank(row["worst"])[:2], -row["count"], row["name"]))

    vulnerable = sum(1 for package in packages if package.vulns)
    unchecked = [package for package in packages if package.unchecked_reason]
    head = f"# supply-scan: {'FAIL' if status else 'PASS'} (exit {status}) - {snapshot.target}"
    lines = [head, ""]
    where = " on ".join(
        part for part in (f"Commit `{snapshot.commit[:7]}`" if snapshot.commit else None,
                          f"`{snapshot.branch}`" if snapshot.branch else None) if part
    )
    counts = f"Packages: {len(packages)}, vulnerable: {vulnerable}, unchecked: {len(unchecked)}."
    lines.append(f"{where}. {counts}" if where else counts)
    lines.append(_rule(strict, fail_on))
    lines.append("")

    if rows:
        direct = sum(1 for row in rows if row["direct"])
        lines.append(f"{len(rows)} packages fail ({direct} direct, {len(rows) - direct} transitive).")
        lines.append("")
        for title, flag in (("Direct dependencies", True), ("Transitive dependencies", False)):
            chosen = [row for row in rows if row["direct"] == flag]
            if not chosen:
                continue
            lines += [
                f"## {title}",
                "",
                f"| Package | Versions in use | Upgrade to | Worst | {_advisory_header(strict, fail_on)} advisories | Worst advisory (OSV summary) |",
                "|---|---|---|---|---|---|",
            ]
            for row in chosen:
                worst = row["worst"]
                severity = "malware" if worst.kind == "malware" else worst.severity
                lines.append(
                    f"| {_cell(row['name'])} | {_cell(', '.join(row['versions']))} "
                    f"| {_cell(', '.join(row['fix']))} | {severity} | {row['count']} "
                    f"| {_ref(worst)}: {_cell(worst.summary)} |"
                )
            lines.append("")

        lines += ["## All advisories for the failing packages", "",
                  "Expand a package to see every advisory for every version in use, all severities.", ""]
        for row in rows:
            group = row["group"]
            total = len({finding.osv_id for package in group for finding in package.vulns})
            lines.append(
                f"<details><summary>{_cell(row['name'])}: {total} advisories "
                f"across {len(group)} version(s)</summary>"
            )
            lines.append("")
            for package in group:
                relation = "direct" if package.direct else "transitive"
                scope = ", dev" if package.dev else ""
                lines.append(
                    f"**{_cell(package.version or '-')}** ({relation}{scope}, {_cell(package.manifest)}): "
                    f"upgrade to {_cell(package.recommend or 'none')}"
                )
                lines.append("")
                for finding in sorted(package.vulns, key=_rank):
                    kind = "malware" if finding.kind == "malware" else finding.severity
                    fixed = f", fixed in {_cell(finding.fixed_in)}" if finding.fixed_in else ""
                    lines.append(f"- {kind}: {_ref(finding)}{fixed}: {_cell(finding.summary)}")
                lines.append("")
            lines += ["</details>", ""]

    dev_only = 0
    other: dict[str, int] = defaultdict(int)
    for package in packages:
        for finding in package.vulns:
            if finding_fails(package, finding, strict, fail_on):
                continue
            if package.dev:
                dev_only += 1
            else:
                other[finding.severity] += 1
    parts = [f"{dev_only} findings in dev-only packages"]
    levels = [f"{other[level]} {level}" for level in sorted(other, key=lambda level: _ORDER.get(level, 9))]
    if len(levels) > 1:
        levels = [", ".join(levels[:-1]) + " and " + levels[-1]]
    left_out = parts[0] + (", " + levels[0] + " in other packages" if levels else "")
    lines += ["## Not listed above", ""]
    lines.append(
        f"{left_out}. They do not fail the run. "
        "The full list is in the scan's JSON report and on the supply-scan page."
    )
    if unchecked:
        lines += ["", f"{len(unchecked)} packages could not be checked:", ""]
        for package in unchecked[:20]:
            lines.append(f"- {_cell(package.name)} ({_cell(package.manifest)}): {_cell(package.unchecked_reason)}")
        if len(unchecked) > 20:
            lines.append(f"- ... and {len(unchecked) - 20} more")
    return "\n".join(lines).rstrip() + "\n"
