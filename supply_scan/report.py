"""Text, JSON, and HTML copies of one scan."""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass

from supply_scan.inventory import Package
from supply_scan.match import Finding

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


@dataclass
class Snapshot:
    target: str
    commit: str | None
    branch: str | None
    packages: list[Package]


def _relation(package: Package) -> str:
    return "direct" if package.direct else "transitive"


def _scope(package: Package) -> str:
    return "dev" if package.dev else "prod"


def _package_line(package: Package) -> str:
    version = package.version or "-"
    line = (
        f"{package.name}  {version}  {package.ecosystem}  "
        f"{_relation(package)}  {_scope(package)}  {package.manifest}"
    )
    if package.alias:
        line += f"  as {package.alias}"
    return line


def unrecognised_names(packages: list[Package]) -> list[str]:
    """Property names from a pom that did not resolve to a version written in the repo."""
    found: list[str] = []
    seen: set[str] = set()
    for package in packages:
        if not package.unchecked_reason:
            continue
        manifest = package.manifest.replace("\\", "/").lower()
        if not manifest.endswith("pom.xml"):
            continue
        tokens: list[str] = []
        for source in (package.version, package.name):
            if source:
                tokens.extend(part.strip() for part in re.findall(r"\$\{([^{}]+)\}", source))
        if package.alias:
            tokens.extend(part.strip() for part in package.alias.split(", ") if part.strip())
        for token in tokens:
            if token and token not in seen:
                seen.add(token)
                found.append(token)
    found.sort()
    return found


def _finding_key(finding: Finding) -> tuple:
    malware = 0 if finding.kind == "malware" else 1
    return (malware, _SEVERITY_ORDER.get(finding.severity, 9), finding.osv_id)


def render_text(snapshot: Snapshot) -> str:
    vulnerable = [package for package in snapshot.packages if package.vulns]
    unchecked = [package for package in snapshot.packages if package.unchecked_reason]
    lines = [
        "supply-scan",
        f"target: {snapshot.target}",
        f"commit: {snapshot.commit or '-'}  branch: {snapshot.branch or '-'}",
        (
            f"packages: {len(snapshot.packages)}  "
            f"vulnerable: {len(vulnerable)}  "
            f"unchecked: {len(unchecked)}"
        ),
        "",
    ]
    if not vulnerable and not unchecked:
        lines.append("No known vulnerabilities in resolved packages.")
        return "\n".join(lines) + "\n"

    vulnerable.sort(key=lambda package: (package.dev, package.name, package.version or ""))
    for package in vulnerable:
        lines.append(_package_line(package))
        for finding in sorted(package.vulns, key=_finding_key):
            if finding.kind == "malware":
                lines.append(f"  {finding.osv_id}  malware  {finding.severity}")
            else:
                cve = f"  {finding.cve}" if finding.cve else ""
                also = ""
                if finding.related_ids:
                    also = f"  (also {' '.join(finding.related_ids)})"
                lines.append(f"  {finding.osv_id}{cve}{also}  {finding.severity}")
            if finding.summary:
                lines.append(f"  {finding.summary}")
            if finding.fixed_in:
                lines.append(f"  fixed in {finding.fixed_in}")
            elif finding.precise:
                lines.append("  no patched release")
        if package.recommend:
            lines.append(f"  upgrade to {package.recommend}")
        lines.append("")

    if unchecked:
        lines.append("unchecked:")
        for package in unchecked:
            lines.append(f"  {_package_line(package)}")
            lines.append(f"  {package.unchecked_reason}")
        lines.append("")
    names = unrecognised_names(snapshot.packages)
    if names:
        lines.append("unrecognised names:")
        for name in names:
            lines.append(f"  {name}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _package_dict(package: Package) -> dict:
    return {
        "ecosystem": package.ecosystem,
        "name": package.name,
        "version": package.version,
        "direct": package.direct,
        "dev": package.dev,
        "manifest": package.manifest,
        "unchecked_reason": package.unchecked_reason,
        "recommend": package.recommend,
        "alias": package.alias,
        "vulns": [
            {
                "id": finding.osv_id,
                "cve": finding.cve,
                "severity": finding.severity,
                "summary": finding.summary,
                "fixed_in": finding.fixed_in,
                "kind": finding.kind,
                **({"related_ids": list(finding.related_ids)} if finding.related_ids else {}),
            }
            for finding in package.vulns
        ],
    }


def snapshot_from_report(report: dict) -> Snapshot:
    """The reverse of render_json, for reports saved earlier or opened from a file."""
    packages = []
    for row in report.get("packages") or []:
        package = Package(
            str(row.get("ecosystem") or ""),
            str(row.get("name") or ""),
            row.get("version"),
            bool(row.get("direct")),
            bool(row.get("dev")),
            str(row.get("manifest") or ""),
            row.get("unchecked_reason"),
            recommend=row.get("recommend"),
            alias=row.get("alias"),
        )
        for item in row.get("vulns") or []:
            package.vulns.append(Finding(
                str(item.get("id") or "unknown"),
                item.get("cve"),
                str(item.get("severity") or "unknown"),
                str(item.get("summary") or ""),
                item.get("fixed_in"),
                str(item.get("kind") or "vulnerability"),
                True,
                tuple(item.get("related_ids") or ()),
            ))
        packages.append(package)
    return Snapshot(
        target=str(report.get("target") or ""),
        commit=report.get("commit"),
        branch=report.get("branch"),
        packages=packages,
    )


def render_json(snapshot: Snapshot) -> str:
    vulnerable = sum(1 for package in snapshot.packages if package.vulns)
    unchecked = sum(1 for package in snapshot.packages if package.unchecked_reason)
    payload = {
        "target": snapshot.target,
        "commit": snapshot.commit,
        "branch": snapshot.branch,
        "counts": {
            "packages": len(snapshot.packages),
            "vulnerable": vulnerable,
            "unchecked": unchecked,
        },
        "unrecognised_names": unrecognised_names(snapshot.packages),
        "packages": [_package_dict(package) for package in snapshot.packages],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_html(snapshot: Snapshot) -> str:
    body = html.escape(render_text(snapshot))
    title = html.escape(f"supply-scan {snapshot.target}")
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{title}</title>"
        "<style>body{font:14px/1.45 ui-monospace,monospace;margin:2rem;"
        "background:#111;color:#eee}pre{white-space:pre-wrap}</style>"
        f"</head><body><pre>{body}</pre></body></html>\n"
    )


def worst_exit_code(codes: list[int]) -> int:
    if 2 in codes:
        return 2
    if 1 in codes:
        return 1
    return 0


FAIL_LEVELS = ("critical", "high", "medium", "low", "unknown", "none")


def fail_threshold(strict: bool, fail_on: str | None = None) -> str:
    return fail_on or ("medium" if strict else "high")


def finding_fails(package: Package, finding: Finding, strict: bool, fail_on: str | None = None) -> bool:
    """True when this finding breaks the rule.

    Malware always fails. Otherwise a finding fails when its severity is at or above
    the threshold: fail_on if given, else "medium" under strict and "high" without.
    Dev-only packages are skipped unless strict. Unchecked packages never fail here.
    "none" turns the severity rule off (malware still fails).
    """
    if package.unchecked_reason:
        return False
    if finding.kind == "malware":
        return True
    if package.dev and not strict:
        return False
    level = fail_threshold(strict, fail_on)
    if level == "none":
        return False
    return finding.severity in FAIL_LEVELS[: FAIL_LEVELS.index(level) + 1]


def exit_code(packages: list[Package], strict: bool, fail_on: str | None = None) -> int:
    """1 when any finding breaks the rule in finding_fails, else 0."""
    for package in packages:
        for finding in package.vulns:
            if finding_fails(package, finding, strict, fail_on):
                return 1
    return 0
