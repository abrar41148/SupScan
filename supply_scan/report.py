"""Text, JSON, and HTML copies of one scan."""

from __future__ import annotations

import html
import json
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
                lines.append(f"  {finding.osv_id}{cve}  {finding.severity}")
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
            }
            for finding in package.vulns
        ],
    }


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


def exit_code(packages: list[Package], strict: bool) -> int:
    for package in packages:
        if package.unchecked_reason:
            continue
        if any(finding.kind == "malware" for finding in package.vulns):
            return 1
        if package.dev and not strict:
            continue
        for finding in package.vulns:
            if finding.severity in ("critical", "high"):
                return 1
            if strict and finding.severity == "medium":
                return 1
    return 0
