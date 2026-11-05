"""Colour for the text report. Only used on a real terminal; stripping the codes gives back the plain text."""

from __future__ import annotations

import os
import re
import sys

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"


def _rgb(red: int, green: int, blue: int) -> str:
    return f"\x1b[38;2;{red};{green};{blue}m"


SEVERITY = {
    "critical": _BOLD + _rgb(255, 45, 120),
    "high": _rgb(255, 130, 40),
    "medium": _rgb(255, 215, 0),
    "low": _rgb(0, 200, 255),
    "unknown": _rgb(150, 150, 170),
}
_MALWARE = "\x1b[1;97;41m"
_GOOD = _rgb(60, 235, 150)
_BAD = _rgb(255, 45, 120)
_WARN = _rgb(255, 215, 0)
_ID = _rgb(120, 140, 255)
_NAME = _BOLD + _rgb(0, 229, 255)

_FINDING = re.compile(
    r"^(  )(\S+)((?:  CVE-\S+)?)((?:  \(also [^)]*\))?)  (critical|high|medium|low|unknown)$"
)
_MALWARE_LINE = re.compile(r"^(  )(\S+)  malware  (\w+)$")
_PACKAGE = re.compile(r"^(\S+)(  .*  )(direct|transitive)(  )(dev|prod)(  .*)$")
_ANSI = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\")
_OSV = "https://osv.dev/vulnerability/"


def strip(text: str) -> str:
    return _ANSI.sub("", text)


def use_color(stream=None) -> bool:
    stream = sys.stdout if stream is None else stream
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()) or "NO_COLOR" in os.environ:
        return False
    if os.name == "nt":
        os.system("")  # makes the Windows console understand colour codes
    return True


def link(text: str, vuln_id: str) -> str:
    """Make text a clickable link to the advisory (OSC 8, understood by modern terminals)."""
    return f"\x1b]8;;{_OSV}{vuln_id}\x1b\\{text}\x1b]8;;\x1b\\"


def _linked_ids(text: str) -> str:
    """Link every GHSA/CVE/other advisory id inside a run of text like '  CVE-1  (also GHSA-x GHSA-y)'."""
    return re.sub(r"\b(?:GHSA(?:-[a-z0-9]{4}){3}|CVE-\d{4}-\d+|[A-Z]+-\d{4}-\d+|MAL-\d+)\b",
                  lambda match: link(match.group(0), match.group(0)), text)


def _count(label: str, value: str, bad: bool) -> str:
    colour = _BAD if bad else _GOOD
    return f"{label}: {colour}{_BOLD}{value}{_RESET}"


def _line(line: str) -> str:
    if line == "supply-scan":
        return _NAME + line + _RESET
    if line.startswith(("target: ", "commit: ")):
        label, _, rest = line.partition(": ")
        return f"{_DIM}{label}:{_RESET} {rest}"
    if line.startswith("packages: ") and "vulnerable: " in line:
        packages, vulnerable, unchecked = re.split(r"  (?=vulnerable: |unchecked: )", line)
        count = int(vulnerable.split(": ")[1])
        loose = int(unchecked.split(": ")[1])
        return "  ".join((
            packages,
            _count("vulnerable", str(count), count > 0),
            f"unchecked: {_WARN}{unchecked.split(': ')[1]}{_RESET}" if loose else unchecked,
        ))
    if line.startswith("No known vulnerabilities"):
        return _GOOD + _BOLD + line + _RESET
    if line in ("unchecked:", "unrecognised names:"):
        return _WARN + line + _RESET
    found = _MALWARE_LINE.match(line)
    if found:
        return f"{found[1]}{_ID}{link(found[2], found[2])}{_RESET}  {_MALWARE}malware{_RESET}  {SEVERITY.get(found[3], _DIM)}{found[3]}{_RESET}"
    found = _FINDING.match(line)
    if found:
        indent, osv_id, cve, also, severity = found.groups()
        return (
            f"{indent}{_ID}{link(osv_id, osv_id)}{_RESET}{_DIM}{_linked_ids(cve + also)}{_RESET}"
            f"  {SEVERITY[severity]}{severity}{_RESET}"
        )
    found = _PACKAGE.match(line)
    if found:
        name, middle, relation, gap, scope, tail = found.groups()
        scope_text = f"{_DIM}{scope}{_RESET}" if scope == "dev" else scope
        return f"{_NAME}{name}{_RESET}{middle}{relation}{gap}{scope_text}{_DIM}{tail}{_RESET}"
    stripped = line.strip()
    if stripped.startswith("fixed in "):
        return f"  {_GOOD}{stripped}{_RESET}"
    if stripped == "no patched release":
        return f"  {_BAD}{stripped}{_RESET}"
    if stripped.startswith("upgrade to "):
        return f"  {_GOOD}{_BOLD}{stripped}{_RESET}"
    if line.startswith("=== ") and line.endswith(" ==="):
        return _BOLD + line + _RESET
    return line


def colorize(text: str) -> str:
    return "\n".join(_line(line) for line in text.split("\n"))


def verdict(status: int) -> str:
    """One coloured result line for the end of a scan."""
    if status == 0:
        return f"{_GOOD}{_BOLD}PASS{_RESET}  no finding breaks the rule (exit 0)"
    if status == 1:
        return f"{_BAD}{_BOLD}FAIL{_RESET}  a finding breaks the rule (exit 1)"
    return f"{_WARN}{_BOLD}ERROR{_RESET}  the scan could not be completed (exit {status})"
