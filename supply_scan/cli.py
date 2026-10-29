"""supply-scan <git-url | local-path>"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from supply_scan.acquire import AcquireError
from supply_scan.match import MatchError
from supply_scan.report import exit_code, render_html, render_json, render_text
from supply_scan.run import collect


def _emit(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        sys.stdout.buffer.write(text.encode(encoding, errors="replace"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="supply-scan",
        description="Report known-vulnerable dependency versions and the release that fixes them.",
    )
    parser.add_argument("target", help="Git URL (http, https, git@) or a local directory")
    parser.add_argument("--branch", help="Branch to clone. Local directories ignore this.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also fail on dev dependencies and medium severity",
    )
    parser.add_argument("--json", default="supply-scan-report.json", help="JSON report path")
    parser.add_argument(
        "--html",
        nargs="?",
        const="supply-scan-report.html",
        help="Also write an HTML copy of the text report",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Ask OSV again instead of reusing answers saved in the last 24 hours",
    )
    args = parser.parse_args(argv)

    try:
        snapshot, packages, cloned = collect(
            args.target,
            args.branch,
            use_cache=not args.no_cache,
        )
    except (AcquireError, MatchError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if cloned:
        print(f"cloned {snapshot.target}", file=sys.stderr)
    text = render_text(snapshot)
    Path(args.json).write_text(render_json(snapshot), encoding="utf-8")
    if args.html:
        Path(args.html).write_text(render_html(snapshot), encoding="utf-8")

    _emit(text)
    print(f"wrote {args.json}", file=sys.stderr)
    if args.html:
        print(f"wrote {args.html}", file=sys.stderr)
    return exit_code(packages, args.strict)
