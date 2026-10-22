"""supply-scan <git-url | local-path>"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from supply_scan.acquire import AcquireError, open_workspace
from supply_scan.cache import DiskCache, NullCache, default_cache_dir
from supply_scan.inventory import dedupe, scan_tree
from supply_scan.match import MatchError, query_osv
from supply_scan.report import Snapshot, exit_code, render_html, render_json, render_text


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
        with open_workspace(args.target, args.branch) as workspace:
            if workspace.cloned:
                print(f"cloned {workspace.target}", file=sys.stderr)
            packages = dedupe(scan_tree(workspace.path))
            packages.sort(key=lambda package: (package.manifest, package.name, package.version or ""))
            cache = NullCache() if args.no_cache else DiskCache(default_cache_dir())
            query_osv(packages, cache=cache)
            snapshot = Snapshot(
                target=workspace.target,
                commit=workspace.commit,
                branch=workspace.branch,
                packages=packages,
            )
            text = render_text(snapshot)
            Path(args.json).write_text(render_json(snapshot), encoding="utf-8")
            if args.html:
                Path(args.html).write_text(render_html(snapshot), encoding="utf-8")
    except (AcquireError, MatchError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    _emit(text)
    print(f"wrote {args.json}", file=sys.stderr)
    if args.html:
        print(f"wrote {args.html}", file=sys.stderr)
    return exit_code(packages, args.strict)
