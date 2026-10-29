"""supply-scan <git-url | local-path>"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from supply_scan.acquire import AcquireError
from supply_scan.match import MatchError
from supply_scan.report import exit_code, render_html, render_json, render_text
from supply_scan.run import MAX_BATCH_TARGETS, TargetSpec, collect, run_batch


def _emit(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        sys.stdout.buffer.write(text.encode(encoding, errors="replace"))


def _json_path(base: str, index: int, count: int) -> str:
    path = Path(base)
    if count == 1:
        return str(path)
    return str(path.with_name(f"{path.stem}-{index + 1}{path.suffix}"))


def _load_batch(path: Path) -> tuple[bool, list[TargetSpec]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read batch file: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("Batch file must be a JSON object")
    strict = bool(payload.get("strict"))
    file_token = payload.get("git_token")
    file_token = file_token.strip() if isinstance(file_token, str) and file_token.strip() else None
    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise SystemExit("Batch file needs a non-empty targets list")
    if len(raw_targets) > MAX_BATCH_TARGETS:
        raise SystemExit(f"At most {MAX_BATCH_TARGETS} targets are allowed")
    specs: list[TargetSpec] = []
    for item in raw_targets:
        if not isinstance(item, dict) or not item.get("target"):
            raise SystemExit("Each target entry needs a target string")
        branch = item.get("branch")
        row_token = item.get("git_token")
        row_token = row_token.strip() if isinstance(row_token, str) and row_token.strip() else None
        specs.append(TargetSpec(
            str(item["target"]),
            str(branch) if branch else None,
            row_token or file_token,
        ))
    return strict, specs


def _run_single(args, specs: list[TargetSpec]) -> int:
    spec = specs[0]
    try:
        snapshot, packages, cloned = collect(
            spec.target,
            spec.branch or args.branch,
            git_token=args.git_token,
            use_cache=not args.no_cache,
        )
    except (AcquireError, MatchError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if cloned:
        print(f"cloned {snapshot.target}", file=sys.stderr)
    text = render_text(snapshot)
    json_path = _json_path(args.json, 0, 1)
    Path(json_path).write_text(render_json(snapshot), encoding="utf-8")
    if args.html:
        Path(args.html).write_text(render_html(snapshot), encoding="utf-8")

    _emit(text)
    print(f"wrote {json_path}", file=sys.stderr)
    if args.html:
        print(f"wrote {args.html}", file=sys.stderr)
    return exit_code(packages, args.strict)


def _run_multi(args, specs: list[TargetSpec]) -> int:
    shared = (args.git_token or "").strip() or None
    for spec in specs:
        if spec.branch is None and args.branch:
            spec.branch = args.branch
        if shared and not spec.git_token:
            spec.git_token = shared
    try:
        status, reports, snapshots = run_batch(
            specs,
            strict=args.strict,
            use_cache=not args.no_cache,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    count = len(reports)
    for index, (report, snapshot) in enumerate(zip(reports, snapshots)):
        target = snapshot.target or specs[index].target
        json_path = _json_path(args.json, index, count)
        snapshot_json = {key: value for key, value in report.items() if key not in ("exit_code", "error")}
        Path(json_path).write_text(json.dumps(snapshot_json, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {json_path}", file=sys.stderr)
        if report.get("error"):
            print(f"{target}: {report['error']}", file=sys.stderr)
        if index:
            _emit("\n")
        _emit(f"=== {target} ===\n")
        if not report.get("error") or snapshot.packages:
            _emit(render_text(snapshot))
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="supply-scan",
        description="Report known-vulnerable dependency versions and the release that fixes them.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Git URL (http, https, git@) or a local directory; up to four for a batch scan",
    )
    parser.add_argument("--branch", help="Branch to clone. Local directories ignore this.")
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="JSON file with strict and targets[{target, branch?}] (max four)",
    )
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
    parser.add_argument(
        "--zip-advisories",
        action="store_true",
        help="Hydrate batch stub advisories from OSV all.zip exports in the cache when possible",
    )
    parser.add_argument(
        "--git-token",
        default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        help="GitHub PAT for private HTTPS repos (or set GITHUB_TOKEN)",
    )
    args = parser.parse_args(argv)

    if args.zip_advisories:
        os.environ["SUPPLY_SCAN_ZIP_ADVISORIES"] = "1"

    batch_strict = False
    specs: list[TargetSpec] = []
    if args.batch:
        batch_strict, specs = _load_batch(Path(args.batch))
        if args.targets:
            print("Ignoring positional targets when --batch is set", file=sys.stderr)
    elif args.targets:
        if len(args.targets) > MAX_BATCH_TARGETS:
            print(f"At most {MAX_BATCH_TARGETS} targets are allowed", file=sys.stderr)
            return 2
        token = (args.git_token or "").strip() or None
        specs = [TargetSpec(target, args.branch, token) for target in args.targets]
    else:
        parser.error("Provide a target or --batch")

    if batch_strict:
        args.strict = True

    if args.html and len(specs) != 1:
        print("--html applies only to a single-target scan", file=sys.stderr)
        return 2

    if len(specs) == 1:
        return _run_single(args, specs)
    return _run_multi(args, specs)
