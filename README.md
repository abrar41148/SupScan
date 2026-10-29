# supply-scan

Reports dependency versions that have a known vulnerability, and a release that fixes them.

Point it at a git URL or a folder. It reads the versions that project already resolved, asks the [OSV](https://osv.dev/) API, and writes a report. Same scan from the command line or from a page on 127.0.0.1.

Python 3.11 or newer. No packages to install. Git has to be on PATH if you pass a URL. A local folder does not need git.

Run the commands from this directory.

## Scan

```
python -m supply_scan <git-url-or-folder>
python -m supply_scan <git-url-or-folder> --branch NAME
python -m supply_scan <git-url-or-folder> --strict
python -m supply_scan <git-url-or-folder> --html
python -m supply_scan <git-url-or-folder> --no-cache
python -m supply_scan <git-url-or-folder> --zip-advisories
python -m supply_scan <git-url-or-folder> --json report.json
```

You can pass up to four targets. They are scanned one after another, and a package version that appears in more than one is only sent to OSV once. `--batch FILE` reads the list from a JSON file. For a private HTTPS repo, `--git-token` or `GITHUB_TOKEN` is used when git has no login saved.

The text report goes to stdout. JSON is written to `supply-scan-report.json` unless `--json` names another path. `--html` also writes `supply-scan-report.html`. Progress lines (`cloned`, `wrote`) go to stderr.

Exit codes:

- `0` nothing failed
- `1` a malware advisory, or a critical or high finding in a production dependency. `--strict` also fails on dev dependencies and on medium severity
- `2` the target could not be opened, or the lookup failed

With more than one target, the process exits with the worst of those codes.

A local folder is scanned where it is and is not deleted. A URL is cloned into a temp directory and that clone is removed when the scan finishes, including when the scan fails.

## Page

```
python -m supply_scan.serve
```

or double-click `serve.bat`. The page is `http://127.0.0.1:8765/` unless you pass `--port`. It serves `gui/index.html`. You can scan a git URL or a folder, and save, compare, or ignore findings. Ignoring a finding records it. The exit code still counts it.

Restart the server after Python changes. The page is read from disk on each request.

## Tests

```
python -m unittest tests.test_scan
```

The tests do not use the network.

## Limits

Versions come from lockfiles and from versions written in the repo. It does not run npm, pip, Cargo, Go, Composer, Bundler, pub, Gradle, or Maven. A range with no lockfile is skipped and is not sent to OSV.

OSV answers are kept for 24 hours. `--no-cache` asks again. `--zip-advisories`, or `SUPPLY_SCAN_ZIP_ADVISORIES=1`, fills in advisory text from OSV's per-ecosystem `all.zip` when a batch result is only a stub. The batch query itself still uses the network.

It does not check whether the vulnerable function is actually called, and it does not open an upgrade pull request.

The page only listens on loopback.
