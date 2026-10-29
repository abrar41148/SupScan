# supply-scan

Report known-vulnerable dependency versions and the release that fixes them.

Point the tool at a git URL or a local directory. It reads the versions that directory already resolved, asks the [OSV](https://osv.dev/) API about those versions, and writes a report. The same scan runs from the command line and from a page bound to `127.0.0.1`.

## Requirements

- Python 3.11 or newer. This tree was checked with Python 3.13.
- No third-party packages. `pyproject.toml` lists an empty dependency set.
- Git on `PATH` when the target is a remote URL. A local directory does not need git.

There is no install step. Run the commands below from this directory.

## Run a scan

```
python -m supply_scan <git-url-or-local-path>
python -m supply_scan <git-url-or-local-path> --branch NAME
python -m supply_scan <git-url-or-local-path> --strict
python -m supply_scan <git-url-or-local-path> --html
python -m supply_scan <git-url-or-local-path> --no-cache
python -m supply_scan <git-url-or-local-path> --json report.json
```

The text report goes to stdout. A JSON report is written to `supply-scan-report.json` unless `--json` names another path. `--html` also writes `supply-scan-report.html`. Progress lines (`cloned`, `wrote`) go to stderr.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No failing finding. |
| 1 | A malware advisory, or a critical or high finding in a production dependency. `--strict` also fails on development dependencies and on medium severity. |
| 2 | The target could not be opened, or the lookup failed. |

A local directory is scanned in place and is not deleted. A remote URL is cloned into a temporary directory and that clone is deleted when the scan finishes, including when the scan fails.

## Local page

```
python -m supply_scan.serve
```

or double-click `serve.bat`. The page is `http://127.0.0.1:8765/` unless `--port` is set. It serves `gui/index.html`, can scan a git URL or a folder you pick in the browser, and can save, compare, and ignore findings. Ignoring a finding records it. The exit code still counts it.

Python changes need a restarted server. The page is read from disk on each request.

## Tests

```
python -m unittest tests.test_scan
```

The suite does not call the network. Three cases used for the written hand-in, and the URL allowlist check, are recorded under `submission/`.

## Limitations

- Versions are taken from lockfiles and from literals written in the repo. The tool does not run npm, pip, Cargo, Go, Composer, Bundler, pub, Gradle, or Maven. A range with no lock stays unchecked and is not sent to OSV.
- Vulnerability data comes from OSV. Answers are reused for 24 hours. `--no-cache` asks again. There is no offline advisory database.
- The scan does not decide whether the vulnerable function is called, and it does not open an upgrade pull request.
- The page listens on loopback only.

A short map of the course hand-in (report, slides, test evidence, security outcome) is in [submission/README.md](submission/README.md).
