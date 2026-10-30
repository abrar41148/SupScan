## Setup

- Python 3.11 or newer. `pyproject.toml` declares no third-party packages.
- Git is required only when the target is a remote URL.

From the parent directory:

```
python -m supply_scan <git-url-or-local-path>
python -m supply_scan <git-url-or-local-path> --html
python -m supply_scan <git-url-or-local-path> --strict
python -m supply_scan <git-url-or-local-path> --no-cache
```

The command writes `supply-scan-report.json` beside the current directory and prints the text report. `--html` also writes `supply-scan-report.html`. Exit `0` means no failing finding. Exit `1` means a failing finding. Exit `2` means the target or the lookup could not be completed.

The local page:

```
python -m supply_scan.serve
```

or `serve.bat`. It listens on `127.0.0.1` port `8765` unless `--port` is set, and opens `gui/index.html`.

Offline tests:

```
python -m unittest tests.test_scan
```

## Limitations

The scan reads versions that are already written in a lockfile or as a literal in the repo. It does not install packages, and a range without a lock stays unchecked. Vulnerability data comes from OSV. Answers are reused for 24 hours. The page is local only. Accepting a finding on the page does not change the exit code. A fuller list is in the technical report.
