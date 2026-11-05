## Setup

- Python 3.11 or newer. `pyproject.toml` declares no third-party packages.
- Git is required only when the target is a remote URL.

From the parent directory:

```
python -m supply_scan <git-url-or-local-path>
python -m supply_scan <git-url-or-local-path> --html
python -m supply_scan <git-url-or-local-path> --strict
python -m supply_scan <git-url-or-local-path> --markdown
python -m supply_scan <git-url-or-local-path> --no-cache
```

The command writes `supply-scan-report.json` beside the current directory and prints the text report. `--html` also writes `supply-scan-report.html`. `--markdown` writes `supply-scan-report.md`: the verdict and rule, tables of the failing packages (direct first, versions merged, upgrade version, linked GHSA/CVE ids with the OSV summary), and a collapsed list of every advisory per failing package. With several targets it writes one file per target. Exit `0` means no failing finding. Exit `1` means a failing finding. Exit `2` means the target or the lookup could not be completed.

Pass/fail rule: any single finding at or above the threshold fails the run (there is no count). The threshold is `high` by default, `medium` with `--strict`, or whatever `--fail-on critical|high|medium|low|unknown|none` says. Malware advisories always fail. Dev-only dependencies are skipped unless `--strict`. Packages that could not be checked (no pinned version) are skipped, not failed. Whether a fix exists, and the GUI's ignore list, do not change the exit code.

Full command-line guide (options, exit codes, CI, batches): [docs/CLI.md](docs/CLI.md).

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
