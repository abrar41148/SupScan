# supply-scan CLI guide

Scan a repository or folder for dependency versions with known vulnerabilities, from the terminal. The command reads lockfiles and manifests, asks [OSV](https://osv.dev) about every resolved package, prints a report, and exits with a code you can use in CI.

## Quick start

```
python -m supply_scan <git-url-or-local-path>
```

Needs Python 3.11 or newer. Git is only needed for remote URLs. There are no third-party Python packages.

```
python -m supply_scan .                                            # the current folder
python -m supply_scan https://github.com/dubinc/dub.git           # a remote repo
python -m supply_scan https://github.com/dubinc/dub.git --branch main
python -m supply_scan . --markdown                                 # also write a markdown report
```

The scan prints the report, writes `supply-scan-report.json`, and exits `0`, `1` or `2`.

## What you see

On a terminal, a scan shows, in order:

1. A neon banner. The gradient moves to the next of six on every run.
2. A progress bar with one line per phase: cloning, counting files, reading manifests, looking up packages, fetching advisories. Finished phases keep a tick.
3. The report, coloured by severity.
4. A one-line result: **PASS**, **FAIL** or **ERROR**, with the exit code.

The banner, bar, colours and result line only appear on a real terminal. In pipes, redirected output and CI they are skipped, so logs and files stay clean.

### Severity colours

| Severity | Colour |
|---|---|
| critical | bold hot pink-red |
| high | orange |
| medium | yellow |
| low | cyan |
| unknown | grey |
| malware | white on red |

Green is used for `fixed in …`, `upgrade to …` and clean results; red for `no patched release`.

### Clickable advisory ids

Every GHSA and CVE id in the report is a link to its page on osv.dev. In Windows Terminal, VS Code's terminal, iTerm2 and most modern terminals, hold **Ctrl** (**Cmd** on macOS) and click the id. Terminals that do not support links just show the plain id. Links are only added on a real terminal, so saved and piped output stays plain text.

## Pass or fail

The exit code is the contract:

| Exit code | Meaning |
|---|---|
| `0` | No finding breaks the rule |
| `1` | At least one finding breaks the rule |
| `2` | The target or the lookup could not be completed |

The rule, in full:

- A **single** finding at or above the threshold fails the run. There is no count.
- The threshold is `high` by default (so any high or critical fails), `medium` with `--strict`, or whatever `--fail-on` says.
- **Malware** advisories always fail.
- **Dev-only** dependencies are skipped unless you pass `--strict`.
- Packages that **could not be checked** (for example, no pinned version) are not counted. They are listed in the report.
- Whether a fix exists, and the GUI's ignore list, do not change the exit code.

```
python -m supply_scan . --fail-on critical    # only critical (and malware) fails
python -m supply_scan . --strict               # medium and worse, dev dependencies included
python -m supply_scan . --fail-on none         # only malware fails
```

## Options

| Option | What it does |
|---|---|
| `targets` | A git URL (`http`, `https`, `git@`) or a local folder. Up to four for a batch scan. |
| `--branch NAME` | Branch to clone. Without it, the repo's default branch. Local folders ignore it. |
| `--batch FILE` | Scan the targets in a JSON file (see below). Up to four. |
| `--strict` | Also fail on dev dependencies and medium severity. |
| `--fail-on LEVEL` | Lowest severity that fails: `critical`, `high`, `medium`, `low`, `unknown` or `none`. |
| `--json PATH` | Where to write the JSON report. Default `supply-scan-report.json`. |
| `--html [PATH]` | Also write an HTML copy of the text report. Default `supply-scan-report.html`. Single target only. |
| `--markdown [PATH]` | Also write the markdown report. Default `supply-scan-report.md`. |
| `--no-banner` | Skip the banner. |
| `--no-progress` | Skip the progress bar. |
| `--no-cache` | Ask OSV again instead of reusing answers from the last 24 hours. |
| `--zip-advisories` | Fill in short advisories from OSV's bulk exports in the cache when possible. |
| `--git-token TOKEN` | GitHub token for private HTTPS repos. Also read from `GITHUB_TOKEN` or `GH_TOKEN`. |

## Reports

| File | Contents | When |
|---|---|---|
| Terminal text | Every vulnerable package and its advisories, with the version to upgrade to | Always |
| `supply-scan-report.json` | The full machine-readable result | Always |
| `--markdown` | The verdict and rule, a table of failing packages (direct first, versions merged), linked GHSA/CVE ids with the OSV summary, and a collapsed list of every advisory per failing package | On request |
| `--html` | The text report in a web page | On request |

The markdown report is built only from the scan and OSV advisory text, nothing is added by hand. It is meant for pull requests, tickets and handoffs. Each advisory links to its page on osv.dev.

With several targets, each file name gets an index: `supply-scan-report-1.json`, `supply-scan-report-2.json`, and so on.

## Scanning private repos

Pass a GitHub token so the clone can authenticate:

```
python -m supply_scan https://github.com/you/private.git --git-token ghp_xxx
```

Better: set `GITHUB_TOKEN` (or `GH_TOKEN`) in your environment and leave the flag off, so the token does not end up in your shell history.

## Scanning several repos at once

```
python -m supply_scan https://github.com/a/one.git https://github.com/b/two.git
```

Or from a file, which also lets each target pick its own branch:

```json
{
  "strict": false,
  "targets": [
    { "target": "https://github.com/a/one.git", "branch": "main" },
    { "target": "https://github.com/b/two.git", "branch": "release" },
    { "target": "C:\\work\\local-app" }
  ]
}
```

```
python -m supply_scan --batch repos.json
```

Rules for batches: at most four targets, one shared OSV lookup, and one failed target does not stop the others. The exit code is the worst of all: `2` if any target failed, otherwise `1` if any failed the rule, otherwise `0`. `strict: true` in the file applies to every target.

## Using it in CI

A scan in CI needs no flags to stay quiet: when the `CI` environment variable is set, the banner, progress bar and colours are skipped.

GitHub Actions example:

```yaml
name: supply-scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Scan dependencies
        run: python -m supply_scan . --fail-on high --markdown supply-scan-report.md
      - name: Keep the reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: supply-scan
          path: |
            supply-scan-report.md
            supply-scan-report.json
```

The step fails the job when a finding breaks the rule (exit `1`) or the scan could not run (exit `2`). The reports are uploaded even when it fails. This assumes the tool is available in the repo being scanned, for example vendored or installed with `pip install` from a checkout of supply-scan.

## Environment variables

| Variable | Effect |
|---|---|
| `GITHUB_TOKEN`, `GH_TOKEN` | Token for private HTTPS clones |
| `NO_COLOR` | Turns colours off (the banner and bar also stay uncoloured) |
| `CI` | Skips the banner, progress bar and colours |
| `SUPPLY_SCAN_NO_BANNER` | Skips the banner |

## Cache and saved state

OSV answers are reused for 24 hours, so repeat scans are fast. They live in the `supply-scan` folder under `%LOCALAPPDATA%` on Windows, `$XDG_CACHE_HOME` if set, or `~/.cache`. The same folder holds the saved GUI scans and a small file, `banner.json`, which remembers the last banner gradient. Use `--no-cache` to force fresh answers.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Exit `2` | The clone failed (bad URL, no access, wrong branch) or OSV could not be reached. The message goes to stderr. |
| Exit `0` but a package is missing | It had no pinned version, so it is listed as unchecked, not scanned. Commit a lockfile. |
| Authentication errors on a private repo | Pass `--git-token`, or set `GITHUB_TOKEN`. |
| Garbled box characters in the banner | The terminal cannot show them. A plain-ASCII version is used automatically on most terminals; `--no-banner` always works. |
| Results look out of date | OSV answers are cached for 24 hours. Use `--no-cache`. |

## Limits

The scan reads versions already written in a lockfile or as a literal in the repository. It does not install packages, and a version range without a lock stays unchecked. Vulnerability data comes from OSV, so an advisory that OSV does not have yet will not show up.
