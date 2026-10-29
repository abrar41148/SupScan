# supply-scan architecture

Working title. The folder name is a placeholder and nothing in the program depends on it. Rename the directory when a real name exists. The command users run is `python -m supply_scan`.

This file is the source of truth for the code in this directory. An earlier design note lives in the VendorPulse repo at `pulsengine-fork/SUPPLY_CHAIN_MONITOR.md`. Where they disagree, this file and the code win.

## What this is

A command-line scanner. Point it at a git URL or a local checkout. It lists the dependency versions that checkout actually resolved, asks the OSV API which of those versions are affected by a known advisory, and names the release that fixes each one.

It is not a website, not a desktop app, and not a feature of VendorPulse. There is no database, no account, and no scheduler. CI is the monitor: run the command on pull requests and on a nightly job. The exit code is the signal.

Python 3.11 or newer. Standard library only (`json`, `tomllib`, `urllib`, `subprocess`, `argparse`, `decimal`, `concurrent.futures`). No third-party packages. No install step. `pyproject.toml` declares the project and a `supply-scan` script entry, but the tested way to run it is from this directory:

```
python -m supply_scan <git-url | local-path> [--branch NAME] [--strict] [--json PATH] [--html [PATH]] [--no-cache]
```

```
python -m unittest tests.test_scan
```

## Where it came from

VendorPulse (`pulsengine-fork`) already clones a repo into a temp sandbox and deletes it. That behavior was copied, not imported.

Taken from `backend/services/git_wrapper.py`:

- Allow only `http://`, `https://`, and `git@` URLs before git sees them. The pattern is the same character class as VendorPulse.
- `git clone --depth 1`, optional `-b`, 180 second timeout.
- Destination under the system temp dir, directory `supply-scan-repos`, name `{repo}_{8 hex chars}`.
- On failure or timeout, delete the partial directory.
- After the scan, always delete the sandbox. On Windows, `.git` objects are read-only, so `delete_tree` clears the read-only bit and retries `rmtree`.
- A local path is scanned in place and never deleted.
- Clone is an argument list to `subprocess.run`, not a shell string, so a weird URL cannot inject commands. `git` must be on `PATH`.

Left in VendorPulse and not used here:

- Service catalog, pricing scraper, cost calculator, sunset checks.
- AST import matching.
- `backend/services/osv_client.py`. That client queries a catalog vendor id with no version, across seven ecosystems, keeps three hits, and labels each one High. This tool queries ecosystem + package name + resolved version.
- React app, WebSocket scan log, SQLite, the hourly pricing scheduler.
- The manifest parsers in `backend/services/scanner.py`. They keep direct dependencies only and turn a range like `^1.2.3` into the string `1.2.3` with `lstrip`. That string is not an installed version. This tool does not do that.

The directory walk still skips the same heavy directories VendorPulse skipped, plus Rust `target`, Go `vendor`, and `site-packages`: `.git`, `node_modules`, `dist`, `build`, `.next`, `__pycache__`, `.venv`, `venv`.

## Layout

```
supply-scan/
  ARCHITECTURE.md          this file
  README.md                how to run it
  pyproject.toml           name, requires-python >= 3.11, no dependencies
  .gitignore               pyc, venv, report files
  supply_scan/
    __init__.py            __version__ = "0.0.0"
    __main__.py            calls cli.main and exits with its code
    cli.py                 argparse, wires the four stages, writes reports
    acquire.py             URL check, clone, local open, delete
    inventory.py           walk the tree, parse manifests, dedupe
    cache.py               disk cache of OSV batch rows and full advisories
    match.py               OSV query, advisory hydration, severity, fixed version
    report.py              text, JSON, HTML, exit code
  tests/
    test_scan.py           unittest, no network
```

There is one pipeline and no plugins. Each stage is a function the next stage calls.

```
cli.main
  acquire.open_workspace     Workspace (path, commit, branch, cloned)
  inventory.scan_tree        list[Package]
  inventory.dedupe
  match.query_osv            mutates Package.vulns and Package.recommend
  report.render_*            text on stdout, JSON file, optional HTML
  report.exit_code           process status
```

Reports are written inside the `with open_workspace` block, before a clone is deleted. Paths are relative to the current working directory, not inside the clone. Stdout is the human report. Progress (`cloned ...`, `wrote ...`) goes to stderr. `AcquireError` and `MatchError` print to stderr and return 2. The clone is still deleted if matching fails, because deletion is in the context manager's `finally`.

## Stage 1 — acquire

`acquire.open_workspace(target, branch)` is a context manager.

A target is a git URL when it starts with `http://`, `https://`, or `git@`. Anything else is a filesystem path and must be an existing directory.

URL flow:

1. `sanitize_git_url` rejects strings that do not match the allowlist regex.
2. `git clone --depth 1 --no-checkout` into `%TEMP%\supply-scan-repos\{name}_{id}`. `--branch` adds `-b`. The clone runs with `GIT_CONFIG_NOSYSTEM=1`, an empty `GIT_CONFIG_GLOBAL`, `GIT_TERMINAL_PROMPT=0`, and `-c submodule.recurse=false`, `-c credential.helper=`, `-c protocol.file.allow=never`.
3. `git ls-tree -r HEAD` lists blobs. Manifest paths that `scan_tree` reads are written into the work tree with `git cat-file blob` (including parent `pom.xml` files when a child pom needs them). Symlinks and submodule gitlinks are skipped. More than 2000 manifests, one file over 16 MB, or more than 48 MB total fails the clone.
4. `git rev-parse HEAD` and `git branch --show-current` fill `commit` and `branch`. If those commands fail, the fields stay `None` and the scan continues.
5. On the way out, `delete_tree` removes the clone.

Local flow: resolve the path, read the same git identity if the directory is a repo, yield it, do not delete it. `--branch` is stored on the workspace but does not check out a different branch of a local directory.

`Workspace` fields: `path`, `cloned`, `target` (sanitized URL or the path string), `commit`, `branch`.

## Stage 2 — inventory

`inventory.scan_tree(root)` walks the workspace and returns `Package` rows. A row is either resolved (safe to send to OSV) or unchecked (shown in the report, never queried).

```
Package
  ecosystem          OSV ecosystem string: npm, PyPI, Go, crates.io
  name
  version            concrete release, a raw range, or None
  direct             declared by the root (or a workspace member), versus pulled in transitively
  dev                development or build dependency
  manifest           path relative to the repo root, forward slashes
  unchecked_reason   None when the version is resolved
  vulns              filled later by match.py
  recommend          one upgrade target, filled later, or None
  alias              manifest nickname when it differs from name, otherwise None
```

Files are read as `utf-8-sig` so a UTF-8 BOM does not make `json.loads` fail. A parser exception becomes one unchecked row, `could not parse {manifest}`, instead of aborting the scan.

### Which file wins in a directory

npm, same directory:

1. `package-lock.json` if present.
2. Otherwise `pnpm-lock.yaml`.
3. Otherwise `package.json`, and only when no ancestor directory has either lockfile. A root lockfile covers nested workspace `package.json` files, so those ranges are not also reported as unchecked.

Rust:

- Every `Cargo.toml` under a `Cargo.lock` contributes direct-dependency names to that lock. The nearest ancestor lock owns the manifest.
- A `Cargo.toml` with no lock anywhere above it becomes unchecked rows (`version is a range, no lockfile`).

Go: every `go.mod` is its own root. Versions in `require` are already exact.

Python, same directory, first match stops the rest:

1. `uv.lock`
2. `poetry.lock` (reads a sibling `pyproject.toml` only to decide which names are direct)
3. `requirements.txt` and any other `requirements*.txt`. A filename containing `dev` is marked dev.
4. `pyproject.toml` alone, every dependency unchecked.

A nested `requirements.txt` is not covered by a parent `uv.lock`. They are separate manifests.

### Parser rules

`package-lock.json` v2 and v3 (`packages` map):

- Direct names come from every lock entry whose path does not contain a `node_modules` segment (the root and workspace packages): `dependencies`, `optionalDependencies`, and `peerDependencies` are prod; `devDependencies` are dev. A package whose name is in either set is direct.
- Each `node_modules/...` entry with a `version` is a package. `link: true` entries are skipped. A link is followed through `resolved` when that path is another entry in the same file.
- Name is `meta.name`, or the last `node_modules/` segment (so `@scope/pkg` stays intact).
- Dev versus prod is a walk from those same roots. Prod edges are `dependencies`, `optionalDependencies`, and `peerDependencies`, followed through every package they reach. `devDependencies` edges are dev, and so is every package reached only from them. Lookup is Node's: `node_modules/<name>` under the requiring package, then each parent directory. A scoped name is one dependency and two path segments. The scope folder is not a parent.
- Production wins. A path reached by both walks is prod. Two installed copies stay separate, so a dev-only copy stays dev when a different version of the same name is prod.
- An entry nothing reaches keeps `dev` or `devOptional` from the lock. With neither flag, a direct dev name is dev and every other name is prod.

`package-lock.json` v1 (only a `dependencies` tree): top-level keys are treated as direct, nested `dependencies` as transitive. There is no separate read of `package.json` for v1.

`package.json` with no lock:

- A spec that is exactly `digits.digits.digits` is resolved and queried.
- Every other spec (`^`, `~`, `>=`, `*`, `workspace:`, `file:`, git, and so on) is unchecked: `version is a range, no lockfile`. The raw spec is kept as `version` for display.

`pnpm-lock.yaml` is parsed as lines, not with a YAML library. Package keys at indent 2 matching `name@version` (optional leading `/`, optional quotes, optional `()` peer suffix) become packages. `dev: true` inside that block marks dev. Direct names come from `dependencies:` / `devDependencies:` at the top level (lockfile v6) or under `importers:` (lockfile v9). This will miss a lockfile shape that does not look like those two. A parse that throws becomes one unchecked row.

`go.mod`: `require (` blocks and single `require` lines. `// indirect` means transitive. The version string is kept as written, including the leading `v` and pseudo-versions. There is no dev scope. `replace` is applied before the row is built. A version on the left of `=>` matches only that required version; without one it matches every require of that module. A version-specific replace wins over a path-wide one. The right side is a local path when it has no version, and a module when it has one. A local path or a different module path is unchecked (`replaced by local path ...` or `replaced by {module}`) and is not queried. The same module path is queried at the replacement version. A module that appears only in `replace` is not a package.

`Cargo.lock`: `[[package]]` entries. No `source` means the local crate and is skipped. `source` starting with `registry+` is queried on `crates.io` under the lock package name, which is the crates.io name. `source` starting with `git+` is unchecked: `git dependency, not a crates.io release`. Direct names come from the owning `Cargo.toml` files: `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, and `[target.*.dependencies]`. A table value with `package = "serde"` queries `serde`; the table key is `alias` when it differs, and the text row ends with `as serde1`. `[dev-dependencies]` and `[build-dependencies]` are dev. Target-specific dependencies count as prod. A `Cargo.toml` with no lock uses the same crates.io name on its unchecked rows.

`uv.lock`: `[[package]]` entries whose `source` is `virtual`, `editable`, `path`, or `directory` are the project itself and are not queried. Their `dependencies` names are the direct prod set. `metadata.requires-dev` and `dev-dependencies` groups are the dev set. `source.registry` packages are queried on PyPI. `source.git` is unchecked. Names are normalized with PEP 503 (`_` and `.` become `-`, lowercased) before the OSV call.

`poetry.lock`: `[[package]]` name and version. `category == "dev"` or groups `dev` / `test` / `tests` mark dev. Direct names come from `pyproject.toml`: `[project].dependencies`, optional groups named dev/test, and Poetry's `[tool.poetry.dependencies]` (the `python` key is ignored), `[tool.poetry.dev-dependencies]`, and `[tool.poetry.group.{dev,test,tests}.dependencies]`. A prod name wins over a dev mark.

`requirements*.txt`: a line `name==version` (optional extras, optional environment marker) is resolved. `*` in the version is not a pin. Other lines are unchecked. Lines starting with `-` (`-r`, `-e`) are skipped. Comments are stripped.

`pyproject.toml` with no lock and no requirements file: every prod and dev name from the same name-collection as Poetry, all unchecked, version `None`.

### Dedupe

`dedupe` runs before any network call.

- Resolved rows merge on `(ecosystem, name, version)`. The same package in two lockfiles becomes one query. Direct wins over transitive and keeps that manifest path. Prod wins over dev.
- Unchecked rows are not merged with resolved rows. They merge only when manifest, name, version, and reason are all the same.

After dedupe, `cli` sorts by manifest, name, version.

## Stage 3 — match

`match.query_osv` sends only rows with a version and no `unchecked_reason`.

### Batch query

`POST https://api.osv.dev/v1/querybatch`, up to 1000 queries per call, 60 second timeout.

```json
{
  "queries": [
    {
      "version": "4.17.20",
      "package": { "name": "lodash", "ecosystem": "npm" }
    }
  ]
}
```

Ecosystem strings are already the OSV ones: `npm`, `PyPI`, `Go`, `crates.io`. Go versions keep the `v` prefix from `go.mod`. The `results` array is aligned with the queries. A short or missing array raises `MatchError` (exit 2). A network or JSON failure does the same. An empty inventory skips the HTTP call.

With `version` set, OSV returns advisories that affect that release. The batch body often contains only `{ "id": "GHSA-..." }`. Severity and the fixed version are not in that stub.

### Hydration

`query_osv` builds one function and passes it to `hydrate`. That function reads the advisory cache. On a miss it calls `GET https://api.osv.dev/v1/vulns/{id}` (30 second timeout), stores the body with `put_advisory`, and returns it. `hydrate` collects ids that have no `affected` array. Duplicate ids are fetched once. One missing id runs on the calling thread. More than one runs in a pool of 8, and the cache check runs inside each worker, so a command-line scan overlaps those GETs. Stderr stays quiet until the pool finishes. `hydrate(results, fetch)` accepts a fake fetch so tests do not touch the network. A failed fetch is `MatchError`.

Batch rows and full advisories are stored for 24 hours by `cache.DiskCache`. The directory is `%LOCALAPPDATA%\supply-scan` on Windows, otherwise `$XDG_CACHE_HOME/supply-scan` or `~/.cache/supply-scan`. A hit is keyed by ecosystem, name, and version for the batch row, and by advisory id for the body. Expired entries are misses, so a newly published advisory can still appear. `--no-cache` uses `NullCache` and always calls OSV. A cache file that cannot be written is ignored. Stderr prints `osv: N cached, M fetched` for the batch rows. The work plan for what to change next is `ROADMAP.md`.

Withdrawn advisories (`withdrawn` set) are dropped.

### Severity

Prefer `severity[]` where `score` is a `CVSS:3.0` or `CVSS:3.1` vector. The base score is computed with the CVSS v3.1 formula and Decimal round-up to one decimal place. Bands: 9.0+ critical, 7.0+ high, 4.0+ medium, otherwise low. A numeric `score` string such as `9.8` uses the same bands. If there is no usable CVSS v3 score, `database_specific.severity` or `ecosystem_specific.severity` is mapped: CRITICAL, HIGH, MODERATE/MEDIUM, LOW. Anything else, including CVSS v4 only, stays `unknown`. Unknown does not fail the exit code.

`id` starting with `MAL-` is `kind: malware`. Other ids are `kind: vulnerability`. The first alias starting with `CVE-` is kept. Summary is one line, trimmed to 200 characters.

### Fixed version

For each advisory, ranges are kept only when `affected[].package.ecosystem` matches and the name matches. PyPI names are compared after the same `-` / lower normalization.

Each range's `events` are walked as pairs: `introduced`, then an optional `fixed` or `last_affected`.

- `introduced <= installed < fixed` → that `fixed` string is the patch.
- `introduced <= installed <= last_affected` → affected, no patched release.
- `introduced <= installed` with no upper bound → affected, no patched release.
- A later pair does not cancel an earlier pair. `introduced 0 / fixed 1.2.0 / introduced 1.4.0 / fixed 1.4.2` contains `1.0.0` and does not contain `1.3.0`.

Version comparison splits on `.`, requires every segment to be digits, pads the shorter tuple with zeros, strips one leading `v`, and strips `+build` metadata. The OSV beginning marker `0` is version `(0,)`. A pre-release (`1.0.0-rc.1`) does not parse. If any bound in a range fails to parse, that advisory is imprecise: every `fixed` string on its ranges is listed, comma-separated, and it does not contribute to the single upgrade line.

Per package, `recommend` is the highest parsed `fixed` version among precise advisories. One bump is meant to clear that set. `recommend` stays `None` when any advisory is imprecise, when a fix string itself does not parse, or when every match has no patched release. Those advisories still appear as their own lines.

## Stage 4 — report

`Snapshot` is the target, commit, branch, and the package list.

Text (stdout) prints a header with package, vulnerable, and unchecked counts, then each vulnerable package (dev after prod), then an `unchecked:` section. Clean packages are counted and omitted from the text. When `alias` is set, a printed row ends with `as {alias}`. A clean renamed crate keeps that nickname only in the JSON. For each finding: id, CVE if any, severity, summary, then `fixed in ...` or, only when the range walk was precise and found no fix, `no patched release`. If `recommend` is set, the package ends with `upgrade to {version}`.

JSON (`--json`, default `supply-scan-report.json`) is the full list, including clean packages:

```json
{
  "target": "",
  "commit": "",
  "branch": "",
  "counts": { "packages": 0, "vulnerable": 0, "unchecked": 0 },
  "packages": [
    {
      "ecosystem": "npm",
      "name": "lodash",
      "version": "4.17.20",
      "direct": true,
      "dev": false,
      "manifest": "package-lock.json",
      "unchecked_reason": null,
      "recommend": "4.18.0",
      "alias": null,
      "vulns": [
        {
          "id": "GHSA-35jh-r3h4-6jhm",
          "cve": "CVE-2021-23337",
          "severity": "high",
          "summary": "Command Injection in lodash",
          "fixed_in": "4.17.21",
          "kind": "vulnerability"
        }
      ]
    }
  ]
}
```

`--html` writes the same text, escaped, inside one dark monospace page. Default path `supply-scan-report.html`. Passing `--html some.html` uses that path.

### Exit code

| Code | When |
| --- | --- |
| 0 | No failing finding. Unchecked rows do not fail the run. Unknown, low, and medium do not fail it. Dev findings do not fail it unless `--strict`. |
| 1 | Any package, including dev, has a `MAL-` advisory. Or a prod package has critical or high. With `--strict`, dev packages and medium severity also fail. |
| 2 | Bad URL, clone failure, clone timeout, git missing, OSV batch failure, OSV advisory fetch failure. |

Unchecked ranges are visible in the header and the text section so a green exit is not a claim that every manifest was resolved.

## What has been run

From this directory, `python -m unittest tests.test_scan` — 22 tests, no network. They cover the URL allowlist, not deleting a local directory, deleting a read-only `.git` blob, npm lock direct/dev/transitive plus a nested `package.json` hidden by a parent lock, bare `package.json` ranges versus an exact pin, pnpm v9 including a scoped name, `go.mod` indirect, a local replace and a different-module replace left unchecked while a same-module replace is queried at the replacement version, requirements pin versus range, `uv.lock` skipping the virtual project package, a Cargo registry crate queried under its crates.io name with the manifest nickname kept as `alias`, a `git+` crate left unchecked, a renamed crate with no lock still unchecked under the crates.io name, a broken lock becoming one unchecked row, dedupe preferring prod, CVSS `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` scoring 9.8, reintroduced ranges, highest-fix recommendation, withdrawn advisories dropped, `last_affected` producing no recommendation, exit code ignoring a dev high until `--strict`, batch id stubs replaced by a fake full advisory, and two stub ids whose fake fetches overlap.

A live OSV check of a one-package lockfile, `lodash@4.17.20`, returned five advisories, `upgrade to 4.18.0`, and exit 1. Two of those were high (`CVE-2021-23337` fixed in `4.17.21`, `CVE-2026-4800` fixed in `4.18.0`). The 4.18.0 line is the max of the precise fixes, so it also covers the medium fixes in `4.17.21` and `4.17.23`.

An offline inventory of the VendorPulse repo next to this folder (`package-lock.json` + `uv.lock`, no OSV) resolved 583 packages: 456 npm, 127 PyPI, 0 unchecked, 58 direct prod npm packages. That was a parser check, not a vulnerability verdict.

On 2026-10-23, `python -m supply_scan https://github.com/dubinc/dub.git` cloned the repo and printed `osv: 0 cached, 3079 fetched`. The process then blocked in `GET /v1/vulns/{id}` and was stopped with Ctrl+C before the 30 second timeout. No report was written. The batch rows were stored. A later run the same day printed `osv: 3079 cached, 0 fetched`, commit `20ca8994950f83d5aedab88b802b55b7243c89b6` on `main`, 3079 packages, 171 vulnerable, 0 unchecked, and wrote `supply-scan-report.json`.

The same day, `python -m supply_scan https://github.com/kubernetes/kubernetes.git` printed `osv: 0 cached, 408 fetched`, commit `061e55d37f0219a7ca8f0b980c8e86b7cd706347` on `master`, 569 packages, 5 vulnerable, 161 unchecked. Every unchecked row was a local `replace` (`replaced by local path ./staging/src/k8s.io/...` from the root `go.mod`, and relative paths such as `../api` from the staging modules). `github.com/golang/glog` `v1.2.2` in `hack/tools/go.mod` recommended `1.2.4`. `golang.org/x/crypto` `v0.57.0` had no patched release. The other three vulnerable modules were `github.com/google/cel-go` `v0.29.2`, `golang.org/x/net` `v0.59.0`, and `golang.org/x/text` `v0.34.0`.

A local scan of `dalek-cryptography/curve25519-dalek` checked out at `61533d75cfc5df3452cbee20181c89ab2e40bccd` printed `osv: 0 cached, 157 fetched`, 157 packages, 4 vulnerable, 0 unchecked. `branch` was empty because the checkout was detached. The text listed `anyhow` `1.0.100`, `crossbeam-epoch` `0.9.18`, `rand` `0.9.2`, and dev `bincode` `1.3.3`. The JSON, not the text, held the renames: `rustcrypto-ff` `0.14.0-rc.0` direct with alias `ff`, and `rustcrypto-group` `0.14.0-rc.0` direct with alias `group`.

## What this tool does not do

- Install packages to resolve ranges. No `npm install`, `pip install`, `cargo fetch`, or `go build`.
- `yarn.lock`. If that is the only npm lock, `package.json` ranges are unchecked.
- Maven, Gradle, RubyGems, Composer, pub.
- Reachability (whether the vulnerable function is called).
- License checks, typosquat detection beyond whatever OSV already returns as `MAL-`, provenance, signatures.
- Opening upgrade pull requests. The report names the version.
- A web UI, a database of past scans, Slack, or a built-in cron. Schedule the command in CI.
- SARIF. JSON is the machine format.
- Failing the process because a lockfile was missing. That shows up as unchecked rows and exit 0 unless some other resolved package is vulnerable.

## Limits that will bite a real repo

- `osv: N cached, M fetched` counts packages, not advisories. After that line, distinct ids without `affected` are fetched up to 8 at a time. A second scan skips the batch posts for those packages and still downloads advisories that were not saved.
- pnpm parsing is line-oriented. A lockfile that is not v6 or v9 shaped can be silently incomplete rather than rejected, as long as it does not throw.
- Pre-release and non-numeric versions are still queried. The upgrade line is withheld when those strings cannot be ordered, and each advisory keeps its own `fixed in` text.
- `recommend` is a version sort of dotted integers, not a full semver or PEP 440 comparator. It is wrong for pre-release ordering, which is why those versions refuse to collapse.
- Malware fails the exit code even for a dev dependency. Severity findings in dev do not, unless `--strict`.
- The JSON file is written even when the process is about to exit 1. It is not written when acquire or OSV fails before that point.
