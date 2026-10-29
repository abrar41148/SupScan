# OSV-Scanner comparison

Both tools list resolved dependency versions and ask OSV.dev which advisories affect them. OSV-Scanner is Google’s general scanner: more ecosystems, images, an offline database, and an experimental command that rewrites files. This scanner is a read-only verdict with an explicit unchecked list, one upgrade line, and a local page for history and comparison.

Sources: google/osv-scanner docs for usage, offline mode, supported lockfiles, configuration, guided remediation, and output, read 29 Oct 2026. This tree: `ROADMAP.md`, `match.py`, `ignore.py`, `inventory.py`. `ARCHITECTURE.md` still omits ecosystems the roadmap marks done.

**Comparison status (29 Oct 2026):** Side-by-side review is **complete** for its scope. Clones (`osv-scanner` `c9c5077`, `osv-scalibr` `94dac8f`), fixture runs, and matcher notes live in [OSV-COMPARISON-HANDOFF.md](OSV-COMPARISON-HANDOFF.md). **Use the backlog below when you want to pull behavior from Google’s tree into this one.** Re-run parity with `compare_reports.py` and `compare-empty.toml` after inventory or match changes.

**Accuracy (summary):** On the default online path, advisory ids **agree** when both tools send the same `(ecosystem, name, version)`. Gaps in real repos are mostly **inventory** (what gets queried), not a second matcher. This scanner already drops some API false positives via a local range walk in `match.py`; see [Source comparison](#source-comparison-local-clones-oct-2026).

---

## Adopt from OSV-Scanner (implementation backlog)

Check items off here as you implement them. **Reference code** is in the local clones under `osv-scalibr/` (extractors + offline matcher) and `osv-scanner/` (CLI, config, fix experiment). Do not commit those clones unless you vendor them.

### Matching and offline

- [x] **One issue, one finding.** Merge OSV records that share an id or alias into one row with `related_ids` (`match.py`). GHSA preferred as primary id; ignore any id in the set on the page; exit code still counts grouped findings.
- [x] **Narrow zip hydrate.** After `querybatch`, load full advisories from cached `{ecosystem}/all.zip` before per-id GET (`supply_scan/osv_zip.py`; `--zip-advisories` / `SUPPLY_SCAN_ZIP_ADVISORIES=1`). Batch still uses the API.
- [ ] **Full offline mode.** Port the Google path: `--download-offline-databases`, then `--offline` with **no** API calls; error if a needed zip is missing. Requires package lookup inside `all.zip` (batch no longer names ids first) and scalibr-style matching: sort range events, per-ecosystem semver, state machine — see `osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns/vulnerability.go` and `vulnerability_test.go`. Keep today’s API path for `--no-cache`. Commit-level git advisories are not in zips either way.
- [ ] **Regression tests from scalibr.** Copy or adapt representative cases from `vulnerability_test.go` (especially unsorted events, npm, Maven) into `tests.test_scan` so offline work does not drift.

### Remediation hints (read-only only)

Do **not** port OSV-Scanner’s **fix** command: it rewrites `package-lock.json` or `pom.xml` and may run `npm install --package-lock-only`, which can execute scripts from an untrusted tree. That conflicts with clone hardening (no checkout, no git config, no file protocol).

- [ ] **Direct parent on npm findings.** OSV’s in-place / relax strategies edit locks; here, only **print** the direct dependency that owns the vulnerable transitive (lock walk already labels dev/prod). `recommend` stays the highest precise fix on the **vulnerable package** itself. No `npm`, no deps.dev, no rewriting locks.
- [ ] **Optional: rank direct deps (read-only).** Like OSV relax, list which direct dependency bumps would clear the most transitive findings — scores only, no file edits.

### Inventory parity (lockfiles and edge cases)

These are what most side-by-side diffs are. Each row is optional until a real project needs it; tick and implement in `inventory.py` (mirror scalibr extractors where they exist).

**Lockfiles Google reads that this scanner does not yet:**

- [ ] C/C++: `conan.lock`; commit checks for submodules and vendored trees
- [ ] Dart: `package_config.json` (`pubspec.lock` already read)
- [ ] Elixir: `mix.lock`
- [ ] Haskell: `cabal.project.freeze`, `stack.yaml.lock`
- [ ] Java: `buildscript-gradle.lockfile`, `gradle/verification-metadata.xml`
- [ ] JavaScript: `bun.lock`
- [ ] .NET: `deps.json`, `packages.config`, `packages.lock.json`
- [ ] Python: `Pipfile.lock`, `pdm.lock`, `pylock.toml`
- [ ] R: `renv.lock`
- [ ] Ruby: `gems.locked`

**Behavior gaps (same repo, different rows queried):**

- [ ] **Skip npm `file:` / workspace locals** when building the query list (Google: `osvutil.IsLocal` in scalibr). Reduces noise vs querying path packages as if they were registry releases.
- [ ] **Go stdlib from the `go` directive** — Google special-cases toolchain/stdlib (e.g. `.99` patch handling); only adopt if you explicitly want stdlib advisories without guessing non-lock versions elsewhere.
- [ ] **Maven transitives** — Google resolves via **deps.dev** when locks are missing; you only read literals in `pom.xml` / lock chains. **Policy choice:** adopting deps.dev closes gaps like `maven-transitive` fixtures but sends inventory to a second service and can hide “unchecked range” signal. If you add it, make it opt-in (e.g. `--resolve-maven-transitives`) and keep the default off.

Manifest-only versions: **keep** leaving ranges unchecked and not sent. OSV queries manifest best-effort with a warning; that is stricter here on purpose.

### Ignore and config

- [ ] **Reason and expiry on ignores.** OSV hides findings by advisory id (+ aliases) with optional reason and expiry. Here, ignore stays **ecosystem + name + version + advisory**; add optional `reason` and `expires` fields in `ignore.py` and the page without changing exit-code semantics unless you document otherwise.
- [ ] **Project ignore file (optional).** OSV uses `osv-scanner.toml` with `PackageOverrides`. A small `supply-scan.toml` (or reuse JSON ignores in-repo) could mirror id/alias ignores for CI; still prefer version-scoped rows for “accepted in this lock.”

### CLI, cache, and page

- [ ] **`--download-offline-databases`** (or env) to fetch `{ecosystem}/all.zip` into the same cache root as today’s 24-hour advisory cache — pairs with full offline above.
- [ ] **Serve: zip hydrate toggle** — expose `--zip-advisories` on `/scan` (see [HANDOFF.md](HANDOFF.md)).

### Exports and scope (low priority)

Only if a consumer asks; they do not improve match accuracy.

- [ ] SARIF, SPDX, or CycloneDX export from existing JSON (OSV emits several formats).
- [ ] Container / OS package scanning (Alpine `status`, dpkg, images) — different product surface; no lockfile unchecked story.

### Explicitly do not port

| Google feature | Why leave it |
| --- | --- |
| Guided **fix** / lock rewrite + `npm install` | Runs untrusted install scripts; out of scope for a read-only scanner |
| **Call analysis** (Go default, Rust opt-in) | Executes or compiles code from the scanned tree |
| **deps.dev** for manifest/range resolution | Hides unchecked ranges; second service (Maven opt-in is the exception if you choose it) |
| Scan **`go` directive** as a dependency | Minimum language version, not installed toolchain (Google also off by default) |

---

## Where they differ (product)

| Capability | This scanner | OSV-Scanner |
| --- | --- | --- |
| Input | Git URL, local directory, or lockfiles a browser folder sends | A directory, or a container image |
| What is queried | Concrete versions only. A range is unchecked and is not sent | Lockfiles preferred. Manifest versions are best-effort and may not be installed |
| Ecosystems | npm, PyPI, Go, crates.io, Packagist, Pub, RubyGems, Maven | Those, plus bun, NuGet, Mix, Haskell, R, Conan, and Linux packages in images |
| Match | Batch API, then a local range walk. Stub ids hydrated via GET or zip | API by default. `--offline` matches against downloaded `{ecosystem}/all.zip` |
| Upgrade line | One read-only version: the highest precise fix on that package | Experimental fix for npm and Maven only. It edits the files |
| Is the function called | Not decided | Go analysis on by default. Rust is opt-in and may run build scripts |
| Ignore | Ecosystem, name, version, and advisory. Exit code still fails | Advisory id, including aliases, with reason and expiry. Finding hidden |
| Review | Loopback page: saved scans, compare, ignore | HTML report. No comparison of two scans |
| Repeat scans | 24-hour cache of batch rows and advisory bodies | After one download, matching stays on disk |
| Machine output | Text, JSON, exit 0, 1, or 2 | Table, markdown, JSON, HTML, SARIF, SPDX, CycloneDX |

Ecosystem list here follows `inventory.py` and done items in `ROADMAP.md` (yarn, Composer, Pub, RubyGems, Gradle, `pom.xml`, etc.).

---

## Keep (do not regress for parity theater)

- **Unchecked rows** instead of guessing manifest or range versions.
- **Read-only upgrade line** on every ecosystem you parse (Google’s fix is npm/Maven-only and mutates files).
- **Version-scoped ignore** for “this installed copy is accepted.”
- **Loopback page** with history and compare-two-scans (not in OSV-Scanner).

---

## Source comparison (local clones, Oct 2026)

Clones: `google/osv-scanner` at `c9c5077`, `google/osv-scalibr` at `94dac8f`.

**Default online scan.** Both use OSV **querybatch** + hydration. Scalibr does not re-run `IsAffected` on API hits. This tree hydrates the same way, then `annotate` in `match.py` walks ranges for fix lines and `recommend`, and drops findings when parsed ranges exclude the installed version. Alias ids merge into one row with `related_ids`.

**Offline / zip.** Scalibr sorts range events then runs a state machine. This tree sorts in `_sort_range_events` before `_matching_interval` (fixes Google’s unsorted npm test vector in unit tests). Full offline still needs zip package lookup + state machine, not only the current pair walk.

**Fixture battery (online).** Google **v2.7.0**, `--config compare-empty.toml`. Full table: [OSV-COMPARISON-HANDOFF.md](OSV-COMPARISON-HANDOFF.md).

| Fixture | Shared-package id agreement |
| --- | --- |
| `fix/testdata/in-place-npm` | **13/13** keys, ids match |
| `scan/source/testdata/locks-many` | **0** vulns; **4/4** inventory |
| `scan/source/testdata/locks-many-with-insecure` | All shared keys match; only Google scans Alpine `musl` |
| `scan/source/testdata/maven-transitive` | No shared vuln keys; Google adds deps.dev transitives |
| `scan/source/testdata/locks-requirements` | All shared keys match; Google adds transitive PyPI |
| `scan/source/testdata/locks-scalibr` | Shared `protobuf` key matches; Google adds other ecosystems |

**Conclusion.** Same `(ecosystem, name, version)` → same advisory ids on the default online path. Implement backlog items above to close **inventory** and **offline** gaps, not to replace the matcher.
