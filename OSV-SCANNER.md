# OSV-Scanner comparison

Both tools list resolved dependency versions and ask OSV.dev which advisories affect them. OSV-Scanner is Google’s general scanner: more ecosystems, images, an offline database, and an experimental command that rewrites files. This scanner is a read-only verdict with an explicit unchecked list, one upgrade line, and a local page for history and comparison.

Sources: google/osv-scanner docs for usage, offline mode, supported lockfiles, configuration, guided remediation, and output, read 29 Oct 2026. This tree: `ROADMAP.md`, `match.py`, `ignore.py`, `inventory.py`. `ARCHITECTURE.md` still omits ecosystems the roadmap marks done.

Do not port the fix command. OSV-Scanner’s guided remediation rewrites `package-lock.json` or `pom.xml` and can run `npm install --package-lock-only`. The project docs warn that this may execute scripts from an untrusted tree. That fights the clone hardening already queued here: no checkout, no git config, no file protocol.

## Where they differ

| Capability | This scanner | OSV-Scanner |
| --- | --- | --- |
| Input | Git URL, local directory, or lockfiles a browser folder sends | A directory, or a container image |
| What is queried | Concrete versions only. A range is unchecked and is not sent | Lockfiles preferred. Manifest versions are best-effort and may not be installed |
| Ecosystems | npm, PyPI, Go, crates.io, Packagist, Pub, RubyGems, Maven | Those, plus bun, NuGet, Mix, Haskell, R, Conan, and Linux packages in images |
| Match | Batch API, then a local range walk. The batch often returns only an id, and each id is a GET | API by default. `--offline` matches against a downloaded `{ecosystem}/all.zip` and does not call the API |
| Upgrade line | One read-only version: the highest precise fix on that package | Experimental fix for npm and Maven only. It edits the files |
| Is the function called | Not decided | Go analysis on by default. Rust is opt-in and may run build scripts |
| Ignore | This ecosystem, name, version, and advisory. Exit code still fails | Advisory id, including aliases, with a reason and an expiry. The finding is hidden |
| Review | Loopback page: saved scans, compare, ignore | HTML report. No comparison of two scans |
| Repeat scans | 24-hour cache of batch rows and advisory bodies. First sight of an id is still a GET | After one download, matching stays on disk. A normal scan does not download the zips |
| Machine output | Text, JSON, exit 0, 1, or 2 | Table, markdown, JSON, HTML, SARIF, SPDX, CycloneDX |

The ecosystem list for this scanner follows the parsers in `inventory.py` and the done items in `ROADMAP.md`, including yarn, Composer, Pub, RubyGems, Gradle, and `pom.xml`.

## Action

Taken from how OSV-Scanner is split, and cut to fit a tool that does not install packages and does not rewrite the tree. The open roadmap items stay a clone that does not check files out, then several repositories at once. These three change the verdict. The clone item does not. The lockfile list below is not part of this action.

- [ ] **Match from a local OSV zip.** The range walk in `match.py` already decides affected and fixed. The per-id GET is what stalled the Dub scan after 3,079 packages. Two shapes are still open. Pick one before writing code.
  - **Narrow.** Keep `querybatch`. Download one `all.zip` for each ecosystem in that batch, from `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`, and read the named ids out of it. One zip per ecosystem the scan actually contains, cached, not every ecosystem OSV publishes. npm, PyPI, Go, and Maven are the large files. A small project with one or two findings downloads more on the first run than a couple of JSON GETs. Later scans of that ecosystem stay local.
  - **Theirs.** No API call. `--offline` reads only the zips and errors if one is missing. `--download-offline-databases` fetches them, and only together with an offline flag. Matching has to find the package inside the zip, because nothing names the ids first. Commit-level git advisories are not in those zips either way. Keep the API path for `--no-cache`.
- [ ] **Say which direct dependency to bump.** OSV-Scanner’s in-place strategy finds the smallest lockfile edits, and its relax strategy ranks direct dependencies by how many transitive findings they clear. Here, `recommend` is only the highest fix on the vulnerable package itself. For npm, the lock walk that already labels dev and prod can record the direct parent and print it. Do not rewrite `package-lock.json`, do not shell out to npm, and do not call deps.dev to fill a range. A range stays unchecked.
- [ ] **One issue, one finding.** OSV-Scanner groups records that list each other as aliases, and an ignore of one id covers the aliases. This scanner stores every id as its own finding and copies only the first CVE into a field, so the count, the page, and the ignore key can split one issue. Do not drop the advisory id. Keep the CVE beside it. Do not change the rule that an ignored finding still fails the exit code.

## Lockfiles they read that this scanner does not

Not scheduled. Tick one only if a real project needs it. `pom.xml` is on both lists. They also resolve Maven transitives through deps.dev, and that resolution is off in their offline mode. This scanner only uses versions written in the pom.

- [ ] C/C++: `conan.lock`, plus commit checks for submodules and vendored trees
- [ ] Dart: `package_config.json` (`pubspec.lock` is already read)
- [ ] Elixir: `mix.lock`
- [ ] Haskell: `cabal.project.freeze`, `stack.yaml.lock`
- [ ] Java: `buildscript-gradle.lockfile`, `gradle/verification-metadata.xml`
- [ ] JavaScript: `bun.lock`
- [ ] .NET: `deps.json`, `packages.config`, `packages.lock.json`
- [ ] Python: `Pipfile.lock`, `pdm.lock`, `pylock.toml`
- [ ] R: `renv.lock`
- [ ] Ruby: `gems.locked`

Container scans are a separate list and stay out: Alpine installed packages, Debian/Ubuntu dpkg status, Ubuntu chiseled manifests, Go binaries, Rust binaries built with cargo-auditable, Java uber jars, `node_modules`, and Python wheels.

## Keep

Unchecked rows. OSV-Scanner will extract a manifest version and warn that it might not be installed. This scanner refuses to send the range. That is the stricter report.

A read-only upgrade line on every ecosystem it parses. OSV-Scanner’s file-editing fix covers npm and Maven only.

An ignore tied to the installed version. Their ignore is global to the advisory id. Version scope is the right key for “this copy is accepted.” A reason and an expiry date are worth adding later. The exit code stays as written.

The loopback page. History and a side-by-side compare of two scans are not in OSV-Scanner.

## Leave with Google

Call analysis. Go is on by default there. Rust compiles dependencies and may run build scripts. Reachability is already out of scope here, and that implementation would run code from the tree being scanned.

Container and OS package scanning. Different input, different extractors, and no lockfile to explain an unchecked row.

deps.dev, used there for graphs, licenses, and image metadata. Using it to resolve a range would hide the unchecked signal and send the inventory to a second service.

SARIF, SPDX, and CycloneDX. JSON is the machine format this project chose. Extra formats do not make the match more accurate.

Scanning the `go` directive in `go.mod`. OSV-Scanner leaves it off by default because that line is a minimum language version, not the toolchain that was used.
