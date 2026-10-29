# Security outcome

supply-scan reports dependency versions that OSV already knows are vulnerable, and the release that fixes them. It does not exploit those findings, and it does not decide whether the vulnerable function is called.

## What was detected

For each resolved package the inventory can name, the matcher asks OSV and keeps an advisory id, a CVE when the advisory has one, a severity, and the fixed version when one is published. Severity for a CVSS v3 vector is computed in the tool. An id that starts with `MAL-` is labelled malware and is listed before ordinary vulnerabilities. Withdrawn advisories are dropped. An advisory with no fixed version is kept and has no upgrade line.

The text report counts packages, vulnerable packages, and unchecked rows. Unchecked means the version was a range, was not written in the repo, or came from a source the scanner does not send to OSV, such as a git checkout or a path dependency.

## Mitigation that was checked

The control under test is the process exit code in `supply_scan/report.py`.

- Malware fails the process even when `--strict` is off.
- A critical or high finding in a production dependency fails the process.
- A high finding that exists only as a development dependency does not fail the process until `--strict`.
- Medium severity fails the process only under `--strict`.
- An ignored advisory still counts.

Case 2 and case 3 in [test-evidence.md](test-evidence.md) are the validation. On 29 October 2026 both tests passed. Ignoring `GHSA-dev` on `left-pad` `1.2.3` left `exit_code` at `1`.

The response the tool recommends is the upgrade, not the ignore. Case 1 passed: two fixes, `4.17.21` and `4.17.23`, produce the single recommendation `4.17.23`. After that upgrade, a second scan can be compared with the first. `compare_reports` treats ecosystem and name as the package identity and treats the version as what changed, so an advisory that remains on another version of the same package is not reported as cleared.

## Preventive controls already in the tool

These are in the current tree. The URL check is the one re-run for this hand-in.

- **Clone URL allowlist.** `sanitize_git_url` accepts `http://`, `https://`, and `git@` URLs that match a narrow pattern. The supporting check rejected a URL with `&& calc.exe`. The git process is started with an argument list.
- **Clone lifetime.** A remote repository is cloned into a temporary directory and that directory is deleted afterwards, including read-only `.git` objects on Windows. A local directory the user already has is not deleted.
- **Local page.** `supply_scan.serve` binds `127.0.0.1` only. Request bodies are size-limited. A folder upload drops paths that sit outside the chosen folder.
- **Cache.** OSV answers are reused for 24 hours under the user cache directory. A cache that cannot be written does not fail the scan. `--no-cache` asks again.

## What this does not claim

There is no local vulnerability database. A machine with no network can list resolved versions and mark them unchecked. The tool does not open an upgrade pull request, emit SARIF, check licenses, or prove that a vulnerable function runs.
