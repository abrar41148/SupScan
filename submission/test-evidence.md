# Test evidence

Ran on 29 October 2026 from the project root with Python 3.13 and `python -m unittest`. The four tests finished in 0.093 seconds. Result: `OK`. The log is [evidence/unittest.txt](evidence/unittest.txt). The three cases below are the required evidence. The fourth is the URL check cited in the security note.

Command:

```
python -m unittest tests.test_scan.MatchTests.test_recommend_is_the_highest_fix tests.test_scan.MatchTests.test_exit_code_ignores_dev_until_strict tests.test_scan.RunScanTests.test_ignore_is_saved_and_does_not_change_the_exit_code tests.test_scan.AcquireTests.test_url_allowlist -v
```

The suite stubs OSV. These results do not depend on a live advisory feed.

## Case 1. The recommended upgrade is the highest fix

**Test.** `MatchTests.test_recommend_is_the_highest_fix` in `tests/test_scan.py`.

**Setup.** An npm package `lodash` `4.17.20`, direct, production, from `package-lock.json`. Two advisories are attached. One is fixed in `4.17.21`. The other is `GHSA-2` / `CVE-2021-2`, fixed in `4.17.23`.

**Expected.** `package.recommend` is `4.17.23`. The first finding stays critical, and its CVE stays `CVE-2021-1`.

**Actual.** Pass. The assertions on `recommend`, `severity`, and `cve` all held.

**Why it matters.** A report that names the lower fix would leave the package inside the second advisory. The implementation collapses fixes to the highest release that it can order.

## Case 2. The exit code fails on malware, and on a dev finding only when asked

**Test.** `MatchTests.test_exit_code_ignores_dev_until_strict`.

**Setup.** A direct dev package `vitest` `1.0.0` with one high finding, `GHSA-dev`, fixed in `1.0.1`. Then a direct production package `left-pad` `1.0.0` with one malware finding, `MAL-1`.

**Expected.**

- Dev finding, strict off: exit `0`.
- Dev finding, strict on: exit `1`.
- Malware finding, strict off: exit `1`.

**Actual.** Pass. `exit_code` returned `0`, then `1`, then `1`, in that order.

**Why it matters.** The default gate is for production risk and for malware. Development-only findings stay visible in the report and fail the process when `--strict` is set. Malware is not given the development exception.

## Case 3. Saving an ignore does not clear the gate

**Test.** `RunScanTests.test_ignore_is_saved_and_does_not_change_the_exit_code`.

**Setup.** A temporary tree with `package.json` depending on `left-pad` `1.2.3`. The OSV call is replaced so that package receives a high finding `GHSA-dev`, fixed in `1.2.4`. The same advisory is written twice to a temporary `ignore.json`.

**Expected.** The ignore file contains one entry after the second write. `run_scan` on that tree, strict off and cache off, still returns `exit_code` `1`. Clearing the ignore leaves an empty list.

**Actual.** Pass. The saved list length was 1, the second write matched the first, the scan exit code was 1, and the cleared list was empty.

**Why it matters.** The page can record that someone has seen a finding. That record is not a bypass. A CI job that uses the exit code still fails until the dependency is upgraded or the finding is no longer present.

## Supporting check. A clone URL cannot carry a shell command

**Test.** `AcquireTests.test_url_allowlist`.

**Expected.** `https://github.com/org/repo.git` is accepted unchanged. `https://github.com/org/repo.git && calc.exe` raises `AcquireError`.

**Actual.** Pass.

The clone itself is started with an argument list, so the shell does not parse the URL. This test checks the allowlist that runs before that call.
