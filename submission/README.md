# Submission map

The working tool is the parent directory. This folder is the written hand-in. Nothing here is required to run a scan.

| # | Deliverable | Where to look | How to reproduce |
| --- | --- | --- | --- |
| 1 | Working prototype | Parent project: `python -m supply_scan` and `python -m supply_scan.serve` (or `serve.bat`) | From the parent directory, scan a local checkout. Exit `0` or `1` is a finished scan. Exit `2` means the target or the lookup failed. The page is `http://127.0.0.1:8765/`. |
| 2 | Source and configuration | Parent tree, plus [../README.md](../README.md) | Python 3.11 or newer. No third-party packages. No secrets. |
| 3 | Test evidence | [test-evidence.md](test-evidence.md) and [evidence/unittest.txt](evidence/unittest.txt) | `python -m unittest` command at the top of the evidence note. |
| 4 | Security outcome | [security-outcome.md](security-outcome.md) | Same three cases, plus the URL allowlist test named in that note. |
| 5 | Technical report | [technical-report.docx](technical-report.docx) | Open in Word. About four pages: problem, objectives, scope, approach, architecture, implementation, test results, limitations, ethics, references. |
| 6 | Presentation | [presentation.pptx](presentation.pptx) | Seven slides: problem, design, implementation, results, mitigation, limitations. |

The report and the slides use the same test results. Those results come from the offline suite, not from a live advisory count on a public repository.
