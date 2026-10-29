# Step 2. Open a report

Load a `supply-scan-report.json` the CLI already writes. No new scan.

## What changed

The Preview control is gone. Empty and error now come from a real file.

- Report, at the top of the rail, opens a JSON file.
- Packages with findings are listed first. Unchecked packages follow.
- Each finding shows the osv id, a CVE when the report has one, the severity word, the summary, and the fixed version when the report has one.
- The fixed version is the teal type. Severity stays a word.
- Counts, target, and branch are filled from the file. A commit is shown as its first 12 characters.
- A report with no findings and nothing unchecked uses the clear state. Package count still comes from the file.
- A file that is not JSON, or has no packages list, uses the error state.

Scan still only switches the page to Scanning. That becomes a real scan in the next step.

## Not in this step

No `run_scan`, no ignore list, no saved scans.

## Done when

A real report file renders, and a report with no findings shows the clear state.
