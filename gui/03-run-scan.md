# Step 3. Run a scan

Scan from the page, through the same function the CLI uses.

## What changed

`run_scan(target, branch, strict, use_cache)` returns the JSON report. The CLI calls the same scan and still prints the text report and writes its files.

The page posts `{target, branch, strict}` to `/scan`.

- Empty target: "Enter a git URL or a local directory."
- Failure: the same sentence the CLI prints (`Not a directory`, clone errors, OSV errors).
- Success: the report renders as in step 2. Counts, target, branch, and commit come from the scan.
- Result is Pass or Fail, using the CLI exit rules. Strict counts dev dependencies and medium severity toward Fail. The list of findings does not change.
- OSV answers are reused for 24 hours, same as the CLI default.

Open report still works. A file has no Pass or Fail, because the CLI file does not store an exit code.

## Start the page

From the repo root:

```
python -m supply_scan.serve
```

Then open `http://127.0.0.1:8765/`.

## Not in this step

No ignore list and no saved scans.

## Done when

A local directory scan from the page matches the JSON the CLI writes for the same directory.
