# Step 1. Shell

A local page with the locked colors, type, and layout. No scan yet.

## What you see

- Header: the name `supply-scan`, and a Scan button.
- Rail: Target, Branch, Strict, counts, and the two compare slots.
- Main column: one of four states.

## States

| State | How to show it | Main column | Counts |
|---|---|---|---|
| Ready | Preview: Ready, or the first load | No scan yet. Says to enter a target and scan. | `-` |
| Scanning | Preview: Scanning, or the Scan button | Scanning. Skeleton rows, no package names. | `-` |
| Empty | Preview: Empty | The CLI sentence: no known vulnerabilities in resolved packages. | `0` |
| Error | Preview: Error | The path could not be opened. | `-` |

Preview is shell-only. Step 3 replaces it with a real scan. The Scan button only switches the page to Scanning.

## Not in this step

No report loading, no `run_scan`, no ignore list, no saved scans.

## Open it

From `gui/`:

```
python -m http.server 8765
```

Then open `http://127.0.0.1:8765/`.

## Done when

The page opens in a browser and all four states can be shown without a network call.
