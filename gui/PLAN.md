# supply-scan screen

Reading this as: a local workbench for a developer reading their own scan, with a cool ledger language, leaning toward one HTML page served by the Python package. No Node, no new runtime.

`design-taste-frontend` does not cover this. That skill is for landing pages and says dashboards are out of scope. This plan uses `frontend-design` for the visual system and `codebase-design` for the seam between the screen and the scanner.

## What the screen is for

The CLI already scans a git URL or a local directory, asks OSV, and writes text, JSON, and a monospace HTML dump. The roadmap item still open is an ignore list and a scan comparison, on a screen.

The screen does four jobs:

1. Show one scan: packages, findings, the release that fixes each finding, rows the scanner could not check.
2. Run that scan from the page, through the same modules the CLI uses.
3. Keep an ignore list, so a finding you have accepted stays marked.
4. Compare two scans: still open, newly found, gone.

The text report and the JSON file stay as they are. The screen reads the same snapshot. It does not parse the text report.

## Design lock

Reviewed against the usual generated-tool look (cream and clay, black and acid green, newspaper rules, rounded card grids, small-caps labels). None of those come from this scanner. The current HTML dump is a dark monospace page. The screen is a reading surface for the same data, not a second terminal skin.

Boldness sits in one place: the fixed version. Everything else stays quiet.

### Color

| Name | Hex | Use |
|---|---|---|
| field | `#e4ecee` | Page background |
| sheet | `#f6fafb` | The reading surface |
| ink | `#17242c` | Text |
| mute | `#5a6c76` | Secondary text |
| rule | `#c5d2d7` | Dividers between packages |
| fix | `#0c6b62` | The patched release, and the Scan button |

Severity is a word in the row (`critical`, `high`, `medium`, `low`, `malware`). It is not a colored pill and not a status dot. One accent on the whole page: `fix`.

### Type

- Chrome: Segoe UI, then IBM Plex Sans, then a generic sans.
- Package names, versions, ids: Cascadia Mono, then IBM Plex Mono, then ui-monospace.

Both faces are already on this machine. No font download.

### Layout

Left aligned. One column of findings. A narrow rail for the target, the counts, and which two scans are being compared. No cards. A hairline only between packages. Corners stay square. The page fits a laptop width and collapses to one column under 768px.

```
+------------------------------------------------------+
| supply-scan                          [ Scan ]        |
+------------------+-----------------------------------+
| target           | package  version                  |
| counts           | finding          fixed in x.y.z   |
| this vs previous | [ Ignore ]                        |
+------------------+-----------------------------------+
```

### Copy

Same voice as the CLI. Sentence case. The button that says Scan produces a scan. Empty means there is nothing to show yet, and says how to run one. An error says what failed (clone, parse, OSV) in one sentence.

### Motion

Almost none. The list updates when a scan finishes. `prefers-reduced-motion` is the default. No entrance animations.

## Module seam

The screen is a thin adapter. Callers learn one function:

```
run_scan(target, branch=None, strict=False, use_cache=True) -> dict
```

That dict is the JSON snapshot `render_json` already builds (`target`, `commit`, `branch`, `counts`, `packages`). `open_workspace`, `scan_tree`, `query_osv`, and `Snapshot` stay inside the function. The page never imports them.

Ignore entries and saved scans live next to that function, not inside `inventory` or `match`. An ignore entry is an id the user chose (`ecosystem`, `name`, `version`, `osv id`). Comparison takes two snapshot dicts and returns three lists: still open, newly found, gone. Matching key is ecosystem + name + version + osv id.

Two adapters at this seam: the CLI (prints and writes files) and the screen (returns the dict). The CLI keeps its current behavior.

## Steps

Each step is one markdown file in `gui/`. Nothing in a later step ships until you approve the step in front of it.

### Step 1. Shell

File: `gui/01-shell.md`

A local page with the locked colors, type, and layout. No scan yet. States that must exist before any data: ready (no scan), scanning, empty result, error. Buttons and fields are visible and labeled. Keyboard focus is visible.

Done when the page opens in a browser and those four states can be shown without a network call.

### Step 2. Open a report

File: `gui/02-open-report.md`

Load a `supply-scan-report.json` the CLI already writes. Render packages that have findings, then unchecked packages. Show name, version, ecosystem, direct or transitive, dev or prod, manifest, osv id, CVE when present, severity, summary, fixed version, upgrade recommendation.

Done when a real report file renders, and a report with no findings shows the empty state.

### Step 3. Run a scan

File: `gui/03-run-scan.md`

Fields: target (git URL or local path), branch (optional), strict (checkbox). Scan calls `run_scan`. The page shows scanning, then the snapshot, or the error string the CLI already prints. Cache behavior matches the CLI (reuse OSV answers for 24 hours unless asked not to).

Done when a local directory scan from the page matches the JSON the CLI writes for the same directory.

### Step 4. Ignore list

File: `gui/04-ignore.md`

Ignore sits on a finding. The row stays visible and reads as ignored. A control shows only open findings. The list is saved on disk and reapplied to the next scan of any target. Ignoring does not change the CLI exit code.

Done when an ignored finding stays ignored after a refresh and after a second scan.

### Step 5. Compare two scans

File: `gui/05-compare.md`

Each finished scan is kept. Pick two. The page groups findings into still open, newly found, and gone. Ignored findings stay marked inside those groups.

Done when two saved scans of the same target show a finding that appeared, one that disappeared, and one that remained.

### Step 6. Check the page

File: `gui/06-check.md`

Open the page and walk the flow: empty, a scan, an ignore, a comparison, an error (bad path). Check the narrow layout. Fix what breaks before calling the screen done.

## Out of this plan

Yarn, Java, Ruby, PHP, richer version sorting, direct-only mode, and offline listing stay parked, as the roadmap says. This screen does not add ecosystems.
