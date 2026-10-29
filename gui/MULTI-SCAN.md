# Multi-repo scan — CLI and GUI handoff

Context for the [ROADMAP](../ROADMAP.md) **Next** item: scan several repositories at once. Written for chat handoff (Oct 2026).

## Scope split

| Layer | Status |
| --- | --- |
| **CLI / Python** | Done in tree: `run_batch` in `supply_scan/run.py`; CLI accepts up to four paths or `--batch FILE` (JSON `targets[]`). Shared OSV per run, per-target JSON (`supply-scan-report-1.json`, …), process exit = worst code. No new public HTTP API yet. |
| **GUI** | Done: multi-row targets in [index.html](index.html), `POST /scan` with `targets[]` (NDJSON progress tags target/branch), batch summary + **Open** per row, each target saved to history. Browse-folder stays single-target only. |

Compare mode stays **two saved scans**, not N-way. Ignore list stays global.

## Backend behavior (roadmap)

- At most **four** targets run concurrently (clone bandwidth and temp disk).
- One **shared** OSV query/hydrate pool per batch run so the same `(ecosystem, name, version)` or advisory id is fetched once across targets.
- Each target: own inventory, findings, text/JSON report, exit code `0` / `1` / `2`.
- One target fails (clone, parse, OSV): that target exits `2`; others still finish.
- Process exit: worst of target codes (`2`, then `1`, then `0`).
- Single-target CLI unchanged: one `supply-scan-report.json`, same exit rules as today.
- **History** (`save_scan`): writes **one row at a time** with locking so two finishes at once do not drop a row.

Suggested batch payload (CLI and later GUI):

```json
{
  "strict": false,
  "targets": [
    { "target": "https://github.com/org/api.git", "branch": "main" },
    { "target": "https://github.com/org/web.git", "branch": "release-1.4" }
  ]
}
```

Local paths and browse-folder scans omit `branch` (same as today). Cap at four entries.

## GUI today (single target)

- One `#target`, one `#branch` `<select>`, one **Scan** → `POST /scan` (NDJSON progress) → one report in the main panel.
- Branches: debounced `POST /branches` with `{ "target": "<one url>" }`; response has `branches` and **`default`** (symref from `git ls-remote --symref`). See `loadBranches` / `setBranchChoices` in [index.html](index.html).
- Scan body: `{ target, branch, strict }`. History label: time · repo · branch.

This **1:1:1** model does not scale to multi-repo without redesign.

## Main GUI concern: branch per repo

A single branch dropdown cannot work for a batch:

- Repos use different default branch names (`main` vs `master` vs `release-*`).
- User may need **different** branches per repo (e.g. `api@main`, `web@release-1.4`).
- One global branch applied to all URLs is wrong for most real setups.

### Required model

- **One row per target**: URL (or local path) + **that row’s** branch `<select>`.
- Each git URL row triggers its **own** `POST /branches` (reuse existing endpoint; no bulk API required for v1).
- Pre-select **`default`** from that response per row (not first alphabetical, not one global choice).
- Per-row request generation id so editing row 2 does not clear row 1’s branch list.
- Scan sends `targets: [{ target, branch? }, …]` (max 4).

### UI sketch (fits [PLAN.md](PLAN.md) — left rail, no cards)

```
| Repo                              | Branch        |
| [https://github.com/org/api.git ] | [main      ▼] |
| [https://github.com/org/web.git ] | [release-1.4▼] |
| [+ Add repo]  (disabled at 4)     |               |
```

- Git URL: enable branch column; list on blur/debounce (same rules as `gitTarget()` today).
- Local path / browse folder row: disable branch column (same as today’s folder behavior).
- Optional later: “Apply branch to all empty rows” shortcut — never the only way to set branches.

### Progress and results

- Progress events should name **repo and branch**, e.g. `Cloning org/api @ main (2 of 3)`.
- NDJSON needs a **target index or URL** on progress (today phases have no `target` field).
- Do **not** show four full finding lists at once. Prefer:
  - **Summary table** after batch (target, branch, counts, pass/fail per row), then **Open** loads one report into the existing single-report view; and/or
  - Auto-save all reports to history; user picks from **Saved scan** (labels already include branch).
- Headline Pass/Fail on the page = **worst** target exit code, with per-row status visible in the summary.

### Edge cases

| Case | Behavior |
| --- | --- |
| User changes URL after picking branch | Clear that row’s branch list; re-fetch; drop branch if missing on new remote |
| Branch list fails for one row | Block scan or block that row; show one-sentence error under the row |
| Mix git URLs and local paths | v1: either disallow mix or folder row has no branch column |
| Browse folder in batch | Out of scope for first GUI batch unless explicitly added |

## Anti-patterns

- Multi-line target box + **one** branch dropdown for all repos.
- Reusing global `listedTarget` / `branchRequest` without scoping by row index.
- One merged “super-report” across repos (compare/history assume one `target` per snapshot).

## API options for GUI (after CLI)

1. **`POST /scan/batch`** or `targets[]` on `/scan`: tagged NDJSON progress, multiple `save_scan` calls, one response with `reports[]` and aggregate `exit_code`.
2. **No batch endpoint**: page fires N parallel `/scan` requests — simpler UI but **no** shared OSV dedup and race-prone history unless server serializes saves (roadmap already requires serialized saves for concurrent finishes).

Prefer (1) aligned with CLI batch implementation.

## Related files

- [ROADMAP.md](../ROADMAP.md) — Next item and Done when (CLI tests).
- [gui/index.html](index.html) — `loadBranches`, `runScan`, history labels.
- [supply_scan/serve.py](../supply_scan/serve.py) — `/scan`, `/branches`, `save_scan` on stream complete.
- [supply_scan/acquire.py](../supply_scan/acquire.py) — `clone_repository(..., branch=...)`.
- [gui/PLAN.md](PLAN.md) — layout and copy tone.

## Suggested GUI Done when (add to roadmap when implementing)

- Batch payload is `{ target, branch? }[]` (max 4); each git row has its own branch dropdown fed by `/branches`.
- Default branch per row comes from symref `default`, not a global select.
- Batch progress names target and branch; finished scans appear as separate history rows with correct branch labels.
- User can open one finished report in the existing report view without losing the others in history.
