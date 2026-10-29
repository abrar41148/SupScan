# Step 4. Ignore list

A finding can be ignored. The CLI exit code stays the same.

## What changed

Ignore is saved at the supply-scan cache folder, in `ignore.json`. An entry is the ecosystem, package name, version, and advisory id. It applies to every target, not just the one on screen.

- Each finding has Ignore. After that, the row stays and reads Ignored. The button becomes Restore.
- Open findings only hides ignored findings. A package whose findings are all ignored hides with them. Unchecked packages stay.
- The list is loaded when the page opens, so a refresh and the next scan show the same ignores.
- Pass or Fail does not change when a finding is ignored.

## Not in this step

No comparison of two scans.

## Done when

An ignored finding stays ignored after a refresh and after a second scan.
