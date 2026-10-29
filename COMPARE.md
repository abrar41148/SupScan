# Compare two scans

The same package is the ecosystem and the name. The version is what changed. It is not part of the identity. Advisories are compared inside that package, across versions.

`compare_reports(current, previous)` returns `rows`. The page paints those rows. It does not decide the package identity again. A direct or dev label that flipped is `note` on the row, not another kind of change. Ignore stays tied to ecosystem, name, version, and advisory id. An ignored finding still appears and still says it was ignored.

## Relation line

One line above the table, from the saved target only.

- Same target: `Same repository`
- Different targets: `Different repositories`

Do not call a different target a fork. A fork, a mirror, and an unrelated repo all have different targets. The table shows which kind of pair it is: an unrelated pair is mostly Added and Removed, and Version changed is empty. Do not block the comparison.

## Type table

Count dependencies, not findings. Show the table first, in this order. Omit a row whose count is zero. Omit clean packages that did not move.

| Change | A dependency is counted here when |
| --- | --- |
| Version changed | The name is in both scans at different versions. |
| Added | The name is only in the current scan. |
| Removed | The name is only in the previous scan. |
| Advisory changed | The version is the same and the advisory set is not. |
| Unchanged finding | The version and the advisory are both the same. |

## Two columns under the table

This is the dependency list. One row per ecosystem and name, in report order: worst severity, then ecosystem, then name.

- Left cell, headed `This scan`: the closed package row the report already uses. Name, ecosystem, version count, finding count, worst severity, and a disclosure triangle.
- Right cell, headed `Previous scan`: the same row, name and ecosystem and a disclosure triangle. No second tally.
- A package on only one side keeps the row. The other cell is empty, so the lists stay aligned.
- Opening a triangle opens that scan's versions and advisories inside its own column.

On a version-changed row, the opened current side shows the old version, then the new version, and each advisory as cleared, still present, or appeared. The opened previous side shows the old version and the advisories that were on it.

## Look

Use the page that already exists. Do not invent a second visual system.

- Field `#e4ecee`, sheet `#f6fafb`, ink `#17242c`, mute `#5a6c76`, rule `#c5d2d7`, fix `#0c6b62`.
- Sans for prose, monospace for package names, versions, and advisory ids.
- Square corners, hairline rules, disclosure triangles `▸` and `▾`.
- The two columns are two sheet panels with a gap between them. Rows share one height so a name on the left meets the same name on the right.
- Below about 560px, stack this scan above the previous scan inside each pair. Do not let the columns overlap.
