# Step 6. Check the page

Walked the page at `http://127.0.0.1:8765/`. Nothing in the flow broke, so no code change came out of this pass.

## What was checked

- Ready. The page opens on "No scan yet."
- Empty directory. Clear, counts 0, result Pass. The scan is saved.
- A directory with a vulnerable package. Findings render, result Fail.
- Ignore. The row stays, reads Ignored, and the button becomes Restore. Result stays Fail.
- A second scan of the same directory after the version changed. Compare shows Still open, Newly found, and Gone. The ignored finding is still marked under Gone. Still open is None, because the version is part of the match.
- A missing path. "Not a directory" and the counts clear.
- Phone width. One column, header on one line, no sideways scroll. The long error path wraps inside the column.

Saved scans that were already on this machine were left in place. The directories and ignores used for this check were removed.
