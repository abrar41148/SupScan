# Handoff

The local page is in the working tree and is not committed. No supply-scan server is running. Start it with `serve.bat`, which binds only `http://127.0.0.1:8765/`. The page is read from disk on each request, but Python changes need a restarted server.

## What the page does

`gui/index.html` is served by `supply_scan/serve.py`. A scan takes a git URL or a local folder, lists remote branches for a git URL, and can be run again on the same target after changing the branch. The branch box says "Enter target first" until a git URL is entered. After a scan, the full branch list stays available.

**Scan history** and **Compare** use the same saved scans (`%LOCALAPPDATA%\supply-scan\scans`). Labels are time, repo, and branch. Nothing runs until **Open** or **Compare** is pressed.

The compare columns stay open and closed together. Each package row is two lines: name plus ecosystem, then version count and findings. An empty cell says "no equivalent". Under the columns, each side lists the packages that exist only on the other side.

**Save report** opens a Save As dialog.

- A scan is named `Repo_branch_YYYY-MM-DD_HHMM.json`.
- A comparison is named `Repo_branch_vs_other_YYYY-MM-DD_HHMM.json`.

**Open report** accepts either file. A comparison file has `"kind": "supply-scan-comparison"` plus `current`, `previous`, and `rows`.

**Browse** uses the browser's own folder window (`showDirectoryPicker` in `gui/index.html`). Cancel stays in the browser. The page reads lockfiles from that folder and sends them to `/scan`. Do not open a folder dialog from Python. That window belonged to python.exe, and Cancel opened it again.

## Do not redo

- Do not put the findings count on the same line as the package name. That wrapped the name and threw the columns out of line.
- Do not replace the branch list with only the branch that was just scanned.
- Do not compare or open a history item on dropdown change.
- Do not open the folder dialog from Python, and do not use the old "Browse For Folder" tree. Browse is the browser's folder window.
- HTML is live after a refresh. A server started before a Python change will still serve the new page and 404 the new route. Restart after editing `serve.py`.

## Checks

`python -m unittest tests.test_scan` is the offline suite. A picked folder is scanned from the lockfiles the browser sends. The folder window is the browser's, not a Python process.
