"""A progress bar for the CLI. Drawn on stderr, only on a real terminal, in the banner's colours.

Each phase of a scan (cloning, counting files, reading manifests, looking up packages,
fetching advisories) gets one line. A finished phase stays on screen with a tick; the
running phase redraws in place. Anything else written to stderr while the bar is up
(for example the "osv: N cached" line) is printed cleanly above it.
"""

from __future__ import annotations

import os
import sys
import time

from supply_scan.banner import PALETTES, _mix

_LABELS = {
    "clone": "cloning",
    "count": "counting files",
    "read": "reading manifests",
    "osv": "looking up packages",
    "advisories": "fetching advisories",
}
_PAIRS = {
    "read": ("files_done", "files_total"),
    "osv": ("packages_done", "packages_total"),
    "advisories": ("advisories_done", "advisories_total"),
}
_WIDTH = 24
_CLEAR = "\r\x1b[K"
_GREY = "\x1b[90m"
_RESET = "\x1b[0m"


class _Proxy:
    """Stands in for sys.stderr so other messages do not collide with the bar."""

    def __init__(self, bar: "Progress", real):
        self._bar = bar
        self._real = real

    def write(self, text: str) -> int:
        return self._bar._write_through(text)

    def __getattr__(self, name: str):
        return getattr(self._real, name)


class Progress:
    def __init__(self, stream, *, palette: int = 1, color: bool = True, fancy: bool = True):
        self._stream = stream
        self._stops = PALETTES.get(palette, PALETTES[1])[1]
        self._color = color
        self._full, self._empty, self._tick = ("█", "░", "✓") if fancy else ("#", "-", "*")
        self._key = None
        self._line = ""
        self._done_line = ""
        self._visible = False
        self._last_draw = 0.0
        self._saved_stderr = None

    @classmethod
    def create(cls, stream=None, *, palette: int | None = None) -> "Progress | None":
        """A bar for this stream, or None when it is not a terminal (pipes, CI, logs)."""
        stream = sys.stderr if stream is None else stream
        isatty = getattr(stream, "isatty", None)
        if not (isatty and isatty()) or os.environ.get("CI"):
            return None
        if os.name == "nt":
            os.system("")  # makes the Windows console understand colour codes
        try:
            "█░✓".encode(getattr(stream, "encoding", None) or "ascii")
            fancy = True
        except (UnicodeEncodeError, LookupError):
            fancy = False
        return cls(stream, palette=palette or 1, color="NO_COLOR" not in os.environ, fancy=fancy)

    # --- context manager: route stderr through the bar while it is up ---------------------

    def __enter__(self) -> "Progress":
        if self._stream is sys.stderr:
            self._saved_stderr = sys.stderr
            sys.stderr = _Proxy(self, self._stream)
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
        if self._saved_stderr is not None:
            sys.stderr = self._saved_stderr
            self._saved_stderr = None

    # --- drawing --------------------------------------------------------------------------

    def _bar(self, fraction: float) -> str:
        filled = round(_WIDTH * min(max(fraction, 0.0), 1.0))
        if not self._color:
            return self._full * filled + self._empty * (_WIDTH - filled)
        cells = []
        for index in range(_WIDTH):
            if index < filled:
                red, green, blue = _mix(self._stops, index / (_WIDTH - 1))
                cells.append(f"\x1b[38;2;{red};{green};{blue}m{self._full}")
            else:
                cells.append(f"{_GREY}{self._empty}")
        return "".join(cells) + _RESET

    def _render(self, event: dict, finished: bool) -> str:
        phase = event.get("phase")
        label = _LABELS.get(phase, str(phase))
        total_targets = event.get("target_total") or 1
        if total_targets > 1 and event.get("target_index") is not None and not event.get("batch_osv"):
            label = f"[{event['target_index'] + 1}/{total_targets}] {label}"
        mark = self._tick if finished else " "
        head = f"{mark} {label:<26}"
        names = _PAIRS.get(phase)
        if not names:
            count = event.get("files_done")
            return head + (f"{count:,}" if count else "")
        done, total = event.get(names[0]) or 0, event.get(names[1]) or 0
        if not total:
            return head + (f"{done:,}" if done else "")
        return f"{head}{self._bar(done / total)} {round(100 * done / total):>3}%  {done:,}/{total:,}"

    def _draw(self, line: str) -> None:
        self._stream.write(_CLEAR + line)
        self._stream.flush()
        self._visible = True

    def update(self, event: dict) -> None:
        key = (event.get("phase"), event.get("target_index", 0), bool(event.get("batch_osv")))
        names = _PAIRS.get(event.get("phase"))
        total = (event.get(names[1]) or 0) if names else 0
        finished = bool(total) and (event.get(names[0]) or 0) >= total
        changed = key != self._key
        if changed:
            self._commit()
            self._key = key
        self._line = self._render(event, finished)
        self._done_line = self._render(event, True)
        now = time.monotonic()
        if changed or finished or now - self._last_draw >= 0.05:
            self._last_draw = now
            self._draw(self._line)

    def _commit(self) -> None:
        """Leave the phase that just ended on screen with a tick."""
        if self._key is None:
            return
        self._stream.write(_CLEAR + self._done_line + "\n")
        self._stream.flush()
        self._visible = False
        self._line = ""

    def close(self) -> None:
        if self._visible:
            self._stream.write(_CLEAR)
            self._stream.flush()
            self._visible = False
        self._line = ""
        self._key = None

    def _write_through(self, text: str) -> int:
        if self._visible:
            self._stream.write(_CLEAR)
            self._visible = False
        count = self._stream.write(text)
        if self._line and text.endswith("\n"):
            self._draw(self._line)
        return count
