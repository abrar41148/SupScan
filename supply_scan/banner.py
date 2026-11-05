"""Neon banner for the terminal. Shown only on a real terminal, never in pipes or CI logs.

The letters are always the same; the gradient moves to the next one on every run, so
consecutive scans in one terminal window never repeat a colour scheme.

    python -m supply_scan.banner        preview every gradient
    python -m supply_scan.banner 3      preview one gradient
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

from supply_scan.cache import default_cache_dir

TAGLINE = "dependency vulnerability scanner"

_BLOCK = r"""
███████╗██╗   ██╗██████╗ ██████╗ ██╗  ██╗   ██╗
██╔════╝██║   ██║██╔══██╗██╔══██╗██║  ╚██╗ ██╔╝
███████╗██║   ██║██████╔╝██████╔╝██║   ╚████╔╝
╚════██║██║   ██║██╔═══╝ ██╔═══╝ ██║    ╚██╔╝
███████║╚██████╔╝██║     ██║     ███████╗██║
╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝

███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██║     ███████║██╔██╗ ██║
╚════██║██║     ██╔══██║██║╚██╗██║
███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

# Used when the terminal cannot show the box-drawing letters above.
_ASCII = r"""
 ____  _   _ ____  ____  _  __   __
/ ___|| | | |  _ \|  _ \| | \ \ / /
\___ \| | | | |_) | |_) | |  \ V /
 ___) | |_| |  __/|  __/| |___| |
|____/ \___/|_|   |_|   |_____|_|

 ____   ____    _    _   _
/ ___| / ___|  / \  | \ | |
\___ \| |     / _ \ |  \| |
 ___) | |___ / ___ \| |\  |
|____/ \____/_/   \_\_| \_|
"""

# name -> colour stops, left/top to right/bottom
PALETTES = {
    1: ("synthwave", ((0, 229, 255), (60, 110, 255), (255, 40, 180))),
    2: ("afterglow", ((255, 40, 180), (150, 70, 255), (0, 229, 255))),
    3: ("ultraviolet", ((40, 140, 255), (140, 60, 255), (255, 60, 220))),
    4: ("ice and rose", ((140, 255, 245), (70, 160, 255), (255, 120, 200))),
    5: ("night drive", ((255, 60, 150), (120, 50, 230), (30, 120, 255))),
    6: ("laser", ((0, 255, 200), (0, 140, 255), (200, 50, 255))),
}

_RESET = "\x1b[0m"
_DIM = "\x1b[2m"


def _mix(stops, t: float) -> tuple[int, int, int]:
    t = min(max(t, 0.0), 1.0) * (len(stops) - 1)
    index = min(int(t), len(stops) - 2)
    frac = t - index
    low, high = stops[index], stops[index + 1]
    return tuple(round(low[i] + (high[i] - low[i]) * frac) for i in range(3))


def render(palette: int = 1, *, color: bool = True, ascii_only: bool = False) -> str:
    stops = PALETTES[palette][1]
    lines = (_ASCII if ascii_only else _BLOCK).strip("\n").split("\n")
    width = max(len(line) for line in lines) + 1
    span = width + len(lines) * 2
    out = []
    for row, line in enumerate(lines):
        if not color:
            out.append(line)
            continue
        cells = []
        for col, char in enumerate(line):
            if char == " ":
                cells.append(char)
                continue
            red, green, blue = _mix(stops, (col + row * 2) / span)
            cells.append(f"\x1b[38;2;{red};{green};{blue}m{char}")
        out.append("".join(cells) + _RESET)
    tagline = f"// {TAGLINE} //"
    pad = " " * max((width - len(tagline)) // 2, 0)
    if color:
        red, green, blue = _mix(stops, 0.0)
        out.append(f"{pad}\x1b[38;2;{red};{green};{blue}m{_DIM}{tagline}{_RESET}")
    else:
        out.append(pad + tagline)
    return "\n".join(out) + "\n"


def _state_path() -> Path:
    return default_cache_dir() / "banner.json"


def next_palette(path: Path | None = None) -> int:
    """The palette after the one used last time, remembered on disk between runs."""
    path = _state_path() if path is None else path
    try:
        last = int(json.loads(path.read_text(encoding="utf-8")).get("last"))
    except (OSError, ValueError, TypeError, AttributeError):
        last = random.choice(list(PALETTES)) - 1  # first run: start anywhere
    number = last % len(PALETTES) + 1
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"last": number}), encoding="utf-8")
    except OSError:
        pass
    return number


def _enable_ansi() -> None:
    if os.name == "nt":
        os.system("")  # makes the Windows console understand colour codes


def _can_show(text: str, stream) -> bool:
    try:
        text.encode(getattr(stream, "encoding", None) or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def show(
    stream=None,
    *,
    palette: int | None = None,
    rng: random.Random | None = None,
    state_path: Path | None = None,
) -> int | None:
    """Print the banner to stream (stderr by default), in the next gradient in the rotation.

    palette forces one gradient, and rng picks at random instead of rotating (used by tests).

    Returns the palette number it used, or None when it stayed quiet: not a terminal, CI,
    or SUPPLY_SCAN_NO_BANNER set.
    """
    stream = sys.stderr if stream is None else stream
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()) or os.environ.get("SUPPLY_SCAN_NO_BANNER") or os.environ.get("CI"):
        return None
    _enable_ansi()
    color = "NO_COLOR" not in os.environ
    if palette in PALETTES:
        choice = palette
    elif rng is not None:
        choice = rng.choice(list(PALETTES))
    else:
        choice = next_palette(state_path)
    text = render(choice, color=color)
    if not _can_show(text, stream):
        text = render(choice, color=color, ascii_only=True)
    stream.write("\n" + text + "\n")
    stream.flush()
    return choice


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    chosen = [int(arg) for arg in args if arg.isdigit() and int(arg) in PALETTES] or list(PALETTES)
    _enable_ansi()
    for number in chosen:
        print(f"\n  [{number}] {PALETTES[number][0]}\n")
        text = render(number)
        try:
            sys.stdout.write(text)
        except UnicodeEncodeError:
            sys.stdout.write(render(number, ascii_only=True))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
