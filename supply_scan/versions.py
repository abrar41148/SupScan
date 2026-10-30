"""Order a version the way its package manager does."""

from __future__ import annotations

import re
from functools import total_ordering

_SEMVER = {"npm", "Go", "crates.io", "Pub", "Hex"}


class _Bound:
    def __init__(self, high: bool):
        self.high = high

    def __lt__(self, other):
        if isinstance(other, _Bound):
            return (not self.high) and other.high
        return not self.high

    def __gt__(self, other):
        if isinstance(other, _Bound):
            return self.high and not other.high
        return self.high

    def __eq__(self, other):
        return isinstance(other, _Bound) and self.high == other.high

    def __le__(self, other):
        return self == other or self < other

    def __ge__(self, other):
        return self == other or self > other

    def __repr__(self):
        return "high" if self.high else "low"


_LOW = _Bound(False)
_HIGH = _Bound(True)


def _pad_cmp(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


@total_ordering
class _Order:
    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self._cmp(other) == 0

    def __lt__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self._cmp(other) < 0


class _Parts(_Order):
    def __init__(self, parts: tuple):
        self.parts = parts

    def _cmp(self, other: _Parts) -> int:
        if self.parts < other.parts:
            return -1
        if self.parts > other.parts:
            return 1
        return 0

    def __repr__(self):
        return f"{type(self).__name__}{self.parts}"


class _Dotted(_Order):
    def __init__(self, parts: tuple[int, ...]):
        self.parts = parts

    def _cmp(self, other: _Dotted) -> int:
        return _pad_cmp(self.parts, other.parts)

    def __repr__(self):
        return f"dotted{self.parts}"


class _Semver(_Order):
    def __init__(self, release: tuple[int, ...], pre: tuple | None):
        self.release = release
        self.pre = pre

    def _cmp(self, other: _Semver) -> int:
        result = _pad_cmp(self.release, other.release)
        if result != 0:
            return result
        if self.pre is None and other.pre is None:
            return 0
        if self.pre is None:
            return 1
        if other.pre is None:
            return -1
        if self.pre < other.pre:
            return -1
        if self.pre > other.pre:
            return 1
        return 0

    def __repr__(self):
        return f"semver({self.release}, {self.pre})"


class _Composer(_Parts):
    pass


class _Pep440(_Parts):
    pass


class _Gem(_Order):
    def __init__(self, parts: tuple):
        self.parts = parts

    def _cmp(self, other: _Gem) -> int:
        width = max(len(self.parts), len(other.parts))
        for index in range(width):
            left = self.parts[index] if index < len(self.parts) else 0
            right = other.parts[index] if index < len(other.parts) else 0
            if left == right:
                continue
            if isinstance(left, str) and isinstance(right, int):
                return -1
            if isinstance(left, int) and isinstance(right, str):
                return 1
            return (left > right) - (left < right)
        return 0

    def __repr__(self):
        return f"gem{self.parts}"


def _parse_dotted(text: str):
    if text.startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    text = text.split("+", 1)[0]
    if "-" in text or not text:
        return None
    parts: list[int] = []
    for piece in text.split("."):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    if not parts:
        return None
    return _Dotted(tuple(parts))


def _numeric_release(text: str) -> tuple[int, ...] | None:
    if not text:
        return None
    parts: list[int] = []
    for piece in text.split("."):
        if not piece.isdigit() or (len(piece) > 1 and piece[0] == "0"):
            return None
        parts.append(int(piece))
    return tuple(parts) or None


def _parse_semver(text: str):
    if text.startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    text = text.split("+", 1)[0]
    if "-" in text:
        release_text, pre_text = text.split("-", 1)
    else:
        release_text, pre_text = text, None
    release = _numeric_release(release_text)
    if release is None:
        return None
    pre = None
    if pre_text is not None:
        if not pre_text:
            return None
        idents = []
        for piece in pre_text.split("."):
            if not piece or re.fullmatch(r"[0-9A-Za-z-]+", piece) is None:
                return None
            if piece.isdigit():
                if len(piece) > 1 and piece[0] == "0":
                    return None
                idents.append((0, int(piece)))
            else:
                idents.append((1, piece))
        pre = tuple(idents)
    return _Semver(release, pre)


_COMPOSER = re.compile(
    r"v?"
    r"(?P<major>\d{1,5})"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<patch>\d+))?"
    r"(?:\.(?P<rev>\d+))?"
    r"(?:[._-]?(?P<stab>stable|beta|b|rc|alpha|a|patch|pl|p)"
    r"(?P<stabnum>(?:[.-]?\d+)*))?"
    r"(?:(?P<dev>[.-]?dev)(?P<devnum>(?:[.-]?\d+)*)?)?",
    re.IGNORECASE,
)
_COMPOSER_RANK = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "stable": 4,
    "patch": 5,
    "pl": 5,
    "p": 5,
}


def _composer_nums(text: str | None) -> tuple[int, ...]:
    if not text:
        return ()
    return tuple(int(piece) for piece in re.findall(r"\d+", text))


def _parse_composer(text: str):
    match = _COMPOSER.fullmatch(text.split("+", 1)[0])
    if not match:
        return None
    release = tuple(int(match.group(name) or 0) for name in ("major", "minor", "patch", "rev"))
    if match.group("dev") is not None:
        rank = _COMPOSER_RANK["dev"]
        nums = _composer_nums(match.group("devnum")) or _composer_nums(match.group("stabnum"))
    elif match.group("stab"):
        rank = _COMPOSER_RANK[match.group("stab").lower()]
        nums = _composer_nums(match.group("stabnum"))
    else:
        rank = _COMPOSER_RANK["stable"]
        nums = ()
    return _Composer((*release, rank, nums))


_PEP440 = re.compile(
    r"(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?"
    r"(?P<post>(?:-(?P<post_n1>[0-9]+)|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?)))?"
    r"(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?",
    re.IGNORECASE,
)
_PRE_LABEL = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "c": 2,
    "rc": 2,
    "pre": 2,
    "preview": 2,
}


def _local_key(local: str | None):
    if local is None:
        return _LOW
    parts = []
    for piece in re.split(r"[\._-]", local):
        if piece.isdigit():
            parts.append((int(piece), ""))
        else:
            parts.append((_LOW, piece.lower()))
    return tuple(parts)


def _parse_pep440(text: str):
    if text[:1] in "vV":
        return None
    match = _PEP440.fullmatch(text)
    if not match:
        return None
    release = [int(part) for part in match.group("release").split(".")]
    while release and release[-1] == 0:
        release.pop()
    pre = None
    if match.group("pre"):
        pre = (_PRE_LABEL[match.group("pre_l").lower()], int(match.group("pre_n") or 0))
    if match.group("post"):
        if match.group("post_n1") is not None:
            post = int(match.group("post_n1"))
        else:
            post = int(match.group("post_n2") or 0)
    else:
        post = None
    dev = int(match.group("dev_n") or 0) if match.group("dev") else None
    if pre is None and post is None and dev is not None:
        pre_key = _LOW
    elif pre is None:
        pre_key = _HIGH
    else:
        pre_key = pre
    return _Pep440((
        int(match.group("epoch") or 0),
        tuple(release),
        pre_key,
        _LOW if post is None else post,
        _HIGH if dev is None else dev,
        _local_key(match.group("local")),
    ))


_GEM = re.compile(
    r"[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def _parse_gem(text: str):
    if not _GEM.fullmatch(text):
        return None
    parts = []
    for piece in re.findall(r"[0-9]+|[A-Za-z]+", text.replace("-", ".pre.")):
        parts.append(int(piece) if piece.isdigit() else piece.lower())
    if not parts:
        return None
    return _Gem(tuple(parts))


_MAVEN_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_MAVEN_RELEASE = {"ga", "final", "release"}
_MAVEN_RELEASE_INDEX = str(_MAVEN_QUALIFIERS.index(""))


def _maven_word(word: str, followed_by_digit: bool) -> str:
    if followed_by_digit and len(word) == 1:
        word = {"a": "alpha", "b": "beta", "m": "milestone"}.get(word, word)
    if word == "cr":
        return "rc"
    return word


def _qualifier_key(word: str) -> str:
    if word in _MAVEN_RELEASE:
        return _MAVEN_RELEASE_INDEX
    try:
        index = _MAVEN_QUALIFIERS.index(word)
    except ValueError:
        return f"{len(_MAVEN_QUALIFIERS)}-{word}"
    return str(index)


class _MInt:
    def __init__(self, value: int):
        self.value = value

    def is_null(self) -> bool:
        return self.value == 0

    def compare(self, other) -> int:
        if other is None:
            return 0 if self.value == 0 else 1
        if isinstance(other, _MInt):
            return (self.value > other.value) - (self.value < other.value)
        if isinstance(other, (_MStr, _MCombo, _MList)):
            return 1
        raise TypeError(type(other))

    def __repr__(self):
        return str(self.value)


class _MStr:
    def __init__(self, value: str):
        self.value = value

    def is_null(self) -> bool:
        return self.value == ""

    def compare(self, other) -> int:
        if other is None:
            return (_qualifier_key(self.value) > _MAVEN_RELEASE_INDEX) - (
                _qualifier_key(self.value) < _MAVEN_RELEASE_INDEX
            )
        if isinstance(other, _MInt):
            return -1
        if isinstance(other, _MStr):
            left = _qualifier_key(self.value)
            right = _qualifier_key(other.value)
            return (left > right) - (left < right)
        if isinstance(other, _MCombo):
            result = self.compare(_MStr(other.word))
            return -1 if result == 0 else result
        if isinstance(other, _MList):
            return -1
        raise TypeError(type(other))

    def __repr__(self):
        return repr(self.value)


class _MCombo:
    def __init__(self, word: str, number: int):
        self.word = word
        self.number = number

    def is_null(self) -> bool:
        return False

    def compare(self, other) -> int:
        if other is None:
            # 1-rc1 is before 1. 1-ga is 1, and 1-ga1 is after 1.
            result = _MStr(self.word).compare(None)
            if result == 0:
                return _MInt(self.number).compare(None)
            return result
        if isinstance(other, _MInt):
            return -1
        if isinstance(other, _MStr):
            result = _MStr(self.word).compare(other)
            return 1 if result == 0 else result
        if isinstance(other, _MList):
            return -1
        if isinstance(other, _MCombo):
            result = _MStr(self.word).compare(_MStr(other.word))
            if result == 0:
                return (self.number > other.number) - (self.number < other.number)
            return result
        raise TypeError(type(other))

    def __repr__(self):
        return f"{self.word}{self.number}"


class _MList:
    def __init__(self):
        self.items: list = []

    def add(self, item):
        self.items.append(item)

    def is_null(self) -> bool:
        return not self.items

    def normalize(self):
        for item in self.items:
            if isinstance(item, _MList):
                item.normalize()
        index = len(self.items) - 1
        while index >= 0:
            item = self.items[index]
            if item.is_null():
                if index == len(self.items) - 1 or isinstance(self.items[index + 1], _MStr):
                    del self.items[index]
                elif isinstance(self.items[index + 1], _MList) and self.items[index + 1].items:
                    head = self.items[index + 1].items[0]
                    if isinstance(head, (_MCombo, _MStr)):
                        del self.items[index]
            index -= 1

    def compare(self, other) -> int:
        if other is None:
            for item in self.items:
                result = item.compare(None)
                if result != 0:
                    return result
            return 0
        if isinstance(other, (_MInt, _MCombo)):
            return -1
        if isinstance(other, _MStr):
            return 1
        if isinstance(other, _MList):
            width = max(len(self.items), len(other.items))
            for index in range(width):
                left = self.items[index] if index < len(self.items) else None
                right = other.items[index] if index < len(other.items) else None
                result = _maven_cmp(left, right)
                if result != 0:
                    return result
            return 0
        raise TypeError(type(other))

    def __repr__(self):
        return repr(self.items)


def _maven_cmp(left, right) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return -_maven_cmp(right, None)
    return left.compare(right)


def _maven_item(is_combination: bool, is_digit: bool, buf: str):
    if is_combination:
        buf = buf.replace("-", "")
        index = next((i for i, char in enumerate(buf) if char.isascii() and char.isdigit()), len(buf))
        word = _maven_word(buf[:index], True)
        number = int(buf[index:].lstrip("0") or "0")
        return _MCombo(word, number)
    if is_digit:
        return _MInt(int(buf.lstrip("0") or "0"))
    return _MStr(_maven_word(buf, False))


def _ascii_digit(char: str) -> bool:
    return char.isascii() and char.isdigit()


class _Maven(_Order):
    def __init__(self, root: _MList):
        self.root = root

    def _cmp(self, other: _Maven) -> int:
        return self.root.compare(other.root)

    def __repr__(self):
        return f"maven{self.root}"


def _parse_maven(text: str):
    version = text.lower().replace("_", "-")
    if not version:
        return None
    items = _MList()
    current = items
    is_digit = False
    is_combination = False
    start = 0
    index = 0
    limit = len(version)
    while index < limit:
        char = version[index]
        if char == ".":
            if index == start:
                current.add(_MInt(0))
            else:
                current.add(_maven_item(is_combination, is_digit, version[start:index]))
            is_combination = False
            start = index + 1
        elif char == "-":
            if index == start:
                current.add(_MInt(0))
            elif (not is_digit) and index != limit - 1 and _ascii_digit(version[index + 1]):
                is_combination = True
                index += 1
                continue
            else:
                current.add(_maven_item(is_combination, is_digit, version[start:index]))
            start = index + 1
            if current.items:
                child = _MList()
                current.add(child)
                current = child
            is_combination = False
        elif _ascii_digit(char):
            if (not is_digit) and index > start:
                is_combination = True
                if current.items:
                    child = _MList()
                    current.add(child)
                    current = child
            is_digit = True
        else:
            if is_digit and index > start:
                current.add(_maven_item(is_combination, True, version[start:index]))
                start = index
                child = _MList()
                current.add(child)
                current = child
                is_combination = False
            is_digit = False
        index += 1
    if limit > start:
        if (not is_digit) and current.items:
            child = _MList()
            current.add(child)
            current = child
        current.add(_maven_item(is_combination, is_digit, version[start:]))
    items.normalize()
    return _Maven(items)


def version_key(value: str | None, ecosystem: str | None = None):
    """A comparable version, or None when this ecosystem cannot order it."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if ecosystem in _SEMVER:
        return _parse_semver(text)
    if ecosystem == "Packagist":
        return _parse_composer(text)
    if ecosystem == "PyPI":
        return _parse_pep440(text)
    if ecosystem == "RubyGems":
        return _parse_gem(text)
    if ecosystem == "Maven":
        return _parse_maven(text)
    return _parse_dotted(text)
