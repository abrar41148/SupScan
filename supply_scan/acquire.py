"""Clone a remote git URL into a temp sandbox, or open a local directory.

The URL check and shallow clone follow backend/services/git_wrapper.py.
A local path is never deleted. A clone is always deleted, including on Windows
where .git objects are read-only.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# Recycled from git_wrapper.sanitize_git_url. The clone itself is a argv list,
# so the shell never sees the string; the pattern rejects anything git would
# not accept as an http(s) or git@ URL.
_URL_RE = re.compile(
    r"^(https?://|git@)([a-zA-Z0-9\-._~%!$&'()*+,;=:@/]+)(\.git)?/?$"
)

REPOS_DIR = Path(tempfile.gettempdir()) / "supply-scan-repos"
CLONE_TIMEOUT_SECONDS = 180


class AcquireError(Exception):
    pass


@dataclass
class Workspace:
    path: Path
    cloned: bool
    target: str
    commit: str | None
    branch: str | None


_SCHEMELESS_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/.*)?$")


def is_git_url(value: str) -> bool:
    text = value.strip()
    return text.startswith(("http://", "https://", "git@"))


def _looks_like_path(text: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return True
    if text.startswith(("/", "\\", "./", "../", ".\\", "..\\")):
        return True
    return "\\" in text


def normalize_target(value: str) -> str:
    """Use https when a host is typed without a scheme. Paths and git@ stay as written."""
    text = value.strip()
    if not text or is_git_url(text) or _looks_like_path(text):
        return text
    if _SCHEMELESS_RE.match(text):
        return "https://" + text
    return text


def sanitize_git_url(url: str) -> str:
    text = url.strip()
    if not _URL_RE.match(text):
        raise AcquireError(
            "Invalid Git repository URL. Use an http(s) or git@ URL."
        )
    return text


def delete_tree(path: Path) -> None:
    if not path.exists():
        return

    def _writable(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    shutil.rmtree(path, onerror=_writable)


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    return text or None


def git_identity(path: Path) -> tuple[str | None, str | None]:
    return _git(["rev-parse", "HEAD"], path), _git(["branch", "--show-current"], path)


def parse_remote_heads(text: str) -> tuple[list[str], str | None]:
    """Read `git ls-remote --symref --heads` output. The default is the HEAD symref."""
    default: str | None = None
    branches: list[str] = []
    for line in text.splitlines():
        if line.startswith("ref:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("refs/heads/"):
                default = parts[1].removeprefix("refs/heads/")
            continue
        if "\t" not in line:
            continue
        ref = line.split("\t", 1)[1].strip()
        if not ref.startswith("refs/heads/"):
            continue
        name = ref.removeprefix("refs/heads/")
        if name and name not in branches:
            branches.append(name)
    if default not in branches:
        default = branches[0] if branches else None
    return branches, default


def list_remote_branches(repo_url: str) -> tuple[list[str], str | None]:
    sanitized = sanitize_git_url(repo_url)
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--symref", sanitized, "HEAD", "refs/heads/*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcquireError("Listing branches timed out.") from exc
    except OSError as exc:
        raise AcquireError("git is not available on PATH.") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Could not list branches."
        raise AcquireError(detail)
    return parse_remote_heads(result.stdout)


def clone_repository(repo_url: str, branch: str | None = None) -> Workspace:
    sanitized = sanitize_git_url(repo_url)
    match = re.search(r"/([^/]+?)(?:\.git)?/?$", sanitized)
    if match is None:
        match = re.search(r":([^/:]+?)(?:\.git)?$", sanitized)
    repo_name = match.group(1) if match else "cloned_repo"
    REPOS_DIR.mkdir(exist_ok=True)
    target = REPOS_DIR / f"{repo_name}_{uuid.uuid4().hex[:8]}"

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["-b", branch])
    cmd.extend([sanitized, str(target)])

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        delete_tree(target)
        raise AcquireError("Git clone timed out.") from exc
    except OSError as exc:
        delete_tree(target)
        raise AcquireError("git is not available on PATH.") from exc

    if result.returncode != 0:
        delete_tree(target)
        detail = result.stderr.strip() or result.stdout.strip() or "git clone failed"
        raise AcquireError(detail)

    commit, actual_branch = git_identity(target)
    return Workspace(
        path=target.resolve(),
        cloned=True,
        target=sanitized,
        commit=commit,
        branch=branch or actual_branch,
    )


@contextmanager
def open_workspace(target: str, branch: str | None = None):
    target = normalize_target(target)
    if is_git_url(target):
        workspace = clone_repository(target, branch)
        try:
            yield workspace
        finally:
            delete_tree(workspace.path)
        return

    path = Path(target).expanduser()
    if not path.is_dir():
        raise AcquireError(f"Not a directory: {target}")
    commit, found_branch = git_identity(path)
    yield Workspace(
        path=path.resolve(),
        cloned=False,
        target=str(path),
        commit=commit,
        branch=branch or found_branch,
    )
