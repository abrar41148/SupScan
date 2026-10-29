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

from supply_scan.git_pat_auth import (
    git_auth_config_args,
    pat_auth_for_clone,
    redact_git_token,
)
from supply_scan.inventory import _pom_parent_file, is_scan_manifest_relpath

# Recycled from git_wrapper.sanitize_git_url. The clone itself is a argv list,
# so the shell never sees the string; the pattern rejects anything git would
# not accept as an http(s) or git@ URL.
_URL_RE = re.compile(
    r"^(https?://|git@)([a-zA-Z0-9\-._~%!$&'()*+,;=:@/]+)(\.git)?/?$"
)

REPOS_DIR = Path(tempfile.gettempdir()) / "supply-scan-repos"
CLONE_TIMEOUT_SECONDS = 180
MAX_SCAN_MANIFESTS = 2000
MAX_SCAN_MANIFEST_BYTES = 16_000_000
MAX_SCAN_TREE_BYTES = 48_000_000

class AcquireError(Exception):
    pass


def short_acquire_error(message: str) -> str:
    """One-line clone/open failure for the page and CLI stderr."""
    text = message.strip()
    if not text:
        return "Could not open that target."
    lower = text.lower()
    if "could not read username" in lower or "terminal prompts disabled" in lower:
        return "Private repository or HTTPS credentials required."
    if "authentication failed" in lower or "invalid username or password" in lower:
        return "Could not authenticate to the remote."
    if "repository not found" in lower:
        return "Repository not found."
    if "timed out" in lower:
        return "Timed out talking to git."
    if "git is not available" in lower:
        return "git is not available on PATH."
    if text.startswith("Not a directory:"):
        return text
    first = next((line.strip() for line in text.splitlines() if line.strip()), text)
    if len(first) > 96:
        return first[:96] + "…"
    return first


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


def list_remote_branches(repo_url: str, git_token: str | None = None) -> tuple[list[str], str | None]:
    sanitized = sanitize_git_url(repo_url)
    try:
        result = subprocess.run(
            ["git", *git_auth_config_args(git_token), "ls-remote", "--symref", sanitized, "HEAD", "refs/heads/*"],
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
        raise AcquireError(redact_git_token(detail, git_token))
    return parse_remote_heads(result.stdout)


def clone_git_config_args() -> list[str]:
    return [
        "-c",
        "submodule.recurse=false",
        "-c",
        "protocol.file.allow=never",
    ]


def build_clone_command(
    repo_url: str,
    target: Path,
    branch: str | None = None,
    git_token: str | None = None,
) -> list[str]:
    auth_config, clone_url = pat_auth_for_clone(repo_url, git_token)
    cmd = [
        "git",
        *auth_config,
        "clone",
        "--depth",
        "1",
        "--no-checkout",
        *clone_git_config_args(),
    ]
    if branch:
        cmd.extend(["-b", branch])
    cmd.extend([clone_url, str(target)])
    return cmd


def build_clone_environment() -> dict[str, str]:
    """Use the same Git config and credential helper as a normal shell."""
    return os.environ.copy()


def _parse_ls_tree_line(line: str) -> tuple[str, str, str] | None:
    parts = line.split("\t", 1)
    if len(parts) != 2:
        return None
    meta, path = parts
    fields = meta.split()
    if len(fields) != 3:
        return None
    mode, obj_type, sha = fields
    if obj_type != "blob":
        return None
    if mode in ("120000", "160000"):
        return None
    if not mode.startswith("100"):
        return None
    return path, sha, mode


def _git_show_text(repo: Path, relpath: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{relpath}"],
            cwd=str(repo),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _git_blob_size(repo: Path, sha: str) -> int | None:
    try:
        result = subprocess.run(
            ["git", "cat-file", "-s", sha],
            cwd=str(repo),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def _expand_pom_parents(
    selected: set[str],
    tree_paths: set[str],
    repo: Path,
) -> None:
    queue = [path for path in selected if path.lower().endswith("pom.xml")]
    seen: set[str] = set()
    while queue:
        relpath = queue.pop()
        if relpath in seen:
            continue
        seen.add(relpath)
        text = _git_show_text(repo, relpath)
        if text is None:
            continue
        pom_file = Path(relpath.replace("\\", "/"))
        parent_file, _label = _pom_parent_file(pom_file, text)
        if parent_file is None:
            continue
        parent_posix = parent_file.as_posix()
        if parent_posix not in tree_paths:
            continue
        if parent_posix in selected:
            continue
        selected.add(parent_posix)
        queue.append(parent_posix)


def select_scan_manifest_paths(repo: Path) -> dict[str, str]:
    """Map repository-relative paths to blob shas for manifests scan_tree reads."""
    try:
        result = subprocess.run(
            ["git", "ls-tree", "-r", "HEAD"],
            cwd=str(repo),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcquireError("Reading the repository tree timed out.") from exc
    except OSError as exc:
        raise AcquireError("git is not available on PATH.") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git ls-tree failed"
        raise AcquireError(detail)

    path_to_sha: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parsed = _parse_ls_tree_line(line)
        if parsed is None:
            continue
        path, sha, _mode = parsed
        path_to_sha[path] = sha

    selected = {path for path in path_to_sha if is_scan_manifest_relpath(path)}
    _expand_pom_parents(selected, set(path_to_sha), repo)
    return {path: path_to_sha[path] for path in selected if path in path_to_sha}


def materialize_scan_manifests(repo: Path) -> None:
    """Write manifest blobs into the work tree after a --no-checkout clone."""
    paths = select_scan_manifest_paths(repo)
    if len(paths) > MAX_SCAN_MANIFESTS:
        raise AcquireError(
            f"The repository has more than {MAX_SCAN_MANIFESTS} manifest files.",
        )

    total_bytes = 0
    sizes: dict[str, int] = {}
    for relpath, sha in paths.items():
        size = _git_blob_size(repo, sha)
        if size is None:
            raise AcquireError(f"Could not read {relpath} from the clone.")
        if size > MAX_SCAN_MANIFEST_BYTES:
            raise AcquireError(f"{relpath} is larger than the scan limit.")
        sizes[relpath] = size
        total_bytes += size
    if total_bytes > MAX_SCAN_TREE_BYTES:
        raise AcquireError("Manifest files in the clone exceed the scan size limit.")

    for relpath, sha in paths.items():
        try:
            result = subprocess.run(
                ["git", "cat-file", "blob", sha],
                cwd=str(repo),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise AcquireError(f"Timed out reading {relpath}.") from exc
        except OSError as exc:
            raise AcquireError("git is not available on PATH.") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise AcquireError(detail or f"Could not write {relpath}.")

        dest = repo / Path(relpath.replace("\\", "/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(result.stdout)


def clone_repository(
    repo_url: str,
    branch: str | None = None,
    git_token: str | None = None,
) -> Workspace:
    sanitized = sanitize_git_url(repo_url)
    match = re.search(r"/([^/]+?)(?:\.git)?/?$", sanitized)
    if match is None:
        match = re.search(r":([^/:]+?)(?:\.git)?$", sanitized)
    repo_name = match.group(1) if match else "cloned_repo"
    REPOS_DIR.mkdir(exist_ok=True)
    target = REPOS_DIR / f"{repo_name}_{uuid.uuid4().hex[:8]}"

    cmd = build_clone_command(sanitized, target, branch, git_token)
    env = build_clone_environment()

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=env,
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
        raise AcquireError(redact_git_token(detail, git_token))

    materialize_scan_manifests(target)

    commit, actual_branch = git_identity(target)
    return Workspace(
        path=target.resolve(),
        cloned=True,
        target=sanitized,
        commit=commit,
        branch=branch or actual_branch,
    )


@contextmanager
def open_workspace(target: str, branch: str | None = None, git_token: str | None = None):
    target = normalize_target(target)
    if is_git_url(target):
        workspace = clone_repository(target, branch, git_token)
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
