"""Optional GitHub PAT auth for CLI/CI (--git-token, GITHUB_TOKEN).

The local page uses your normal Git install (Credential Manager, cached login).
This module is kept for headless runs that cannot use system credentials.
"""

from __future__ import annotations

import base64
import os
import urllib.parse


def git_auth_config_args(git_token: str | None) -> list[str]:
    """Git -c flags for HTTPS PAT auth when credential.helper is disabled."""
    token = (git_token or "").strip()
    if not token:
        return []
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
    return ["-c", f"http.extraHeader=Authorization: Basic {basic}"]


def url_with_git_token(url: str, git_token: str | None) -> str:
    token = (git_token or "").strip()
    if not token:
        return url
    text = url.strip()
    if not text.startswith(("http://", "https://")):
        return url
    parsed = urllib.parse.urlparse(text)
    netloc = parsed.netloc.split("@")[-1]
    safe = urllib.parse.quote(token, safe="")
    return urllib.parse.urlunparse(parsed._replace(netloc=f"x-access-token:{safe}@{netloc}"))


def redact_git_token(text: str, git_token: str | None) -> str:
    token = (git_token or "").strip()
    if not token:
        return text
    return text.replace(token, "***")


def pat_auth_for_clone(repo_url: str, git_token: str | None) -> tuple[list[str], str]:
    """Extra git -c args and clone URL when a PAT is supplied explicitly."""
    token = (git_token or "").strip()
    if not token:
        return [], repo_url
    if os.name == "nt":
        return [], url_with_git_token(repo_url, git_token)
    return git_auth_config_args(git_token), repo_url
