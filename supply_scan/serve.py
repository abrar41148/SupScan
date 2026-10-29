"""Local page that runs a scan. Bind to 127.0.0.1 only."""

from __future__ import annotations

import argparse
import json
import re
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from supply_scan.acquire import (
    AcquireError,
    delete_tree,
    is_git_url,
    list_remote_branches,
    normalize_target,
    short_acquire_error,
)
from supply_scan.compare import compare_reports
from supply_scan.inventory import is_scan_manifest_relpath
from supply_scan.ignore import read_ignores, set_ignored
from supply_scan.match import MatchError
from supply_scan.run import MAX_BATCH_TARGETS, TargetSpec, run_batch, run_scan, run_tree
from supply_scan.scans import list_scans, load_scan, save_scan

PAGE = Path(__file__).resolve().parent.parent / "gui" / "index.html"
MAX_BODY = 1_000_000
MAX_SCAN_BODY = 64_000_000
_MAX_MANIFESTS = 2000
_MAX_MANIFEST_BYTES = 16_000_000
_MAX_FOLDER_BYTES = 48_000_000
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def ignore_response(method: str, payload: dict | None = None) -> tuple[int, dict]:
    if method == "GET":
        return 200, {"ignores": read_ignores()}
    if not isinstance(payload, dict):
        return 400, {"error": "The ignore request was not JSON."}
    ignored = payload.get("ignored")
    if not isinstance(ignored, bool):
        return 400, {"error": "Say whether the finding is ignored."}
    updated = set_ignored(payload, ignored)
    if updated is None:
        return 400, {"error": "An ignore needs an ecosystem, name, and advisory id."}
    return 200, {"ignores": updated}


def compare_response(payload: dict | None) -> tuple[int, dict]:
    if not isinstance(payload, dict):
        return 400, {"error": "Pick two saved scans."}
    current = load_scan(str(payload.get("current") or ""))
    previous = load_scan(str(payload.get("previous") or ""))
    if current is None or previous is None:
        return 400, {"error": "Pick two saved scans."}
    return 200, compare_reports(current, previous)


def _branch_list_error(message: str) -> str:
    text = message.strip()
    if not text:
        return "Could not list branches."
    lower = text.lower()
    if "repository not found" in lower:
        return "Repository not found."
    if "timed out" in lower:
        return "Listing branches timed out."
    if "authentication failed" in lower or "permission denied" in lower:
        return "Could not authenticate to the remote."
    if "could not resolve host" in lower:
        return "Could not reach the host."
    if "invalid" in lower and "repository" in lower:
        return "Not a git repository."
    first = next((line.strip() for line in text.splitlines() if line.strip()), text)
    if len(first) > 72:
        return first[:72] + "…"
    return first


def _git_token_from_payload(payload: dict | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    token = payload.get("git_token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def branches_response(payload: dict | None) -> tuple[int, dict]:
    if not isinstance(payload, dict):
        return 400, {"error": "Enter a git URL."}
    target = payload.get("target")
    target = normalize_target(target) if isinstance(target, str) else ""
    if not is_git_url(target):
        return 400, {"error": "Enter a git URL to list branches."}
    try:
        branches, default = list_remote_branches(target, _git_token_from_payload(payload))
    except AcquireError as exc:
        return 400, {"error": _branch_list_error(str(exc))}
    return 200, {"branches": branches, "default": default}


def _manifest_path(value: object) -> Path | None:
    """A relative lockfile path. Anything that could leave the temp folder is dropped."""
    if not isinstance(value, str):
        return None
    text = value.replace("\\", "/").strip()
    if not text or text.startswith("/"):
        return None
    parts = [part for part in text.split("/") if part]
    if not parts or any(part in (".", "..") for part in parts):
        return None
    if not is_scan_manifest_relpath("/".join(parts)):
        return None
    return Path(*parts)


def _picked_label(value: object) -> str:
    if not isinstance(value, str):
        return "folder"
    text = value.strip()
    if not text or any(char in text for char in "\\/\0\r\n"):
        return "folder"
    return text


def _picked_branch(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(char in text for char in "\0\r\n"):
        return None
    return text


def _picked_commit(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _COMMIT_RE.fullmatch(text):
        return None
    return text


def _picked_folder(payload: dict, on_progress=None) -> tuple[int, dict]:
    """Scan the lockfiles the browser read from its own folder window.

    A dialog opened by this process is a separate Python window, and Cancel
    was opening that window again. The browser already has a folder window.
    """
    files = payload.get("files")
    if not isinstance(files, list):
        return 400, {"error": "That folder could not be read."}
    root = Path(tempfile.mkdtemp(prefix="supply-scan-folder-"))
    try:
        written = 0
        total = 0
        for item in files:
            if not isinstance(item, dict):
                continue
            relative = _manifest_path(item.get("path"))
            text = item.get("text")
            if relative is None or not isinstance(text, str):
                continue
            raw = text.encode("utf-8")
            if len(raw) > _MAX_MANIFEST_BYTES:
                return 400, {"error": "That folder is too large to scan."}
            total += len(raw)
            written += 1
            if total > _MAX_FOLDER_BYTES or written > _MAX_MANIFESTS:
                return 400, {"error": "That folder is too large to scan."}
            dest = root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
        try:
            return 200, run_tree(
                root,
                _picked_label(payload.get("target")),
                _picked_branch(payload.get("branch")),
                _picked_commit(payload.get("commit")),
                bool(payload.get("strict")),
                use_cache=True,
                on_progress=on_progress,
            )
        except (AcquireError, MatchError) as exc:
            return 400, {"error": str(exc)}
    finally:
        delete_tree(root)


def _parse_target_specs(payload: dict) -> tuple[list[TargetSpec] | None, str | None]:
    raw = payload.get("targets")
    if raw is None:
        return None, None
    if not isinstance(raw, list) or not raw:
        return None, "Add at least one target."
    if len(raw) > MAX_BATCH_TARGETS:
        return None, f"At most {MAX_BATCH_TARGETS} targets are allowed."
    specs: list[TargetSpec] = []
    for item in raw:
        if not isinstance(item, dict):
            return None, "Each target must list a git URL or local directory."
        target = item.get("target")
        if not isinstance(target, str) or not target.strip():
            return None, "Each target needs a git URL or local directory."
        branch = item.get("branch")
        if isinstance(branch, str) and branch.strip():
            branch = branch.strip()
        else:
            branch = None
        row_token = item.get("git_token")
        if isinstance(row_token, str) and row_token.strip():
            row_token = row_token.strip()
        else:
            row_token = None
        specs.append(TargetSpec(target.strip(), branch, row_token))
    return specs, None


def batch_scan_response(payload: dict, on_progress=None) -> tuple[int, dict]:
    specs, error = _parse_target_specs(payload)
    if error:
        return 400, {"error": error}
    assert specs is not None
    strict = bool(payload.get("strict"))
    shared_token = _git_token_from_payload(payload)
    if shared_token:
        specs = [
            TargetSpec(
                spec.target,
                spec.branch,
                spec.git_token or shared_token,
            )
            for spec in specs
        ]
    try:
        status, reports, _snapshots = run_batch(
            specs,
            strict=strict,
            use_cache=True,
            on_progress=on_progress,
        )
    except ValueError as exc:
        return 400, {"error": str(exc)}
    return 200, {"exit_code": status, "reports": reports}


def scan_response(payload: dict, on_progress=None) -> tuple[int, dict]:
    if isinstance(payload, dict) and "files" in payload:
        return _picked_folder(payload, on_progress)
    if isinstance(payload, dict) and "targets" in payload:
        return batch_scan_response(payload, on_progress)
    target = payload.get("target")
    target = target.strip() if isinstance(target, str) else ""
    if not target:
        return 400, {"error": "Enter a git URL or a local directory."}
    branch = payload.get("branch")
    if not isinstance(branch, str) or not branch.strip():
        branch = None
    else:
        branch = branch.strip()
    strict = bool(payload.get("strict"))
    git_token = _git_token_from_payload(payload)
    try:
        return 200, run_scan(
            target,
            branch,
            strict,
            git_token=git_token,
            use_cache=True,
            on_progress=on_progress,
        )
    except AcquireError as exc:
        raw = str(exc)
        body: dict = {"error": short_acquire_error(raw)}
        if body["error"] != raw.strip():
            body["error_detail"] = raw
        return 400, body
    except MatchError as exc:
        return 400, {"error": str(exc)}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/ignores":
            status, payload = ignore_response("GET")
            self._send(status, payload)
            return
        if path == "/scans":
            self._send(200, {"scans": list_scans()})
            return
        if path.startswith("/scans/"):
            report = load_scan(path.removeprefix("/scans/"))
            if report is None:
                self._send(404, {"error": "That scan was not saved."})
            else:
                self._send(200, report)
            return
        if path not in ("/", "/index.html"):
            self.send_error(404)
            return
        body = PAGE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path not in ("/scan", "/scan/batch", "/ignores", "/compare", "/branches"):
            self.send_error(404)
            return
        payload, error = self._read_json(MAX_SCAN_BODY if path in ("/scan", "/scan/batch") else MAX_BODY)
        if error is not None:
            self._send(400, {"error": error})
            return
        if path == "/ignores":
            status, body = ignore_response("POST", payload)
        elif path == "/branches":
            status, body = branches_response(payload)
        elif path == "/compare":
            status, body = compare_response(payload)
        elif path == "/scan/batch":
            if not isinstance(payload, dict) or "targets" not in payload:
                self._send(400, {"error": "Send targets with target and optional branch."})
                return
            accept = self.headers.get("Accept", "")
            if "application/x-ndjson" in accept:
                self._stream_scan(payload)
                return
            status, body = scan_response(payload)
            if status == 200:
                body = self._save_batch(body)
        else:
            accept = self.headers.get("Accept", "")
            if "application/x-ndjson" in accept:
                self._stream_scan(payload)
                return
            status, body = scan_response(payload)
            if status == 200 and "reports" in body:
                body = self._save_batch(body)
            elif status == 200:
                saved = save_scan(body)
                body = dict(body)
                body["scan_id"] = saved["id"]
        self._send(status, body)

    def _save_batch(self, body: dict) -> dict:
        saved_rows = []
        for report in body.get("reports") or []:
            if not isinstance(report, dict):
                continue
            saved = save_scan(dict(report))
            row = dict(report)
            row["scan_id"] = saved["id"]
            saved_rows.append(row)
        return {
            "exit_code": body.get("exit_code", 0),
            "reports": saved_rows,
        }

    def _stream_scan(self, payload: dict) -> None:
        """Chunked progress events, then one result. Each event is written to the socket as it happens."""
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.close_connection = True
        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.flush()
        except OSError:
            return
        failed = False
        lock = threading.Lock()

        def send(obj: dict) -> None:
            nonlocal failed
            if failed:
                return
            raw = (json.dumps(obj) + "\n").encode("utf-8")
            packet = f"{len(raw):x}\r\n".encode("ascii") + raw + b"\r\n"
            with lock:
                if failed:
                    return
                try:
                    self.connection.sendall(packet)
                except OSError:
                    failed = True

        def send_tail() -> None:
            if failed:
                return
            try:
                self.connection.sendall(b"0\r\n\r\n")
            except OSError:
                return

        try:
            status, body = scan_response(payload, on_progress=lambda event: send({"event": "progress", **event}))
        except Exception:
            send({"event": "result", "ok": False, "error": "The scan failed."})
            send_tail()
            return
        if status != 200:
            failed = {"event": "result", "ok": False, "error": body.get("error") or "The scan failed."}
            if body.get("error_detail"):
                failed["error_detail"] = body["error_detail"]
            send(failed)
            send_tail()
            return
        if "reports" in body:
            try:
                batch = self._save_batch(body)
            except Exception:
                send({"event": "result", "ok": False, "error": "The scan could not be saved."})
                send_tail()
                return
            send({
                "event": "result",
                "ok": True,
                "exit_code": batch.get("exit_code", 0),
                "reports": batch.get("reports") or [],
            })
            send_tail()
            return
        try:
            saved = save_scan(body)
        except Exception:
            send({"event": "result", "ok": False, "error": "The scan could not be saved."})
            send_tail()
            return
        report = dict(body)
        report["scan_id"] = saved["id"]
        send({"event": "result", "ok": True, "report": report})
        send_tail()

    def _read_json(self, limit: int = MAX_BODY) -> tuple[dict | None, str | None]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > limit:
            return None, "The request was too large."
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "The request was not JSON."
        if not isinstance(payload, dict):
            return None, "The request was not JSON."
        return payload, None

    def _send(self, status: int, payload: dict) -> None:
        raw = (json.dumps(payload) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="supply-scan-serve", description="Open the supply-scan page.")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    class LocalServer(ThreadingHTTPServer):
        # Windows treats SO_REUSEADDR as "share this port". The default
        # ThreadingHTTPServer flag let old servers keep the port, so a scan
        # could still hit a process that blocked Git credentials.
        allow_reuse_address = False

    server = LocalServer(("127.0.0.1", args.port), Handler)
    print(f"supply-scan page at http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
