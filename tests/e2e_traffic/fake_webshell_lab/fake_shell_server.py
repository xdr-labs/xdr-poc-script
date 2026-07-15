#!/usr/bin/env python3
"""Fake JSP webshell HTTP server for DSP Traffic Regression E2E.

Lab-only. Implements the DSP JSP provider command contract:
  GET/POST /shell.jsp with parameter ``cmd`` (aliases: ``command``, ``c``)

Also supports ``remote_path`` GET for file download (cat-style evidence sync).

NOT for production. Do not expose outside the lab network.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

COMMAND_PARAMS = ("cmd", "command", "c")
DEFAULT_TIMEOUT = 600.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _first_param(params: dict[str, list[str]], names: tuple[str, ...]) -> str | None:
    for name in names:
        values = params.get(name)
        if values and values[0] != "":
            return values[0]
    return None


def _run_command(command: str, *, timeout: float) -> tuple[int, bytes]:
    """Execute command via /bin/sh -c; return (exit_code, stdout+stderr)."""
    try:
        completed = subprocess.run(
            ["/bin/sh", "-c", command],
            capture_output=True,
            timeout=timeout,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"") + (exc.stderr or b"")
        msg = b"\n[fake_shell] command timeout\n"
        return 124, (out + msg)[:MAX_RESPONSE_BYTES]
    except OSError as exc:
        return 127, f"[fake_shell] exec failed: {exc}\n".encode()

    body = (completed.stdout or b"") + (completed.stderr or b"")
    return int(completed.returncode), body[:MAX_RESPONSE_BYTES]


def _format_response(exit_code: int, body: bytes) -> bytes:
    """Append DSP-compatible exit marker stripped by strip_webshell_exit_marker."""
    marker = f"\n__EXIT_CODE:{exit_code}\n".encode()
    if len(body) + len(marker) > MAX_RESPONSE_BYTES:
        body = body[: MAX_RESPONSE_BYTES - len(marker)]
    return body + marker


class FakeShellHandler(BaseHTTPRequestHandler):
    server_version = "FakeShellJSP/1.0"
    timeout_seconds: float = DEFAULT_TIMEOUT

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
        sys.stderr.flush()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if path not in ("/shell.jsp", "/shell.jsp/"):
            if path in ("/", "/health", "/healthz"):
                self._respond(200, b"ok\n")
                return
            self._respond(404, b"not found\n")
            return

        remote_path = _first_param(params, ("remote_path",))
        if remote_path is not None:
            self._handle_download(remote_path)
            return

        command = _first_param(params, COMMAND_PARAMS)
        if command is None:
            self._respond(200, b"fake jsp shell ready\n")
            return

        exit_code, body = _run_command(command, timeout=self.timeout_seconds)
        self._respond(200, _format_response(exit_code, body))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path not in ("/shell.jsp", "/shell.jsp/"):
            self._respond(404, b"not found\n")
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b""
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip()

        params: dict[str, list[str]] = {}
        if content_type in ("", "application/x-www-form-urlencoded"):
            params = urllib.parse.parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
        elif content_type == "multipart/form-data":
            # Command-only lab: reject multipart uploads (forbidden artifact path).
            self._respond(403, b"multipart upload disabled (command-only fake shell)\n")
            return
        else:
            # Also accept cmd from query string on POST.
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Merge query params as fallback.
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query_params.items():
            params.setdefault(key, values)

        command = _first_param(params, COMMAND_PARAMS)
        if command is None:
            self._respond(400, b"missing cmd parameter\n")
            return

        exit_code, body = _run_command(command, timeout=self.timeout_seconds)
        self._respond(200, _format_response(exit_code, body))

    def _handle_download(self, remote_path: str) -> None:
        try:
            path = Path(remote_path)
            if not path.is_file():
                self._respond(404, f"not found: {remote_path}\n".encode())
                return
            data = path.read_bytes()
            if len(data) > MAX_RESPONSE_BYTES:
                data = data[:MAX_RESPONSE_BYTES]
            self._respond(200, data)
        except OSError as exc:
            self._respond(500, f"read error: {exc}\n".encode())

    def _respond(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fake JSP webshell for DSP E2E (lab only)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default 8080)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-command timeout seconds",
    )
    args = parser.parse_args(argv)

    FakeShellHandler.timeout_seconds = float(args.timeout)
    httpd = ThreadingHTTPServer((args.host, args.port), FakeShellHandler)
    url = f"http://{args.host}:{args.port}/shell.jsp"
    print(f"FAKE_SHELL_STARTED host={args.host} port={args.port} url={url}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("FAKE_SHELL_STOPPED", flush=True)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
