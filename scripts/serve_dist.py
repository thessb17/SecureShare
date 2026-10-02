#!/usr/bin/env python3
"""Serve the built frontend the way nginx will in production.

Static files from frontend/dist, SPA fallback to index.html, and /api
reverse-proxied to the Django backend. This exists so the *production
bundle* can be exercised before Docker is involved; nginx/conf.d does the
same job in the real deployment.

Usage: python scripts/serve_dist.py [port] [api_base]
"""
from __future__ import annotations

import http.server
import socketserver
import sys
import urllib.error
import urllib.request
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4173
API_BASE = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8100").rstrip("/")
DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIST), **kwargs)

    def log_message(self, fmt, *args):  # quieter output
        pass

    # -- proxy -------------------------------------------------------------
    def _proxy(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        request = urllib.request.Request(f"{API_BASE}{self.path}", data=body, method=self.command)
        for key, value in self.headers.items():
            if key.lower() not in HOP_BY_HOP and key.lower() != "host":
                request.add_header(key, value)

        try:
            with urllib.request.urlopen(request, timeout=60) as upstream:
                self._relay(upstream.status, upstream.headers, upstream.read())
        except urllib.error.HTTPError as exc:
            self._relay(exc.code, exc.headers, exc.read())
        except urllib.error.URLError as exc:
            self.send_error(502, f"upstream unreachable: {exc.reason}")

    def _relay(self, status: int, headers, payload: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() not in HOP_BY_HOP:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # -- routing -----------------------------------------------------------
    def do_GET(self) -> None:
        if self.path.startswith("/api/"):
            return self._proxy()
        candidate = DIST / self.path.lstrip("/").split("?")[0]
        if self.path != "/" and not candidate.is_file():
            self.path = "/index.html"  # SPA deep links
        return super().do_GET()

    def do_POST(self) -> None:
        self._proxy()

    def do_PATCH(self) -> None:
        self._proxy()

    def do_PUT(self) -> None:
        self._proxy()

    def do_DELETE(self) -> None:
        self._proxy()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    if not (DIST / "index.html").is_file():
        sys.exit(f"no build found at {DIST} - run `npm run build` first")
    print(f"serving {DIST} on 0.0.0.0:{PORT}, /api -> {API_BASE}")
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
