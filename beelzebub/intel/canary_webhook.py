#!/usr/bin/env python3
"""Stub webhook for Canarytokens until the full Telegram receiver exists."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "0.0.0.0"
PORT = 8080
LOG = Path("/home/ubuntu/beelzebub/data/canary-events.jsonl")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}")

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/health", "/hook/canary"):
            self._send(200, {"ok": True, "service": "hlp-canary-webhook", "path": path})
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/hook/canary":
            self._send(404, {"ok": False, "error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode("utf-8", errors="replace")}
        event = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent"),
            "payload": parsed,
        }
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
        print(f"canary event stored from {event['source_ip']}")
        self._send(200, {"ok": True})


if __name__ == "__main__":
    LOG.parent.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"listening on {HOST}:{PORT}")
    httpd.serve_forever()
