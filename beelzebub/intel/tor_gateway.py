#!/usr/bin/env python3
"""Public :80 gateway: block confirmed Tor exits, proxy everything else to Beelzebub."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("TOR_GATEWAY_PORT", "80"))
UPSTREAM = os.environ.get("BEELZEBUB_UPSTREAM", "127.0.0.1:9080")
ALERT_URL = os.environ.get("POLICY_ALERT_URL", "http://127.0.0.1:8080/hook/policy")
DATA = Path("/home/ubuntu/beelzebub/data")
TOR_CACHE = DATA / "tor-exits.txt"
_TOR_EXITS: set[str] = set()
_TOR_FETCHED_AT = 0.0

BLOCK_BODY = {
    "error": "access_denied",
    "code": "ANON_NETWORK_BLOCKED",
    "message": (
        "Tor, VPN, and proxy access is not permitted on the HLP Logistics Control Plane. "
        "Connect from a direct (non-anonymised) network and retry."
    ),
    "policy": "HLP-SEC-ANON-01",
    "hint": "Corporate/NGO egress IPs are allowed. Anonymising networks are blocked for auditability.",
    "docs": "/v1/openapi.json",
}


def refresh_tor_exits(force: bool = False) -> None:
    global _TOR_FETCHED_AT, _TOR_EXITS
    now = time.time()
    if not force and now - _TOR_FETCHED_AT < 6 * 3600 and _TOR_EXITS:
        return
    try:
        req = urllib.request.Request(
            "https://check.torproject.org/torbulkexitlist",
            headers={"User-Agent": "hlp-tarpit-gateway/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode(errors="replace")
        exits = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
        if exits:
            _TOR_EXITS = exits
            _TOR_FETCHED_AT = now
            DATA.mkdir(parents=True, exist_ok=True)
            TOR_CACHE.write_text("\n".join(sorted(exits)) + "\n", encoding="utf-8")
            print("tor exits loaded", len(_TOR_EXITS))
            return
    except Exception as exc:
        print("tor list fetch failed", exc)
    if TOR_CACHE.exists() and not _TOR_EXITS:
        _TOR_EXITS = {
            line.strip()
            for line in TOR_CACHE.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        }
        print("tor exits loaded from cache", len(_TOR_EXITS))


def is_tor(ip: str) -> bool:
    refresh_tor_exits()
    return ip in _TOR_EXITS


def notify_block(ip: str, path: str, ua: str) -> None:
    payload = {
        "DateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "Protocol": "HTTP",
        "SourceIp": ip,
        "RequestURI": path,
        "UserAgent": ua,
        "Msg": "Tor exit blocked by HLP-SEC-ANON-01",
        "Status": "Blocked",
        "Description": "Anonymous network policy denial",
    }
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            ALERT_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as exc:
        print("policy alert failed", exc)


def proxy_request(handler: BaseHTTPRequestHandler) -> None:
    host, port_s = UPSTREAM.split(":", 1)
    port = int(port_s)
    length = int(handler.headers.get("Content-Length", "0") or 0)
    body = handler.rfile.read(length) if length else None
    headers = {k: v for k, v in handler.headers.items() if k.lower() != "host"}
    headers["Host"] = UPSTREAM
    headers["X-Forwarded-For"] = handler.client_address[0]
    headers["X-Real-IP"] = handler.client_address[0]
    conn = HTTPConnection(host, port, timeout=60)
    try:
        conn.request(handler.command, handler.path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        handler.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() in ("transfer-encoding", "connection"):
                continue
            handler.send_header(key, value)
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}")

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _handle(self) -> None:
        ip = self._client_ip()
        path = self.path.split("?", 1)[0]
        ua = self.headers.get("User-Agent", "")
        if is_tor(ip):
            body = json.dumps(BLOCK_BODY).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "nginx/1.24.0")
            self.send_header("X-HLP-Policy", "HLP-SEC-ANON-01")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            threading.Thread(target=notify_block, args=(ip, path, ua), daemon=True).start()
            return
        proxy_request(self)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()


def tor_refresh_loop() -> None:
    while True:
        refresh_tor_exits(force=True)
        time.sleep(6 * 3600)


if __name__ == "__main__":
    # Prefer binding privileged port as root via systemd AmbientCapabilities, or run as root.
    DATA.mkdir(parents=True, exist_ok=True)
    refresh_tor_exits(force=True)
    threading.Thread(target=tor_refresh_loop, daemon=True).start()
    print(f"tor gateway listening on {LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM}")
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()
