#!/usr/bin/env python3
"""Canary + Beelzebub webhook receiver with CVSS 4.0 Telegram alerts."""
from __future__ import annotations

import json
import os
import threading
import time
import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("WEBHOOK_PORT", "8080"))
DATA = Path("/home/ubuntu/beelzebub/data")
CANARY_LOG = DATA / "canary-events.jsonl"
BEE_LOG = DATA / "beelzebub.log"
ALERT_LOG = DATA / "telegram-alerts.jsonl"
STATE = DATA / "receiver-state.json"
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
_IP_CACHE: dict[str, tuple[float, dict]] = {}
_TOR_EXITS: set[str] = set()
_TOR_FETCHED_AT = 0.0
_CACHE_TTL = 3600.0
_VPN_HINTS = (
    "vpn", "proxy", "tor-exit", "mullvad", "nordvpn", "expressvpn", "surfshark",
    "proton", "datacamp", "m247", "ovh", "digitalocean", "linode", "vultr",
    "hosting", "cloudflare", "amazon", "google", "microsoft", "hetzner", "contabo",
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_json(url: str, timeout: float = 6.0) -> dict | list | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hlp-tarpit-intel/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode())
        except Exception:
            print("intel lookup failed", url, exc)
            return None
    except Exception as exc:
        print("intel lookup failed", url, exc)
        return None


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        obj.is_private or obj.is_loopback or obj.is_reserved
        or obj.is_multicast or obj.is_link_local or obj.is_unspecified
    )


def extract_src_ip(event: dict) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    extra = payload.get("additional_data") if isinstance(payload.get("additional_data"), dict) else {}
    aws = extra.get("aws_key_log_data") if isinstance(extra.get("aws_key_log_data"), dict) else {}
    candidates = [
        payload.get("src_ip"),
        payload.get("source_ip"),
        payload.get("ip"),
        payload.get("ip_address"),
        extra.get("src_ip"),
        extra.get("ip"),
        aws.get("ip"),
        event.get("SourceIp"),
        event.get("source_ip"),
    ]
    remote = event.get("RemoteAddr") or ""
    if ":" in remote and not remote.startswith("["):
        candidates.append(remote.rsplit(":", 1)[0])
    cleaned = []
    for value in candidates:
        if isinstance(value, str) and value.strip() and value.strip() != "unknown":
            cleaned.append(value.strip())
    for ip in cleaned:
        if _is_public_ip(ip):
            return ip
    return cleaned[0] if cleaned else "unknown"


def _refresh_tor_exits() -> None:
    global _TOR_FETCHED_AT, _TOR_EXITS
    now = time.time()
    if now - _TOR_FETCHED_AT < 6 * 3600 and _TOR_EXITS:
        return
    try:
        req = urllib.request.Request(
            "https://check.torproject.org/torbulkexitlist",
            headers={"User-Agent": "hlp-tarpit-intel/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode(errors="replace")
        _TOR_EXITS = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
        _TOR_FETCHED_AT = now
        print("tor exits loaded", len(_TOR_EXITS))
    except Exception as exc:
        print("tor list fetch failed", exc)


def lookup_ip(ip: str) -> dict:
    if not ip or ip == "unknown" or not _is_public_ip(ip):
        return {
            "ip": ip,
            "public": False,
            "geo": "private/internal (not geolocatable)",
            "isp": "",
            "malicious": "n/a",
            "anon": "n/a",
        }
    cached = _IP_CACHE.get(ip)
    if cached and time.time() - cached[0] < _CACHE_TTL:
        return cached[1]

    geo = _http_json(
        f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,country,regionName,city,lat,lon,isp,org,as,query"
    ) or {}
    country = geo.get("country") or "unknown"
    region = geo.get("regionName") or ""
    city = geo.get("city") or ""
    lat, lon = geo.get("lat"), geo.get("lon")
    isp = geo.get("isp") or geo.get("org") or ""
    asn = geo.get("as") or ""
    place = ", ".join(p for p in (city, region, country) if p)
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        place = f"{place} ({lat:.2f},{lon:.2f})"

    gn = _http_json(f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}") or {}
    classification = (gn.get("classification") or "").lower()
    noise = gn.get("noise")
    riot = gn.get("riot")
    gn_name = gn.get("name") or ""
    if classification == "malicious":
        mal = f"YES — GreyNoise malicious {gn_name}".strip()
    elif classification == "benign" or riot:
        mal = f"known benign/scanner infra ({gn_name or classification or 'riot'})"
    elif noise:
        mal = "seen as internet noise/scanner (GreyNoise)"
    elif gn:
        mal = "not listed as malicious (GreyNoise community)"
    else:
        mal = "intel lookup unavailable"

    _refresh_tor_exits()
    hay = f"{isp} {asn} {geo.get('org') or ''}".lower()
    vpnish = any(h in hay for h in _VPN_HINTS)
    tor = ip in _TOR_EXITS
    if tor:
        anon = "TOR exit node"
    elif vpnish:
        anon = f"likely VPN/proxy/hosting ({isp or asn})"
    else:
        anon = f"no strong VPN/Tor signal ({isp or 'isp unknown'})"

    result = {
        "ip": ip,
        "public": True,
        "geo": place or "unknown",
        "isp": f"{isp} {asn}".strip(),
        "malicious": mal,
        "anon": anon,
    }
    _IP_CACHE[ip] = (time.time(), result)
    return result


def append_jsonl(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj) + "\n")


def load_state() -> dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def save_state(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2) + "\n")


def score_event(kind: str, event: dict) -> dict:
    """Map deception events to an explainable CVSS 4.0 vector."""
    uri = (event.get("RequestURI") or event.get("path") or "").lower()
    protocol = (event.get("Protocol") or event.get("protocol") or kind).upper()
    msg = event.get("Msg") or event.get("msg") or ""
    command = event.get("Command") or ""
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

    canary = kind == "canary" or "canary" in json.dumps(payload).lower() or "aws" in json.dumps(payload).lower() and "manage.canarytokens.org" in json.dumps(payload).lower()
    if kind == "canary":
        canary = True

    tor_block = (
        kind == "policy"
        or "tor exit blocked" in msg.lower()
        or "anon_network_blocked" in json.dumps(event).lower()
        or "hlp-sec-anon" in json.dumps(event).lower()
    )
    secret_path = any(x in uri for x in ["/.env", "ci/secrets", "openapi", "aws", "credential"])
    admin_path = any(x in uri for x in ["/admin", "/token", "pipeline"])
    ssh = protocol == "SSH" or "SSH" in msg
    http = protocol == "HTTP" or kind == "http"

    if canary:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"
        score, severity = 9.3, "CRITICAL"
        why = "Canary AWS key was used or the token was triggered — likely credential theft against the public lure."
    elif tor_block:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity = 6.5, "HIGH"
        why = "Confirmed Tor exit node blocked (HLP-SEC-ANON-01). Policy denies Tor/VPN/proxy; attacker must use a direct IP."
    elif secret_path:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
        score, severity = 8.7, "HIGH"
        why = "Unauthenticated access to leaked env/secrets endpoints on the decoy API."
    elif admin_path or command:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
        score, severity = 8.3, "HIGH"
        why = "Interactive probing of admin/CI routes or shell commands inside the tarpit."
    elif ssh and "Login" in msg:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
        score, severity = 6.9, "MEDIUM"
        why = "Internet-facing SSH login attempt against the decoy listener."
    elif http:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity = 5.3, "MEDIUM"
        why = "External HTTP reconnaissance against the logistics API decoy."
    else:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity = 5.1, "MEDIUM"
        why = "Unclassified deception event."

    return {
        "vector": vector,
        "score": score,
        "severity": severity,
        "rationale": why,
    }


def resolve_chat_id() -> str:
    global TELEGRAM_CHAT_ID
    if TELEGRAM_CHAT_ID:
        return TELEGRAM_CHAT_ID
    state = load_state()
    if state.get("chat_id"):
        TELEGRAM_CHAT_ID = str(state["chat_id"])
        return TELEGRAM_CHAT_ID
    if not TELEGRAM_TOKEN:
        return ""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        print("getUpdates failed", exc)
        return ""
    for upd in data.get("result") or []:
        chat = (upd.get("message") or upd.get("my_chat_member") or {}).get("chat") or {}
        if chat.get("id") is not None:
            TELEGRAM_CHAT_ID = str(chat["id"])
            state["chat_id"] = TELEGRAM_CHAT_ID
            save_state(state)
            print("learned chat_id", TELEGRAM_CHAT_ID)
            return TELEGRAM_CHAT_ID
    return ""


def send_telegram(text: str) -> bool:
    chat_id = resolve_chat_id()
    if not TELEGRAM_TOKEN or not chat_id:
        print("telegram skipped: missing token or chat_id (open t.me/hlp_tarpit_bot and tap Start)")
        return False
    body = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}
    ).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        data=body,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            ok = json.loads(resp.read().decode()).get("ok")
            return bool(ok)
    except Exception as exc:
        print("telegram send failed", exc)
        return False


def format_alert(kind: str, event: dict, cvss: dict, intel: dict) -> str:
    src = intel.get("ip") or extract_src_ip(event)
    proto = event.get("Protocol") or kind
    uri = event.get("RequestURI") or event.get("Command") or ""
    user = event.get("User") or ""
    ua = event.get("UserAgent") or event.get("user_agent") or ""
    when = event.get("DateTime") or event.get("received_at") or utcnow()
    lines = [
        f"HLP TARPIT ALERT [{cvss['severity']}]",
        f"CVSS: {cvss['score']}  {cvss['vector']}",
        f"Why: {cvss['rationale']}",
        f"When: {when}",
        f"Kind: {kind}  Proto: {proto}",
        f"Source: {src}",
        f"Geo: {intel.get('geo')}",
        f"ISP: {intel.get('isp') or 'n/a'}",
        f"Known malicious: {intel.get('malicious')}",
        f"VPN/Proxy/Tor: {intel.get('anon')}",
    ]
    if user:
        lines.append(f"User: {user}")
    if uri:
        lines.append(f"Activity: {uri[:300]}")
    if ua:
        lines.append(f"UA: {ua[:180]}")
    lines.append("Node: 18.171.222.41  API: http://18.171.222.41")
    return "\n".join(lines)


def handle_event(kind: str, event: dict) -> None:
    cvss = score_event(kind, event)
    intel = lookup_ip(extract_src_ip(event))
    text = format_alert(kind, event, cvss, intel)
    sent = send_telegram(text)
    append_jsonl(
        ALERT_LOG,
        {"received_at": utcnow(), "kind": kind, "cvss": cvss, "intel": intel, "sent": sent, "event": event},
    )
    print("alert", kind, cvss["severity"], intel.get("geo"), "sent" if sent else "not-sent")


def extract_beelzebub_event(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    event = rec.get("event")
    if not isinstance(event, dict):
        return None
    return event


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
            self._send(
                200,
                {
                    "ok": True,
                    "service": "hlp-tarpit-receiver",
                    "telegram_chat": bool(resolve_chat_id()),
                    "path": path,
                },
            )
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode("utf-8", errors="replace")}

        if path == "/hook/canary":
            event = {
                "received_at": utcnow(),
                "source_ip": self.client_address[0],
                "user_agent": self.headers.get("User-Agent"),
                "payload": parsed,
            }
            append_jsonl(CANARY_LOG, event)
            handle_event("canary", event)
            self._send(200, {"ok": True})
            return
        if path == "/hook/beelzebub":
            handle_event("beelzebub", parsed if isinstance(parsed, dict) else {"payload": parsed})
            self._send(200, {"ok": True})
            return
        if path == "/hook/policy":
            handle_event("policy", parsed if isinstance(parsed, dict) else {"payload": parsed})
            self._send(200, {"ok": True})
            return
        self._send(404, {"ok": False, "error": "not_found"})


def follow_beelzebub() -> None:
    BEE_LOG.parent.mkdir(parents=True, exist_ok=True)
    if not BEE_LOG.exists():
        BEE_LOG.write_text("")
    while True:
        try:
            with BEE_LOG.open(encoding="utf-8", errors="replace") as fh:
                fh.seek(0, os.SEEK_END)
                while True:
                    pos = fh.tell()
                    line = fh.readline()
                    if not line:
                        try:
                            size = BEE_LOG.stat().st_size
                        except OSError:
                            time.sleep(0.4)
                            continue
                        if pos > size:
                            fh.seek(0)
                        else:
                            time.sleep(0.4)
                        continue
                    event = extract_beelzebub_event(line)
                    if event:
                        kind = "ssh" if (event.get("Protocol") or "").upper() == "SSH" else "http"
                        handle_event(kind, event)
        except Exception as exc:
            print("beelzebub follow retry:", exc)
            time.sleep(2)


def poll_chat_id() -> None:
    while not resolve_chat_id():
        time.sleep(5)


if __name__ == "__main__":
    if not TELEGRAM_TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN is not set")
    DATA.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=follow_beelzebub, daemon=True).start()
    threading.Thread(target=poll_chat_id, daemon=True).start()
    threading.Thread(target=_refresh_tor_exits, daemon=True).start()
    print(f"listening on {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
