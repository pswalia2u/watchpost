#!/usr/bin/env python3
"""Parse Beelzebub NDJSON events into IOC extracts."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LOG = Path("/home/ubuntu/beelzebub/data/beelzebub.log")
OUT = Path("/home/ubuntu/beelzebub/data/intel")


def events():
    if not LOG.exists():
        return
    with LOG.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = rec.get("event")
            if isinstance(event, dict):
                yield event


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    creds, commands, ips, users, clients, passwords = [], [], [], [], [], []
    msgs = Counter()

    with (OUT / "events.jsonl").open("w", encoding="utf-8") as ev_out:
        for event in events():
            ev_out.write(json.dumps(event, ensure_ascii=True) + "\n")
            msgs[event.get("Msg") or event.get("Status") or "unknown"] += 1
            ip = event.get("SourceIp") or ""
            if ip:
                ips.append(ip)
            user = event.get("User") or ""
            password = event.get("Password") or ""
            if user or password:
                creds.append(
                    {
                        "time": event.get("DateTime"),
                        "ip": ip,
                        "user": user,
                        "password": password,
                        "client": event.get("Client") or "",
                        "protocol": event.get("Protocol") or "",
                    }
                )
                if user:
                    users.append(user)
                if password:
                    passwords.append(password)
            cmd = event.get("Command") or ""
            if cmd:
                commands.append(
                    {
                        "time": event.get("DateTime"),
                        "ip": ip,
                        "user": user,
                        "command": cmd,
                        "output": (event.get("CommandOutput") or "")[:4000],
                        "session": event.get("ID") or "",
                    }
                )
            client = event.get("Client") or ""
            if client:
                clients.append(client)

    def unique(values):
        seen = []
        for value in values:
            if value not in seen:
                seen.append(value)
        return seen

    (OUT / "source_ips.txt").write_text("\n".join(unique(ips)) + ("\n" if ips else ""), encoding="utf-8")
    (OUT / "usernames.txt").write_text("\n".join(unique(users)) + ("\n" if users else ""), encoding="utf-8")
    (OUT / "passwords.txt").write_text("\n".join(unique(passwords)) + ("\n" if passwords else ""), encoding="utf-8")
    (OUT / "clients.txt").write_text("\n".join(unique(clients)) + ("\n" if clients else ""), encoding="utf-8")
    with (OUT / "credentials.jsonl").open("w", encoding="utf-8") as fh:
        for row in creds:
            fh.write(json.dumps(row) + "\n")
    with (OUT / "commands.jsonl").open("w", encoding="utf-8") as fh:
        for row in commands:
            fh.write(json.dumps(row) + "\n")

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(LOG),
        "event_count": sum(msgs.values()),
        "unique_source_ips": len(unique(ips)),
        "unique_usernames": len(unique(users)),
        "unique_passwords": len(unique(passwords)),
        "commands_captured": len(commands),
        "event_types": dict(msgs),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
