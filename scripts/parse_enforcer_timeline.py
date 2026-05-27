#!/usr/bin/env python3
"""Extract CSW enforcement timeline from tet-enforcer.log.

Usage:
  python3 parse_enforcer_timeline.py /path/to/*_csw-logs
  python3 parse_enforcer_timeline.py /path/to/log/tet-enforcer.log
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+.*?(Enforcement enabled:\s*(\d+)|"
    r"Received Policy config version[:\s]+(\d+)|"
    r"Received policy.*?version[:\s]+(\d+)|"
    r"Firewall is now enabled|"
    r"Staged rules have been committed|"
    r"Policy config has been applied successfully.*?(\d+))"
)


def find_enforcer_log(path: Path) -> Path:
    path = path.resolve()
    if path.is_file() and path.name == "tet-enforcer.log":
        return path
    if path.is_dir():
        candidate = path / "log" / "tet-enforcer.log"
        if candidate.is_file():
            return candidate
        for p in path.rglob("tet-enforcer.log"):
            if "log" in p.parts:
                return p
    raise FileNotFoundError(f"tet-enforcer.log not found under {path}")


def parse_events(lines: list[str]) -> list[dict]:
    events: list[dict] = []
    for line in lines:
        m = TS_RE.search(line.strip())
        if not m:
            continue
        ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        label = "unknown"
        version = None
        if "Enforcement enabled" in line:
            label = f"enforcement_enabled_{m.group(3)}"
        elif m.group(4) or m.group(5):
            version = m.group(4) or m.group(5)
            label = "policy_received"
        elif "Firewall is now enabled" in line:
            label = "firewall_enabled"
        elif "Staged rules have been committed" in line:
            label = "rules_committed"
        elif "applied successfully" in line:
            version = m.group(6)
            label = "policy_applied"
        events.append(
            {"ts": ts, "label": label, "version": version, "line": line.strip()[:120]}
        )
    return events


def fmt_delta(a: datetime, b: datetime) -> str:
    sec = (b - a).total_seconds()
    if sec < 120:
        return f"{sec:.2f} s"
    if sec < 7200:
        return f"{sec / 60:.1f} min"
    return f"{sec / 3600:.2f} h"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    log_path = find_enforcer_log(Path(sys.argv[1]))
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    events = parse_events(lines)

    print(f"# CSW enforcer timeline\n\n**Source:** `{log_path}`\n")
    if not events:
        print("_No matching events — check log format or extend TS_RE in script._\n")
        return 1

    print("| Timestamp | Event | Version |")
    print("|-----------|--------|---------|")
    for e in events:
        ver = e["version"] or "—"
        print(f"| {e['ts']} | {e['label']} | {ver} |")

    enforce_on = next((e for e in events if e["label"] == "enforcement_enabled_1"), None)
    firewall = next((e for e in events if e["label"] == "firewall_enabled"), None)
    applies = [e for e in events if e["label"] == "policy_applied"]

    print("\n## Deltas\n")
    if enforce_on and firewall:
        print(f"- Enforce ON → firewall enabled: **{fmt_delta(enforce_on['ts'], firewall['ts'])}**")
    if enforce_on and applies:
        print(f"- Enforce ON → last policy applied: **{fmt_delta(enforce_on['ts'], applies[-1]['ts'])}**")
    for i, e in enumerate(events):
        if e["label"] == "policy_received" and i + 1 < len(events):
            nxt = events[i + 1]
            if nxt["label"] in ("rules_committed", "policy_applied"):
                print(
                    f"- Policy received (v {e['version']}) → commit/apply: "
                    f"**{fmt_delta(e['ts'], nxt['ts'])}**"
                )

    if applies:
        print(f"\n**Latest applied version:** `{applies[-1]['version']}` at `{applies[-1]['ts']}`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
