#!/usr/bin/env python3
"""Summarize a CSW *_csw-logs diagnostic bundle.

Usage:
  python3 parse_bundle_summary.py /path/to/*_csw-logs
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

BUNDLE_NAME_RE = re.compile(
    r"^(?P<host>[^_]+)_(?P<uuid>[0-9a-f]{40})_(?P<epoch>\d+)_csw-logs$"
)
NETWORK_POLICY_RE = re.compile(
    r"network_policy\s*\{[^}]*?id:\s*(\d+)[^}]*?action\s*\{\s*type:\s*(\w+)",
    re.DOTALL,
)
PROTO_VERSION_RE = re.compile(r"policy_config_version[:\s]+(\d+)", re.I)
ENFORCE_RE = re.compile(r"Enforcement enabled:\s*(\d+)")
APPLY_RE = re.compile(
    r"Policy config has been applied successfully.*?(\d+)", re.I
)
RECEIVED_RE = re.compile(
    r"Received (?:Policy config version|policy).*?(\d+)", re.I
)
NFLOG_RE = re.compile(r"nflog.*?(?:group|device).*?(\d{5})", re.I)


def find_bundle_root(path: Path) -> Path:
    path = path.resolve()
    if path.is_dir() and path.name.endswith("_csw-logs"):
        return path
    if path.is_dir():
        for p in path.iterdir():
            if p.is_dir() and p.name.endswith("_csw-logs"):
                return p
    raise FileNotFoundError(f"No *_csw-logs directory under {path}")


def read_text(path: Path, limit: int | None = None) -> str:
    if not path.is_file():
        return ""
    data = path.read_text(encoding="utf-8", errors="replace")
    if limit:
        return data[:limit]
    return data


def parse_bundle_name(name: str) -> dict[str, str]:
    m = BUNDLE_NAME_RE.match(name)
    if not m:
        return {"folder": name}
    out = m.groupdict()
    try:
        ts = datetime.fromtimestamp(int(out["epoch"]), tz=timezone.utc)
        out["export_utc"] = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        pass
    return out


def detect_firewall_stack(bundle: Path) -> str:
    nft = bundle / "policyagent-staged-nft"
    if nft.is_file() and nft.stat().st_size > 50:
        return "nftables (policyagent-staged-nft)"
    staged = list(bundle.glob("policyagent-staged-*"))
    ipt = bundle / "firewallDump" / "iptables_v4"
    if ipt.is_file():
        body = read_text(ipt, 4000)
        if body.strip() and "*filter" in body and len(body) > 200:
            return "iptables (firewallDump/iptables_v4)"
    if staged:
        return f"staged files: {', '.join(p.name for p in staged[:5])}"
    return "unknown — check policyagent-staged-* and firewallDump/"


def extract_policies(proto: str) -> list[dict[str, str]]:
    policies: list[dict[str, str]] = []
    for block in re.finditer(r"network_policy\s*\{[^}]*\}", proto, re.DOTALL):
        chunk = block.group(0)
        pid = re.search(r"id:\s*(\d+)", chunk)
        action = re.search(r"type:\s*(\w+)", chunk)
        proto_m = re.search(r"ip_protocol:\s*(\w+)", chunk)
        direction = re.search(r"inspection_point:\s*(\w+)", chunk)
        if pid:
            policies.append(
                {
                    "id": pid.group(1),
                    "action": action.group(1) if action else "?",
                    "protocol": proto_m.group(1) if proto_m else "—",
                    "direction": direction.group(1) if direction else "—",
                }
            )
    return policies


def enforcer_highlights(log: str) -> dict:
    lines = log.splitlines()
    enforce_events: list[tuple[str, str]] = []
    applies: list[tuple[str, str]] = []
    received: list[tuple[str, str]] = []
    errors: list[str] = []

    ts_prefix = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

    for line in lines:
        ts_m = ts_prefix.match(line)
        ts = ts_m.group(1) if ts_m else ""
        em = ENFORCE_RE.search(line)
        if em and ts:
            enforce_events.append((ts, em.group(1)))
        am = APPLY_RE.search(line)
        if am and ts:
            applies.append((ts, am.group(1)))
        rm = RECEIVED_RE.search(line)
        if rm and ts:
            received.append((ts, rm.group(1)))
        if re.search(r"\b(ERROR|error|failed|rollback)\b", line):
            if "Enforcement" in line or "Policy" in line or "Firewall" in line:
                errors.append(line.strip()[:140])

    last_enforce = enforce_events[-1] if enforce_events else None
    last_apply = applies[-1] if applies else None

    return {
        "last_enforcement": last_enforce,
        "last_apply": last_apply,
        "policy_receive_count": len(received),
        "apply_count": len(applies),
        "errors": errors[-10:],
    }


def sensor_highlights(log: str) -> list[str]:
    hits: list[str] = []
    for line in log.splitlines():
        if "nflog" in line.lower() or "50660" in line or "50880" in line:
            if "DENY" in line.upper() or "nflog" in line.lower():
                hits.append(line.strip()[:120])
    return hits[-8:]


def count_nft_policy_ids(nft: str) -> list[str]:
    return sorted(set(re.findall(r'comment "id: (\d+)"', nft)))


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    bundle = find_bundle_root(Path(sys.argv[1]))
    meta = parse_bundle_name(bundle.name)

    sensor_uuid = read_text(bundle / ".sensor_uuid").strip()
    sensor_id = read_text(bundle / "sensor_id").strip()
    proto_path = bundle / "proto" / "latest_e2a_npc_proto_file"
    proto = read_text(proto_path)
    enforcer_path = bundle / "log" / "tet-enforcer.log"
    enforcer = read_text(enforcer_path)
    sensor_path = bundle / "log" / "tet-sensor.log"
    sensor = read_text(sensor_path)
    nft_path = bundle / "policyagent-staged-nft"
    nft = read_text(nft_path)

    print(f"# CSW bundle summary\n\n**Path:** `{bundle}`\n")

    print("## Identity\n")
    print("| Field | Value |")
    print("|-------|--------|")
    if meta.get("host"):
        print(f"| Hostname (folder) | {meta['host']} |")
    if meta.get("uuid"):
        print(f"| Agent UUID (folder) | `{meta['uuid']}` |")
    if meta.get("export_utc"):
        print(f"| Export time (epoch→UTC) | {meta['export_utc']} |")
    if sensor_uuid:
        print(f"| `.sensor_uuid` | `{sensor_uuid}` |")
    if sensor_id:
        print(f"| `sensor_id` | `{sensor_id}` |")

    print("\n## Firewall stack\n")
    print(f"- **Detected:** {detect_firewall_stack(bundle)}")

    if nft:
        ids = count_nft_policy_ids(nft)
        if ids:
            print(f"- **nft policy ids on host:** {', '.join(ids)}")

    print("\n## Policy config (`proto/latest_e2a_npc_proto_file`)\n")
    if not proto:
        print("_Proto file missing or empty._\n")
    else:
        pv = PROTO_VERSION_RE.search(proto)
        if pv:
            print(f"- **policy_config_version:** `{pv.group(1)}`")
        policies = extract_policies(proto)
        if policies:
            print("\n| id | action | protocol | direction |")
            print("|----|--------|----------|-----------|")
            for p in policies:
                print(
                    f"| {p['id']} | {p['action']} | {p['protocol']} | {p['direction']} |"
                )
        else:
            print("_No network_policy blocks parsed — extend NETWORK_POLICY_RE or inspect manually._")

    print("\n## Enforcer highlights (`log/tet-enforcer.log`)\n")
    if not enforcer:
        print("_Enforcer log missing._\n")
    else:
        h = enforcer_highlights(enforcer)
        if h["last_enforcement"]:
            ts, val = h["last_enforcement"]
            print(f"- **Last enforcement state:** `{val}` at `{ts}`")
        if h["last_apply"]:
            ts, ver = h["last_apply"]
            print(f"- **Last successful apply:** version `{ver}` at `{ts}`")
        print(f"- **Policy receive events (count):** {h['policy_receive_count']}")
        print(f"- **Successful apply events (count):** {h['apply_count']}")
        if h["errors"]:
            print("\n**Recent enforcer errors/warnings:**")
            for e in h["errors"]:
                print(f"- `{e}`")

    print("\n## Sensor / deny telemetry (`log/tet-sensor.log`)\n")
    if not sensor:
        print("_Sensor log missing — cannot confirm nflog listeners._\n")
    else:
        highlights = sensor_highlights(sensor)
        if highlights:
            print("Recent nflog / deny listener lines:")
            for line in highlights:
                print(f"- `{line}`")
        else:
            print("_No nflog/DENY lines found in tail scan — may need post-test export._")

    print("\n## Artifact checklist\n")
    artifacts = [
        ("log/tet-enforcer.log", enforcer_path),
        ("log/tet-sensor.log", sensor_path),
        ("proto/latest_e2a_npc_proto_file", proto_path),
        ("policyagent-staged-nft", nft_path),
        ("firewallDump/iptables_v4", bundle / "firewallDump" / "iptables_v4"),
    ]
    print("| File | Present |")
    print("|------|---------|")
    for label, p in artifacts:
        print(f"| `{label}` | {'yes' if p.is_file() else 'no'} |")

    print("\n---\n_Run `parse_enforcer_timeline.py` on the same bundle for full event timeline._")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
