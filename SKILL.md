---
name: csw-logs-check
description: >-
  Analyze Cisco Secure Workload (CSW) agent diagnostic log bundles — enforcement
  timing, policy versions, host firewall (nftables/iptables), ICMP/network policy
  validation, and multi-host comparison. Use when the user asks to check CSW logs,
  csw-logs, tet-enforcer.log, enforcement validation, policy landed vs enforced,
  or comparative timing between agents.
---

# CSW agent log check

Analyze **CSW agent diagnostic exports** (`*_csw-logs` directories) to answer: policy defined? on-host rules? when applied? enforce mode vs policy live?

## When to use

- User provides or points to a `*_csw-logs` bundle (or `log/tet-enforcer.log`)
- Validate ICMP / network policy enforcement for a POV
- Compare two hosts on enforcement timing
- Write findings for customer engineering / SecOps

## Quick workflow

```text
1. Locate bundle → log/tet-enforcer.log, proto/latest_e2a_npc_proto_file
2. Run parser (optional) → scripts/parse_enforcer_timeline.py <bundle_path>
3. Grep policy id / ICMP in proto + staged nft or iptables dump
4. Build timeline: enforce ON → firewall ON → policy versions → target rule apply
5. State what logs prove vs do not prove
6. Emit report (single-host and/or comparison) — see templates in reference.md
```

**Reference:** [reference.md](reference.md) — log phrases, definitions, report templates.

## Bundle layout (typical)

| Path | Purpose |
|------|---------|
| `log/tet-enforcer.log` | Policy receive, enforce mode, commit timestamps |
| `log/tet-sensor.log` | nflog / deny listener startup |
| `proto/latest_e2a_npc_proto_file` | Policy protobuf — `network_policy { id: N }` |
| `policyagent-staged-nft` | Committed **nftables** (WAF) |
| `firewallDump/iptables_v4` | May be empty if agent uses nft only |
| `.sensor_uuid` / `sensor_id` | Agent UUID |

Bundle folder name often: `{hostname}_{agent_uuid}_{epoch}_csw-logs`.

## Definitions (use consistently)

| Term | Log signal |
|------|------------|
| **Enforcement mode ON** | `Enforcement enabled: 1` |
| **Policy landed** | `Received Policy config version` / `Received policy` from EFE |
| **Enforced on host** | `Staged rules have been committed` + `Policy config has been applied successfully` |
| **Functional rule live** | Version that contains target `network_policy id` (e.g. ICMP id **1**) is **applied** — not merely enforce=1 |

**Critical:** `Enforcement enabled: 1` can precede the POV policy by **minutes**. Tests must use the **apply timestamp** of the version that contains the rule under test.

## Parser script

From bundle root or any path inside bundle:

```bash
python3 scripts/parse_enforcer_timeline.py /path/to/agent_csw-logs
python3 scripts/parse_enforcer_timeline.py /path/to/log/tet-enforcer.log
```

Outputs markdown timeline + deltas (enforce→firewall, enforce→last apply, receive→commit).

## Single-host analysis checklist

- [ ] Agent UUID and primary IP documented
- [ ] Target rule in `proto/latest_e2a_npc_proto_file` (id, action, match_set / src)
- [ ] On-host rule: `policyagent-staged-nft` (`comment "id: N"`) or iptables/ipset
- [ ] Timeline from `tet-enforcer.log` with policy version numbers
- [ ] Deltas: enforce ON → firewall; enforce ON → rule-live version; receive → commit (ms)
- [ ] **Test cutoff** datetime for functional validation
- [ ] **Does not prove:** specific ping/deny event unless sensor log or CSW Denied Connections cited

## Multi-host comparison

When comparing two bundles (same test window):

1. Run parser on each bundle
2. Fill comparison table: enforce ON, firewall ON, policy version apply, enforce→live gap, receive→commit
3. Note firewall stack: **nftables** vs **iptables + ipset**
4. Conclusion: agent apply latency is usually **sub-second**; gaps are **CSW/EFE delivery**, not OS firewall slowness

See [examples/two-host-comparison.md](examples/two-host-comparison.md) for a generic pattern (no real customer data).

## What to tell stakeholders

**Prove with logs:** policy in agent config, rendered on host, committed at timestamp T, enforcement enabled.

**Do not claim:** a specific flow was dropped unless deny telemetry / Denied Connections / post-test log shows it.

**Recommend:** test traffic after cutoff T; CSW UI **Enforce** (not Monitor); check VIP/LB path and upstream ACLs if traffic still passes.

## Deliverable naming

| Audience | Suggested file |
|----------|----------------|
| Engineering | `CSW-Log-Analysis-<host-or-ip>.md` |
| Two hosts | `CSW-Enforcement-Timing-Comparison-<hostA>-vs-<hostB>.md` |
| Summary | `CSW-Enforcement-Validation-Findings.md` |
