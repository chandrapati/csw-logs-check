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

**Detailed how-to with logs:** [docs/USAGE-WITH-LOGS.md](docs/USAGE-WITH-LOGS.md)  
**Extraction catalog & grep patterns:** [reference.md](reference.md)

## When to use

- User provides or points to a `*_csw-logs` bundle (or `log/tet-enforcer.log`)
- Validate ICMP / network / L4 policy enforcement for a POV
- Compare two hosts on enforcement timing
- Write findings for customer engineering / SecOps

## Quick workflow

```text
1. Obtain bundle → verify log/, proto/, policyagent-staged-*
2. python3 scripts/parse_bundle_summary.py <bundle>   # identity, policies, stack
3. python3 scripts/parse_enforcer_timeline.py <bundle> # timeline + deltas
4. Grep proto for network_policy id + staged nft/iptables for comment "id: N"
5. Correlate: version V containing id N → apply timestamp = functional test cutoff
6. State what logs prove vs do not prove → report (templates in reference.md)
```

## Bundle layout (typical)

| Path | Purpose |
|------|---------|
| `log/tet-enforcer.log` | Policy receive, enforce mode, commit timestamps |
| `log/tet-sensor.log` | nflog / deny listener (50660, 50880) |
| `proto/latest_e2a_npc_proto_file` | Policy protobuf — `network_policy { id: N }` |
| `policyagent-staged-nft` | Committed **nftables** (WAF) |
| `firewallDump/iptables_v4` | May be empty if agent uses nft only |
| `.sensor_uuid` / `sensor_id` | Agent UUID |

Bundle folder name often: `{hostname}_{agent_uuid}_{epoch}_csw-logs`.

## What you can extract (summary)

| Category | Examples |
|----------|----------|
| **Identity** | Hostname, agent UUID, bundle export time (epoch) |
| **Policy config** | All `network_policy` ids, DROP/ALLOW, protocol, INGRESS/EGRESS, address sets |
| **Host programming** | nft/iptables rules, `comment "id: N"`, ipset members, nflog group |
| **Timing** | Enforce on/off, firewall on, per-version receive/apply, deltas |
| **Connectivity** | Proxy, WSS/cluster from enforcer log (early lines) |
| **Telemetry readiness** | nflog DENY listeners in tet-sensor.log |
| **Gaps / errors** | Apply failures, rollback, ERROR lines |
| **Not in bundle** | Specific packet denied unless sensor/UI forensics cited |

Full table per file: [reference.md — Extraction catalog](reference.md#extraction-catalog--by-artifact).

## Definitions (use consistently)

| Term | Log signal |
|------|------------|
| **Enforcement mode ON** | `Enforcement enabled: 1` |
| **Policy landed** | `Received Policy config version` / `Received policy` from EFE |
| **Enforced on host** | `Staged rules have been committed` + `Policy config has been applied successfully` |
| **Functional rule live** | Version that contains target `network_policy id` is **applied** — not merely enforce=1 |

**Critical:** `Enforcement enabled: 1` can precede the POV policy by **minutes**. Tests must use the **apply timestamp** of the version that contains the rule under test.

## Parser scripts

```bash
python3 scripts/parse_bundle_summary.py /path/to/*_csw-logs
python3 scripts/parse_enforcer_timeline.py /path/to/*_csw-logs
```

## Single-host analysis checklist

- [ ] Run both parser scripts; paste summary into report
- [ ] Agent UUID and primary IP documented
- [ ] Target rule in proto (id, action, match_set / src IPs)
- [ ] On-host rule: `comment "id: N"` in nft or iptables
- [ ] Timeline with policy version numbers
- [ ] Deltas: enforce→firewall; enforce→rule-live; receive→commit
- [ ] Sensor: nflog 50660/50880 if deny proof needed later
- [ ] **Test cutoff** datetime for functional validation
- [ ] **Does not prove:** specific deny without sensor/UI evidence

## Multi-host comparison

1. `parse_bundle_summary.py` + `parse_enforcer_timeline.py` on each bundle
2. Comparison matrix (see reference.md template)
3. Note firewall stack: **nftables** vs **iptables + ipset**
4. Conclusion: on-host apply is usually **sub-second**; enforce→live gap is **CSW delivery**

Pattern: [examples/two-host-comparison.md](examples/two-host-comparison.md)

## Cursor prompts (examples)

```text
Use csw-logs-check on /path/to/host_*_csw-logs. Policy id 1 ICMP DROP ingress.
Run both parser scripts, grep proto and nft, write single-host report with test cutoff.
```

```text
Compare two csw-logs bundles (paths …). Same policy id. Timing comparison only.
```

## What to tell stakeholders

**Prove with logs:** policy in agent config, rendered on host, committed at T, enforcement enabled, nflog listeners up.

**Do not claim:** a specific flow was dropped unless deny telemetry / Denied Connections cited.

**Recommend:** test after cutoff T; CSW **Enforce** mode; Denied Connections after ping/curl.

## Deliverable naming

| Audience | Suggested file |
|----------|----------------|
| Engineering | `CSW-Log-Analysis-<host-or-ip>.md` |
| Two hosts | `CSW-Enforcement-Timing-Comparison-<hostA>-vs-<hostB>.md` |
| Summary | `CSW-Enforcement-Validation-Findings.md` |
