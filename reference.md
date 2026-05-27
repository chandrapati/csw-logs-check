# CSW logs check — reference

## Grep patterns (`tet-enforcer.log`)

```bash
LOG="$BUNDLE/log/tet-enforcer.log"

rg -n "Enforcement enabled" "$LOG"
rg -n "Received Policy config version|Received policy" "$LOG"
rg -n "Firewall is now enabled" "$LOG"
rg -n "Staged rules have been committed" "$LOG"
rg -n "Policy config has been applied successfully" "$LOG"
```

## Policy protobuf (`proto/latest_e2a_npc_proto_file`)

```bash
rg -n "network_policy|id: 1|ICMP|DROP|INGRESS" "$BUNDLE/proto/latest_e2a_npc_proto_file" | head -80
```

Map `src_set_id` to IPs via address-set definitions in the same file (or decode embedded addresses in the protobuf text export).

## Host firewall

| Stack | Artifact | Confirm |
|-------|----------|---------|
| nftables | `policyagent-staged-nft` | `comment "id: N"`, `ip protocol 1` for ICMP |
| iptables | `policyagent-staged-*` / dumps | ipset names `ta_*`, `comment "id: N"` |

Empty `firewallDump/iptables_v4` with active `policyagent-staged-nft` is **normal** (nft WAF path).

## Report template — single host

```markdown
# CSW [test name] — agent log analysis

**Audience:** Customer engineering / SecOps / Cisco SE  
**Date:** YYYY-MM-DD  
**Subject:** [one sentence]  
**Log bundle:** `[folder name]`  
**Agent UUID:** `[uuid]`  
**Host IP:** `[ip]`

## Executive summary

| Question | Answer |
|----------|--------|
| Policy in agent config? | Yes/No — network_policy id N, … |
| On-host firewall rule? | Yes/No — nft/iptables excerpt |
| Applied on server? | Yes/No — version X at TIMESTAMP |
| Enforcement enabled? | Yes/No — from TIMESTAMP |
| Logs prove post-test deny? | No — recommend functional test |

## Timeline

| Timestamp (local) | Event | Policy version |
|-------------------|--------|----------------|
| … | Enforcement enabled: 0/1 | — |
| … | Received policy | … |
| … | Firewall enabled / committed | … |

## Deltas

| Interval | Duration |
|----------|----------|
| Enforce ON → rule-live version | … |
| Policy received → committed | … ms |

## Test cutoff

Functional validation **after** [TIMESTAMP] for [test description].

## What logs do not show

1. No captured deny for a specific test flow in the bundle  
2. …

## Conclusion

[Configured, applied on host, recommend functional test + Denied Connections]
```

## Report template — two-host comparison

```markdown
# CSW enforcement timing — [hostA] vs [hostB]

## Executive summary

| Question | Host A | Host B |
|----------|--------|--------|
| Enforcement mode ON | … | … |
| Host firewall active | … | … |
| [Test] policy applied | … | … |
| Enforce ON → rule live | … | … |
| Receive → commit | … | … |
| Firewall stack | nftables / iptables | … |

**Bottom line:** Same agent pattern; long enforce→live gap is usually policy delivery, not slow host apply.

## Side-by-side timeline

[ASCII diagram — host A left, host B right]

## Comparison matrix

| Metric | Host A | Host B | Notes |
|--------|--------|--------|-------|

## Testing implications

1. Do not treat `Enforcement enabled: 1` as rule live  
2. Host A functional cutoff: …  
3. Host B functional cutoff: …
```

## Illustrative comparison (synthetic)

Use only as a **pattern** — always re-derive from fresh exports:

| | Host A (nftables) | Host B (iptables) |
|--|-------------------|-------------------|
| Role | e.g. legacy test server | e.g. app POV server |
| Enforce ON → rule live | often **many minutes** | often **fewer minutes** |
| Receive → commit | typically **&lt;100 ms** | typically **&lt;100 ms** |

## CSW UI cross-checks

- Scope mode: **Enforce** vs Monitor  
- **Denied Connections** / forensics for protocol + src/dst after test  
- Policy version in UI vs `current version` in enforcer log
