# CSW logs check — reference

Detailed grep patterns, **what you can extract** from each artifact, and report templates.

**Step-by-step usage:** [docs/USAGE-WITH-LOGS.md](docs/USAGE-WITH-LOGS.md)

---

## Bundle file inventory

Typical `*_csw-logs` layout (names vary slightly by agent version):

| Path | Role |
|------|------|
| `log/tet-enforcer.log` | Policy receive, staging, commit, enforcement on/off |
| `log/tet-sensor.log` | nflog listeners, deny telemetry threads, flow/deny hooks |
| `log/tet-*.log` | Other agent components (sensor, discovery, etc.) |
| `proto/latest_e2a_npc_proto_file` | Text export of NPC policy protobuf |
| `policyagent-staged-nft` | Committed **nftables** ruleset (WAF mode) |
| `policyagent-staged-*` | Staged iptables/ipset or transitional artifacts |
| `firewallDump/iptables_v4` | iptables snapshot (often empty if nft-only) |
| `firewallDump/ip6tables_*` | IPv6 tables if collected |
| `.sensor_uuid` / `sensor_id` | Agent identifiers |
| `version` / `build-info` | Agent build (if present) |

Folder name pattern: `{hostname}_{40-char-hex-uuid}_{unix_epoch}_csw-logs`

---

## Extraction catalog — by artifact

### `log/tet-enforcer.log`

| Extractable detail | Log pattern / method | Use in report |
|--------------------|----------------------|---------------|
| Enforcement on/off | `Enforcement enabled: 0\|1` | Last value = current mode |
| First enforce on test day | First `enabled: 1` after prior `0` | **T_enforce** (not rule-live) |
| Firewall activated | `Firewall is now enabled` | **T_firewall** |
| Policy version received | `Received Policy config version` / `Received policy` | Version queue from CSW |
| Rules staged | `Staged rules have been committed` | Host programmed |
| Apply success | `Policy config has been applied successfully, current version: N` | **T_live** for version N |
| Apply failures | `ERROR`, `failed`, `rollback` | Troubleshooting |
| On-host commit latency | Δ(receive version N → commit/apply) | Usually &lt;100 ms |
| Delivery latency | Δ(T_enforce → apply of test version) | Often minutes |
| Proxy / egress | `http.proxy`, `proxy` in early lines | Connectivity context |
| WSS / cluster | `wss://`, cluster hostname in URL | Which EFE/tenant path |
| Agent restart | Gap in timestamps, `starting`, version banners | Exclude stale tail |

```bash
LOG="$BUNDLE/log/tet-enforcer.log"

rg -n "Enforcement enabled" "$LOG"
rg -n "Received Policy config version|Received policy" "$LOG"
rg -n "Firewall is now enabled" "$LOG"
rg -n "Staged rules have been committed" "$LOG"
rg -n "Policy config has been applied successfully" "$LOG"
rg -n "ERROR|failed|rollback" "$LOG" | tail -30
rg -n "proxy|wss://|cluster" "$LOG" | head -20
```

### `proto/latest_e2a_npc_proto_file`

| Extractable detail | Where in proto | Use in report |
|--------------------|----------------|---------------|
| `policy_config_version` | Top-level version field | Must match applied version in enforcer |
| Per-rule `network_policy id` | `network_policy { id: N }` | Map to nft `comment "id: N"` |
| Action | `action { type: DROP\|ALLOW }` | DROP vs ALLOW |
| Protocol | `ip_protocol: ICMP\|TCP\|...` or port lists | ICMP = protocol 1 on host |
| Direction | `inspection_point: INGRESS\|EGRESS` | Server ingress vs egress test |
| Source/dest sets | `src_set_id`, `dst_set_id` | Resolve to IPs in set definitions |
| Catch-all rules | High id ALLOW/DENY | Explain evaluation order |
| L4 ports | `port: 22`, lists in match | SSH/RDP deny policies |

```bash
PROTO="$BUNDLE/proto/latest_e2a_npc_proto_file"

rg -n "policy_config_version" "$PROTO" | head -5
rg -n "network_policy" "$PROTO"
rg -n "id: [0-9]+" "$PROTO" | head -60
rg -n "ICMP|INGRESS|EGRESS|DROP|ALLOW" "$PROTO" | head -80
rg -n "src_set_id|dst_set_id" "$PROTO"
rg -n "ip_address|prefix|ipv4" "$PROTO" | head -40
```

**Resolve address set:** Find `src_set_id: "IPv4_..."` in your policy block, then `rg` that set name in the same file for member IPs or encoded addresses.

### `policyagent-staged-nft` (nftables)

| Extractable detail | nft syntax | Use in report |
|--------------------|------------|---------------|
| Policy id on rule | `comment "id: N"` | Tie to `network_policy id` |
| ICMP rule | `ip protocol 1` | Matches ICMP policy |
| Source set | `ip saddr @ta_*` + `elements = { x.x.x.x/32 }` | Functional test source IP |
| Drop target | `jump ta_drop` | Deny path |
| nflog group | `log group 50660` in `ta_drop` | Deny telemetry to CSW |
| Table/chain | `inet csw-agent`, `ta_input` | WAF INPUT hook |
| Counter hits | `counter` on rule | If non-zero after test, traffic hit rule |

```bash
NFT="$BUNDLE/policyagent-staged-nft"

rg -n 'comment "id:' "$NFT"
rg -n "ip protocol 1|ta_drop|50660" "$NFT"
rg -n "elements = {" "$NFT" -A2
```

### iptables / ipset path

| Extractable detail | Where | Notes |
|--------------------|-------|-------|
| Policy id | `comment "id: N"` on rule | Same id scheme as proto |
| ipset name | `ta_*`, `match-set` | Map to CSW address sets |
| Empty iptables dump | `firewallDump/iptables_v4` | Normal if nft WAF is active |

```bash
rg -n 'comment "id:|match-set|ta_' "$BUNDLE"/policyagent-staged-* 2>/dev/null
rg -n "." "$BUNDLE/firewallDump/iptables_v4" | head -40
```

### `log/tet-sensor.log`

| Extractable detail | Pattern | Use in report |
|--------------------|---------|---------------|
| Deny nflog ready | group **50660**, DENY | Host can emit deny events |
| CA-DENY nflog | **50880** | Certificate / CA deny path |
| Listener start time | Timestamp on nflog open | Correlate with T_enforce |
| Actual deny records | Src/dst IP, ICMP after test | Rare in pre-test bundles |

```bash
SENSOR="$BUNDLE/log/tet-sensor.log"

rg -n "nflog|50660|50880|DENY" "$SENSOR" | tail -40
```

### Bundle metadata

| Extractable detail | Source |
|--------------------|--------|
| Hostname | Folder name prefix |
| Agent UUID | Folder name or `.sensor_uuid` |
| Export time | Epoch suffix in folder name → UTC |
| Collection after apply | Compare export epoch to T_live in enforcer |

---

## Correlating policy id → version → time

1. In **proto**, note `policy_config_version` and confirm your `network_policy { id: N }` exists.
2. In **enforcer**, list applies: each `current version: V` at timestamp `T`.
3. If proto version `V` contains id `N`, then **T** is your functional test cutoff for that bundle snapshot.
4. If enforce turned on at `T0` but id `N` first appears in version `V2` at `T2`, the gap `T2 - T0` is **delivery**, not host slowness.

---

## Grep patterns (`tet-enforcer.log`) — quick copy

```bash
LOG="$BUNDLE/log/tet-enforcer.log"

rg -n "Enforcement enabled" "$LOG"
rg -n "Received Policy config version|Received policy" "$LOG"
rg -n "Firewall is now enabled" "$LOG"
rg -n "Staged rules have been committed" "$LOG"
rg -n "Policy config has been applied successfully" "$LOG"
```

---

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
| Deny telemetry listeners up? | Yes/No — nflog 50660 in tet-sensor |
| Logs prove post-test deny? | No — recommend functional test |

## Policy definition (proto excerpt)

[network_policy id, action, protocol, direction, src set → IP]

## Host firewall (nft/iptables excerpt)

[comment "id: N", protocol, source set]

## Timeline

| Timestamp (local) | Event | Policy version |
|-------------------|--------|----------------|
| … | Enforcement enabled: 0/1 | — |
| … | Received policy | … |
| … | Firewall enabled / committed | … |
| … | Target version applied | … |

## Deltas

| Interval | Duration |
|----------|----------|
| Enforce ON → firewall ON | … |
| Enforce ON → target rule live | … |
| Policy received → committed (target version) | … ms |

## Test cutoff

Functional validation **after** [TIMESTAMP] for version [V] containing policy id [N].

## What logs do not show

1. No captured deny for a specific test flow in the bundle  
2. …

## Conclusion

[Configured, applied, recommend functional test + Denied Connections]
```

## Report template — two-host comparison

```markdown
# CSW enforcement timing — [hostA] vs [hostB]

## Executive summary

| Question | Host A | Host B |
|----------|--------|--------|
| Enforcement mode ON | … | … |
| Host firewall active | … | … |
| [Test] policy applied (version) | … | … |
| Enforce ON → rule live | … | … |
| Receive → commit (target ver.) | … | … |
| Firewall stack | nftables / iptables | … |
| nflog DENY listener | … | … |

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

---

## Illustrative comparison (synthetic)

Use only as a **pattern** — always re-derive from fresh exports:

| | Host A (nftables) | Host B (iptables) |
|--|-------------------|-------------------|
| Role | e.g. legacy test server | e.g. app POV server |
| Enforce ON → rule live | often **many minutes** | often **fewer minutes** |
| Receive → commit | typically **&lt;100 ms** | typically **&lt;100 ms** |

---

## CSW UI cross-checks

- Scope mode: **Enforce** vs Monitor  
- **Denied Connections** / forensics for protocol + src/dst after test  
- Policy version in UI vs `current version` in enforcer log  
- Flow table: confirm traffic uses the instrumented host (not bypass via LB)
- Agent Config Profile → **Preserve Rules** (coexistence with local firewall—not reboot persistence)

---

## Preserve Rules and reboot (see full note)

**[docs/PRESERVE-RULES.md](docs/PRESERVE-RULES.md)**

| Topic | Summary |
|-------|---------|
| What it is | Coexist with **existing** host `iptables`/`ipset` (ON) vs clear then apply CSW (OFF, default) |
| What it is not | Keeping CSW deny rules in memory across reboot |
| `/opt/cisco/tetration/backup` | One-time backup of **pre-CSW local** firewall at **first** enforce enable |
| Post-reboot ping allowed briefly | Usually **before** agent applies policy; use `T_live` from enforcer log |
| Will toggling preserve fix reboot gap? | **Unlikely** — address agent start order, test timing, network ACLs |

```bash
rg -n "deviation|reprogram|preserve|backup|Firewall is now enabled" "$BUNDLE/log/tet-enforcer.log" | tail -40
```

---

## Automation scripts

| Script | Output |
|--------|--------|
| `scripts/parse_bundle_summary.py` | Identity, stack, policy table, enforcer/sensor highlights |
| `scripts/parse_enforcer_timeline.py` | Full enforce/apply timeline + deltas |
