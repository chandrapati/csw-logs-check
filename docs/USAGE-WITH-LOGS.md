# Using csw-logs-check with CSW agent log bundles

This guide walks through **obtaining**, **unpacking**, **analyzing**, and **reporting** on Cisco Secure Workload (CSW) agent diagnostic exports (`*_csw-logs`).

---

## Part 1 — Obtain a log bundle

### From CSW UI (typical POV path)

1. In CSW, open the **inventory** view for the workload / agent under test.
2. Select the agent (server VM or host) that should enforce the policy.
3. Use the agent **diagnostics** or **support bundle** action (wording varies by CSW version) to export **`csw-logs`**.
4. Download the archive and extract it locally. You should see a folder named like:

   `{hostname}_{agent_uuid}_{epoch}_csw-logs`

5. Note the **export time** (epoch in folder name is Unix seconds when the bundle was collected). Rules applied **after** export will not appear.

### When to re-export

| Situation | Action |
|-----------|--------|
| Policy changed after first export | Export again **after** the change |
| Functional test just ran | Export **after** ping/curl test to capture sensor/nflog activity |
| Comparing two hosts | Export both agents the same day, ideally after the same test window |

### What you need before analysis

| Input | Why |
|-------|-----|
| Bundle path(s) on disk | All commands take a path |
| **Test policy** `network_policy id` (e.g. `1`) | Tie timeline to the rule you care about |
| **Source / dest IPs** (functional test) | Map protobuf `src_set_id` to addresses |
| **Approximate test time** (local TZ) | Find the right section of `tet-enforcer.log` |

---

## Part 2 — Verify bundle structure

```bash
export BUNDLE="/path/to/myhost_<uuid>_<epoch>_csw-logs"

# Quick inventory
ls -la "$BUNDLE"
ls -la "$BUNDLE/log" 2>/dev/null
test -f "$BUNDLE/log/tet-enforcer.log" && echo "OK: enforcer log"
test -f "$BUNDLE/proto/latest_e2a_npc_proto_file" && echo "OK: policy proto"
```

**Minimum viable bundle** for enforcement validation:

- `log/tet-enforcer.log`
- `proto/latest_e2a_npc_proto_file`
- `policyagent-staged-nft` **or** `policyagent-staged-*` / non-empty iptables dumps

Optional but valuable: `log/tet-sensor.log`, `firewallDump/`, `.sensor_uuid`, `sensor_id`.

---

## Part 3 — Automated first pass (scripts)

Run from the repo root (or any directory with the scripts on your `PATH`):

```bash
# Bundle summary: identity, firewall stack, policy IDs, enforce state, proto version
python3 scripts/parse_bundle_summary.py "$BUNDLE"

# Enforcement timeline + deltas
python3 scripts/parse_enforcer_timeline.py "$BUNDLE"
```

Save output to files for reports:

```bash
python3 scripts/parse_bundle_summary.py "$BUNDLE" > /tmp/csw-summary.md
python3 scripts/parse_enforcer_timeline.py "$BUNDLE" > /tmp/csw-timeline.md
```

---

## Part 4 — Manual extraction (by question)

Use this table to pick files and commands. Full patterns: [reference.md](../reference.md).

| Question | Primary artifacts | What to extract |
|----------|-------------------|-----------------|
| Is enforcement on? | `tet-enforcer.log` | Last `Enforcement enabled: 0/1` |
| When did firewall start? | `tet-enforcer.log` | `Firewall is now enabled` |
| What policy version is live? | `tet-enforcer.log` | Last `current version:` on apply line |
| When did **my** rule go live? | `tet-enforcer.log` + proto | Apply time of version that contains your `network_policy id` |
| Is rule defined in CSW config? | `proto/latest_e2a_npc_proto_file` | `network_policy { id: N }`, action, protocol, INGRESS/EGRESS |
| Is rule on the host? | `policyagent-staged-nft` or iptables | `comment "id: N"`, ipset members, `ip protocol 1` for ICMP |
| nft vs iptables? | staged files + `firewallDump/` | nft file present vs `iptables_v4` rules |
| Deny telemetry ready? | `tet-sensor.log` | nflog group **50660** (DENY), **50880** (CA-DENY) |
| Agent identity | folder name, `.sensor_uuid` | hostname, UUID |
| Connectivity / proxy | `tet-enforcer.log` (head) | proxy URL, WSS path, cluster hostname |
| Errors during apply? | `tet-enforcer.log` | `ERROR`, `failed`, `rollback` |

### Example: confirm ICMP deny policy id 1

```bash
BUNDLE="/path/to/*_csw-logs"
PROTO="$BUNDLE/proto/latest_e2a_npc_proto_file"
NFT="$BUNDLE/policyagent-staged-nft"
LOG="$BUNDLE/log/tet-enforcer.log"

# 1) Policy definition
rg -n "network_policy|id: 1|ICMP|DROP|INGRESS" "$PROTO" | head -40

# 2) On-host rule (nftables)
rg -n 'comment "id: 1"|ip protocol 1' "$NFT" | head -20

# 3) When version containing id 1 was applied — use timeline script, then grep versions:
rg -n "Received Policy config version|applied successfully" "$LOG" | tail -30
```

### Map `src_set_id` to IP addresses

In the protobuf text export, search for the set name referenced by your policy (e.g. `IPv4_...`), then find the `ip_address` / `prefix` blocks under that set. Alternatively decode hex blobs in the set definition (see reference.md).

---

## Part 5 — Build the enforcement timeline (manual)

Work **chronologically** in `tet-enforcer.log` for the test day:

```text
1. Last "Enforcement enabled: 0" before test  →  confirms prior state
2. First "Enforcement enabled: 1" on test day →  T_enforce (do NOT use as rule-live)
3. "Firewall is now enabled"                  →  T_firewall (~seconds after T_enforce)
4. "Received Policy config version" entries   →  note version numbers in order
5. For target version V (contains your policy id in proto):
     - "Received Policy config version: V"
     - "Staged rules have been committed"
     - "Policy config has been applied successfully, current version: V"
   →  T_live = apply timestamp (functional test cutoff)
6. Compute deltas:
     - T_enforce → T_firewall (expect 1–5 s)
     - T_enforce → T_live (often minutes — CSW delivery)
     - receive V → commit (expect tens of ms on host)
```

**Test cutoff statement for reports:**

> Functional validation (ping, curl, app test) must occur **after** `T_live` for policy version `V` that includes `network_policy id N`.

---

## Part 6 — Two-host comparison

```bash
BUNDLE_A="/path/to/hostA_*_csw-logs"
BUNDLE_B="/path/to/hostB_*_csw-logs"

python3 scripts/parse_bundle_summary.py "$BUNDLE_A" > /tmp/hostA-summary.md
python3 scripts/parse_bundle_summary.py "$BUNDLE_B" > /tmp/hostB-summary.md
python3 scripts/parse_enforcer_timeline.py "$BUNDLE_A" > /tmp/hostA-timeline.md
python3 scripts/parse_enforcer_timeline.py "$BUNDLE_B" > /tmp/hostB-timeline.md
```

Fill the comparison matrix (template in [reference.md](../reference.md)):

- Enforcement ON time
- Firewall ON time
- **Target policy** apply time and version
- Enforce ON → rule-live gap
- Receive → commit per version
- Firewall stack (nftables vs iptables+ipset)

Pattern doc: [examples/two-host-comparison.md](../examples/two-host-comparison.md).

---

## Part 7 — Use with Cursor Agent

### Install the skill

```bash
git clone https://github.com/chandrapati/csw-logs-check.git
cp -R csw-logs-check ~/.cursor/skills/csw-logs-check
```

### Example prompts

**Single host — full report**

```text
Use the csw-logs-check skill on /path/to/server_*_csw-logs.
Test: block inbound ICMP from 10.1.2.3 to this server (network_policy id 1).
Run parse_bundle_summary and parse_enforcer_timeline.
Write CSW-Log-Analysis with timeline, proto excerpt, nft/iptables excerpt,
test cutoff time, and what logs do NOT prove.
```

**Two-host comparison**

```text
Use csw-logs-check to compare:
  /path/to/hostA_*_csw-logs
  /path/to/hostB_*_csw-logs
Same ICMP deny test (policy id 1). Produce a timing comparison table and
conclusion on delivery vs on-host apply latency.
```

**Troubleshooting “ping still works”**

```text
Policy id 1 ICMP DROP is in proto and nft rules, but ping still works.
Using only the csw-logs bundle at /path/to/..., list:
enforce vs rule-live times, monitor vs enforce signals in logs,
and recommended UI + functional checks. Do not claim a deny without evidence.
```

The agent should read `SKILL.md`, `reference.md`, and this file; run scripts; grep artifacts; and use report templates.

---

## Part 8 — Cross-check CSW UI

Logs prove **configuration and host programming**. They rarely prove a **specific packet** was dropped.

| UI area | Confirms |
|---------|----------|
| Scope mode **Enforce** | Not monitor-only |
| Policy version | Matches `current version` in enforcer log |
| **Denied Connections** / forensics | Actual deny after functional test |
| Flow / process inventory | Traffic path reaches this agent |

---

## Part 9 — Deliverables checklist

- [ ] Bundle name, agent UUID, hostname documented
- [ ] Target `network_policy id` with proto excerpt (action, protocol, direction, src set)
- [ ] On-host rule excerpt (`comment "id: N"`)
- [ ] Timeline table with version numbers
- [ ] Deltas (enforce→firewall, enforce→live, receive→commit)
- [ ] Explicit **test cutoff** timestamp
- [ ] “What logs do not show” section
- [ ] Recommended functional + UI validation steps

---

## Common mistakes

| Mistake | Correct approach |
|---------|------------------|
| Using first `Enforcement enabled: 1` as “rule live” | Use apply time of version containing your policy id |
| Empty `iptables_v4` = broken | Normal when agent uses **nftables** only |
| Bundle exported before policy push | Re-export after push; old proto won’t have new rules |
| Claiming deny without sensor/UI proof | State “configured + applied”; recommend Denied Connections |
| Ignoring other policies in bundle | Document catch-all ALLOW/DENY order (ids 2–5, etc.) |
