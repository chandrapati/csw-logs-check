# Preserve Rules (CSW Agent Config Profile)

Reference for POV and log analysis when customers ask about **Preserve Rules**, host firewall backup, coexistence with EDR/local `iptables`, and **traffic allowed briefly after reboot**.

**Cisco docs (3.10):** [Enforce Policies with Agents](https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/user-guide/3_10/cisco-secure-workload-user-guide-saas-v310/m-policy-enforcement-with-agents.html) · Agent profile attributes in the CSW user guide (*Creating an Agent Config Profile*).

---

## What Preserve Rules is (and is not)

| Common misconception | Actual meaning |
|--------------------|----------------|
| “Keeps CSW policy in memory across reboot” | **No.** CSW policies are re-fetched and re-programmed after the agent starts. |
| “Same as persisting CSW rules on disk” | **No.** The on-disk backup under `/opt/cisco/tetration/backup` is a snapshot of **pre-existing host** `iptables`/`ipset` (and IPv6), not a CSW policy cache for reboot. |
| “Only affects Windows” | **No.** Behavior is **platform-specific**; Linux RHEL and others have distinct semantics. |

**Preserve Rules** controls how the CSW enforcement agent **coexists with firewall rules that already exist on the host** when enforcement is enabled—not how long CSW remembers policy after a reboot.

From the Agent Config Profile (high level):

| Setting | Profile text (summary) |
|---------|-------------------------|
| **Enable** | Preserves **existing** firewall rules on the agent (coexistence model). |
| **Disable** (default) | **Clears** existing firewall rules before applying CSW enforcement rules from the controller. |

Platform details are in the *Preserve Rules* subsection for each OS in the user guide.

---

## Linux (iptables / ipset / nft WAF)

### Host firewall backup (first time enforcement is enabled)

When enforcement is turned on **for the first time** in the Agent Config profile on a Linux host, Cisco documents that the agent:

1. Stores current **ipset** and **ip[6]tables** content in **`/opt/cisco/tetration/backup`**
2. Then takes control of the host firewall and programs CSW **TA** chains / rules

Notes from documentation:

- **Successive** disable/enable toggles of enforcement **do not** create new backups.
- The backup directory is **not** removed on agent uninstall.
- This backup is for **rollback / reference of the old local firewall**, not automatic restore on every reboot.

### Preserve Rules ON vs OFF (operational model)

| | **Preserve Rules ON** | **Preserve Rules OFF** (default) |
|--|------------------------|----------------------------------|
| **Pre-existing local rules** | Intended to **coexist**; agent monitors firewall state | **Cleared** before CSW rules are applied |
| **Typical use** | EDR or another product also manages host firewall (e.g. isolation); Calico/K8s in some designs | CSW is primary host firewall; full TA chain control |
| **ipset `max_sets`** | Agent **checks** only; does not reload module | Agent may **reload** ipset module if `max_sets` too small |
| **Admin adds conflicting rule** | Deviation monitoring applies; CSW may **reprogram** its policy; coexistence semantics—**do not assume “CSW always wins” without testing** | CSW owns TA chains; conflicting local rules are cleared on enforce |
| **WFP mode** | N/A on Linux WAF path | — |

After programming, the agent **monitors** the firewall for deviation and **reprograms** CSW policy when needed (see user guide *Agent Enforcement on the Linux Platform*).

**EDR coexistence (field pattern):** Cisco TAC has described *Preserve Rules ON* as allowing Secure Workload to coexist with EDR that manages the host firewall (e.g. isolation workflows), with both products’ expected behaviors validated in lab—not as a reboot persistence feature.

---

## Reboot: brief window where ping (or other traffic) is allowed

### What customers often see

After **reboot**, a host under CSW enforcement may **briefly** accept traffic (e.g. **ICMP ping succeeds**) until policy is fully effective again.

### Root cause (separate from Preserve Rules semantics)

That window is usually **boot → agent ready → policy applied**, not “Preserve Rules forgot the deny”:

```text
Power on
  → OS networking up (firewall may be empty, default ACCEPT, or non-CSW rules)
  → csw-agent / tet-enforcer starts (systemd)
  → Agent connects to CSW / EFE, receives policy version
  → "Firewall is now enabled" / staged commit / nft or iptables programmed
  → CSW segmentation effective (T_live in tet-enforcer.log)
```

Any test during this interval can **false-pass** even when CSW UI shows Enforce and policy exists in the tenant.

Use **`csw-logs-check`** to measure:

- `Enforcement enabled: 1` vs **apply** of the version containing your `network_policy id`
- `Firewall is now enabled` → `Policy config has been applied successfully`

See [USAGE-WITH-LOGS.md](USAGE-WITH-LOGS.md) for timeline steps.

### Would changing Preserve Rules fix post-reboot ping?

| Expectation | Guidance |
|-------------|----------|
| **Preserve OFF → ON** to “keep denies across reboot” | **Unlikely.** ON is for **coexisting with pre-existing/EDR rules**, not persisting CSW denies through reboot. |
| **Preserve ON → OFF** to “lock down faster” | May change **which rules exist** once the agent runs (clears non-CSW rules on enforce), but does **not** remove the **pre-agent-start** gap. |
| **Actual mitigations** | Ensure `csw-agent` starts early (`systemd` ordering / `After=network-online`); minimize boot-time tests; use **network controls** (ACL, NSG, physical firewall) for crown jewels until agent reports healthy; re-test only after `T_live` in logs; consider **warm reboot** tests in POV docs. |

Document observed reboot gap **in seconds** with timestamps from `tet-enforcer.log` on the test host; compare to policy delivery gaps measured by this skill.

---

## What to check in CSW UI and on the host

| Check | Why |
|-------|-----|
| Agent Config Profile → **Preserve Rules** | ON vs OFF for this workload class |
| **Enforcement mode** (WAF vs WFP) | Preserve Rules has **no effect** in Windows **WFP** mode (per Cisco) |
| Scope **Enforce** vs Monitor | Monitor does not drop in the same way |
| `/opt/cisco/tetration/backup` | Exists if enforcement was ever enabled; contents = **old local** firewall, not current CSW export |
| `tet-enforcer.log` after reboot | Time from service start to `applied successfully` for target version |
| `policyagent-staged-nft` or staged iptables | CSW `comment "id: N"` present only after apply |
| Functional test time | Must be **after** `T_live`, not immediately at login after reboot |

---

## Log bundle signals (indirect)

`csw-logs` bundles rarely log “Preserve Rules=ON” explicitly. Infer from context:

| Signal | Interpretation |
|--------|----------------|
| Many non-TA `iptables` rules in `firewallDump/` | Possible coexistence / preserve or third-party firewall |
| Empty `iptables_v4`, active `policyagent-staged-nft` | Common **nft WAF** path |
| `Enforcement enabled: 1` long before target policy version | Delivery gap; not preserve-rules |
| First enforce after install in logs + `backup` on host | First-enable backup likely occurred on that host |

Grep enforcer log for deviation/reprogram (wording varies by version):

```bash
rg -n "deviation|reprogram|iptables|ipset|preserve|backup" "$BUNDLE/log/tet-enforcer.log" | tail -50
```

---

## POV talking points (customer-safe)

1. **Clarify the setting:** Preserve Rules is about **coexistence with existing host firewall rules**, not keeping CSW policy across reboot.
2. **Backup directory:** One-time snapshot of **pre-CSW** `iptables`/`ipset` before first enforce—not CSW policy storage.
3. **Reboot gap:** Treat as **agent startup + policy apply latency**; measure with `tet-enforcer.log`; don’t claim ICMP/policy is live until **apply timestamp** for the correct version.
4. **Changing preserve:** Unlikely to fix brief post-reboot allow; validate with TAC if EDR coexistence is required (**ON**) vs CSW-only control (**OFF**).
5. **Evidence:** Post-reboot test only after enforcer shows apply; use CSW **Denied Connections** for drops, not ping alone before `T_live`.

---

## Related skill docs

- [USAGE-WITH-LOGS.md](USAGE-WITH-LOGS.md) — policy timing and test cutoff
- [reference.md](../reference.md) — artifact extraction catalog
