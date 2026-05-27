# Example — two-host enforcement timing comparison (generic)

Synthetic pattern observed across POV engagements. **Do not use these timestamps in production reports** — parse real `tet-enforcer.log` files.

## Executive summary (pattern)

| Question | Host A | Host B |
|----------|--------|--------|
| Enforcement mode ON | T0 | T0 + offset |
| Host firewall active | T0 + ~1–5 s | T0 + ~1–5 s |
| Target policy applied | T0 + **long gap** | T0 + **shorter gap** |
| Receive → commit on host | ~20–50 ms | ~20–50 ms |
| Firewall stack | nftables | iptables + ipset |

**Bottom line:** Both hosts enable enforcement and apply an older policy version within seconds. The **test policy** (e.g. ICMP deny `network_policy id 1`) goes live when CSW pushes the **newer version**. The gap between enforce-on and rule-live is **cloud delivery**, not nftables vs iptables programming time.

## ASCII timeline (pattern)

```text
HOST A                              HOST B

T0     Enforcement ON               T0'    Enforcement ON
T0+1s  Firewall + old version       T0'+5s Firewall + old version
       (test rule NOT present)             (test rule NOT present)

T0+Nm  New version — rule LIVE      T0'+Mm New version — rule LIVE
```

## Testing implications

1. Functional tests (ping, curl, app traffic) only after the **second** apply timestamp for the version containing the rule under test.  
2. Cite **policy version ID** and **apply time** from `tet-enforcer.log` as evidence.  
3. Logs alone rarely prove a specific packet was dropped — use CSW Denied Connections or a post-test export.
