# csw-logs-check

Cursor Agent Skill for analyzing **Cisco Secure Workload (CSW)** agent diagnostic log bundles (`*_csw-logs`).

Answers common POV questions from agent exports:

- Is the policy defined on the agent?
- Is it rendered on the host (nftables / iptables)?
- When was it **applied** vs when did **enforcement mode** turn on?
- What else is in the bundle (all policies, nflog, proxy, errors)?
- How do two hosts compare on delivery vs on-host commit latency?

## Install (Cursor)

```bash
git clone https://github.com/chandrapati/csw-logs-check.git
mkdir -p ~/.cursor/skills
cp -R csw-logs-check ~/.cursor/skills/csw-logs-check
```

Or symlink: `ln -s "$(pwd)/csw-logs-check" ~/.cursor/skills/csw-logs-check`

Example prompt:

> Use csw-logs-check on `/path/to/my_host_*_csw-logs` and write an enforcement validation report.

## Documentation

| Doc | Contents |
|-----|----------|
| [**docs/USAGE-WITH-LOGS.md**](docs/USAGE-WITH-LOGS.md) | Step-by-step: obtain bundle → scripts → manual grep → timeline → Cursor prompts |
| [**reference.md**](reference.md) | Full extraction catalog, grep patterns, report templates |
| [**SKILL.md**](SKILL.md) | Agent skill instructions (loaded by Cursor) |

## Scripts (Python 3.9+, stdlib only)

```bash
# Summary: identity, firewall stack, policy table, enforcer/sensor highlights
python3 scripts/parse_bundle_summary.py /path/to/agent_csw-logs

# Timeline: enforce on, firewall, receive/apply per version, deltas
python3 scripts/parse_enforcer_timeline.py /path/to/agent_csw-logs
```

## Repository layout

| Path | Description |
|------|-------------|
| `SKILL.md` | Cursor agent skill |
| `docs/USAGE-WITH-LOGS.md` | Detailed usage with real log workflows |
| `reference.md` | What to extract from each log/artifact |
| `examples/two-host-comparison.md` | Generic comparison pattern |
| `scripts/parse_bundle_summary.py` | Bundle inventory + policy highlights |
| `scripts/parse_enforcer_timeline.py` | Enforcer event timeline |

## Key concept

`Enforcement enabled: 1` does **not** mean your test rule is live. Use the timestamp when the policy version that contains your `network_policy id` is **applied successfully** on the host.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This skill assists log analysis only. It does not replace CSW product documentation, TAC, or formal security assessments. Always validate with functional tests and CSW UI (Enforce mode, Denied Connections).
