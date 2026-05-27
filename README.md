# csw-logs-check

Cursor Agent Skill for analyzing **Cisco Secure Workload (CSW)** agent diagnostic log bundles (`*_csw-logs`).

Answers common POV questions from `tet-enforcer.log` and related artifacts:

- Is the policy defined on the agent?
- Is it rendered on the host (nftables / iptables)?
- When was it **applied** vs when did **enforcement mode** turn on?
- How do two hosts compare on delivery vs on-host commit latency?

## Install (Cursor)

Clone and copy the skill folder into your personal skills directory:

```bash
git clone https://github.com/chandrapati/csw-logs-check.git
mkdir -p ~/.cursor/skills
cp -R csw-logs-check ~/.cursor/skills/csw-logs-check
```

Or symlink:

```bash
ln -s "$(pwd)/csw-logs-check" ~/.cursor/skills/csw-logs-check
```

In Cursor, ask the agent to use **csw-logs-check**, for example:

> Use csw-logs-check on `/path/to/my_host_*_csw-logs` and write an enforcement validation report.

## Parser utility

No extra dependencies (Python 3.9+ stdlib only):

```bash
python3 scripts/parse_enforcer_timeline.py /path/to/agent_csw-logs
```

## Repository layout

| Path | Description |
|------|-------------|
| `SKILL.md` | Agent skill instructions |
| `reference.md` | Grep patterns and report templates |
| `examples/two-host-comparison.md` | Generic comparison pattern (synthetic) |
| `scripts/parse_enforcer_timeline.py` | Timeline extractor |

## Key concept

`Enforcement enabled: 1` does **not** mean your test rule is live. Use the timestamp when the policy version that contains your `network_policy id` is **applied successfully** on the host.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This skill assists log analysis only. It does not replace CSW product documentation, TAC, or formal security assessments. Always validate with functional tests and CSW UI (Enforce mode, Denied Connections).
