# ShieldPilot for Claude Code

Real-time security monitoring for Claude Code autonomous mode. ShieldPilot intercepts every tool call and runs it through a multi-layered defense system before execution.

## What It Does

When Claude Code runs in autonomous mode, it executes commands without asking. ShieldPilot sits between Claude Code and the system, analyzing every tool call in real-time:

- **Risk Engine** (9 analyzers): Detects destructive commands, credential access, network exfiltration, supply chain attacks, and more
- **Prompt Injection Scanner**: 178+ patterns across 19 categories catch injection attempts hiding in code, comments, or filenames
- **ML Classifier**: Secondary neural classifier for low-confidence commands
- **Protected Paths**: Blocks writes to sensitive directories (`~/.ssh`, `~/.aws`, `/etc`)
- **Rate Limiting**: Detects and blocks best-of-N injection brute-force patterns

## Decision Flow

```
Tool Call → ShieldPilot Hook
                ├── Risk Score < 40  → ALLOW (silent, no interruption)
                ├── Risk Score 40-79 → ASK  (user sees a confirmation prompt)
                └── Risk Score ≥ 80  → DENY (blocked, incident logged)
```

## Installation

```bash
# From the project root:
bash plugin/claude-code/install.sh

# Or install from PyPI:
bash plugin/claude-code/install.sh --pypi
```

The installer will:
1. Install the `sentinelai` Python package
2. Configure the PreToolUse hook in `.claude/settings.json`
3. Create a default `sentinel.yaml` if none exists
4. Verify the hook works

## Configuration

Edit `sentinel.yaml` in your project root:

```yaml
mode: enforce    # enforce | audit | disabled

risk_thresholds:
  block: 80      # Risk score to auto-block
  warn: 40       # Risk score to prompt user
  allow: 0       # Below this: auto-allow

auth:
  local_first: true   # Skip auth for localhost

billing:
  enabled: false       # Enable usage limits
```

### Modes

| Mode | Behavior |
|------|----------|
| `enforce` | Blocks dangerous commands, prompts on warnings |
| `audit` | Logs everything but never blocks (good for evaluation) |
| `disabled` | Hook exits immediately, no analysis |

## Dashboard

ShieldPilot includes a web dashboard for reviewing audit logs, incidents, and scan results:

```bash
python3 -m uvicorn sentinelai.api.app:app --port 8420
# Open http://localhost:8420
```

## Uninstallation

```bash
# Remove hook only (keeps package and data):
bash plugin/claude-code/uninstall.sh

# Full removal (also uninstalls Python package):
bash plugin/claude-code/uninstall.sh --full
```

Your `sentinel.yaml` and `sentinel.db` (audit logs) are always preserved.

## Requirements

- Python 3.9+
- macOS or Linux
- Claude Code 1.0+

## License

MIT
