# ShieldPilot Security Guard for OpenClaw

Real-time security monitoring for AI coding agents. ShieldPilot analyzes every tool call for prompt injection attacks, credential exfiltration, supply chain compromises, and destructive operations.

## Features

- **9 Risk Analyzers**: Filesystem, network, credential access, supply chain, privilege escalation, prompt injection, and more
- **178+ Injection Patterns**: Detects prompt injection, policy overrides, state spoofing, narrative erosion, and presupposition attacks
- **Real-time Analysis**: Every tool call is analyzed in <100ms
- **Fail-Open Design**: If the hook encounters an error, commands are allowed (never blocks your workflow)
- **Two Hook Types**: Pure bash (no Node.js needed) or Node.js wrapper
- **Configurable Modes**: enforce, audit, or disabled

## Quick Start

```bash
# Install with bash hook (recommended, no Node.js needed)
cd plugin/openclaw
./install.sh

# Or install with Node.js hook
./install.sh --hook-type node
```

Add to your OpenClaw configuration:

```yaml
# Using bash hook (recommended)
plugins:
  - path: ./plugin/openclaw
    hooks:
      preToolExecution: ./hook.sh

# Using Node.js hook (alternative)
plugins:
  - path: ./plugin/openclaw
    hooks:
      preToolExecution: ./index.js
```

## How It Works

```
OpenClaw Tool Call
    |
    v
preToolExecution Event (JSON on stdin)
    |
    v
hook.sh / index.js
    |
    v
ShieldPilot Python Risk Engine (sentinelai.hooks.sentinel_hook)
    |
    v
Decision: allow / deny / review (JSON on stdout)
```

1. OpenClaw triggers a `preToolExecution` event before every tool call
2. The hook script (bash or Node.js) pipes the event to ShieldPilot's Python risk engine
3. ShieldPilot runs 9 analyzers + prompt injection scanner + ML model
4. Returns a decision: `allow`, `deny`, or `review` (ask the user)

## Event Mapping

| OpenClaw Tool | ShieldPilot Name | Risk Level |
|:---|:---|:---|
| `shell` / `bash` | `Bash` | High |
| `writeFile` / `write_file` | `Write` | Medium |
| `editFile` / `edit_file` | `Edit` | Medium |
| `readFile` / `read_file` | `Read` | Low |
| `search` | `Grep` | Low |
| `glob` | `Glob` | Low |
| `webSearch` | `WebSearch` | Low |
| `webFetch` | `WebFetch` | Medium |

## Configuration

### Environment Variables

| Variable | Default | Description |
|:---|:---|:---|
| `SHIELDPILOT_PYTHON` | `python3` | Path to Python interpreter |
| `SHIELDPILOT_CONFIG` | `sentinel.yaml` | Path to config file |
| `SHIELDPILOT_TIMEOUT` | `10` | Hook timeout in seconds (bash) or ms (node) |
| `SHIELDPILOT_MODE` | `enforce` | Security mode (see below) |
| `SHIELDPILOT_HOOK_TYPE` | `bash` | Hook implementation for install.sh |

### Security Modes

| Mode | Behavior |
|:---|:---|
| `enforce` | **Default.** Blocks dangerous commands, prompts on medium-risk. |
| `audit` | Logs all decisions but never blocks. Good for initial rollout. |
| `disabled` | Hook returns `allow` immediately. No Python process spawned. |

To change mode at runtime:

```bash
# Temporarily switch to audit mode
export SHIELDPILOT_MODE=audit

# Or set in sentinel.yaml
# risk_engine:
#   mode: audit
```

### sentinel.yaml

The main config file controls analyzer weights, thresholds, and mode:

```yaml
risk_engine:
  mode: enforce          # enforce / audit / disabled
  block_threshold: 80    # risk score >= 80 = block
  warn_threshold: 50     # risk score >= 50 = review (ask)
```

## Installation

### Prerequisites

- Python 3.8+
- ShieldPilot Python package (`pip install shieldpilot`)
- Node.js 18+ (only if using `--hook-type node`)

### Automated Install

```bash
./install.sh                         # Default: bash hook
./install.sh --hook-type node        # Use Node.js hook
./install.sh --python /usr/bin/python3.11  # Custom Python path
./install.sh --config ~/sentinel.yaml     # Custom config path
```

### Manual Install

```bash
# 1. Install Python package
pip install shieldpilot

# 2. Make hook executable
chmod +x plugin/openclaw/hook.sh

# 3. Add to OpenClaw config
# See "Quick Start" above
```

## Uninstall

```bash
# Remove hook registration (keeps database and config)
./uninstall.sh

# Full removal (removes config too, keeps database)
./uninstall.sh --full
```

The database (`sentinel.db`) is always preserved during uninstall to retain your audit trail. Delete it manually if needed:

```bash
rm -f sentinel.db
```

## Troubleshooting

**Hook returns empty response:**
- Check Python path: `which python3`
- Verify package: `python3 -c "import sentinelai; print('OK')"`
- Check config: `ls sentinel.yaml`

**Commands blocked unexpectedly:**
- Switch to audit mode: `export SHIELDPILOT_MODE=audit`
- Check the decision: pipe a test event manually through `hook.sh`

**Timeout errors:**
- Increase timeout: `export SHIELDPILOT_TIMEOUT=30`

## Requirements

- Python 3.8+
- ShieldPilot Python package (`pip install shieldpilot`)
- Node.js 18+ (optional, only for `index.js` hook type)

## License

MIT
