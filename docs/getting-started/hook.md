# Claude Code Hook

ShieldPilot integrates with Claude Code as a `pre-tool-use` hook — the same extension point used by other Claude Code security tools.

## Install

```bash
sentinel hook install
```

Adds to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "python3 -m sentinelai.hooks.sentinel_hook"
      }]
    }]
  }
}
```

## How it works

1. Claude Code prepares a Bash command
2. ShieldPilot hook receives the command JSON
3. Risk engine + injection scanner evaluate it (< 50ms typical)
4. Exit code 0 → Claude executes the command
5. Exit code 2 → Claude Code blocks it and shows the reason

## Uninstall

```bash
sentinel hook uninstall
```

## Status

```bash
sentinel hook status
```

## Test

```bash
sentinel hook test "rm -rf /"
# → BLOCK (score: 98) — destructive_fs: Recursive deletion of root
```

## Modes

Set `mode` in `sentinel.yaml`:

| Mode | Behavior |
|------|----------|
| `protect` | Block commands scoring ≥ 80 (default) |
| `monitor` | Log everything, block nothing |
| `audit` | Log and execute all; warn only |
| `disabled` | Passthrough — ShieldPilot inactive |
