# sentinel hook

Manage the Claude Code pre-tool-use hook integration.

## Subcommands

### install

```bash
sentinel hook install
```

Registers ShieldPilot in `~/.claude/settings.json` as a `PreToolUse` hook for Bash commands.

### uninstall

```bash
sentinel hook uninstall
```

Removes the ShieldPilot hook entry from Claude Code settings.

### status

```bash
sentinel hook status
```

Shows whether the hook is installed, which config file it points to, and when it was last triggered.

### test

```bash
sentinel hook test "COMMAND"
```

Simulates what the hook would decide for a given command without executing it.

```bash
sentinel hook test "pip install requests"
# ✓  ALLOW (score: 5)

sentinel hook test "rm -rf ~/.ssh"
# 🛑  BLOCK (score: 91)
#    credential_access: SSH key directory deletion
#    destructive_fs: Recursive deletion of sensitive path
```
