# Risk Thresholds

ShieldPilot uses a 0–100 risk score to decide what to do with each command.

## Default Thresholds

| Range | Action | Behavior |
|-------|--------|----------|
| 0–39 | ALLOW | Executed automatically |
| 40–79 | WARN | User prompted to confirm |
| 80–100 | BLOCK | Rejected; incident created |

## Customizing

In `sentinel.yaml`:

```yaml
thresholds:
  block: 90    # More permissive — only block very high risk
  warn: 50     # Higher warn threshold
```

For CI/CD environments where you want zero human prompts:

```yaml
mode: protect
thresholds:
  block: 60   # Stricter threshold
  warn: 60    # Same as block = no WARN state, only ALLOW or BLOCK
```

## Score Composition

The final score is the **maximum** across all active analyzers (not an average). This ensures a single high-confidence signal is never diluted.

Analyzers and their weight contributions:

| Analyzer | Focus |
|----------|-------|
| `destructive_fs` | File deletion, overwrites, dangerous path ops |
| `privilege_escalation` | sudo, chmod, user/group manipulation |
| `network_exfil` | curl/wget with sensitive data, DNS tunneling |
| `credential_access` | SSH keys, env vars, credential files |
| `persistence` | Cron jobs, startup scripts, rc files |
| `obfuscation` | Base64 decode+exec, eval, character encoding |
| `supply_chain` | Unverified remote scripts, package substitution |
| `malware_patterns` | Known attack patterns, C2 indicators |
| `injection` | Prompt injection in command arguments |
