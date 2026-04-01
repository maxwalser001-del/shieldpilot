# CLI Reference

All ShieldPilot functionality is accessible via the `sentinel` CLI.

## Commands

| Command | Description |
|---------|-------------|
| `sentinel run CMD` | Evaluate + execute a shell command |
| `sentinel scan FILE` | Scan file for prompt injection |
| `sentinel hook install` | Install Claude Code hook |
| `sentinel hook uninstall` | Remove Claude Code hook |
| `sentinel hook status` | Show hook status |
| `sentinel hook test CMD` | Test what the hook would decide |
| `sentinel logs` | Browse activity logs |
| `sentinel status` | System overview and health |
| `sentinel perf` | Performance statistics |
| `sentinel config --validate` | View / validate configuration |
| `sentinel verify` | Verify log chain integrity |
| `sentinel init` | Set up ShieldPilot for a project |
| `sentinel dashboard` | Launch the web dashboard |

## Global Options

```
--config PATH   Path to sentinel.yaml (default: ./sentinel.yaml)
--version       Show version and exit
--help          Show help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Command allowed and executed successfully |
| `1` | Command blocked or execution failed |
| `2` | Configuration or input error |
