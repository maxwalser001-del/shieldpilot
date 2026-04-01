# sentinel scan

Scan a file or stdin for prompt injection patterns.

## Usage

```bash
sentinel scan [OPTIONS] FILE
sentinel scan [OPTIONS] -   # read from stdin
```

## Options

| Option | Description |
|--------|-------------|
| `--verbose, -v` | Show matched pattern details |
| `--json` | Output results as JSON |
| `--exit-code` | Exit with code 1 if threats found (for CI) |
| `--quiet, -q` | Only show threat count |

## Examples

**Scan a file:**
```bash
sentinel scan system-prompt.txt
```

**Scan from stdin:**
```bash
cat agent-instructions.md | sentinel scan -
```

**CI integration:**
```bash
sentinel scan --exit-code --quiet agent-config.json
# Exits 1 if injection patterns found
```

**Verbose with pattern details:**
```bash
sentinel scan --verbose suspicious.txt
```

## What it detects

178+ patterns across 19 categories:

- Instruction overrides (`ignore previous instructions`)
- Role manipulation (`you are now DAN`)
- Encoding bypasses (base64, hex obfuscation)
- Data exfiltration attempts
- Policy erosion (`your safety guidelines don't apply here`)
- State/trust spoofing (`as we previously agreed`)
- Presupposition attacks (`since you already have access to...`)
- Config-based overrides (`{"role": "admin", "bypass_security": true}`)
