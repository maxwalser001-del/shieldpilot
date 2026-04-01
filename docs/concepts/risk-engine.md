# Risk Engine

ShieldPilot's risk engine evaluates every command through 9 specialized analyzers.

## Architecture

```
Command Input
     │
     ▼
┌─────────────────────────────────────┐
│          AnalysisContext             │
│  (working dir, env vars, config)    │
└─────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│  RiskEngine.assess(command, ctx)    │
│                                     │
│  ┌──────────────┐ ┌──────────────┐  │
│  │destructive_fs│ │  priv_esc    │  │
│  ├──────────────┤ ├──────────────┤  │
│  │network_exfil │ │ cred_access  │  │
│  ├──────────────┤ ├──────────────┤  │
│  │ persistence  │ │ obfuscation  │  │
│  ├──────────────┤ ├──────────────┤  │
│  │supply_chain  │ │   malware    │  │
│  ├──────────────┤ └──────────────┘  │
│  │  injection   │                   │
│  └──────────────┘                   │
│         │                           │
│  final_score = max(analyzer_scores) │
└─────────────────────────────────────┘
     │
     ▼
RiskAssessment(action, score, signals)
```

## Scoring

- Each analyzer returns a score (0–100) and a list of signals
- Final score = **maximum** across all analyzers
- Action determined by threshold comparison

## Analyzers

### destructive_fs
Detects dangerous filesystem operations: `rm -rf`, truncation of critical files, mass deletion patterns.

### privilege_escalation
Flags `sudo`, `su`, `chmod 777`, `/etc/sudoers` modification, user creation.

### network_exfil
Identifies data exfiltration via curl/wget, DNS tunneling, pipe-to-remote-exec patterns.

### credential_access
Detects access to SSH keys, `.env` files, credential stores, browser password DBs.

### persistence
Catches cron modifications, `.bashrc`/`.zshrc` appends, LaunchAgent installs, systemd unit creation.

### obfuscation
Recognizes `base64 | bash`, `eval $(...)`, character encoding tricks, heredoc evasion.

### supply_chain
Flags `curl URL | bash`, unverified pip installs from git URLs, package name typosquatting indicators.

### malware_patterns
Matches known attack tool patterns: reverse shells, bind shells, C2 beacon patterns.

### injection
Detects prompt injection attempts embedded in command arguments that could manipulate AI agent behavior.

## LLM Second Pass (optional)

When `llm.enabled: true`, commands scoring 30–79 get a second evaluation by Claude. The LLM can raise or lower the score and provides natural-language reasoning.
