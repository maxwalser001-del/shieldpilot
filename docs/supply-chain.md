# Supply Chain Audit

## What It Does

The supply chain audit checks every package your AI agent installs or imports against:

1. **Typosquatting detection** — package names that closely resemble popular packages (`requets`, `numpy2`, `pip-tools-dev`)
2. **Known malicious packages** — cross-referenced against public threat intelligence feeds
3. **Suspicious install behaviors** — packages that run arbitrary code at install time (`setup.py` with `os.system`, `pty`, network calls)
4. **Dependency confusion attacks** — internal package names that match public PyPI packages
5. **Hash verification** — expected vs. actual SHA-256 of downloaded wheels

The `supply_chain` analyzer in the Risk Engine runs on every `pip install`, `npm install`, or package-management command the AI agent attempts, scoring it before execution. The `sentinel supply-chain-audit` command performs a deeper offline audit of your entire dependency tree.

---

## Usage

Audit the current project's dependencies:

```bash
sentinel supply-chain-audit
```

Audit a specific requirements file:

```bash
sentinel supply-chain-audit --requirements requirements.txt
```

Audit with a JSON report:

```bash
sentinel supply-chain-audit --format json --output audit-report.json
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--requirements FILE` | auto-detect | Path to requirements file |
| `--format` | table | Output: `table`, `json`, `sarif` |
| `--output FILE` | stdout | Write to file |
| `--fail-on LEVEL` | high | Exit non-zero at: `low`, `medium`, `high`, `critical` |
| `--no-network` | false | Skip live threat feed queries |

---

## What Gets Checked

| Check | Description |
|-------|-------------|
| Typosquatting | Levenshtein distance < 2 from top-1000 packages |
| Malicious package DB | Known bad packages from OSV, PyPI Advisory DB |
| Install-time code execution | Presence of `os.system`, `subprocess`, `pty` in `setup.py` |
| Dependency confusion | Package exists on both internal index and public PyPI |
| Metadata anomalies | No author, no homepage, registered < 7 days ago |
| Hash integrity | SHA-256 of downloaded wheel vs. PyPI-reported hash |

---

## Example Output

```
Supply Chain Audit — 47 packages scanned
══════════════════════════════════════════════════

CRITICAL  colourama==0.4.4
  Reason: Known malicious package (typosquats 'colorama')
  CVE: N/A  |  First seen: 2022-08-14

HIGH      setup-tools==65.0.0
  Reason: Typosquats 'setuptools' (edit distance: 1)
  Recommendation: Use setuptools==68.2.2

MEDIUM    requests-async==0.6.2
  Reason: No maintainer activity in 890 days, 0 recent downloads
  Recommendation: Use httpx instead

──────────────────────────────────────────────────
47 packages  |  1 CRITICAL  |  1 HIGH  |  1 MEDIUM  |  44 CLEAN

Exit code: 1 (--fail-on high)
```

---

## CI/CD Integration

=== "GitHub Actions"

    ```yaml
    - name: Supply chain audit
      run: |
        pip install shieldpilot
        sentinel supply-chain-audit \
          --requirements requirements.txt \
          --fail-on high \
          --format sarif \
          --output supply-chain.sarif

    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: supply-chain.sarif
    ```

=== "Pre-commit hook"

    ```yaml
    # .pre-commit-config.yaml
    repos:
      - repo: local
        hooks:
          - id: supply-chain-audit
            name: ShieldPilot Supply Chain Audit
            entry: sentinel supply-chain-audit --fail-on high
            language: system
            files: requirements.*\.txt$
            pass_filenames: false
    ```

---

## Real-Time Protection

In addition to offline audits, the `supply_chain` analyzer in the Risk Engine intercepts live install commands from your AI agent:

```
Agent attempts: pip install colourama

ShieldPilot Risk Engine:
  supply_chain  +85  known malicious package: colourama
  DECISION: BLOCK
```

This catches attacks that happen during an agentic session — for example, an agent that has been prompt-injected into installing a malicious package.
