# Contributing to ShieldPilot

## Before you start

- Check [open issues](https://github.com/maxwalser001-del/Cyber-Security-/issues) to avoid duplicate work.
- For significant changes, open an issue first to discuss scope and approach.
- Security vulnerabilities go to [SECURITY.md](SECURITY.md), not public issues.

---

## Development setup

**Requirements:** Python 3.9+, Git

```bash
git clone https://github.com/maxwalser001-del/Cyber-Security-.git
cd Cyber-Security-
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
sentinel init
```

**Run tests:**
```bash
python3 -m pytest tests/ -x -q --tb=short
```

**Start dev server:**
```bash
python3 -m uvicorn sentinelai.api.app:app --host 0.0.0.0 --port 8420 --reload
```

**Import check (catches syntax errors across all modules):**
```bash
python3 -c "from sentinelai.api.app import create_app; print('OK')"
```

---

## Project structure

```
sentinelai/         # Main Python package
  adapters/         # Platform adapters (Claude Code, OpenClaw, generic)
  api/              # FastAPI routers and services
  engine/           # Risk scoring engine + analyzers
  scanner/          # Prompt injection scanner
  hooks/            # Claude Code pre-tool-use hook
  logger/           # Tamper-evident audit logging
tests/              # pytest test suite (2200+ tests)
features/           # Design docs and specs
```

---

## Code style

- **Python:** follow existing patterns. No black/isort enforcement currently, but keep diffs clean.
- **No type annotation churn** — don't add annotations to code you didn't change.
- **No docstring inflation** — only add docstrings where the logic isn't self-evident.
- **No speculative abstractions** — solve the actual problem, not hypothetical future ones.
- **Frontend (JS/CSS):** vanilla JS, no build step. Escape all user-controlled content via `escapeHtml()`.
- **SQL:** use SQLAlchemy ORM. No raw string interpolation in queries.

---

## PR process

1. Fork and create a branch: `git checkout -b feat/your-feature` or `fix/your-fix`
2. Make your change. Keep scope focused — one issue per PR.
3. Add or update tests. A task is not done until tests pass.
4. Run the full test suite: `python3 -m pytest tests/ -x -q --tb=short`
5. Open a PR against `main`. Fill out the PR template.
6. A maintainer will review within a few business days.

**PR checklist:**
- [ ] Tests pass locally
- [ ] New behavior is covered by tests (or documented why it isn't)
- [ ] No secrets, credentials, or PII in the diff
- [ ] `sentinel.example.yaml` updated if config schema changed
- [ ] `CHANGELOG.md` entry added for user-visible changes

---

## Adding injection patterns

The scanner lives at `sentinelai/scanner/patterns.py`. Each category is a named list of compiled regex patterns.

```python
# Example: add a pattern to an existing category
_YOUR_CATEGORY = [
    re.compile(r"your pattern here", re.IGNORECASE),
]
```

Before submitting:
1. Add the pattern to the appropriate category list.
2. Add at least 3 true-positive test cases to `tests/test_scanner.py`.
3. Verify no false positives on the existing clean test set.
4. Run `python3 -m pytest tests/test_scanner.py -v`.

---

## Adding risk analyzers

Analyzers live at `sentinelai/engine/`. Each analyzer is a class that inherits from `BaseAnalyzer` and implements `analyze(command: str) -> AnalyzerResult`.

See `sentinelai/engine/destructive_fs.py` for a reference implementation.

---

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add MCP tool definition scanner
fix: prevent false positive on quoted shell strings
docs: update configuration reference
test: add coverage for supply chain analyzer
```

---

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
