# Contributing

## Getting Started

Clone the repository and set up a development environment:

```bash
git clone https://github.com/maxwalser001-del/Cyber-Security-
cd Cyber-Security-
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Copy the example config:

```bash
cp sentinel.example.yaml sentinel.yaml
```

Run the test suite:

```bash
python3 -m pytest tests/ -x -q --tb=short
```

All 2261 tests must pass before submitting a PR.

---

## Project Structure

```
sentinelai/
├── api/            # FastAPI routers (18 domain files)
├── engine/         # Risk Engine + 9 analyzers
├── scanner/        # Prompt injection scanner (178+ patterns)
├── hooks/          # Pre-tool-use hook (sentinel_hook.py)
├── adapters/       # Platform adapters (Claude Code, OpenClaw, Generic)
├── services/       # Business logic (auth, billing, rules, reports)
├── logger/         # SQLite database models and migrations
├── migrations/     # Alembic migration runner
├── core/           # Config models (Pydantic)
├── cli/            # CLI entry point (main.py)
└── web/            # Vanilla JS SPA (static/, templates/)
```

---

## Development Guidelines

- **Python 3.9+** — use `python3`, not `python`
- **No `requests`** — use `httpx` for HTTP clients
- **`escapeHtml()`** — all user-controlled content in the frontend must be escaped
- **No hardcoded secrets** — use environment variables only
- **SQLite constraints** — no `SELECT ... FOR UPDATE`, no row-level locking

### Adding a New Risk Analyzer

1. Create `sentinelai/engine/analyzers/your_analyzer.py`
2. Inherit from `BaseAnalyzer` and implement `analyze(command: str) -> AnalyzerResult`
3. Register in `sentinelai/engine/engine.py`
4. Add tests in `tests/test_engine/`

### Adding Injection Patterns

See the [Prompt Injection](prompt-injection.md) section for pattern categories. Add new patterns to the appropriate category list in `sentinelai/scanner/patterns.py`, then run the training suite:

```bash
python3 -m pytest tests/test_scanner/ -v
```

---

## Running the Dev Server

```bash
python3 -m uvicorn sentinelai.api.app:app --host 0.0.0.0 --port 8420 --reload
```

Dashboard: http://localhost:8420
API docs: http://localhost:8420/api/docs

---

## Submitting a Pull Request

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make changes with tests
4. Run `python3 -m pytest tests/ -x -q --tb=short` — all tests must pass
5. Run the import check: `python3 -c "from sentinelai.api.app import create_app; print('OK')"`
6. Open a PR against `main`

---

## Security Vulnerabilities

Do not open a public issue for security vulnerabilities. Email the maintainers directly or use GitHub's private vulnerability reporting.
