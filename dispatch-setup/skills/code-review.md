# Skill: Code Review

When I ask about code or ShieldPilot:
1. ShieldPilot codebase is in ~/Desktop/Cyber Security Claude/sentinelai/
2. Python 3.9+, FastAPI, SQLAlchemy, SQLite
3. Don't rewrite entire files — show only the diff
4. Always mention which file and line number
5. Run `python3 -m pytest tests/ -x -q --tb=short` before confirming any change works
6. Security first — flag any OWASP Top 10 issues
