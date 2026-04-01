"""Verification script for the Alembic migration setup.

Tests three scenarios:
1. Fresh database: init_database() should run Alembic migrations from scratch
2. Existing database without alembic_version: should stamp at head (not re-create)
3. Existing database with alembic_version at head: should be a no-op
"""

import os
import sqlite3
import tempfile

from sqlalchemy import inspect as sa_inspect


def test_fresh_db():
    """Fresh DB: init_database runs both Alembic migrations."""
    from sentinelai.logger.database import init_database

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_path = f.name

    try:
        engine, Session = init_database(tmp_path)
        inspector = sa_inspect(engine)
        tables = sorted(inspector.get_table_names())

        assert "alembic_version" in tables, "alembic_version missing"
        assert "custom_rules" in tables, "custom_rules missing"
        assert "team_invites" in tables, "team_invites missing"
        assert "commands" in tables, "commands missing"

        conn = sqlite3.connect(tmp_path)
        try:
            rev = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            assert rev and rev[0] == "a1b2c3d4e5f6", f"Bad revision: {rev}"
        finally:
            conn.close()

        cr_idx = {i["name"] for i in inspector.get_indexes("custom_rules")}
        assert "ix_custom_rules_tenant" in cr_idx
        assert "ix_custom_rules_enabled" in cr_idx

        ti_idx = {i["name"] for i in inspector.get_indexes("team_invites")}
        assert "ix_team_invites_email" in ti_idx
        assert "ix_team_invites_tenant" in ti_idx

        rl_idx = {i["name"] for i in inspector.get_indexes("rate_limit_attempts")}
        assert "ix_ratelimit_name_key_at" in rl_idx

        print("PASS: test_fresh_db")
    finally:
        _cleanup(tmp_path)


def test_existing_db_no_alembic():
    """Existing DB without alembic_version: should stamp, not re-create."""
    from sentinelai.logger.database import Base, _fallback_create_all, init_database
    from sqlalchemy import create_engine, text

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_path = f.name

    try:
        _fallback_create_all(tmp_path)

        conn = sqlite3.connect(tmp_path)
        try:
            tables_before = sorted(
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            )
            assert "alembic_version" not in tables_before
            assert "commands" in tables_before
        finally:
            conn.close()

        engine, Session = init_database(tmp_path)

        conn = sqlite3.connect(tmp_path)
        try:
            rev = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            assert rev and rev[0] == "a1b2c3d4e5f6", f"Should be stamped at head: {rev}"
        finally:
            conn.close()

        print("PASS: test_existing_db_no_alembic")
    finally:
        _cleanup(tmp_path)


def test_idempotent():
    """Running init_database twice should not fail."""
    from sentinelai.logger.database import init_database

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_path = f.name

    try:
        init_database(tmp_path)
        engine, Session = init_database(tmp_path)

        conn = sqlite3.connect(tmp_path)
        try:
            rev = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            assert rev and rev[0] == "a1b2c3d4e5f6"
        finally:
            conn.close()

        print("PASS: test_idempotent")
    finally:
        _cleanup(tmp_path)


def _cleanup(path):
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = path + suffix
        if os.path.exists(p):
            os.unlink(p)


if __name__ == "__main__":
    test_fresh_db()
    test_existing_db_no_alembic()
    test_idempotent()
    print("\nALL CHECKS PASSED")
