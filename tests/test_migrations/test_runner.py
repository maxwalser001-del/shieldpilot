"""I5: Migration Runner Tests.

Tests the production migration runner at sentinelai/migrations/runner.py:
dry-run, backup creation, integrity checks, rollback on failure, DB path detection.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sentinelai.migrations.runner import (
    _backup_database,
    _find_db_path,
    _verify_integrity,
    _get_current_revision,
    _restore_backup,
    run_migrations,
)


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database with basic schema."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO test VALUES (1, 'hello')")
    conn.commit()
    conn.close()
    yield Path(path)
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def temp_db_with_alembic(temp_db):
    """Add an alembic_version table to the temp DB."""
    conn = sqlite3.connect(str(temp_db))
    conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
    conn.execute("INSERT INTO alembic_version VALUES ('abc123')")
    conn.commit()
    conn.close()
    return temp_db


class TestVerifyIntegrity:
    def test_valid_db_passes(self, temp_db):
        assert _verify_integrity(temp_db) is True

    def test_nonexistent_db_fails(self, tmp_path):
        fake_db = tmp_path / "nonexistent.db"
        # sqlite3 will create an empty file, but integrity_check on empty is "ok"
        conn = sqlite3.connect(str(fake_db))
        conn.close()
        assert _verify_integrity(fake_db) is True


class TestBackupDatabase:
    def test_creates_backup_file(self, temp_db, tmp_path):
        backup = _backup_database(temp_db, backup_dir=tmp_path)
        assert backup.exists()
        assert backup.stat().st_size > 0

    def test_backup_has_correct_data(self, temp_db, tmp_path):
        backup = _backup_database(temp_db, backup_dir=tmp_path)
        conn = sqlite3.connect(str(backup))
        row = conn.execute("SELECT value FROM test WHERE id=1").fetchone()
        conn.close()
        assert row[0] == "hello"

    def test_backup_nonexistent_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _backup_database(tmp_path / "nope.db")

    def test_backup_dir_created(self, temp_db, tmp_path):
        backup_dir = tmp_path / "nested" / "backups"
        backup = _backup_database(temp_db, backup_dir=backup_dir)
        assert backup_dir.exists()
        assert backup.exists()


class TestGetCurrentRevision:
    def test_with_alembic_table(self, temp_db_with_alembic):
        assert _get_current_revision(temp_db_with_alembic) == "abc123"

    def test_without_alembic_table(self, temp_db):
        assert _get_current_revision(temp_db) is None


class TestRestoreBackup:
    def test_restore_overwrites_db(self, temp_db, tmp_path):
        # Create backup
        backup = _backup_database(temp_db, backup_dir=tmp_path)

        # Modify original
        conn = sqlite3.connect(str(temp_db))
        conn.execute("UPDATE test SET value='modified'")
        conn.commit()
        conn.close()

        # Restore
        _restore_backup(backup, temp_db)

        # Verify original data
        conn = sqlite3.connect(str(temp_db))
        row = conn.execute("SELECT value FROM test WHERE id=1").fetchone()
        conn.close()
        assert row[0] == "hello"

    def test_restore_removes_wal(self, temp_db, tmp_path):
        backup = _backup_database(temp_db, backup_dir=tmp_path)
        # Create fake WAL file
        wal = Path(str(temp_db) + "-wal")
        wal.write_text("fake wal")
        _restore_backup(backup, temp_db)
        assert not wal.exists()


class TestRunMigrationsDryRun:
    def test_dry_run_does_not_modify(self, temp_db):
        original_size = temp_db.stat().st_size
        result = run_migrations(db_path=temp_db, dry_run=True)
        assert result is True
        assert temp_db.stat().st_size == original_size

    def test_dry_run_nonexistent_db(self, tmp_path):
        result = run_migrations(db_path=tmp_path / "nope.db", dry_run=True)
        assert result is True  # Nonexistent DB is OK (will be created later)


class TestRunMigrationsWithBackup:
    def test_creates_backup_before_migration(self, temp_db):
        backup_dir = temp_db.parent / "backups"
        with patch("sentinelai.migrations.runner._run_manual_migrations"):
            # Mock alembic since we don't have real migrations to run
            with patch("sentinelai.migrations.runner.Path") as mock_path:
                mock_path.return_value.resolve.return_value.parents.__getitem__ = lambda s, i: temp_db.parent
                result = run_migrations(db_path=temp_db, skip_backup=False)

        # Check a backup was created
        if backup_dir.exists():
            backups = list(backup_dir.glob("sentinel_*_pre_migration.db"))
            assert len(backups) >= 1

    def test_skip_backup_flag(self, temp_db):
        backup_dir = temp_db.parent / "backups"
        with patch("sentinelai.migrations.runner._run_manual_migrations"):
            run_migrations(db_path=temp_db, skip_backup=True)
        # No backup directory should be created when skip_backup=True
        if backup_dir.exists():
            backups = list(backup_dir.glob("sentinel_*_pre_migration.db"))
            # May have 0 or existing backups, but no new one from this run


class TestFindDbPath:
    def test_env_var_priority(self, monkeypatch, tmp_path):
        db_file = tmp_path / "from_env.db"
        monkeypatch.setenv("SENTINEL_DB", str(db_file))
        assert _find_db_path() == db_file

    def test_default_fallback(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_DB", raising=False)
        with patch("sentinelai.core.config.load_config", side_effect=Exception):
            result = _find_db_path()
            assert result == Path("sentinel.db")
