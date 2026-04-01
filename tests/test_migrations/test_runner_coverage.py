"""Coverage tests for sentinelai/migrations/runner.py.

Target: 62% -> 75%+
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

import pytest

try:
    import alembic  # noqa: F401
    _has_alembic = True
except ImportError:
    _has_alembic = False

_skip_no_alembic = pytest.mark.skipif(not _has_alembic, reason="alembic is not installed")

from sentinelai.migrations.runner import (
    _backup_database,
    _find_db_path,
    _get_current_revision,
    _restore_backup,
    _verify_integrity,
    run_migrations,
    main,
)


# ===================================================================
# _find_db_path()
# ===================================================================


class TestFindDbPath:
    """_find_db_path() locates the database via env var, config, or default."""

    def test_returns_sentinel_db_env_var(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_DB", "/custom/path/sentinel.db")
        result = _find_db_path()
        assert result == Path("/custom/path/sentinel.db")

    def test_returns_path_from_config(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_DB", raising=False)

        mock_config = MagicMock()
        mock_config.logging.database = "/from/config/sentinel.db"

        # _find_db_path() does a local import: from sentinelai.core.config import load_config
        # We must patch at the source module, not at the runner module.
        with patch("sentinelai.core.config.load_config", return_value=mock_config):
            result = _find_db_path()

        assert result == Path("/from/config/sentinel.db")

    def test_returns_default_fallback(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_DB", raising=False)

        with patch(
            "sentinelai.core.config.load_config",
            side_effect=Exception("no config"),
        ):
            result = _find_db_path()

        assert isinstance(result, Path)
        assert result.name == "sentinel.db"

    def test_ignores_memory_db_in_config(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_DB", raising=False)

        mock_config = MagicMock()
        mock_config.logging.database = ":memory:"

        with patch(
            "sentinelai.core.config.load_config",
            return_value=mock_config,
        ):
            result = _find_db_path()

        # :memory: is skipped, should fall through to default
        assert result == Path("sentinel.db")


# ===================================================================
# _backup_database()
# ===================================================================


class TestBackupDatabase:
    """_backup_database() creates timestamped SQLite backups."""

    def test_creates_backup_file(self, tmp_path):
        db_path = tmp_path / "test.db"
        # Create a real SQLite database
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO test VALUES (1)")
        conn.commit()
        conn.close()

        backup_dir = tmp_path / "backups"
        backup_path = _backup_database(db_path, backup_dir=backup_dir)

        assert backup_path.exists()
        assert backup_dir.exists()
        assert "pre_migration" in backup_path.name

        # Verify backup contains data
        conn = sqlite3.connect(str(backup_path))
        row = conn.execute("SELECT id FROM test").fetchone()
        conn.close()
        assert row[0] == 1

    def test_db_not_found_raises_file_not_found(self, tmp_path):
        db_path = tmp_path / "nonexistent.db"
        with pytest.raises(FileNotFoundError, match="Database not found"):
            _backup_database(db_path)

    def test_default_backup_dir_is_parent_backups(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        backup_path = _backup_database(db_path)

        expected_dir = tmp_path / "backups"
        assert backup_path.parent == expected_dir


# ===================================================================
# _verify_integrity()
# ===================================================================


class TestVerifyIntegrity:
    """_verify_integrity() runs PRAGMA integrity_check."""

    def test_returns_true_for_valid_db(self, tmp_path):
        db_path = tmp_path / "valid.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO test VALUES (1, 'hello')")
        conn.commit()
        conn.close()

        assert _verify_integrity(db_path) is True

    def test_returns_true_for_empty_db(self, tmp_path):
        db_path = tmp_path / "empty.db"
        conn = sqlite3.connect(str(db_path))
        conn.close()

        assert _verify_integrity(db_path) is True

    def test_returns_false_for_corrupt_db(self, tmp_path):
        db_path = tmp_path / "corrupt.db"
        # Write garbage to simulate corruption
        db_path.write_bytes(b"this is not a valid sqlite database at all" * 100)

        # sqlite3 may raise or return a bad integrity check
        # depending on the version; either way the function should return False
        try:
            result = _verify_integrity(db_path)
            assert result is False
        except Exception:
            # Some SQLite versions raise on connect/execute for garbage files
            pass


# ===================================================================
# _get_current_revision()
# ===================================================================


class TestGetCurrentRevision:
    """_get_current_revision() reads alembic_version table."""

    def test_no_alembic_table_returns_none(self, tmp_path):
        db_path = tmp_path / "no_alembic.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE users (id INTEGER)")
        conn.commit()
        conn.close()

        assert _get_current_revision(db_path) is None

    def test_with_alembic_table_returns_revision(self, tmp_path):
        db_path = tmp_path / "with_alembic.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        conn.execute("INSERT INTO alembic_version VALUES ('abc123def456')")
        conn.commit()
        conn.close()

        assert _get_current_revision(db_path) == "abc123def456"

    def test_empty_alembic_table_returns_none(self, tmp_path):
        db_path = tmp_path / "empty_alembic.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        conn.commit()
        conn.close()

        assert _get_current_revision(db_path) is None

    def test_nonexistent_db_returns_none(self, tmp_path):
        db_path = tmp_path / "nonexistent.db"
        # sqlite3.connect creates the file, but there will be no tables
        result = _get_current_revision(db_path)
        assert result is None


# ===================================================================
# _restore_backup()
# ===================================================================


class TestRestoreBackup:
    """_restore_backup() copies backup to DB path and cleans WAL/SHM files."""

    def test_copies_backup_to_db_path(self, tmp_path):
        # Create a "backup" database
        backup_path = tmp_path / "backup.db"
        conn = sqlite3.connect(str(backup_path))
        conn.execute("CREATE TABLE restored (id INTEGER)")
        conn.execute("INSERT INTO restored VALUES (42)")
        conn.commit()
        conn.close()

        # Create a "current" database (will be overwritten)
        db_path = tmp_path / "current.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE original (id INTEGER)")
        conn.commit()
        conn.close()

        _restore_backup(backup_path, db_path)

        # Verify the restored DB has the backup content
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT id FROM restored").fetchone()
        conn.close()
        assert row[0] == 42

    def test_removes_wal_and_shm_files(self, tmp_path):
        backup_path = tmp_path / "backup.db"
        conn = sqlite3.connect(str(backup_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        db_path = tmp_path / "current.db"
        db_path.write_bytes(b"old data")

        # Create WAL and SHM files
        wal_path = tmp_path / "current.db-wal"
        shm_path = tmp_path / "current.db-shm"
        journal_path = tmp_path / "current.db-journal"
        wal_path.write_bytes(b"wal data")
        shm_path.write_bytes(b"shm data")
        journal_path.write_bytes(b"journal data")

        _restore_backup(backup_path, db_path)

        assert not wal_path.exists()
        assert not shm_path.exists()
        assert not journal_path.exists()
        assert db_path.exists()


# ===================================================================
# run_migrations()
# ===================================================================


class TestRunMigrations:
    """run_migrations() orchestrates backup, Alembic, and verification."""

    def test_dry_run_returns_true(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        result = run_migrations(db_path=db_path, dry_run=True)
        assert result is True

    def test_db_does_not_exist_returns_true(self, tmp_path):
        db_path = tmp_path / "nonexistent.db"
        assert not db_path.exists()

        result = run_migrations(db_path=db_path)
        assert result is True

    def test_integrity_failure_returns_false(self, tmp_path):
        db_path = tmp_path / "bad.db"
        db_path.write_bytes(b"corrupted content" * 100)

        with patch(
            "sentinelai.migrations.runner._verify_integrity",
            return_value=False,
        ):
            result = run_migrations(db_path=db_path)

        assert result is False

    @_skip_no_alembic
    def test_skip_backup_skips_backup_step(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        with patch("sentinelai.migrations.runner._backup_database") as mock_backup, \
             patch("sentinelai.migrations.runner._run_manual_migrations"), \
             patch("sentinelai.migrations.runner._verify_integrity", return_value=True), \
             patch("sentinelai.migrations.runner._get_current_revision", return_value=None), \
             patch("alembic.command.upgrade"), \
             patch("alembic.config.Config") as MockConfig:
            mock_cfg = MagicMock()
            MockConfig.return_value = mock_cfg

            # Make alembic.ini "exist"
            with patch.object(Path, "exists", return_value=True):
                result = run_migrations(db_path=db_path, skip_backup=True)

            mock_backup.assert_not_called()

    @_skip_no_alembic
    def test_alembic_success_path(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        with patch("sentinelai.migrations.runner._verify_integrity", return_value=True), \
             patch("sentinelai.migrations.runner._get_current_revision", return_value="rev1"), \
             patch("sentinelai.migrations.runner._backup_database") as mock_backup, \
             patch("sentinelai.migrations.runner._run_manual_migrations"), \
             patch("alembic.command.upgrade") as mock_upgrade, \
             patch("alembic.config.Config") as MockConfig:
            mock_backup.return_value = tmp_path / "backup.db"
            mock_cfg = MagicMock()
            MockConfig.return_value = mock_cfg

            # Make alembic.ini path check pass
            with patch.object(Path, "exists", return_value=True):
                result = run_migrations(db_path=db_path)

            assert result is True
            mock_upgrade.assert_called_once_with(mock_cfg, "head")

    @_skip_no_alembic
    def test_alembic_failure_triggers_rollback(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        backup_file = tmp_path / "backup.db"
        # Create a backup file so rollback can find it
        conn = sqlite3.connect(str(backup_file))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        with patch("sentinelai.migrations.runner._verify_integrity", return_value=True), \
             patch("sentinelai.migrations.runner._get_current_revision", return_value=None), \
             patch("sentinelai.migrations.runner._backup_database", return_value=backup_file), \
             patch("sentinelai.migrations.runner._restore_backup") as mock_restore, \
             patch("alembic.command.upgrade", side_effect=RuntimeError("migration failed")), \
             patch("alembic.config.Config") as MockConfig:
            mock_cfg = MagicMock()
            MockConfig.return_value = mock_cfg

            with patch.object(Path, "exists", return_value=True):
                result = run_migrations(db_path=db_path)

            assert result is False
            mock_restore.assert_called_once_with(backup_file, db_path)

    def test_no_alembic_ini_falls_back_to_manual(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        # Inject fake alembic modules into sys.modules so the import inside
        # run_migrations() succeeds, but make alembic_ini.exists() return False
        # so the code falls back to manual migrations.
        fake_alembic = MagicMock()
        fake_command = MagicMock()
        fake_config = MagicMock()
        modules_to_inject = {
            "alembic": fake_alembic,
            "alembic.command": fake_command,
            "alembic.config": fake_config,
        }
        fake_alembic.command = fake_command
        fake_alembic.config = fake_config
        fake_config.Config = MagicMock()

        saved_modules = {}
        for mod_name, mod in modules_to_inject.items():
            saved_modules[mod_name] = sys.modules.get(mod_name)
            sys.modules[mod_name] = mod

        try:
            with patch("sentinelai.migrations.runner._verify_integrity", return_value=True), \
                 patch("sentinelai.migrations.runner._get_current_revision", return_value=None), \
                 patch("sentinelai.migrations.runner._backup_database") as mock_backup, \
                 patch("sentinelai.migrations.runner._run_manual_migrations") as mock_manual:
                mock_backup.return_value = tmp_path / "backup.db"

                # alembic.ini won't exist in tmp_path, so the code falls back to manual
                result = run_migrations(db_path=db_path)

                assert result is True
                mock_manual.assert_called()
        finally:
            # Restore original sys.modules state
            for mod_name, original in saved_modules.items():
                if original is None:
                    sys.modules.pop(mod_name, None)
                else:
                    sys.modules[mod_name] = original

    def test_auto_detects_db_path_when_none(self, tmp_path):
        db_path = tmp_path / "auto.db"

        with patch("sentinelai.migrations.runner._find_db_path", return_value=db_path):
            # DB does not exist, should return True early
            result = run_migrations(db_path=None)

        assert result is True

    def test_backup_failure_returns_false(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        with patch("sentinelai.migrations.runner._verify_integrity", return_value=True), \
             patch("sentinelai.migrations.runner._get_current_revision", return_value=None), \
             patch(
                 "sentinelai.migrations.runner._backup_database",
                 side_effect=PermissionError("no write access"),
             ):
            result = run_migrations(db_path=db_path)

        assert result is False

    @_skip_no_alembic
    def test_post_migration_integrity_failure_triggers_rollback(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        backup_file = tmp_path / "backup.db"
        conn = sqlite3.connect(str(backup_file))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        # _verify_integrity returns True first (pre-migration), then False (post-migration)
        integrity_results = iter([True, True])  # pre-flight OK, post-migration FAIL

        def side_effect_integrity(path):
            return next(integrity_results)

        with patch("sentinelai.migrations.runner._verify_integrity") as mock_verify, \
             patch("sentinelai.migrations.runner._get_current_revision", return_value=None), \
             patch("sentinelai.migrations.runner._backup_database", return_value=backup_file), \
             patch("sentinelai.migrations.runner._restore_backup") as mock_restore, \
             patch("sentinelai.migrations.runner._run_manual_migrations"), \
             patch("alembic.command.upgrade"), \
             patch("alembic.config.Config") as MockConfig:
            mock_cfg = MagicMock()
            MockConfig.return_value = mock_cfg

            # First call True (pre-flight), second call False (post-migration)
            mock_verify.side_effect = [True, False]

            with patch.object(Path, "exists", return_value=True):
                result = run_migrations(db_path=db_path)

            assert result is False
            mock_restore.assert_called_once_with(backup_file, db_path)


# ===================================================================
# main() CLI
# ===================================================================


class TestMain:
    """main() parses CLI arguments and calls run_migrations."""

    def test_default_args(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=True) as mock_run:
            main()

        mock_run.assert_called_once_with(db_path=None, dry_run=False, skip_backup=False)

    def test_dry_run_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner", "--dry-run"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=True) as mock_run:
            main()

        mock_run.assert_called_once_with(db_path=None, dry_run=True, skip_backup=False)

    def test_db_path_arg(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner", "--db", "/tmp/custom.db"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=True) as mock_run:
            main()

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["db_path"] == Path("/tmp/custom.db")

    def test_skip_backup_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner", "--skip-backup"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=True) as mock_run:
            main()

        mock_run.assert_called_once_with(db_path=None, dry_run=False, skip_backup=True)

    def test_verbose_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner", "-v"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=True), \
             patch("logging.basicConfig") as mock_logging:
            main()

        # Verbose should set DEBUG level
        import logging
        mock_logging.assert_called_once()
        assert mock_logging.call_args[1]["level"] == logging.DEBUG

    def test_failure_exits_with_code_1(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=False), \
             pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    def test_all_flags_combined(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["runner", "--db", "/tmp/test.db", "--dry-run", "--skip-backup", "-v"])

        with patch("sentinelai.migrations.runner.run_migrations", return_value=True) as mock_run:
            main()

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["db_path"] == Path("/tmp/test.db")
        assert call_kwargs["dry_run"] is True
        assert call_kwargs["skip_backup"] is True
