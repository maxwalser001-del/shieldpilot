"""Production-safe migration runner for ShieldPilot.

Creates a backup of the SQLite database before running Alembic migrations,
verifies integrity after migration, and supports rollback on failure.

Usage:
    # Run pending migrations (auto-backup first):
    python -m sentinelai.migrations.runner

    # Dry-run (show what would be done):
    python -m sentinelai.migrations.runner --dry-run

    # Run with explicit database path:
    python -m sentinelai.migrations.runner --db /path/to/sentinel.db
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _find_db_path() -> Path:
    """Locate the sentinel.db file."""
    # Check environment variable first
    env_db = os.environ.get("SENTINEL_DB")
    if env_db:
        return Path(env_db)

    # Check sentinel.yaml config
    try:
        from sentinelai.core.config import load_config

        config = load_config()
        if config.logging.database and config.logging.database != ":memory:":
            return Path(config.logging.database)
    except Exception:
        pass

    # Default fallback
    return Path("sentinel.db")


def _backup_database(db_path: Path, backup_dir: Path | None = None) -> Path:
    """Create a timestamped backup of the database using SQLite's backup API.

    Returns the path to the backup file.
    """
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    if backup_dir is None:
        backup_dir = db_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"sentinel_{timestamp}_pre_migration.db"

    # Use SQLite's online backup API (safe even if WAL mode is active)
    source = sqlite3.connect(str(db_path))
    dest = sqlite3.connect(str(backup_path))
    try:
        source.backup(dest)
    finally:
        dest.close()
        source.close()

    logger.info("Backup created: %s", backup_path)
    return backup_path


def _verify_integrity(db_path: Path) -> bool:
    """Run SQLite PRAGMA integrity_check on the database."""
    conn = sqlite3.connect(str(db_path))
    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()
        ok = result is not None and result[0] == "ok"
        if not ok:
            logger.error("Integrity check failed: %s", result)
        return ok
    finally:
        conn.close()


def _get_current_revision(db_path: Path) -> str | None:
    """Get the current Alembic revision from the database."""
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        )
        if cursor.fetchone() is None:
            return None
        row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        return row[0] if row else None
    except Exception:
        return None
    finally:
        conn.close()


def _restore_backup(backup_path: Path, db_path: Path) -> None:
    """Restore a database from a backup file."""
    logger.warning("Restoring database from backup: %s", backup_path)
    # Remove WAL/SHM files
    for suffix in ("-wal", "-shm", "-journal"):
        wal_path = Path(str(db_path) + suffix)
        if wal_path.exists():
            wal_path.unlink()

    shutil.copy2(str(backup_path), str(db_path))
    logger.info("Database restored from backup")


def run_migrations(
    db_path: Path | None = None,
    dry_run: bool = False,
    skip_backup: bool = False,
) -> bool:
    """Run Alembic migrations with safety checks.

    Args:
        db_path: Path to the SQLite database. Auto-detected if None.
        dry_run: If True, only show what would be done without executing.
        skip_backup: If True, skip the pre-migration backup.

    Returns:
        True if migrations succeeded (or nothing to do), False on failure.
    """
    if db_path is None:
        db_path = _find_db_path()

    db_path = Path(db_path).resolve()

    if not db_path.exists():
        logger.info("Database does not exist yet: %s (will be created by init_database)")
        return True

    # Pre-flight integrity check
    logger.info("Pre-migration integrity check on %s...", db_path)
    if not _verify_integrity(db_path):
        logger.error("Database failed integrity check BEFORE migration. Aborting.")
        return False

    current_rev = _get_current_revision(db_path)
    logger.info("Current Alembic revision: %s", current_rev or "(none)")

    if dry_run:
        logger.info("[DRY RUN] Would backup database and run alembic upgrade head")
        return True

    # Create backup
    backup_path = None
    if not skip_backup:
        try:
            backup_path = _backup_database(db_path)
        except Exception as e:
            logger.error("Failed to create backup: %s", e)
            return False

    # Run Alembic migrations
    try:
        from alembic import command
        from alembic.config import Config

        # Find alembic.ini relative to the project
        project_root = Path(__file__).resolve().parents[2]
        alembic_ini = project_root / "alembic.ini"

        if not alembic_ini.exists():
            logger.warning("alembic.ini not found at %s, skipping Alembic migrations", alembic_ini)
            # Fall back to manual migrate_database()
            _run_manual_migrations(db_path)
            return True

        alembic_cfg = Config(str(alembic_ini))
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")

        command.upgrade(alembic_cfg, "head")
        logger.info("Alembic migrations completed successfully")

    except Exception as e:
        logger.error("Migration failed: %s", e)

        # Restore from backup
        if backup_path and backup_path.exists():
            _restore_backup(backup_path, db_path)
            logger.info("Database rolled back to pre-migration state")
        return False

    # Also run manual migrations (for columns not tracked by Alembic)
    try:
        _run_manual_migrations(db_path)
    except Exception as e:
        logger.warning("Manual migrations had issues (non-fatal): %s", e)

    # Post-migration integrity check
    if not _verify_integrity(db_path):
        logger.error("Database failed integrity check AFTER migration!")
        if backup_path and backup_path.exists():
            _restore_backup(backup_path, db_path)
        return False

    new_rev = _get_current_revision(db_path)
    logger.info("Migration complete. Revision: %s -> %s", current_rev or "(none)", new_rev or "(none)")
    return True


def _run_manual_migrations(db_path: Path) -> None:
    """Run the legacy manual ALTER TABLE migrations from database.py.

    Calls _fallback_create_all() directly instead of init_database() to
    avoid re-entering the Alembic upgrade path.
    """
    try:
        from sentinelai.logger.database import _fallback_create_all

        _fallback_create_all(str(db_path))
        logger.info("Manual migrations (_fallback_create_all) completed")
    except Exception as e:
        logger.warning("Manual migration warning: %s", e)


def main() -> None:
    """CLI entry point for the migration runner."""
    parser = argparse.ArgumentParser(
        description="ShieldPilot production migration runner",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to sentinel.db (auto-detected if omitted)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing",
    )
    parser.add_argument(
        "--skip-backup",
        action="store_true",
        help="Skip pre-migration backup (not recommended)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    db_path = Path(args.db) if args.db else None
    success = run_migrations(db_path=db_path, dry_run=args.dry_run, skip_backup=args.skip_backup)

    if success:
        logger.info("Migration runner finished successfully")
    else:
        logger.error("Migration runner failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
