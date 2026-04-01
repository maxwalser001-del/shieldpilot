"""Alembic environment configuration for ShieldPilot."""

import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Ensure the project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import our models so Alembic can detect them for autogenerate
from sentinelai.logger.database import Base  # noqa: E402

target_metadata = Base.metadata


def _get_db_url() -> str:
    """Get database URL, respecting programmatic overrides.

    Priority order:
    1. URL already set programmatically (differs from alembic.ini default)
       -- this allows callers like _run_alembic_upgrade() to set the URL
       via alembic_cfg.set_main_option() before calling command.upgrade().
    2. Sentinel config (sentinel.yaml logging.database)
    3. alembic.ini default (sqlite:///sentinel.db)
    """
    _ALEMBIC_INI_DEFAULT = "sqlite:///sentinel.db"

    current_url = config.get_main_option("sqlalchemy.url")

    # If the URL was explicitly set to something other than the default,
    # a caller (e.g. _run_alembic_upgrade or runner.py) overrode it -- respect that.
    if current_url and current_url != _ALEMBIC_INI_DEFAULT:
        return current_url

    # Try loading the DB path from sentinel config
    try:
        from sentinelai.core.config import load_config

        cfg = load_config()
        db_path = cfg.logging.database
        if db_path and db_path != ":memory:":
            return f"sqlite:///{db_path}"
    except Exception:
        pass

    return current_url or _ALEMBIC_INI_DEFAULT


# Override the sqlalchemy.url so both offline and online modes use the right DB
config.set_main_option("sqlalchemy.url", _get_db_url())


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and emits SQL to script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Required for SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an Engine and associates a connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Required for SQLite ALTER TABLE support
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
