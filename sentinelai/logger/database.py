"""SQLAlchemy ORM models and database initialization for ShieldPilot."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class CommandLog(Base):
    """Audit log of all commands evaluated by the risk engine."""
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    command = Column(Text, nullable=False)  # masked command text
    raw_command_hash = Column(String(64), nullable=False)  # SHA-256 of original
    working_directory = Column(String(1024))
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    action_taken = Column(String(10), nullable=False)  # block/warn/allow
    executed = Column(Boolean, nullable=False, default=False)
    exit_code = Column(Integer, nullable=True)
    output_snippet = Column(Text, nullable=True)  # first 1000 chars, masked
    signals_json = Column(Text, nullable=False)  # JSON array of RiskSignal
    llm_used = Column(Boolean, default=False)
    llm_reasoning = Column(Text, nullable=True)
    execution_time_ms = Column(Float, nullable=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)

    # Relationships
    file_changes = relationship("FileChangeLog", back_populates="command")
    network_accesses = relationship("NetworkAccessLog", back_populates="command")
    incidents = relationship("IncidentLog", back_populates="command")

    __table_args__ = (
        Index("ix_commands_risk_score", "risk_score"),
        Index("ix_commands_action", "action_taken"),
        Index("ix_commands_action_ts", "action_taken", "timestamp"),
    )


class PromptScanLog(Base):
    """Log of prompt injection scan results."""
    __tablename__ = "prompt_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    source = Column(String(512), nullable=False)
    content_hash = Column(String(64), nullable=False)
    content_length = Column(Integer, nullable=False)
    overall_score = Column(Integer, nullable=False)
    threat_count = Column(Integer, nullable=False)
    threats_json = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_prompt_scans_threats_ts", "threat_count", "timestamp"),
    )


class FileChangeLog(Base):
    """Log of file system changes triggered by commands."""
    __tablename__ = "file_changes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    file_path = Column(String(1024), nullable=False)
    change_type = Column(String(20), nullable=False)  # created/modified/deleted/moved
    hash_before = Column(String(64), nullable=True)
    hash_after = Column(String(64), nullable=True)
    size_before = Column(Integer, nullable=True)
    size_after = Column(Integer, nullable=True)
    command_id = Column(Integer, ForeignKey("commands.id"), nullable=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)

    command = relationship("CommandLog", back_populates="file_changes")


class NetworkAccessLog(Base):
    """Log of network access detected in commands."""
    __tablename__ = "network_access"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    destination = Column(String(512), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    direction = Column(String(10), nullable=False, default="outbound")
    blocked = Column(Boolean, nullable=False, default=False)
    command_id = Column(Integer, ForeignKey("commands.id"), nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)

    command = relationship("CommandLog", back_populates="network_accesses")


class IncidentLog(Base):
    """Security incidents generated by high-risk detections."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    severity = Column(String(20), nullable=False)
    category = Column(String(50), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)  # masked
    command_id = Column(Integer, ForeignKey("commands.id"), nullable=True)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)

    command = relationship("CommandLog", back_populates="incidents")

    __table_args__ = (
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_resolved", "resolved"),
        Index("ix_incidents_resolved_ts", "resolved", "timestamp"),
    )


class Tenant(Base):
    """Multi-tenant account for SaaS mode."""
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    email = Column(String(256), nullable=False, unique=True)
    api_key_hash = Column(String(64), nullable=False)
    tier = Column(String(20), nullable=False, default="free")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class UsageRecord(Base):
    """Usage metering per user per day (or global if user_email is NULL)."""
    __tablename__ = "usage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=True, index=True)
    user_email = Column(String(256), nullable=True, index=True)  # Per-user tracking
    date = Column(String(10), nullable=False)  # YYYY-MM-DD
    commands_evaluated = Column(Integer, default=0)
    scans_performed = Column(Integer, default=0)
    llm_calls = Column(Integer, default=0)
    api_requests = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_usage_tenant_date", "tenant_id", "date"),
        Index("ix_usage_user_date", "user_email", "date"),
    )


class User(Base):
    """Dashboard user account."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(128), nullable=False, unique=True)
    email = Column(String(256), nullable=True, unique=True)  # For login & password reset
    password_hash = Column(String(256), nullable=True)  # bcrypt, nullable for OAuth-only users
    google_id = Column(String(256), nullable=True, unique=True)  # For Google OAuth
    tenant_id = Column(String(64), ForeignKey("tenants.id"), nullable=True)
    role = Column(String(20), nullable=False, default="viewer")  # admin/analyst/viewer
    tier = Column(String(20), nullable=False, default="free")  # free/pro/enterprise/unlimited
    is_super_admin = Column(Boolean, default=False)  # Bypasses all limits
    email_verified = Column(Boolean, default=False)  # Email verification status
    api_key_hash = Column(String(64), nullable=True, unique=True)  # SHA-256 of API key
    stripe_customer_id = Column(String(256), nullable=True, unique=True)  # Stripe cus_xxx
    stripe_subscription_id = Column(String(256), nullable=True)  # Stripe sub_xxx
    subscription_status = Column(String(20), nullable=True)  # active/past_due/canceled/unpaid
    current_period_end = Column(Integer, nullable=True)  # Unix timestamp
    cancel_at_period_end = Column(Boolean, default=False)  # Stripe: subscription ending at period end
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    tos_accepted_at = Column(DateTime, nullable=True)  # When user accepted ToS
    tos_version = Column(String(20), nullable=True)  # e.g. "2026-02-01"
    tos_ip_address = Column(String(45), nullable=True)  # Anonymized IPv4/IPv6
    tos_user_agent = Column(String(512), nullable=True)  # Browser User-Agent


class WebhookEvent(Base):
    """Processed Stripe webhook events for idempotency."""
    __tablename__ = "webhook_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    stripe_event_id = Column(String(256), unique=True, nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    processed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    status = Column(String(20), nullable=False, default="processed")  # processed / error


class BoosterCredit(Base):
    """One-time command booster credits purchased by users."""
    __tablename__ = "booster_credits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(256), nullable=False, index=True)
    credits_remaining = Column(Integer, nullable=False, default=500)
    purchased_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(String(10), nullable=False)  # ISO date, midnight UTC
    stripe_payment_id = Column(String(256), nullable=True)


class PasswordResetToken(Base):
    """Time-limited password reset tokens."""
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 of token
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class EmailVerificationToken(Base):
    """Time-limited email verification tokens."""
    __tablename__ = "email_verification_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 of token
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class OAuthState(Base):
    """Database-backed OAuth state tokens (replaces in-memory dict)."""
    __tablename__ = "oauth_states"

    id = Column(Integer, primary_key=True, autoincrement=True)
    state = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class TeamInvite(Base):
    """Pending team invitations."""
    __tablename__ = "team_invites"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    email = Column(String(256), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin/analyst/viewer
    invited_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    accepted = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_team_invites_email", "email"),
        Index("ix_team_invites_tenant", "tenant_id"),
    )


class RateLimitAttempt(Base):
    """Database-backed rate limit tracking (persists across restarts)."""
    __tablename__ = "rate_limit_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    limiter_name = Column(String(64), nullable=False)  # e.g. "login", "password_reset"
    key = Column(String(256), nullable=False)  # IP or email
    attempted_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_ratelimit_name_key", "limiter_name", "key"),
        Index("ix_ratelimit_name_key_at", "limiter_name", "key", "attempted_at"),
    )


class CustomRule(Base):
    """User-defined detection rules integrated into PromptScanner."""
    __tablename__ = "custom_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), nullable=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(512), nullable=True)
    pattern = Column(Text, nullable=False)  # regex pattern
    severity = Column(String(20), nullable=False, default="medium")  # low/medium/high/critical
    category = Column(String(50), nullable=False, default="custom")
    enabled = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_custom_rules_tenant", "tenant_id"),
        Index("ix_custom_rules_enabled", "enabled"),
    )


class LibraryItem(Base):
    """Curated prompts and skills library."""
    __tablename__ = "library_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(20), nullable=False)  # "prompt" or "skill"
    title = Column(String(256), nullable=False)
    tags = Column(Text, nullable=True)  # JSON array: '["security", "code-review"]'
    short_preview = Column(String(512), nullable=False)  # Always visible to all users
    full_content = Column(Text, nullable=False)  # Protected by paywall
    category = Column(String(100), nullable=True)  # e.g., "Security", "Code Review"
    display_order = Column(Integer, default=0)  # For manual ordering within category
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_published = Column(Boolean, default=False)

    topic_id = Column(Integer, ForeignKey("library_topics.id"), nullable=True)
    topic = relationship("LibraryTopic", back_populates="items")

    __table_args__ = (
        Index("ix_library_items_type", "type"),
        Index("ix_library_items_is_published", "is_published"),
        Index("ix_library_items_category", "category"),
        Index("ix_library_items_topic_id", "topic_id"),
    )


class LibraryTopic(Base):
    """Hierarchical topic for organizing library items (max 2 levels)."""
    __tablename__ = "library_topics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False)
    slug = Column(String(256), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    icon = Column(String(50), nullable=True)  # emoji
    parent_id = Column(Integer, ForeignKey("library_topics.id"), nullable=True)
    display_order = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    parent = relationship("LibraryTopic", remote_side="LibraryTopic.id", backref="children")
    items = relationship("LibraryItem", back_populates="topic")

    __table_args__ = (
        Index("ix_library_topics_parent_id", "parent_id"),
        Index("ix_library_topics_slug", "slug"),
    )


def migrate_database(engine) -> None:
    """DEPRECATED: Legacy manual migrations. Use Alembic instead.

    Kept as fallback for environments without Alembic installed.
    This function is called by _fallback_create_all() when Alembic is not available.
    """
    inspector = inspect(engine)

    # Check if users table exists and needs migration
    if "users" in inspector.get_table_names():
        existing_columns = [col["name"] for col in inspector.get_columns("users")]

        migrations = [
            ("email", "ALTER TABLE users ADD COLUMN email VARCHAR(256)"),
            ("google_id", "ALTER TABLE users ADD COLUMN google_id VARCHAR(256)"),
            ("is_super_admin", "ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN DEFAULT 0"),
            ("tier", "ALTER TABLE users ADD COLUMN tier VARCHAR(20) DEFAULT 'free'"),
            ("email_verified", "ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0"),
            ("api_key_hash", "ALTER TABLE users ADD COLUMN api_key_hash VARCHAR(64)"),
            ("stripe_customer_id", "ALTER TABLE users ADD COLUMN stripe_customer_id VARCHAR(256)"),
            ("stripe_subscription_id", "ALTER TABLE users ADD COLUMN stripe_subscription_id VARCHAR(256)"),
            ("subscription_status", "ALTER TABLE users ADD COLUMN subscription_status VARCHAR(20)"),
            ("current_period_end", "ALTER TABLE users ADD COLUMN current_period_end INTEGER"),
            ("tos_accepted_at", "ALTER TABLE users ADD COLUMN tos_accepted_at DATETIME"),
            ("tos_version", "ALTER TABLE users ADD COLUMN tos_version VARCHAR(20)"),
            ("tos_ip_address", "ALTER TABLE users ADD COLUMN tos_ip_address VARCHAR(45)"),
            ("tos_user_agent", "ALTER TABLE users ADD COLUMN tos_user_agent VARCHAR(512)"),
            ("cancel_at_period_end", "ALTER TABLE users ADD COLUMN cancel_at_period_end BOOLEAN DEFAULT 0"),
        ]

        with engine.connect() as conn:
            for col_name, sql in migrations:
                if col_name not in existing_columns:
                    try:
                        conn.execute(text(sql))
                        conn.commit()
                    except Exception:
                        pass  # Column might already exist

    # Create webhook_events table if it doesn't exist
    if "webhook_events" not in inspector.get_table_names():
        try:
            WebhookEvent.__table__.create(bind=engine)
        except Exception:
            pass  # Table might already exist

    # Create booster_credits table if it doesn't exist
    if "booster_credits" not in inspector.get_table_names():
        try:
            BoosterCredit.__table__.create(bind=engine)
        except Exception:
            pass  # Table might already exist

    # Check if library_items table exists and needs migration
    if "library_items" in inspector.get_table_names():
        existing_columns = [col["name"] for col in inspector.get_columns("library_items")]

        library_migrations = [
            ("category", "ALTER TABLE library_items ADD COLUMN category VARCHAR(100)"),
            ("display_order", "ALTER TABLE library_items ADD COLUMN display_order INTEGER DEFAULT 0"),
        ]

        with engine.connect() as conn:
            for col_name, sql in library_migrations:
                if col_name not in existing_columns:
                    try:
                        conn.execute(text(sql))
                        conn.commit()
                    except Exception:
                        pass  # Column might already exist

    # Create library_topics table if it doesn't exist
    if "library_topics" not in inspector.get_table_names():
        try:
            LibraryTopic.__table__.create(bind=engine)
        except Exception:
            pass

    # Add topic_id column to library_items if missing
    if "library_items" in inspector.get_table_names():
        existing_columns = [col["name"] for col in inspector.get_columns("library_items")]
        if "topic_id" not in existing_columns:
            with engine.connect() as conn:
                try:
                    conn.execute(text(
                        "ALTER TABLE library_items ADD COLUMN topic_id INTEGER REFERENCES library_topics(id)"
                    ))
                    conn.commit()
                except Exception:
                    pass

            # One-time migration: convert existing category strings to topics
            with engine.connect() as conn:
                has_unmigrated = conn.execute(text(
                    "SELECT COUNT(*) FROM library_items WHERE category IS NOT NULL AND topic_id IS NULL"
                )).scalar()

                if has_unmigrated and has_unmigrated > 0:
                    rows = conn.execute(text(
                        "SELECT DISTINCT category FROM library_items WHERE category IS NOT NULL"
                    )).fetchall()

                    for row in rows:
                        cat_name = row[0]
                        slug = cat_name.lower().replace(" ", "-").replace("_", "-")
                        existing = conn.execute(text(
                            "SELECT id FROM library_topics WHERE slug = :slug"
                        ), {"slug": slug}).fetchone()

                        if existing:
                            topic_id = existing[0]
                        else:
                            conn.execute(text(
                                "INSERT INTO library_topics (name, slug, display_order) VALUES (:name, :slug, 0)"
                            ), {"name": cat_name, "slug": slug})
                            topic_id = conn.execute(text(
                                "SELECT id FROM library_topics WHERE slug = :slug"
                            ), {"slug": slug}).fetchone()[0]

                        conn.execute(text(
                            "UPDATE library_items SET topic_id = :tid WHERE category = :cat AND topic_id IS NULL"
                        ), {"tid": topic_id, "cat": cat_name})

                    conn.commit()

    # Create oauth_states table if it doesn't exist
    if "oauth_states" not in inspector.get_table_names():
        try:
            OAuthState.__table__.create(bind=engine)
        except Exception:
            pass

    # Create rate_limit_attempts table if it doesn't exist
    if "rate_limit_attempts" not in inspector.get_table_names():
        try:
            RateLimitAttempt.__table__.create(bind=engine)
        except Exception:
            pass

    # Ensure named index on prompt_scans.timestamp for scan count queries
    if "prompt_scans" in inspector.get_table_names():
        existing_indexes = {idx["name"] for idx in inspector.get_indexes("prompt_scans") if idx["name"]}
        if "ix_prompt_scans_timestamp" not in existing_indexes:
            with engine.connect() as conn:
                try:
                    conn.execute(text(
                        "CREATE INDEX IF NOT EXISTS ix_prompt_scans_timestamp ON prompt_scans (timestamp)"
                    ))
                    conn.commit()
                except Exception:
                    pass  # Index already exists or cannot be created

    # Ensure composite index on rate_limit_attempts for sliding-window queries
    if "rate_limit_attempts" in inspector.get_table_names():
        existing_indexes = {idx["name"] for idx in inspector.get_indexes("rate_limit_attempts") if idx["name"]}
        if "ix_ratelimit_name_key_at" not in existing_indexes:
            with engine.connect() as conn:
                try:
                    conn.execute(text(
                        "CREATE INDEX IF NOT EXISTS ix_ratelimit_name_key_at "
                        "ON rate_limit_attempts (limiter_name, key, attempted_at)"
                    ))
                    conn.commit()
                except Exception:
                    pass  # Index already exists

    # Add user_email column to usage table for per-user tracking
    if "usage" in inspector.get_table_names():
        existing_columns = [col["name"] for col in inspector.get_columns("usage")]
        if "user_email" not in existing_columns:
            with engine.connect() as conn:
                try:
                    conn.execute(text(
                        "ALTER TABLE usage ADD COLUMN user_email VARCHAR(256)"
                    ))
                    conn.commit()
                except Exception:
                    pass  # Column might already exist
                try:
                    conn.execute(text(
                        "CREATE INDEX IF NOT EXISTS ix_usage_user_date ON usage (user_email, date)"
                    ))
                    conn.commit()
                except Exception:
                    pass  # Index might already exist

    # Create custom_rules table if missing
    if "custom_rules" not in inspector.get_table_names():
        try:
            CustomRule.__table__.create(bind=engine)
        except Exception:
            pass  # Table might already exist

    # Create team_invites table if missing
    if "team_invites" not in inspector.get_table_names():
        try:
            TeamInvite.__table__.create(bind=engine)
        except Exception:
            pass  # Table might already exist


def _ensure_indexes(engine) -> None:
    """Create missing compound indexes on existing databases (idempotent).

    New databases get these indexes automatically via ``__table_args__`` when
    ``Base.metadata.create_all()`` runs.  For *existing* databases that were
    created before the compound indexes were added, this function creates them
    via raw DDL so no data migration is needed.
    """
    inspector = inspect(engine)
    existing: set[str] = set()
    for table_name in inspector.get_table_names():
        for idx in inspector.get_indexes(table_name):
            existing.add(idx["name"])

    new_indexes = [
        ("ix_commands_action_ts", "commands", "action_taken, timestamp"),
        ("ix_prompt_scans_threats_ts", "prompt_scans", "threat_count, timestamp"),
        ("ix_incidents_resolved_ts", "incidents", "resolved, timestamp"),
    ]

    # Validate index definitions (all hardcoded, but guard against injection)
    _valid_ident = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_, ]*$")
    with engine.connect() as conn:
        for name, table, columns in new_indexes:
            if name not in existing:
                assert _valid_ident.match(name), f"Invalid index name: {name}"
                assert _valid_ident.match(table), f"Invalid table name: {table}"
                assert _valid_ident.match(columns), f"Invalid column spec: {columns}"
                try:
                    conn.execute(text(f"CREATE INDEX {name} ON {table} ({columns})"))
                except Exception as exc:
                    logging.getLogger(__name__).warning("Index %s creation failed: %s", name, exc)
        conn.commit()


def _run_alembic_upgrade(db_path: str) -> None:
    """Run Alembic upgrade head, falling back to create_all if Alembic is unavailable."""
    try:
        from alembic import command
        from alembic.config import Config

        project_root = Path(__file__).resolve().parents[2]
        alembic_ini = project_root / "alembic.ini"

        if not alembic_ini.exists():
            # Alembic not available -- fall back to create_all
            _fallback_create_all(db_path)
            return

        alembic_cfg = Config(str(alembic_ini))
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")

        # Check if this is an existing DB without alembic_version table
        import sqlite3

        conn = sqlite3.connect(db_path)
        try:
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
        finally:
            conn.close()

        if tables and "alembic_version" not in tables:
            # Existing database from before Alembic -- stamp it at head
            # (assumes current schema matches head)
            command.stamp(alembic_cfg, "head")
            return

        # Run upgrade (creates tables for fresh DB, or applies pending migrations)
        command.upgrade(alembic_cfg, "head")

    except ImportError:
        # Alembic not installed -- fall back
        _fallback_create_all(db_path)
    except Exception as e:
        logging.getLogger(__name__).warning(
            "Alembic migration failed, falling back to create_all: %s", e
        )
        _fallback_create_all(db_path)


def _fallback_create_all(db_path: str) -> None:
    """Legacy fallback: create tables via SQLAlchemy metadata + manual migrations."""
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    migrate_database(engine)
    Base.metadata.create_all(engine)


def init_database(db_path: str = "sentinel.db") -> tuple:
    """Initialize database and return (engine, SessionFactory).

    Uses WAL mode for better concurrent read performance.
    Runs Alembic migrations when available, falling back to legacy
    migrate_database() + create_all() if Alembic is not installed.
    """
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )

    # Enable WAL mode for better concurrency + busy timeout for cross-process safety
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA busy_timeout=5000"))
        conn.commit()

    # Run Alembic migrations (preferred)
    _run_alembic_upgrade(db_path)

    # Ensure compound indexes exist on pre-existing databases
    _ensure_indexes(engine)

    Session = sessionmaker(bind=engine)
    return engine, Session
