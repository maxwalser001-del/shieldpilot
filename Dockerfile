# ============================================================
# ShieldPilot — Dockerfile
# ============================================================

FROM python:3.12-slim

LABEL maintainer="ShieldPilot Team"
LABEL description="ShieldPilot — Security platform for autonomous AI coding agents"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps for compiling native wheels (bcrypt, cryptography)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency metadata first for better layer caching
COPY pyproject.toml README.md ./
COPY sentinelai/ ./sentinelai/

# Install the project with all runtime dependencies
RUN pip install --no-cache-dir .

# Copy config, plugin, and migrations
COPY plugin/ ./plugin/
COPY sentinel.yaml ./
COPY alembic.ini ./

# Create non-root user and data directory for SQLite volume
RUN groupadd --gid 1000 shieldpilot && \
    useradd --uid 1000 --gid shieldpilot --shell /bin/bash --create-home shieldpilot && \
    mkdir -p /app/data /app/backups && \
    chown -R shieldpilot:shieldpilot /app

USER shieldpilot

ENV SENTINEL_DB=/app/data/sentinel.db \
    SENTINEL_CONFIG=/app/sentinel.yaml

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "sentinelai.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
