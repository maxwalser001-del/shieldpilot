#!/usr/bin/env bash
# ============================================================
# ShieldPilot — Database Backup Script
# ============================================================
# Creates a timestamped backup of sentinel.db using SQLite's
# online backup API (safe even with WAL mode active).
#
# Usage:
#   bash scripts/backup.sh                          # Auto-detect DB
#   bash scripts/backup.sh /path/to/sentinel.db     # Explicit path
#   bash scripts/backup.sh --dir /backups           # Custom backup dir
#
# Backups are stored in: <db_dir>/backups/ (default)
# Format: sentinel_YYYYMMDD_HHMMSS.db
# ============================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${CYAN}[backup]${NC} $*"; }
ok()    { echo -e "${GREEN}[backup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[backup]${NC} $*"; }
error() { echo -e "${RED}[backup]${NC} $*" >&2; }

# ── Parse arguments ────────────────────────────────────────────
DB_PATH=""
BACKUP_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        -*)
            error "Unknown option: $1"
            exit 1
            ;;
        *)
            DB_PATH="$1"
            shift
            ;;
    esac
done

# ── Find database ──────────────────────────────────────────────
if [ -z "$DB_PATH" ]; then
    # Check SENTINEL_DB env var
    if [ -n "${SENTINEL_DB:-}" ]; then
        DB_PATH="$SENTINEL_DB"
    # Check common locations
    elif [ -f "sentinel.db" ]; then
        DB_PATH="sentinel.db"
    elif [ -f "/app/data/sentinel.db" ]; then
        DB_PATH="/app/data/sentinel.db"
    else
        error "Could not find sentinel.db. Provide the path as an argument."
        exit 1
    fi
fi

if [ ! -f "$DB_PATH" ]; then
    error "Database not found: $DB_PATH"
    exit 1
fi

DB_PATH="$(cd "$(dirname "$DB_PATH")" && pwd)/$(basename "$DB_PATH")"
info "Database: $DB_PATH"

# ── Set backup directory ──────────────────────────────────────
if [ -z "$BACKUP_DIR" ]; then
    BACKUP_DIR="$(dirname "$DB_PATH")/backups"
fi
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/sentinel_${TIMESTAMP}.db"

# ── Pre-backup integrity check ────────────────────────────────
info "Running integrity check..."
INTEGRITY=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;" 2>&1)
if [ "$INTEGRITY" != "ok" ]; then
    error "Database failed integrity check: $INTEGRITY"
    error "Backup aborted. Fix the database first."
    exit 1
fi
ok "Integrity check passed"

# ── Create backup using SQLite .backup command ────────────────
info "Creating backup..."
sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

if [ ! -f "$BACKUP_FILE" ]; then
    error "Backup file was not created"
    exit 1
fi

# ── Verify backup integrity ──────────────────────────────────
info "Verifying backup integrity..."
BACKUP_INTEGRITY=$(sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" 2>&1)
if [ "$BACKUP_INTEGRITY" != "ok" ]; then
    error "Backup failed integrity check: $BACKUP_INTEGRITY"
    rm -f "$BACKUP_FILE"
    exit 1
fi

# ── Report ────────────────────────────────────────────────────
ORIGINAL_SIZE=$(stat -f%z "$DB_PATH" 2>/dev/null || stat -c%s "$DB_PATH" 2>/dev/null)
BACKUP_SIZE=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE" 2>/dev/null)

# Count rows in key tables
ROW_COUNTS=$(sqlite3 "$BACKUP_FILE" "
    SELECT 'commands: ' || COUNT(*) FROM commands;
    SELECT 'incidents: ' || COUNT(*) FROM incidents;
    SELECT 'prompt_scans: ' || COUNT(*) FROM prompt_scans;
    SELECT 'users: ' || COUNT(*) FROM users;
" 2>/dev/null || echo "(could not count rows)")

echo ""
ok "============================================="
ok "  Backup complete"
ok "============================================="
echo ""
info "Source:     $DB_PATH ($(numfmt --to=iec "$ORIGINAL_SIZE" 2>/dev/null || echo "${ORIGINAL_SIZE} bytes"))"
info "Backup:     $BACKUP_FILE ($(numfmt --to=iec "$BACKUP_SIZE" 2>/dev/null || echo "${BACKUP_SIZE} bytes"))"
info "Timestamp:  $TIMESTAMP"
echo ""
info "Row counts:"
echo "$ROW_COUNTS" | while IFS= read -r line; do
    info "  $line"
done
echo ""

# ── Cleanup old backups (keep last 10) ────────────────────────
BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/sentinel_*.db 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 10 ]; then
    REMOVE_COUNT=$((BACKUP_COUNT - 10))
    info "Cleaning up $REMOVE_COUNT old backup(s) (keeping last 10)..."
    ls -1t "$BACKUP_DIR"/sentinel_*.db | tail -n "$REMOVE_COUNT" | xargs rm -f
fi
