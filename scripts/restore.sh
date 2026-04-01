#!/usr/bin/env bash
# ============================================================
# ShieldPilot — Database Restore Script
# ============================================================
# Restores sentinel.db from a backup file. Creates a safety
# backup of the current database before restoring.
#
# Usage:
#   bash scripts/restore.sh <backup_file>
#   bash scripts/restore.sh backups/sentinel_20260217_120000.db
#   bash scripts/restore.sh --list                   # List available backups
#   bash scripts/restore.sh --latest                 # Restore most recent
#
# The script will:
#   1. Verify the backup file's integrity
#   2. Create a safety backup of the current database
#   3. Stop WAL mode cleanly
#   4. Replace the database with the backup
#   5. Verify integrity of the restored database
# ============================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${CYAN}[restore]${NC} $*"; }
ok()    { echo -e "${GREEN}[restore]${NC} $*"; }
warn()  { echo -e "${YELLOW}[restore]${NC} $*"; }
error() { echo -e "${RED}[restore]${NC} $*" >&2; }

# ── Find target database ─────────────────────────────────────
find_db() {
    if [ -n "${SENTINEL_DB:-}" ]; then
        echo "$SENTINEL_DB"
    elif [ -f "sentinel.db" ]; then
        echo "sentinel.db"
    elif [ -f "/app/data/sentinel.db" ]; then
        echo "/app/data/sentinel.db"
    else
        echo ""
    fi
}

# ── Find backup directory ────────────────────────────────────
find_backup_dir() {
    local db_path="$1"
    local db_dir
    db_dir="$(dirname "$db_path")"
    echo "$db_dir/backups"
}

# ── List available backups ───────────────────────────────────
list_backups() {
    local db_path
    db_path="$(find_db)"
    if [ -z "$db_path" ]; then
        error "Could not find sentinel.db"
        exit 1
    fi

    local backup_dir
    backup_dir="$(find_backup_dir "$db_path")"

    if [ ! -d "$backup_dir" ]; then
        info "No backups found (directory does not exist: $backup_dir)"
        exit 0
    fi

    echo ""
    info "Available backups in $backup_dir:"
    echo ""

    ls -lht "$backup_dir"/sentinel_*.db 2>/dev/null | while IFS= read -r line; do
        echo "  $line"
    done

    local count
    count=$(ls -1 "$backup_dir"/sentinel_*.db 2>/dev/null | wc -l)
    echo ""
    info "Total: $count backup(s)"
}

# ── Main ─────────────────────────────────────────────────────
if [ $# -eq 0 ]; then
    error "Usage: bash scripts/restore.sh <backup_file>"
    error "       bash scripts/restore.sh --list"
    error "       bash scripts/restore.sh --latest"
    exit 1
fi

case "$1" in
    --list)
        list_backups
        exit 0
        ;;
    --latest)
        DB_PATH="$(find_db)"
        if [ -z "$DB_PATH" ]; then
            error "Could not find sentinel.db"
            exit 1
        fi
        BACKUP_DIR="$(find_backup_dir "$DB_PATH")"
        BACKUP_FILE=$(ls -1t "$BACKUP_DIR"/sentinel_*.db 2>/dev/null | head -1)
        if [ -z "$BACKUP_FILE" ]; then
            error "No backups found in $BACKUP_DIR"
            exit 1
        fi
        info "Using most recent backup: $BACKUP_FILE"
        ;;
    *)
        BACKUP_FILE="$1"
        DB_PATH="$(find_db)"
        if [ -z "$DB_PATH" ]; then
            error "Could not find sentinel.db. Set SENTINEL_DB environment variable."
            exit 1
        fi
        ;;
esac

# ── Validate backup file ────────────────────────────────────
if [ ! -f "$BACKUP_FILE" ]; then
    error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

BACKUP_FILE="$(cd "$(dirname "$BACKUP_FILE")" && pwd)/$(basename "$BACKUP_FILE")"
DB_PATH="$(cd "$(dirname "$DB_PATH")" && pwd)/$(basename "$DB_PATH")"

info "Backup file: $BACKUP_FILE"
info "Target DB:   $DB_PATH"

# ── Step 1: Verify backup integrity ─────────────────────────
info "Verifying backup integrity..."
INTEGRITY=$(sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" 2>&1)
if [ "$INTEGRITY" != "ok" ]; then
    error "Backup file failed integrity check: $INTEGRITY"
    error "Cannot restore from a corrupt backup."
    exit 1
fi
ok "Backup integrity verified"

# ── Step 2: Safety backup of current database ────────────────
if [ -f "$DB_PATH" ]; then
    SAFETY_BACKUP="${DB_PATH}.pre_restore_$(date +%Y%m%d_%H%M%S)"
    info "Creating safety backup of current database..."
    sqlite3 "$DB_PATH" ".backup '$SAFETY_BACKUP'" 2>/dev/null || cp "$DB_PATH" "$SAFETY_BACKUP"
    ok "Safety backup: $SAFETY_BACKUP"
fi

# ── Step 3: Confirm restore ─────────────────────────────────
BACKUP_SIZE=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE" 2>/dev/null)
echo ""
warn "This will REPLACE the current database with the backup."
warn "Backup size: $(numfmt --to=iec "$BACKUP_SIZE" 2>/dev/null || echo "${BACKUP_SIZE} bytes")"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Restore cancelled."
    exit 0
fi

# ── Step 4: Remove WAL/SHM files ────────────────────────────
info "Cleaning WAL/SHM files..."
rm -f "${DB_PATH}-wal" "${DB_PATH}-shm" "${DB_PATH}-journal"

# ── Step 5: Restore from backup ─────────────────────────────
info "Restoring database..."
sqlite3 "$BACKUP_FILE" ".backup '$DB_PATH'"

# ── Step 6: Verify restored database ────────────────────────
info "Verifying restored database..."
RESTORED_INTEGRITY=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;" 2>&1)
if [ "$RESTORED_INTEGRITY" != "ok" ]; then
    error "Restored database failed integrity check!"
    if [ -n "${SAFETY_BACKUP:-}" ] && [ -f "$SAFETY_BACKUP" ]; then
        warn "Reverting to safety backup..."
        cp "$SAFETY_BACKUP" "$DB_PATH"
    fi
    exit 1
fi

# ── Report ───────────────────────────────────────────────────
ROW_COUNTS=$(sqlite3 "$DB_PATH" "
    SELECT 'commands: ' || COUNT(*) FROM commands;
    SELECT 'incidents: ' || COUNT(*) FROM incidents;
    SELECT 'users: ' || COUNT(*) FROM users;
" 2>/dev/null || echo "(could not count rows)")

echo ""
ok "============================================="
ok "  Database restored successfully"
ok "============================================="
echo ""
info "Restored from: $BACKUP_FILE"
info "Target:        $DB_PATH"
if [ -n "${SAFETY_BACKUP:-}" ]; then
    info "Safety backup: $SAFETY_BACKUP"
fi
echo ""
info "Row counts:"
echo "$ROW_COUNTS" | while IFS= read -r line; do
    info "  $line"
done
echo ""
