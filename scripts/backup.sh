#!/bin/bash
# SignedByMe Database Backup Script
# Run daily via cron: 0 3 * * * /opt/sbm-api/scripts/backup.sh
#
# Creates timestamped SQLite backups with rotation (keeps last 30 days)
# Backup location: /opt/sbm-api/backups/

set -euo pipefail

# Configuration
DB_PATH="${SBM_DB_PATH:-/opt/sbm-api/signedby.db}"
BACKUP_DIR="${SBM_BACKUP_DIR:-/opt/sbm-api/backups}"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/signedby_${TIMESTAMP}.db"

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

# Check if database exists
if [ ! -f "${DB_PATH}" ]; then
    echo "ERROR: Database not found at ${DB_PATH}"
    exit 1
fi

echo "Starting backup: ${DB_PATH} -> ${BACKUP_FILE}"

# Create backup using Python's sqlite3 backup API (safe for live database)
python3 << EOF
import sqlite3
import os
import sys

source_path = "${DB_PATH}"
dest_path = "${BACKUP_FILE}"

try:
    source = sqlite3.connect(source_path)
    dest = sqlite3.connect(dest_path)
    source.backup(dest)
    dest.close()
    source.close()
    
    # Verify backup integrity
    check = sqlite3.connect(dest_path)
    result = check.execute("PRAGMA integrity_check;").fetchone()[0]
    check.close()
    
    if result != "ok":
        print(f"ERROR: Backup integrity check failed: {result}")
        os.remove(dest_path)
        sys.exit(1)
    
    print(f"Backup created successfully: {dest_path}")
    print(f"Size: {os.path.getsize(dest_path)} bytes")
    
except Exception as e:
    print(f"ERROR: Backup failed: {e}")
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    echo "Backup failed"
    exit 1
fi

# Compress backup
gzip "${BACKUP_FILE}"
echo "Compressed: ${BACKUP_FILE}.gz"

# Remove old backups (older than RETENTION_DAYS)
echo "Removing backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "signedby_*.db.gz" -type f -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

# List current backups
echo ""
echo "Current backups:"
ls -lh "${BACKUP_DIR}"/signedby_*.db.gz 2>/dev/null || echo "  (none)"

echo ""
echo "Backup complete."
