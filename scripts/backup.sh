#!/bin/bash
# =============================================================================
# SignedByMe Daily Backup Script (Phase 26)
# =============================================================================
#
# Per Bible Section 13.12b: Automated SQLite backup to DO Spaces
# 
# What's backed up:
#   - SQLite database (sessions, roots, enrollments)
#   - OIDC signing key (if present)
#   - clients.json
#
# NOT backed up (too large, can be regenerated):
#   - Proving key / verification key
#
# Usage:
#   ./backup.sh              # Run backup
#   ./backup.sh --restore    # List available backups
#   ./backup.sh --restore <filename>  # Restore specific backup
#
# Cron setup (run daily at 3 AM):
#   0 3 * * * /opt/sbm-api/scripts/backup.sh >> /var/log/sbm-backup.log 2>&1
#
# Requirements:
#   - sqlite3
#   - gzip  
#   - s3cmd (for DO Spaces) OR aws cli
#   - Environment vars: DO_SPACES_KEY, DO_SPACES_SECRET, DO_SPACES_BUCKET
#
# =============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}/.."
DATA_DIR="${APP_DIR}/app/var"
KEYS_DIR="${APP_DIR}/keys"
BACKUP_DIR="/tmp/sbm-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="signedby_backup_${TIMESTAMP}"
RETENTION_DAYS=30

# DO Spaces configuration (set via environment)
DO_SPACES_ENDPOINT="${DO_SPACES_ENDPOINT:-nyc3.digitaloceanspaces.com}"
DO_SPACES_BUCKET="${DO_SPACES_BUCKET:-}"
DO_SPACES_KEY="${DO_SPACES_KEY:-}"
DO_SPACES_SECRET="${DO_SPACES_SECRET:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

check_requirements() {
    for cmd in sqlite3 gzip; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is required but not installed"
            exit 1
        fi
    done
}

create_backup() {
    log_info "Starting SignedByMe backup..."
    
    # Create backup directory
    mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"
    
    # 1. Backup SQLite database using online backup API
    DB_FILE="${DATA_DIR}/signedby.db"
    if [[ -f "${DB_FILE}" ]]; then
        log_info "Backing up SQLite database..."
        sqlite3 "${DB_FILE}" ".backup '${BACKUP_DIR}/${BACKUP_NAME}/signedby.db'"
        
        # Verify backup integrity
        if ! sqlite3 "${BACKUP_DIR}/${BACKUP_NAME}/signedby.db" "PRAGMA integrity_check;" | grep -q "ok"; then
            log_error "Database backup integrity check failed!"
            exit 1
        fi
        log_info "Database backup verified OK"
    else
        log_warn "Database file not found: ${DB_FILE}"
    fi
    
    # 2. Backup OIDC signing key (critical!)
    if [[ -f "${KEYS_DIR}/oidc_rs256.pem" ]]; then
        log_info "Backing up OIDC signing key..."
        cp "${KEYS_DIR}/oidc_rs256.pem" "${BACKUP_DIR}/${BACKUP_NAME}/"
        cp "${KEYS_DIR}/jwks.json" "${BACKUP_DIR}/${BACKUP_NAME}/" 2>/dev/null || true
    else
        log_warn "OIDC signing key not found"
    fi
    
    # 3. Backup clients.json
    CLIENTS_FILE="${APP_DIR}/clients.json"
    if [[ -f "${CLIENTS_FILE}" ]]; then
        log_info "Backing up clients.json..."
        cp "${CLIENTS_FILE}" "${BACKUP_DIR}/${BACKUP_NAME}/"
    fi
    
    # 4. Create manifest
    cat > "${BACKUP_DIR}/${BACKUP_NAME}/manifest.json" << EOF
{
    "timestamp": "${TIMESTAMP}",
    "created_at": "$(date -Iseconds)",
    "version": "phase26",
    "files": [
        $(ls -1 "${BACKUP_DIR}/${BACKUP_NAME}" | grep -v manifest.json | sed 's/^/"/' | sed 's/$/"/' | paste -sd,)
    ]
}
EOF
    
    # 5. Compress backup
    log_info "Compressing backup..."
    cd "${BACKUP_DIR}"
    tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}"
    rm -rf "${BACKUP_NAME}"
    
    BACKUP_SIZE=$(du -h "${BACKUP_NAME}.tar.gz" | cut -f1)
    log_info "Backup created: ${BACKUP_NAME}.tar.gz (${BACKUP_SIZE})"
    
    # 6. Upload to DO Spaces (if configured)
    if [[ -n "${DO_SPACES_BUCKET}" && -n "${DO_SPACES_KEY}" ]]; then
        upload_to_spaces "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    else
        log_warn "DO Spaces not configured - backup stored locally only"
        log_info "Set DO_SPACES_BUCKET, DO_SPACES_KEY, DO_SPACES_SECRET to enable remote backup"
    fi
    
    # 7. Cleanup old local backups
    cleanup_old_backups
    
    log_info "Backup complete!"
}

upload_to_spaces() {
    local backup_file="$1"
    local filename=$(basename "${backup_file}")
    
    log_info "Uploading to DO Spaces: ${DO_SPACES_BUCKET}..."
    
    # Use s3cmd if available, otherwise try aws cli
    if command -v s3cmd &> /dev/null; then
        s3cmd put "${backup_file}" "s3://${DO_SPACES_BUCKET}/backups/${filename}" \
            --access_key="${DO_SPACES_KEY}" \
            --secret_key="${DO_SPACES_SECRET}" \
            --host="${DO_SPACES_ENDPOINT}" \
            --host-bucket="%(bucket)s.${DO_SPACES_ENDPOINT}"
    elif command -v aws &> /dev/null; then
        AWS_ACCESS_KEY_ID="${DO_SPACES_KEY}" \
        AWS_SECRET_ACCESS_KEY="${DO_SPACES_SECRET}" \
        aws s3 cp "${backup_file}" "s3://${DO_SPACES_BUCKET}/backups/${filename}" \
            --endpoint-url="https://${DO_SPACES_ENDPOINT}"
    else
        log_warn "Neither s3cmd nor aws cli available - skipping upload"
        return 1
    fi
    
    log_info "Upload complete"
}

cleanup_old_backups() {
    log_info "Cleaning up backups older than ${RETENTION_DAYS} days..."
    
    # Local cleanup
    find "${BACKUP_DIR}" -name "signedby_backup_*.tar.gz" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
    
    # Remote cleanup (if configured)
    if [[ -n "${DO_SPACES_BUCKET}" && -n "${DO_SPACES_KEY}" ]]; then
        # List and delete old backups from DO Spaces
        if command -v s3cmd &> /dev/null; then
            s3cmd ls "s3://${DO_SPACES_BUCKET}/backups/" \
                --access_key="${DO_SPACES_KEY}" \
                --secret_key="${DO_SPACES_SECRET}" \
                --host="${DO_SPACES_ENDPOINT}" \
                --host-bucket="%(bucket)s.${DO_SPACES_ENDPOINT}" 2>/dev/null | \
            while read -r line; do
                backup_date=$(echo "$line" | awk '{print $1}')
                backup_file=$(echo "$line" | awk '{print $4}')
                if [[ $(date -d "${backup_date}" +%s 2>/dev/null || echo 0) -lt $(date -d "-${RETENTION_DAYS} days" +%s) ]]; then
                    log_info "Deleting old backup: ${backup_file}"
                    s3cmd del "${backup_file}" \
                        --access_key="${DO_SPACES_KEY}" \
                        --secret_key="${DO_SPACES_SECRET}" \
                        --host="${DO_SPACES_ENDPOINT}" \
                        --host-bucket="%(bucket)s.${DO_SPACES_ENDPOINT}" 2>/dev/null || true
                fi
            done
        fi
    fi
}

list_backups() {
    log_info "Available backups:"
    
    # Local backups
    echo -e "\n${GREEN}Local backups:${NC}"
    ls -lh "${BACKUP_DIR}"/signedby_backup_*.tar.gz 2>/dev/null || echo "  (none)"
    
    # Remote backups (if configured)
    if [[ -n "${DO_SPACES_BUCKET}" && -n "${DO_SPACES_KEY}" ]]; then
        echo -e "\n${GREEN}Remote backups (DO Spaces):${NC}"
        if command -v s3cmd &> /dev/null; then
            s3cmd ls "s3://${DO_SPACES_BUCKET}/backups/" \
                --access_key="${DO_SPACES_KEY}" \
                --secret_key="${DO_SPACES_SECRET}" \
                --host="${DO_SPACES_ENDPOINT}" \
                --host-bucket="%(bucket)s.${DO_SPACES_ENDPOINT}" 2>/dev/null || echo "  (none or not configured)"
        fi
    fi
}

restore_backup() {
    local backup_file="$1"
    
    if [[ -z "${backup_file}" ]]; then
        list_backups
        echo -e "\n${YELLOW}Usage: ./backup.sh --restore <backup_file>${NC}"
        exit 1
    fi
    
    # Check if backup exists locally or remotely
    if [[ ! -f "${backup_file}" ]]; then
        # Try to download from DO Spaces
        if [[ -n "${DO_SPACES_BUCKET}" && -n "${DO_SPACES_KEY}" ]]; then
            log_info "Downloading backup from DO Spaces..."
            local remote_path="s3://${DO_SPACES_BUCKET}/backups/$(basename ${backup_file})"
            if command -v s3cmd &> /dev/null; then
                s3cmd get "${remote_path}" "${backup_file}" \
                    --access_key="${DO_SPACES_KEY}" \
                    --secret_key="${DO_SPACES_SECRET}" \
                    --host="${DO_SPACES_ENDPOINT}" \
                    --host-bucket="%(bucket)s.${DO_SPACES_ENDPOINT}" || {
                    log_error "Failed to download backup"
                    exit 1
                }
            fi
        else
            log_error "Backup file not found: ${backup_file}"
            exit 1
        fi
    fi
    
    log_info "Restoring from: ${backup_file}"
    
    # Create restore directory
    RESTORE_DIR="${BACKUP_DIR}/restore_${TIMESTAMP}"
    mkdir -p "${RESTORE_DIR}"
    
    # Extract backup
    tar -xzf "${backup_file}" -C "${RESTORE_DIR}"
    
    # Find the extracted directory
    EXTRACTED_DIR=$(ls -d "${RESTORE_DIR}"/*/ 2>/dev/null | head -1)
    
    # Restore database
    if [[ -f "${EXTRACTED_DIR}/signedby.db" ]]; then
        log_info "Restoring database..."
        # Stop the server first (if running as service)
        systemctl stop sbm-api 2>/dev/null || true
        
        # Backup current database
        if [[ -f "${DATA_DIR}/signedby.db" ]]; then
            mv "${DATA_DIR}/signedby.db" "${DATA_DIR}/signedby.db.pre-restore"
        fi
        
        cp "${EXTRACTED_DIR}/signedby.db" "${DATA_DIR}/"
        log_info "Database restored"
    fi
    
    # Restore OIDC key
    if [[ -f "${EXTRACTED_DIR}/oidc_rs256.pem" ]]; then
        log_info "Restoring OIDC signing key..."
        mkdir -p "${KEYS_DIR}"
        cp "${EXTRACTED_DIR}/oidc_rs256.pem" "${KEYS_DIR}/"
        cp "${EXTRACTED_DIR}/jwks.json" "${KEYS_DIR}/" 2>/dev/null || true
        log_info "OIDC key restored"
    fi
    
    # Restore clients.json
    if [[ -f "${EXTRACTED_DIR}/clients.json" ]]; then
        log_info "Restoring clients.json..."
        cp "${EXTRACTED_DIR}/clients.json" "${APP_DIR}/"
        log_info "clients.json restored"
    fi
    
    # Restart service
    systemctl start sbm-api 2>/dev/null || true
    
    # Cleanup
    rm -rf "${RESTORE_DIR}"
    
    log_info "Restore complete!"
    log_info "Please verify: GET /health should return 200"
}

# Main
check_requirements

case "${1:-}" in
    --restore)
        restore_backup "${2:-}"
        ;;
    --list)
        list_backups
        ;;
    *)
        create_backup
        ;;
esac
