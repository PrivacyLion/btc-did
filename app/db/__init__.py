"""
SignedByMe Database Module

Phase 26: Simplified architecture with NOSTR-native authorization

Tables:
- merkle_leaves: Stores leaf commitments with authorization_event reference
- merkle_roots: Published roots per tree (last 30 valid)
- login_verifications: Successful login receipts
- merkle_trees: Incremental tree state
- merkle_witnesses: Per-leaf membership witnesses
- audit_log: Optional debugging

Key change: enrollment_id eliminated — kind 28200 NOSTR event signature IS the authorization
"""

import sqlite3
import json
import logging
import time
from pathlib import Path
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

logger = logging.getLogger("db")

# Database location
DB_DIR = Path(__file__).resolve().parents[1] / "var"
DB_PATH = DB_DIR / "signedby.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Connection pool (single connection for SQLite)
_connection: Optional[sqlite3.Connection] = None


def get_connection() -> sqlite3.Connection:
    """Get or create database connection."""
    global _connection
    if _connection is None:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        _connection = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _connection.row_factory = sqlite3.Row
        _connection.execute("PRAGMA foreign_keys = ON")
        _connection.execute("PRAGMA journal_mode = WAL")
        _init_schema(_connection)
    return _connection


def _init_schema(conn: sqlite3.Connection) -> None:
    """Initialize database schema if needed (safe for existing tables)."""
    if SCHEMA_PATH.exists():
        schema_sql = SCHEMA_PATH.read_text()
        # Execute each statement separately to handle partial failures gracefully
        # CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS are safe
        for statement in schema_sql.split(';'):
            statement = statement.strip()
            if statement and not statement.startswith('--'):
                try:
                    conn.execute(statement)
                except sqlite3.OperationalError as e:
                    # Log but continue - table/index may already exist with different schema
                    if "already exists" not in str(e).lower():
                        logger.debug(f"Schema statement skipped: {e}")
        conn.commit()
        logger.info(f"Database schema checked at {DB_PATH}")
    
    # Run migrations for columns added after initial deployment
    _run_migrations(conn)


def _run_migrations(conn: sqlite3.Connection) -> None:
    """
    Run migrations to add missing columns to existing tables.
    
    Uses ALTER TABLE ADD COLUMN for each missing column.
    SQLite doesn't support IF NOT EXISTS for ADD COLUMN, so we check first.
    Never wipes data - additive only.
    """
    # Define expected columns per table: {table: [(column_name, column_def), ...]}
    # column_def includes type and DEFAULT if any (constraints stripped for ALTER)
    expected_columns = {
        "schema_version": [
            ("version", "INTEGER"),
            ("applied_at", "TEXT DEFAULT (datetime('now'))"),
        ],
        "merkle_leaves": [
            ("id", "INTEGER"),
            ("tree_id", "TEXT"),
            ("leaf_index", "INTEGER"),
            ("leaf_commitment", "TEXT"),
            ("authorization_event_id", "TEXT"),
            ("authorization_pubkey", "TEXT"),
            ("created_at", "INTEGER DEFAULT (strftime('%s', 'now'))"),
        ],
        "merkle_roots": [
            ("id", "INTEGER"),
            ("tree_id", "TEXT"),
            ("root_hash", "TEXT"),
            ("leaf_index", "INTEGER"),
            ("created_at", "INTEGER DEFAULT (strftime('%s', 'now'))"),
        ],
        "login_verifications": [
            ("id", "INTEGER"),
            ("npub", "TEXT"),
            ("client_id", "TEXT"),
            ("merkle_root", "TEXT"),
            ("login_event_id", "TEXT"),
            ("payment_hash_user", "TEXT"),
            ("payment_hash_operator", "TEXT"),
            ("verified_at", "INTEGER"),
        ],
        "merkle_trees": [
            ("id", "TEXT"),
            ("client_id", "TEXT"),
            ("purpose", "TEXT"),
            ("depth", "INTEGER DEFAULT 20"),
            ("next_leaf_index", "INTEGER DEFAULT 0"),
            ("state_json", "TEXT DEFAULT '[]'"),
            ("created_at", "INTEGER DEFAULT (strftime('%s', 'now'))"),
            ("updated_at", "INTEGER DEFAULT (strftime('%s', 'now'))"),
        ],
        "merkle_witnesses": [
            ("leaf_id", "INTEGER"),
            ("tree_id", "TEXT"),
            ("siblings_json", "TEXT"),
            ("path_bits_json", "TEXT"),
            ("leaf_index", "INTEGER"),
            ("root_hash", "TEXT"),
        ],
        "audit_log": [
            ("id", "INTEGER"),
            ("event_type", "TEXT"),
            ("client_id", "TEXT"),
            ("session_id", "TEXT"),
            ("details_json", "TEXT"),
            ("created_at", "INTEGER DEFAULT (strftime('%s', 'now'))"),
        ],
        # enrollment_nonces table REMOVED — Phase 26
        # Nonce eliminated. Authorization via kind 28200 NOSTR event signature.
        "used_event_ids": [
            ("event_id", "TEXT"),
            ("client_id", "TEXT"),
            ("used_at", "INTEGER DEFAULT (strftime('%s', 'now'))"),
        ],
    }
    
    migrations_run = 0
    existing_tables = _get_tables(conn)
    
    for table, columns in expected_columns.items():
        if table not in existing_tables:
            # Table doesn't exist - _init_schema CREATE TABLE handles it
            continue
        
        # Get existing columns
        existing_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        
        # Add missing columns
        for col_name, col_def in columns:
            if col_name not in existing_cols:
                try:
                    alter_sql = f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}"
                    conn.execute(alter_sql)
                    logger.info(f"Migration: Added column {table}.{col_name}")
                    migrations_run += 1
                except sqlite3.OperationalError as e:
                    if "duplicate column name" not in str(e).lower():
                        logger.warning(f"Migration failed for {table}.{col_name}: {e}")
    
    if migrations_run > 0:
        conn.commit()
        logger.info(f"Database migrations complete: {migrations_run} columns added")


def _get_tables(conn: sqlite3.Connection) -> List[str]:
    """Get list of existing tables."""
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [row[0] for row in cursor.fetchall()]


@contextmanager
def transaction():
    """Context manager for database transactions."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ============================================================================
# MERKLE LEAVES (Phase 26)
# Authorization via kind 28200 NOSTR event signature
# ============================================================================

def add_merkle_leaf(
    tree_id: str,
    leaf_index: int,
    leaf_commitment: str,
    authorization_event_id: str,
    authorization_pubkey: str,
) -> int:
    """
    Add a leaf to the Merkle tree.
    
    Phase 26: Authorization is the kind 28200 NOSTR event signature.
    No enrollment_id needed.
    
    Returns: leaf_id (primary key)
    """
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO merkle_leaves 
        (tree_id, leaf_index, leaf_commitment, authorization_event_id, authorization_pubkey)
        VALUES (?, ?, ?, ?, ?)
    """, (tree_id, leaf_index, leaf_commitment, authorization_event_id, authorization_pubkey))
    conn.commit()
    return cursor.lastrowid


def get_merkle_leaf(tree_id: str, leaf_commitment: str) -> Optional[Dict[str, Any]]:
    """Get leaf by tree_id and commitment."""
    conn = get_connection()
    row = conn.execute("""
        SELECT * FROM merkle_leaves 
        WHERE tree_id = ? AND leaf_commitment = ?
    """, (tree_id, leaf_commitment)).fetchone()
    return dict(row) if row else None


def get_merkle_leaf_by_id(leaf_id: int) -> Optional[Dict[str, Any]]:
    """Get leaf by primary key."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM merkle_leaves WHERE id = ?",
        (leaf_id,)
    ).fetchone()
    return dict(row) if row else None


def get_merkle_leaf_by_event(authorization_event_id: str) -> Optional[Dict[str, Any]]:
    """Get leaf by authorization event ID (for dedup)."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM merkle_leaves WHERE authorization_event_id = ?",
        (authorization_event_id,)
    ).fetchone()
    return dict(row) if row else None


def list_merkle_leaves(
    tree_id: str,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List leaves for a tree."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM merkle_leaves 
        WHERE tree_id = ?
        ORDER BY leaf_index ASC
        LIMIT ? OFFSET ?
    """, (tree_id, limit, offset)).fetchall()
    return [dict(row) for row in rows]


def count_merkle_leaves(tree_id: str) -> int:
    """Count leaves in a tree."""
    conn = get_connection()
    return conn.execute(
        "SELECT COUNT(*) FROM merkle_leaves WHERE tree_id = ?",
        (tree_id,)
    ).fetchone()[0]


def leaf_commitment_exists(tree_id: str, leaf_commitment: str) -> bool:
    """Check if a leaf commitment already exists in tree (prevents duplicates)."""
    conn = get_connection()
    row = conn.execute("""
        SELECT 1 FROM merkle_leaves 
        WHERE tree_id = ? AND leaf_commitment = ?
        LIMIT 1
    """, (tree_id, leaf_commitment)).fetchone()
    return row is not None


# ============================================================================
# MERKLE ROOTS
# Published roots per tree (last 30 valid)
# ============================================================================

def add_merkle_root(
    tree_id: str,
    root_hash: str,
    leaf_index: int,
) -> int:
    """Add a root to history. Returns row ID."""
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO merkle_roots (tree_id, root_hash, leaf_index)
        VALUES (?, ?, ?)
    """, (tree_id, root_hash, leaf_index))
    conn.commit()
    return cursor.lastrowid


def get_valid_roots(tree_id: str, limit: int = 30) -> List[str]:
    """Get last N valid roots for a tree."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT root_hash FROM merkle_roots
        WHERE tree_id = ?
        ORDER BY id DESC
        LIMIT ?
    """, (tree_id, limit)).fetchall()
    return [row[0] for row in rows]


def is_root_valid(tree_id: str, root_hash: str, limit: int = 30) -> bool:
    """Check if a root is in the valid window."""
    valid_roots = get_valid_roots(tree_id, limit)
    return root_hash in valid_roots


def get_current_root(tree_id: str) -> Optional[str]:
    """Get the most recent root for a tree."""
    conn = get_connection()
    row = conn.execute("""
        SELECT root_hash FROM merkle_roots
        WHERE tree_id = ?
        ORDER BY id DESC
        LIMIT 1
    """, (tree_id,)).fetchone()
    return row[0] if row else None


def is_root_valid_for_client(client_id: str, root_hash: str, limit: int = 30) -> bool:
    """
    Check if a merkle root is valid for ANY tree belonging to a client.
    """
    conn = get_connection()
    
    # Find all trees for this client
    trees = conn.execute(
        "SELECT id FROM merkle_trees WHERE client_id = ?",
        (client_id,)
    ).fetchall()
    
    if not trees:
        return False
    
    tree_ids = [t[0] for t in trees]
    
    # Check if root_hash is in any of these trees' recent roots
    placeholders = ",".join("?" * len(tree_ids))
    row = conn.execute(f"""
        SELECT 1 FROM merkle_roots
        WHERE tree_id IN ({placeholders}) AND root_hash = ?
        AND id >= (
            SELECT COALESCE(MIN(cutoff.id), 0)
            FROM (
                SELECT id FROM merkle_roots
                WHERE tree_id IN ({placeholders})
                ORDER BY id DESC
                LIMIT ?
            ) cutoff
        )
        LIMIT 1
    """, tree_ids + [root_hash] + tree_ids + [limit]).fetchone()
    
    return row is not None


# ============================================================================
# LOGIN VERIFICATIONS
# Log of successful logins (receipts for audit)
# ============================================================================

def log_verification(
    npub: str,
    client_id: str,
    merkle_root: str,
    payment_hash_user: Optional[str] = None,
    payment_hash_operator: Optional[str] = None,
    verified_at: Optional[int] = None,
    login_event_id: Optional[str] = None,
) -> int:
    """Log a successful login verification. Returns the row ID."""
    import time
    if verified_at is None:
        verified_at = int(time.time())
    
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO login_verifications
        (npub, client_id, merkle_root, payment_hash_user, payment_hash_operator, verified_at, login_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (npub, client_id, merkle_root, payment_hash_user, payment_hash_operator, verified_at, login_event_id))
    conn.commit()
    return cursor.lastrowid


def get_verification_by_event(login_event_id: str) -> Optional[Dict[str, Any]]:
    """Get verification by NOSTR event ID (for dedup)."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM login_verifications WHERE login_event_id = ?",
        (login_event_id,)
    ).fetchone()
    return dict(row) if row else None


def get_verifications(
    client_id: Optional[str] = None,
    npub: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get login verifications with optional filters."""
    conn = get_connection()
    query = "SELECT * FROM login_verifications WHERE 1=1"
    params = []
    
    if client_id:
        query += " AND client_id = ?"
        params.append(client_id)
    if npub:
        query += " AND npub = ?"
        params.append(npub)
    
    query += " ORDER BY verified_at DESC LIMIT ?"
    params.append(limit)
    
    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def count_verifications(client_id: Optional[str] = None) -> int:
    """Get total count of login verifications."""
    conn = get_connection()
    if client_id:
        return conn.execute(
            "SELECT COUNT(*) FROM login_verifications WHERE client_id = ?",
            (client_id,)
        ).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM login_verifications").fetchone()[0]


# ============================================================================
# MERKLE TREES (state tracking)
# Stores incremental tree state for O(log n) updates
# ============================================================================

def create_merkle_tree(
    tree_id: str,
    client_id: str,
    purpose: str,
    depth: int = 20,
) -> None:
    """Create a new incremental Merkle tree."""
    conn = get_connection()
    # Initialize with empty state (zeros at each level)
    initial_state = ["0" * 64] * depth  # 32-byte zeros as hex
    conn.execute("""
        INSERT OR IGNORE INTO merkle_trees (id, client_id, purpose, depth, state_json)
        VALUES (?, ?, ?, ?, ?)
    """, (tree_id, client_id, purpose, depth, json.dumps(initial_state)))
    conn.commit()


def get_merkle_tree(tree_id: str) -> Optional[Dict[str, Any]]:
    """Get Merkle tree state."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM merkle_trees WHERE id = ?",
        (tree_id,)
    ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["state"] = json.loads(result["state_json"])
    return result


def update_merkle_tree(
    tree_id: str,
    next_leaf_index: int,
    state: List[str],
) -> None:
    """Update Merkle tree state after insertion."""
    import time
    conn = get_connection()
    conn.execute("""
        UPDATE merkle_trees 
        SET next_leaf_index = ?, state_json = ?, updated_at = ?
        WHERE id = ?
    """, (next_leaf_index, json.dumps(state), int(time.time()), tree_id))
    conn.commit()


def list_merkle_trees(client_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all Merkle trees, optionally filtered by client."""
    conn = get_connection()
    if client_id:
        rows = conn.execute(
            "SELECT * FROM merkle_trees WHERE client_id = ? ORDER BY created_at DESC",
            (client_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM merkle_trees ORDER BY created_at DESC"
        ).fetchall()
    
    results = []
    for row in rows:
        r = dict(row)
        r["state"] = json.loads(r["state_json"])
        results.append(r)
    return results


# ============================================================================
# MERKLE WITNESSES
# Per-leaf witnesses for proving membership
# ============================================================================

def save_witness(
    leaf_id: int,
    tree_id: str,
    siblings: List[str],
    path_bits: List[int],
    leaf_index: int,
    root_hash: str,
) -> None:
    """Save a witness for a leaf."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO merkle_witnesses
        (leaf_id, tree_id, siblings_json, path_bits_json, leaf_index, root_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (leaf_id, tree_id, json.dumps(siblings), json.dumps(path_bits), leaf_index, root_hash))
    conn.commit()


def get_witness(leaf_id: int) -> Optional[Dict[str, Any]]:
    """Get witness for a leaf."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM merkle_witnesses WHERE leaf_id = ?",
        (leaf_id,)
    ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["siblings"] = json.loads(result["siblings_json"])
    result["path_bits"] = json.loads(result["path_bits_json"])
    return result


def get_witness_by_commitment(tree_id: str, leaf_commitment: str) -> Optional[Dict[str, Any]]:
    """Get witness by tree_id and leaf_commitment."""
    leaf = get_merkle_leaf(tree_id, leaf_commitment)
    if not leaf:
        return None
    return get_witness(leaf["id"])


# ============================================================================
# AUDIT LOG
# ============================================================================

def audit_log(
    event_type: str,
    client_id: Optional[str] = None,
    session_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log an audit event."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_log (event_type, client_id, session_id, details_json)
        VALUES (?, ?, ?, ?)
    """, (event_type, client_id, session_id, json.dumps(details) if details else None))
    conn.commit()


# ============================================================================
# SESSION MANAGEMENT (for polling flow compatibility)
# ============================================================================

def create_session(
    session_id: str,
    client_id: str,
    nonce: str,
    expires_at: int,
) -> None:
    """Create a login session (for RP polling flow)."""
    conn = get_connection()
    # Use audit_log table for lightweight session storage
    conn.execute("""
        INSERT INTO audit_log (event_type, client_id, session_id, details_json)
        VALUES ('session_created', ?, ?, ?)
    """, (client_id, session_id, json.dumps({"nonce": nonce, "expires_at": expires_at, "status": "pending"})))
    conn.commit()


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session by ID."""
    conn = get_connection()
    row = conn.execute("""
        SELECT * FROM audit_log 
        WHERE event_type = 'session_created' AND session_id = ?
        ORDER BY created_at DESC LIMIT 1
    """, (session_id,)).fetchone()
    if not row:
        return None
    result = dict(row)
    if result.get("details_json"):
        result.update(json.loads(result["details_json"]))
    return result


def complete_session(
    session_id: str,
    npub: str,
    merkle_root: str,
) -> None:
    """Mark session as completed."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_log (event_type, client_id, session_id, details_json)
        VALUES ('session_completed', NULL, ?, ?)
    """, (session_id, json.dumps({"npub": npub, "merkle_root": merkle_root, "status": "completed"})))
    conn.commit()


# ============================================================================
# STATS
# ============================================================================

def get_stats() -> Dict[str, int]:
    """Get database statistics."""
    conn = get_connection()
    
    # Check which tables exist
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    table_names = [t[0] for t in tables]
    
    stats = {}
    
    if "merkle_leaves" in table_names:
        stats["leaves"] = conn.execute("SELECT COUNT(*) FROM merkle_leaves").fetchone()[0]
    
    if "merkle_roots" in table_names:
        stats["roots"] = conn.execute("SELECT COUNT(*) FROM merkle_roots").fetchone()[0]
    
    if "merkle_trees" in table_names:
        stats["trees"] = conn.execute("SELECT COUNT(*) FROM merkle_trees").fetchone()[0]
    
    if "login_verifications" in table_names:
        stats["verifications"] = conn.execute("SELECT COUNT(*) FROM login_verifications").fetchone()[0]
    
    # Legacy table support
    if "enrollments" in table_names:
        stats["enrollments_legacy"] = conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0]
    
    return stats


# ============================================================================
# LEGACY COMPATIBILITY
# These functions support the old enrollment-based flow during migration
# ============================================================================

def create_enrollment(
    enrollment_id: str,
    client_id: str,
    purpose: str,
    leaf_commitment: str,
    email_hash: Optional[str] = None,
    status: str = "pending",
) -> None:
    """Legacy: Create enrollment (use add_merkle_leaf for Phase 26)."""
    logger.warning("create_enrollment is deprecated - use add_merkle_leaf")
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO enrollments (id, client_id, purpose, leaf_commitment, email_hash, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (enrollment_id, client_id, purpose, leaf_commitment, email_hash, status))
        conn.commit()
    except sqlite3.OperationalError:
        # Table doesn't exist in Phase 26 schema
        pass


def get_enrollment(enrollment_id: str) -> Optional[Dict[str, Any]]:
    """Legacy: Get enrollment by ID."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM enrollments WHERE id = ?",
            (enrollment_id,)
        ).fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError:
        return None


def list_enrollments(
    client_id: Optional[str] = None,
    purpose: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Legacy: List enrollments."""
    conn = get_connection()
    try:
        query = "SELECT * FROM enrollments WHERE 1=1"
        params = []
        
        if client_id:
            query += " AND client_id = ?"
            params.append(client_id)
        if purpose:
            query += " AND purpose = ?"
            params.append(purpose)
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    except sqlite3.OperationalError:
        return []


def update_enrollment(enrollment_id: str, **kwargs) -> None:
    """Legacy: Update enrollment."""
    if not kwargs:
        return
    conn = get_connection()
    try:
        fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [enrollment_id]
        conn.execute(f"UPDATE enrollments SET {fields} WHERE id = ?", values)
        conn.commit()
    except sqlite3.OperationalError:
        pass


def approve_enrollment(enrollment_id: str) -> None:
    """Legacy: Approve enrollment."""
    import time
    update_enrollment(enrollment_id, status="approved", approved_at=int(time.time()))


def reject_enrollment(enrollment_id: str) -> None:
    """Legacy: Reject enrollment."""
    import time
    update_enrollment(enrollment_id, status="rejected", rejected_at=int(time.time()))


# Enrollment nonce functions REMOVED — Phase 26
# Nonce eliminated. No server-generated secrets.
# Authorization via kind 28200 NOSTR event signature only.
# Replay protection via used_event_ids table.


# Used event IDs (replay protection for enterprise-generated kind 28200 events)
def is_event_id_used(event_id: str) -> bool:
    """Check if an authorization event ID has already been used."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM used_event_ids WHERE event_id = ?",
            (event_id,)
        ).fetchone()
        return row is not None
    except sqlite3.OperationalError:
        return False


def mark_event_id_used(event_id: str, client_id: str) -> None:
    """Mark an authorization event ID as used."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO used_event_ids (event_id, client_id) VALUES (?, ?)",
            (event_id, client_id)
        )
        conn.commit()
    except sqlite3.OperationalError:
        # Table might not exist yet - create it
        conn.execute("""
            CREATE TABLE IF NOT EXISTS used_event_ids (
                event_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                used_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)
        conn.execute(
            "INSERT INTO used_event_ids (event_id, client_id) VALUES (?, ?)",
            (event_id, client_id)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Already exists - that's fine
        pass


# Legacy stub functions (deprecated in Phase 26)
def create_enrollment_session(*args, **kwargs): pass
def get_enrollment_session(*args, **kwargs): return None
def mark_session_verified(*args, **kwargs): return False
def commit_enrollment_session(*args, **kwargs): return None
def delete_enrollment_session(*args, **kwargs): return False
def add_root_to_history(tree_id: str, root_hash: str, leaf_index: int) -> None:
    """Alias for add_merkle_root (backward compat)."""
    add_merkle_root(tree_id, root_hash, leaf_index)


# ============================================================================
# OIDC AUTHORIZATION CODES
# Stores temporary authorization codes for OAuth2/OIDC code flow
# ============================================================================

def create_oidc_code(
    code: str,
    client_id: str,
    iat: int,
    exp: int,
    redirect_uri: str,
    nonce: str,
    code_challenge: Optional[str] = None,
    code_challenge_method: str = "S256",
) -> None:
    """Store an OIDC authorization code."""
    conn = get_connection()
    # Ensure table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oidc_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            iat INTEGER NOT NULL,
            exp INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            nonce TEXT,
            code_challenge TEXT,
            code_challenge_method TEXT DEFAULT 'S256',
            used INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        INSERT INTO oidc_codes (code, client_id, iat, exp, redirect_uri, nonce, code_challenge, code_challenge_method)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (code, client_id, iat, exp, redirect_uri, nonce, code_challenge, code_challenge_method))
    conn.commit()


def get_oidc_code(code: str) -> Optional[Dict[str, Any]]:
    """Get an OIDC authorization code record."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM oidc_codes WHERE code = ? AND used = 0 AND exp > ?",
            (code, int(time.time()))
        ).fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError:
        return None


def use_oidc_code(code: str) -> None:
    """Mark an OIDC authorization code as used."""
    conn = get_connection()
    try:
        conn.execute("UPDATE oidc_codes SET used = 1 WHERE code = ?", (code,))
        conn.commit()
    except sqlite3.OperationalError:
        pass


# =============================================================================
# ROOT REGISTRY FUNCTIONS (for routes/roots.py)
# =============================================================================

def create_root(
    root_id: str,
    client_id: str,
    purpose: str,
    root_hash: str,
    tree_depth: int = 20,
    not_before: Optional[int] = None,
    expires_at: Optional[int] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new root entry.
    
    This creates/updates a merkle_tree and adds the root to merkle_roots.
    root_id becomes tree_id.
    """
    import time
    conn = get_connection()
    now = int(time.time())
    
    # Ensure tree exists
    existing_tree = get_merkle_tree(root_id)
    if not existing_tree:
        # Create tree
        conn.execute(
            """INSERT INTO merkle_trees (id, client_id, purpose, depth, next_leaf_index, state_json)
               VALUES (?, ?, ?, ?, 0, '[]')""",
            (root_id, client_id, purpose, tree_depth)
        )
    
    # Add root to merkle_roots
    cursor = conn.execute(
        """INSERT INTO merkle_roots (tree_id, root_hash, leaf_index, created_at)
           VALUES (?, ?, 0, ?)""",
        (root_id, root_hash, now)
    )
    conn.commit()
    
    return {
        "id": root_id,
        "client_id": client_id,
        "purpose": purpose,
        "root_hash": root_hash,
        "tree_depth": tree_depth,
        "created_at": now,
        "superseded_at": None,
    }


def get_root_by_id(root_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a root by its ID (tree_id).
    
    Returns the most recent root for this tree along with tree metadata.
    """
    conn = get_connection()
    
    # Get tree metadata
    tree = get_merkle_tree(root_id)
    if not tree:
        return None
    
    # Get most recent root for this tree
    row = conn.execute(
        """SELECT root_hash, created_at FROM merkle_roots 
           WHERE tree_id = ? ORDER BY created_at DESC LIMIT 1""",
        (root_id,)
    ).fetchone()
    
    if not row:
        return None
    
    return {
        "id": root_id,
        "client_id": tree["client_id"],
        "purpose": tree["purpose"],
        "root_hash": row["root_hash"],
        "tree_depth": tree["depth"],
        "created_at": row["created_at"],
        "superseded_at": None,  # Most recent is never superseded
    }


def get_active_root(client_id: str, purpose: str = "allowlist") -> Optional[Dict[str, Any]]:
    """
    Get the active root for a client and purpose.
    
    Returns the most recently created root for matching trees.
    """
    conn = get_connection()
    
    # Find trees for this client+purpose
    tree_row = conn.execute(
        """SELECT id, client_id, purpose, depth FROM merkle_trees 
           WHERE client_id = ? AND purpose = ?
           ORDER BY created_at DESC LIMIT 1""",
        (client_id, purpose)
    ).fetchone()
    
    if not tree_row:
        return None
    
    tree_id = tree_row["id"]
    
    # Get most recent root for this tree
    root_row = conn.execute(
        """SELECT root_hash, created_at FROM merkle_roots 
           WHERE tree_id = ? ORDER BY created_at DESC LIMIT 1""",
        (tree_id,)
    ).fetchone()
    
    if not root_row:
        return None
    
    return {
        "id": tree_id,
        "client_id": tree_row["client_id"],
        "purpose": tree_row["purpose"],
        "root_hash": root_row["root_hash"],
        "tree_depth": tree_row["depth"],
        "created_at": root_row["created_at"],
        "superseded_at": None,
    }


def list_roots(
    client_id: Optional[str] = None,
    active_only: bool = False,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    List roots, optionally filtered by client_id.
    
    If active_only=True, returns only the most recent root per tree.
    """
    conn = get_connection()
    results = []
    
    # Build query for trees
    tree_query = "SELECT id, client_id, purpose, depth FROM merkle_trees WHERE 1=1"
    tree_params = []
    
    if client_id:
        tree_query += " AND client_id = ?"
        tree_params.append(client_id)
    
    tree_rows = conn.execute(tree_query, tree_params).fetchall()
    
    for tree in tree_rows:
        tree_id = tree["id"]
        
        # Get roots for this tree
        if active_only:
            # Only most recent
            root_rows = conn.execute(
                """SELECT root_hash, created_at FROM merkle_roots 
                   WHERE tree_id = ? ORDER BY created_at DESC LIMIT 1""",
                (tree_id,)
            ).fetchall()
        else:
            # All roots
            root_rows = conn.execute(
                """SELECT root_hash, created_at FROM merkle_roots 
                   WHERE tree_id = ? ORDER BY created_at DESC LIMIT ?""",
                (tree_id, limit)
            ).fetchall()
        
        for root in root_rows:
            results.append({
                "id": tree_id,
                "client_id": tree["client_id"],
                "purpose": tree["purpose"],
                "root_hash": root["root_hash"],
                "tree_depth": tree["depth"],
                "created_at": root["created_at"],
                "superseded_at": None,
            })
    
    # Sort by created_at descending
    results.sort(key=lambda x: x["created_at"], reverse=True)
    return results[:limit]
