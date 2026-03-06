"""
SignedByMe Database Module

SQLite-based persistent storage for:
- Enrollments (membership)
- Merkle roots & witnesses
- Incremental Merkle trees
- Root history (validity window)
- Login verifications (receipts)

Phase 8: Stateless architecture - no sessions, no DIDs on server.
"""

import sqlite3
import json
import logging
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
    """Initialize database schema if needed."""
    if SCHEMA_PATH.exists():
        schema_sql = SCHEMA_PATH.read_text()
        conn.executescript(schema_sql)
        conn.commit()
        logger.info(f"Database initialized at {DB_PATH}")


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
# ENROLLMENTS
# ============================================================================

def create_enrollment(
    enrollment_id: str,
    client_id: str,
    purpose: str,
    leaf_commitment: str,
    email_hash: Optional[str] = None,
    status: str = "pending",
) -> None:
    """Create a new enrollment."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO enrollments (id, client_id, purpose, leaf_commitment, email_hash, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (enrollment_id, client_id, purpose, leaf_commitment, email_hash, status))
    conn.commit()


def get_enrollment(enrollment_id: str) -> Optional[Dict[str, Any]]:
    """Get enrollment by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM enrollments WHERE id = ?",
        (enrollment_id,)
    ).fetchone()
    return dict(row) if row else None


def list_enrollments(
    client_id: Optional[str] = None,
    purpose: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List enrollments with optional filters."""
    conn = get_connection()
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


def update_enrollment(enrollment_id: str, **kwargs) -> None:
    """Update enrollment fields."""
    if not kwargs:
        return
    conn = get_connection()
    fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [enrollment_id]
    conn.execute(f"UPDATE enrollments SET {fields} WHERE id = ?", values)
    conn.commit()


def approve_enrollment(enrollment_id: str) -> None:
    """Approve an enrollment."""
    import time
    update_enrollment(enrollment_id, status="approved", approved_at=int(time.time()))


def reject_enrollment(enrollment_id: str) -> None:
    """Reject an enrollment."""
    import time
    update_enrollment(enrollment_id, status="rejected", rejected_at=int(time.time()))


# ============================================================================
# MERKLE ROOTS
# ============================================================================

def create_root(
    root_id: str,
    client_id: str,
    purpose: str,
    root_hash: str,
    leaf_count: int,
    tree_depth: int,
) -> None:
    """Create a new Merkle root, deactivating previous ones."""
    conn = get_connection()
    
    # Deactivate previous active root
    import time
    conn.execute("""
        UPDATE merkle_roots SET active = 0, superseded_at = ?
        WHERE client_id = ? AND purpose = ? AND active = 1
    """, (int(time.time()), client_id, purpose))
    
    # Insert new root
    conn.execute("""
        INSERT INTO merkle_roots (id, client_id, purpose, root_hash, leaf_count, tree_depth)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (root_id, client_id, purpose, root_hash, leaf_count, tree_depth))
    conn.commit()


def get_active_root(client_id: str, purpose: str) -> Optional[Dict[str, Any]]:
    """Get the active root for client+purpose."""
    conn = get_connection()
    row = conn.execute("""
        SELECT * FROM merkle_roots
        WHERE client_id = ? AND purpose = ? AND active = 1
    """, (client_id, purpose)).fetchone()
    return dict(row) if row else None


def get_root_by_id(root_id: str) -> Optional[Dict[str, Any]]:
    """Get root by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM merkle_roots WHERE id = ?",
        (root_id,)
    ).fetchone()
    return dict(row) if row else None


def list_roots(client_id: Optional[str] = None, active_only: bool = True) -> List[Dict[str, Any]]:
    """List roots with optional filters."""
    conn = get_connection()
    query = "SELECT * FROM merkle_roots WHERE 1=1"
    params = []
    
    if client_id:
        query += " AND client_id = ?"
        params.append(client_id)
    if active_only:
        query += " AND active = 1"
    
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


# ============================================================================
# MERKLE WITNESSES
# ============================================================================

def save_witness(
    enrollment_id: str,
    root_id: str,
    siblings: List[str],
    path_bits: List[int],
    leaf_index: int,
) -> None:
    """Save a witness for an enrollment."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO merkle_witnesses
        (enrollment_id, root_id, siblings_json, path_bits_json, leaf_index)
        VALUES (?, ?, ?, ?, ?)
    """, (enrollment_id, root_id, json.dumps(siblings), json.dumps(path_bits), leaf_index))
    conn.commit()


def get_witness(enrollment_id: str) -> Optional[Dict[str, Any]]:
    """Get witness for an enrollment."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM merkle_witnesses WHERE enrollment_id = ?",
        (enrollment_id,)
    ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["siblings"] = json.loads(result["siblings_json"])
    result["path_bits"] = json.loads(result["path_bits_json"])
    return result


# ============================================================================
# INCREMENTAL MERKLE TREES
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


def add_root_to_history(
    tree_id: str,
    root_hash: str,
    leaf_index: int,
) -> None:
    """Add a root to history."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO root_history (tree_id, root_hash, leaf_index)
        VALUES (?, ?, ?)
    """, (tree_id, root_hash, leaf_index))
    conn.commit()


def get_valid_roots(tree_id: str, limit: int = 30) -> List[str]:
    """Get last N valid roots for a tree."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT root_hash FROM root_history
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
        SELECT root_hash FROM root_history
        WHERE tree_id = ?
        ORDER BY id DESC
        LIMIT 1
    """, (tree_id,)).fetchone()
    return row[0] if row else None


def prune_root_history(tree_id: str, keep: int = 100) -> int:
    """Prune old roots, keeping the most recent N. Returns count deleted."""
    conn = get_connection()
    # Get the ID threshold
    row = conn.execute("""
        SELECT id FROM root_history
        WHERE tree_id = ?
        ORDER BY id DESC
        LIMIT 1 OFFSET ?
    """, (tree_id, keep - 1)).fetchone()
    
    if not row:
        return 0
    
    threshold_id = row[0]
    cursor = conn.execute("""
        DELETE FROM root_history
        WHERE tree_id = ? AND id < ?
    """, (tree_id, threshold_id))
    conn.commit()
    return cursor.rowcount


def is_root_valid_for_client(client_id: str, root_hash: str, limit: int = 30) -> bool:
    """
    Check if a merkle root is valid for ANY tree belonging to a client.
    
    Searches the last N roots across all trees owned by client_id.
    This is the check for Phase 8: "merkle_root is in the valid root set (last 30 roots)"
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
    
    # Check if root_hash is in any of these trees' recent history
    placeholders = ",".join("?" * len(tree_ids))
    row = conn.execute(f"""
        SELECT 1 FROM root_history
        WHERE tree_id IN ({placeholders}) AND root_hash = ?
        AND id >= (
            SELECT COALESCE(MIN(cutoff.id), 0)
            FROM (
                SELECT id FROM root_history
                WHERE tree_id IN ({placeholders})
                ORDER BY id DESC
                LIMIT ?
            ) cutoff
        )
        LIMIT 1
    """, tree_ids + [root_hash] + tree_ids + [limit]).fetchone()
    
    return row is not None


def is_root_in_history(root_hash: str) -> bool:
    """
    Check if a root exists in any root_history (any tree).
    Simpler check than is_root_valid_for_client - just checks existence.
    """
    conn = get_connection()
    row = conn.execute(
        "SELECT 1 FROM root_history WHERE root_hash = ? LIMIT 1",
        (root_hash,)
    ).fetchone()
    return row is not None


# ============================================================================
# LOGIN VERIFICATIONS
# Phase 8: Log successful Groth16 verifications (receipts only)
# ============================================================================

def log_verification(
    npub: str,
    client_id: str,
    merkle_root: str,
    payment_hash_user: str,
    payment_hash_operator: str,
    verified_at: int,
) -> int:
    """Log a successful login verification. Returns the row ID."""
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO login_verifications
        (npub, client_id, merkle_root, payment_hash_user, payment_hash_operator, verified_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (npub, client_id, merkle_root, payment_hash_user, payment_hash_operator, verified_at))
    conn.commit()
    return cursor.lastrowid


def get_verifications(
    client_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get login verifications with optional client_id filter."""
    conn = get_connection()
    if client_id:
        rows = conn.execute("""
            SELECT * FROM login_verifications
            WHERE client_id = ?
            ORDER BY verified_at DESC
            LIMIT ?
        """, (client_id, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM login_verifications
            ORDER BY verified_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def count_verifications() -> int:
    """Get total count of login verifications."""
    conn = get_connection()
    return conn.execute("SELECT COUNT(*) FROM login_verifications").fetchone()[0]


# ============================================================================
# AUDIT LOG
# ============================================================================

def audit_log(
    event_type: str,
    client_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log an audit event."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_log (event_type, client_id, details_json)
        VALUES (?, ?, ?)
    """, (event_type, client_id, json.dumps(details) if details else None))
    conn.commit()


# ============================================================================
# STATS
# ============================================================================

def get_stats() -> Dict[str, int]:
    """Get database statistics."""
    conn = get_connection()
    return {
        "enrollments": conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0],
        "roots": conn.execute("SELECT COUNT(*) FROM merkle_roots WHERE active = 1").fetchone()[0],
        "verifications": conn.execute("SELECT COUNT(*) FROM login_verifications").fetchone()[0],
    }
