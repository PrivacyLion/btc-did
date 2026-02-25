"""
SignedByMe Database Module

SQLite-based persistent storage for:
- Sessions (login flows)
- Enrollments (membership)
- Merkle roots & witnesses
- Nullifiers (replay protection)
- Payment confirmations
- OIDC codes
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
# SESSIONS
# ============================================================================

def create_session(
    session_id: str,
    client_id: str,
    nonce: str,
    enterprise: str,
    amount_sats: int = 500,
    expires_at: int = 0,
    required_root_id: Optional[str] = None,
    required_purpose_id: int = 0,
) -> None:
    """Create a new login session."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO sessions (
            session_id, client_id, nonce, enterprise, amount_sats,
            expires_at, required_root_id, required_purpose_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, client_id, nonce, enterprise, amount_sats,
          expires_at, required_root_id, required_purpose_id))
    conn.commit()


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM sessions WHERE session_id = ?",
        (session_id,)
    ).fetchone()
    return dict(row) if row else None


def update_session(session_id: str, **kwargs) -> None:
    """Update session fields."""
    if not kwargs:
        return
    conn = get_connection()
    fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [session_id]
    conn.execute(
        f"UPDATE sessions SET {fields}, updated_at = strftime('%s', 'now') WHERE session_id = ?",
        values
    )
    conn.commit()


def verify_session(session_id: str, npub: str, merkle_root: str) -> None:
    """Mark session as verified with proof data."""
    update_session(session_id, verified=1, npub=npub, merkle_root=merkle_root)


def confirm_payment(session_id: str, preimage_hex: str) -> None:
    """Mark session as paid."""
    import time
    update_session(session_id, paid=1, paid_at=int(time.time()), preimage_hex=preimage_hex)


def delete_expired_sessions(before_ts: int) -> int:
    """Delete sessions that expired before timestamp. Returns count deleted."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM sessions WHERE expires_at < ? AND expires_at > 0",
        (before_ts,)
    )
    conn.commit()
    return cursor.rowcount


# ============================================================================
# OIDC CODES
# ============================================================================

def create_oidc_code(
    code: str,
    client_id: str,
    iat: int,
    exp: int,
    redirect_uri: Optional[str] = None,
    nonce: Optional[str] = None,
    code_challenge: Optional[str] = None,
    session_id: Optional[str] = None,
    npub: Optional[str] = None,
) -> None:
    """Create a new OIDC auth code."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO oidc_codes (
            code, client_id, redirect_uri, nonce, code_challenge,
            session_id, npub, iat, exp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (code, client_id, redirect_uri, nonce, code_challenge,
          session_id, npub, iat, exp))
    conn.commit()


def get_oidc_code(code: str) -> Optional[Dict[str, Any]]:
    """Get OIDC code if valid and unused."""
    import time
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM oidc_codes WHERE code = ? AND used = 0 AND exp > ?",
        (code, int(time.time()))
    ).fetchone()
    return dict(row) if row else None


def use_oidc_code(code: str) -> bool:
    """Mark code as used. Returns True if code was valid."""
    conn = get_connection()
    cursor = conn.execute(
        "UPDATE oidc_codes SET used = 1 WHERE code = ? AND used = 0",
        (code,)
    )
    conn.commit()
    return cursor.rowcount > 0


def delete_expired_oidc_codes(before_ts: int) -> int:
    """Delete expired OIDC codes. Returns count deleted."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM oidc_codes WHERE exp < ?",
        (before_ts,)
    )
    conn.commit()
    return cursor.rowcount


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
# NULLIFIERS
# ============================================================================

def check_nullifier(nullifier: str) -> bool:
    """Check if nullifier has been used. Returns True if already used."""
    conn = get_connection()
    row = conn.execute(
        "SELECT 1 FROM nullifiers WHERE nullifier = ?",
        (nullifier,)
    ).fetchone()
    return row is not None


def use_nullifier(nullifier: str, session_id: Optional[str] = None, npub: Optional[str] = None) -> bool:
    """Mark nullifier as used. Returns False if already used."""
    if check_nullifier(nullifier):
        return False
    conn = get_connection()
    conn.execute(
        "INSERT INTO nullifiers (nullifier, session_id, npub) VALUES (?, ?, ?)",
        (nullifier, session_id, npub)
    )
    conn.commit()
    return True


# ============================================================================
# PAYMENT CONFIRMATIONS
# ============================================================================

def confirm_payment_hash(
    payment_hash: str,
    preimage_hex: str,
    session_id: Optional[str] = None,
    amount_sats: Optional[int] = None,
) -> None:
    """Record a payment confirmation."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO payment_confirmations
        (payment_hash, preimage_hex, session_id, amount_sats)
        VALUES (?, ?, ?, ?)
    """, (payment_hash, preimage_hex, session_id, amount_sats))
    conn.commit()


def get_payment_confirmation(payment_hash: str) -> Optional[Dict[str, Any]]:
    """Get payment confirmation by hash."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM payment_confirmations WHERE payment_hash = ?",
        (payment_hash,)
    ).fetchone()
    return dict(row) if row else None


# ============================================================================
# AUDIT LOG
# ============================================================================

def audit_log(
    event_type: str,
    session_id: Optional[str] = None,
    client_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log an audit event."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_log (event_type, session_id, client_id, details_json)
        VALUES (?, ?, ?, ?)
    """, (event_type, session_id, client_id, json.dumps(details) if details else None))
    conn.commit()


# ============================================================================
# MAINTENANCE
# ============================================================================

def cleanup_expired(max_age_hours: int = 24) -> Dict[str, int]:
    """Clean up expired records. Returns counts of deleted records."""
    import time
    cutoff = int(time.time()) - (max_age_hours * 3600)
    
    return {
        "sessions": delete_expired_sessions(cutoff),
        "oidc_codes": delete_expired_oidc_codes(cutoff),
    }


def get_stats() -> Dict[str, int]:
    """Get database statistics."""
    conn = get_connection()
    return {
        "sessions": conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
        "enrollments": conn.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0],
        "roots": conn.execute("SELECT COUNT(*) FROM merkle_roots WHERE active = 1").fetchone()[0],
        "nullifiers": conn.execute("SELECT COUNT(*) FROM nullifiers").fetchone()[0],
    }
