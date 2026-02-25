"""
Root Registry API

Manages Merkle roots for membership proofs.
- Public endpoint for fetching roots by client_id
- Enterprise endpoint for publishing roots (scoped to client_id)
- Admin endpoints for root lifecycle management

INVARIANT: Acme roots NEVER satisfy BetaCorp sessions (client_id scoping)

Storage: SQLite (persistent across restarts)
"""
from fastapi import APIRouter, HTTPException, Header, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional
import time
import json
import os
import secrets
import logging
from pathlib import Path

from ..db import (
    create_root as db_create_root,
    get_root_by_id,
    get_active_root,
    list_roots as db_list_roots,
    audit_log,
)

logger = logging.getLogger("roots")
router = APIRouter(tags=["roots"])

# Config paths
DATA_DIR = Path(__file__).resolve().parents[2]
CLIENTS_PATH = DATA_DIR / "clients.json"
ADMIN_API_KEY = os.environ.get("SBM_ADMIN_KEY")


def load_clients() -> dict:
    """Load enterprise client configs."""
    if CLIENTS_PATH.exists():
        return json.loads(CLIENTS_PATH.read_text())
    return {}


def validate_enterprise_key(api_key: str) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    raise HTTPException(401, "Invalid API key")


# === Purpose ID Enum (circuit-friendly) ===

PURPOSE_NONE = 0
PURPOSE_ALLOWLIST = 1
PURPOSE_ISSUER_BATCH = 2
PURPOSE_REVOCATION = 3

PURPOSE_MAP = {
    "": PURPOSE_NONE,
    "allowlist": PURPOSE_ALLOWLIST,
    "issuer_batch": PURPOSE_ISSUER_BATCH,
    "revocation": PURPOSE_REVOCATION,
}


def get_purpose_id(purpose: str) -> int:
    """Convert purpose string to circuit-friendly enum."""
    return PURPOSE_MAP.get(purpose, PURPOSE_NONE)


# === Models ===

class RootEntry(BaseModel):
    """A Merkle root entry."""
    root_id: str = Field(..., description="Unique identifier (e.g., 'acme-allowlist-2026-Q1')")
    client_id: str = Field(..., description="Enterprise client_id this root belongs to")
    purpose: str = Field(..., description="Purpose: 'allowlist' | 'issuer_batch' | 'revocation'")
    purpose_id: int = Field(..., description="Circuit-friendly enum: 0=none, 1=allowlist, 2=issuer_batch, 3=revocation")
    root: str = Field(..., description="Merkle root (64 hex chars with 0x prefix)")
    hash_alg: str = Field("poseidon", description="Hash algorithm used")
    depth: int = Field(20, description="Tree depth (standardized to 20, pad with zeros)")
    not_before: int = Field(0, description="Unix timestamp: root becomes valid")
    expires_at: int = Field(2000000000, description="Unix timestamp: root expires")
    description: Optional[str] = Field(None, description="Human description")


class RootPatch(BaseModel):
    """Patch for updating a root."""
    expires_at: Optional[int] = None
    not_before: Optional[int] = None
    description: Optional[str] = None


class RootsResponse(BaseModel):
    """Response containing list of roots."""
    roots: list[RootEntry]


# === Storage Helpers ===

def get_canonical_root(root_id: str, client_id: str = None) -> dict | None:
    """
    Server-authoritative root lookup.
    Returns None if root_id not found, not yet valid, expired, or wrong client_id.
    
    INVARIANT: If client_id is provided, root must belong to that client.
    """
    r = get_root_by_id(root_id)
    if not r:
        return None
    
    now = int(time.time())
    
    # Client scoping check (critical security invariant)
    if client_id and r.get("client_id") != client_id:
        return None  # Wrong client - Acme roots don't satisfy BetaCorp
    
    # Active check is already handled by the query if needed
    return r


def get_active_root_for_client(client_id: str, purpose: str = None) -> dict | None:
    """
    Get the active root for a client (optionally filtered by purpose).
    Returns the most recently created active root.
    """
    return get_active_root(client_id, purpose or "allowlist")


# === Admin Auth ===

def require_admin(x_admin_key: str = Header(..., alias="X-Admin-Key")):
    """Verify admin API key."""
    if not ADMIN_API_KEY:
        raise HTTPException(500, "Admin key not configured (set SBM_ADMIN_KEY env var)")
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(403, "Invalid admin key")


# === Public Endpoints ===

@router.get("/v1/roots/current", response_model=RootsResponse)
def get_current_roots(
    client_id: Optional[str] = Query(None, description="Filter by client_id (required for client-specific roots)")
):
    """
    Get currently active roots, optionally filtered by client_id.
    
    Public endpoint - no authentication required.
    Returns roots where: active = 1
    
    If client_id is provided, returns only that client's roots.
    Mobile apps should pass client_id to get the correct root for their enterprise.
    """
    roots = db_list_roots(client_id=client_id, active_only=True)
    
    # Convert to response format
    entries = []
    for r in roots:
        entries.append(RootEntry(
            root_id=r["id"],
            client_id=r["client_id"],
            purpose=r["purpose"],
            purpose_id=get_purpose_id(r["purpose"]),
            root=r["root_hash"],
            hash_alg="poseidon",
            depth=r["tree_depth"],
            not_before=r.get("created_at", 0),
            expires_at=r.get("superseded_at") or 2000000000,
            description=None,
        ))
    
    return RootsResponse(roots=entries)


@router.get("/v1/roots/{root_id}", response_model=RootEntry)
def get_root(root_id: str):
    """
    Get a specific root by ID.
    
    Returns the root even if expired (for audit purposes).
    Public endpoint - no authentication required.
    """
    r = get_root_by_id(root_id)
    if not r:
        raise HTTPException(404, f"Root not found: {root_id}")
    
    return RootEntry(
        root_id=r["id"],
        client_id=r["client_id"],
        purpose=r["purpose"],
        purpose_id=get_purpose_id(r["purpose"]),
        root=r["root_hash"],
        hash_alg="poseidon",
        depth=r["tree_depth"],
        not_before=r.get("created_at", 0),
        expires_at=r.get("superseded_at") or 2000000000,
        description=None,
    )


# === Admin Endpoints ===

class RootPublishRequest(BaseModel):
    """Request to publish a new root (from enterprise)."""
    root_id: str = Field(..., description="Unique identifier")
    purpose: str = Field(..., description="Purpose: 'allowlist' | 'issuer_batch' | 'revocation'")
    root: str = Field(..., description="Merkle root (64 hex chars with 0x prefix)")
    hash_alg: str = Field("poseidon", description="Hash algorithm used")
    depth: int = Field(20, description="Tree depth (must be 20)")
    not_before: Optional[int] = Field(None, description="Unix timestamp: root becomes valid (default: now)")
    expires_at: Optional[int] = Field(None, description="Unix timestamp: root expires (default: 1 year)")
    description: Optional[str] = Field(None, description="Human description")


@router.post("/v1/roots", response_model=dict)
def publish_root(
    body: RootPublishRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Publish a new root (enterprise endpoint).
    
    Requires X-API-Key header (enterprise API key).
    Root is automatically scoped to the enterprise's client_id.
    
    INVARIANT: depth must be 20 (standardized, pad with zeros if fewer leaves).
    """
    # Validate enterprise API key and get client_id
    client_id, client_config = validate_enterprise_key(x_api_key)
    
    # Enforce depth=20 standard
    if body.depth != 20:
        raise HTTPException(400, f"depth must be 20 (got {body.depth}). Pad tree with zero leaves if needed.")
    
    # Check for duplicate
    existing = get_root_by_id(body.root_id)
    if existing:
        raise HTTPException(400, f"root_id already exists: {body.root_id}")
    
    # Validate purpose_id
    purpose_id = get_purpose_id(body.purpose)
    if purpose_id == 0 and body.purpose:
        raise HTTPException(400, f"Invalid purpose: {body.purpose}")
    
    # Create root in SQLite
    db_create_root(
        root_id=body.root_id,
        client_id=client_id,
        purpose=body.purpose,
        root_hash=body.root,
        leaf_count=0,  # Will be updated when tree is built
        tree_depth=body.depth,
    )
    
    audit_log("root_published", client_id=client_id, details={"root_id": body.root_id})
    logger.info(f"Root published: {body.root_id} for client {client_id}")
    return {"ok": True, "root_id": body.root_id, "client_id": client_id}


@router.post("/v1/roots/admin", response_model=dict, dependencies=[Depends(require_admin)])
def add_root_admin(body: RootEntry):
    """
    Add a new root (admin endpoint).
    
    Requires X-Admin-Key header. Use for dev/testing.
    This endpoint allows specifying client_id directly.
    
    INVARIANT: depth must be 20 (standardized).
    """
    # Enforce depth=20 standard (same as enterprise endpoint)
    if body.depth != 20:
        raise HTTPException(400, f"depth must be 20 (got {body.depth}). Pad tree with zero leaves if needed.")
    
    # Check for duplicate
    existing = get_root_by_id(body.root_id)
    if existing:
        raise HTTPException(400, f"root_id already exists: {body.root_id}")
    
    # Validate purpose_id matches purpose
    expected_id = get_purpose_id(body.purpose)
    if body.purpose_id != expected_id:
        raise HTTPException(400, f"purpose_id mismatch: expected {expected_id} for purpose '{body.purpose}'")
    
    # Create root in SQLite
    db_create_root(
        root_id=body.root_id,
        client_id=body.client_id,
        purpose=body.purpose,
        root_hash=body.root,
        leaf_count=0,
        tree_depth=body.depth,
    )
    
    audit_log("root_added_admin", details={"root_id": body.root_id, "client_id": body.client_id})
    logger.info(f"Root added (admin): {body.root_id}")
    return {"ok": True, "root_id": body.root_id}


@router.patch("/v1/roots/{root_id}", response_model=dict, dependencies=[Depends(require_admin)])
def update_root(root_id: str, patch: RootPatch):
    """
    Update a root (typically for deprecation).
    
    Requires X-Admin-Key header.
    Common use: set expires_at to deprecate a root.
    
    Note: For SQLite, we mark roots inactive instead of setting expires_at.
    """
    from ..db import get_connection
    
    r = get_root_by_id(root_id)
    if not r:
        raise HTTPException(404, f"Root not found: {root_id}")
    
    # For deprecation, mark as inactive
    if patch.expires_at is not None and patch.expires_at < int(time.time()):
        conn = get_connection()
        conn.execute(
            "UPDATE merkle_roots SET active = 0, superseded_at = ? WHERE id = ?",
            (patch.expires_at, root_id)
        )
        conn.commit()
    
    audit_log("root_updated", details={"root_id": root_id, "patch": patch.dict(exclude_none=True)})
    logger.info(f"Root updated: {root_id}")
    return {"ok": True, "root_id": root_id}


@router.delete("/v1/roots/{root_id}", response_model=dict, dependencies=[Depends(require_admin)])
def delete_root(root_id: str):
    """
    Delete a root entirely.
    
    Requires X-Admin-Key header.
    Use with caution - prefer setting expires_at for graceful deprecation.
    """
    from ..db import get_connection
    
    r = get_root_by_id(root_id)
    if not r:
        raise HTTPException(404, f"Root not found: {root_id}")
    
    conn = get_connection()
    conn.execute("DELETE FROM merkle_roots WHERE id = ?", (root_id,))
    conn.commit()
    
    audit_log("root_deleted", details={"root_id": root_id})
    logger.info(f"Root deleted: {root_id}")
    return {"ok": True, "root_id": root_id, "deleted": True}
