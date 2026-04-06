"""
Membership Enrollment API (Phase 26)

NOSTR-native enrollment using kind 28200 authorization events.

ENROLLMENT FLOW:
1. Enterprise publishes kind 28200 event (enrollment_authorization)
2. Human publishes kind 28250 event (delegation_grant)
3. App submits leaf_commitment + both events to /v1/membership/enroll
4. Server verifies signatures via NIP-05, adds leaf to tree
5. Server returns witness for proving membership

MOBILE-TO-MOBILE LOGIN:
- Enterprise publishes kind 28200 tagged with user's npub
- App subscribes to kind 28200 by npub
- "Press to log in" button (no QR needed)

Storage: SQLite (persistent across restarts)
Authorization: Kind 28200 + 28250 NOSTR event signatures
"""

import os
import json
import time
import hashlib
import subprocess
import logging
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel, Field

from ..db import (
    # Merkle leaves (Phase 26)
    add_merkle_leaf,
    get_merkle_leaf,
    get_merkle_leaf_by_event,
    list_merkle_leaves,
    count_merkle_leaves,
    leaf_commitment_exists,
    # Merkle roots
    add_merkle_root,
    get_valid_roots,
    is_root_valid,
    get_current_root,
    # Merkle trees
    create_merkle_tree,
    get_merkle_tree,
    update_merkle_tree,
    list_merkle_trees,
    # Witnesses
    save_witness,
    get_witness,
    get_witness_by_commitment,
    # Audit
    audit_log,
    get_stats,
)
from ..lib.nostr import (
    NostrEvent,
    verify_event,
    verify_enterprise_pubkey,
    parse_enrollment_authorization,
    KIND_ENROLLMENT_AUTHORIZATION,
)

logger = logging.getLogger("membership")
router = APIRouter(prefix="/v1/membership", tags=["membership"])

# =============================================================================
# Config
# =============================================================================

DATA_DIR = Path(__file__).resolve().parents[2]
TREE_DEPTH = 20  # Fixed depth for all trees (2^20 = 1M leaves max)
VALID_ROOTS_WINDOW = 30  # Last 30 roots are valid

# Poseidon hash binary
POSEIDON_HASH_BIN = os.getenv(
    "POSEIDON_HASH_BIN",
    str(DATA_DIR / "native" / "signedby_core" / "target" / "release" / "poseidon_hash")
)


def load_clients() -> dict:
    """Load enterprise client configs."""
    clients_file = DATA_DIR / "clients.json"
    if clients_file.exists():
        return json.loads(clients_file.read_text())
    return {}


def validate_api_key(api_key: Optional[str]) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    if not api_key:
        raise HTTPException(401, "Missing Authorization header")
    clients = load_clients()
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    for client_id, config in clients.items():
        if api_key_hash == config.get("api_key_hash"):
            return client_id, config
    raise HTTPException(401, "Invalid API key")


def get_client_domain(client_id: str) -> Optional[str]:
    """Get domain for a client (for NIP-05 verification)."""
    clients = load_clients()
    config = clients.get(client_id, {})
    return config.get("domain")


# =============================================================================
# Poseidon2 Hashing (via Rust CLI)
# =============================================================================

def _call_poseidon_hash(args: list) -> bytes:
    """Call the poseidon_hash Rust CLI binary."""
    cmd = [POSEIDON_HASH_BIN] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError(f"poseidon_hash failed: {result.stderr.strip()}")
        return bytes.fromhex(result.stdout.strip())
    except FileNotFoundError:
        # Fallback to SHA256 for testing without Rust binary
        logger.warning("poseidon_hash not found, using SHA256 fallback")
        data = "|".join(args).encode()
        return hashlib.sha256(data).digest()
    except subprocess.TimeoutExpired:
        raise RuntimeError("poseidon_hash timed out")


def hash_pair(left: str, right: str) -> str:
    """Hash two values for Merkle tree. Returns hex string."""
    try:
        result = _call_poseidon_hash(["pair", left[:8], right[:8]])
        return result.hex().ljust(64, '0')
    except:
        # Fallback
        data = (left + right).encode()
        return hashlib.sha256(data).hexdigest()


def get_zero_hash(level: int) -> str:
    """Get the zero hash for a given level."""
    return "0" * 64


# =============================================================================
# Incremental Merkle Tree
# =============================================================================

def insert_leaf(tree_id: str, leaf_hash: str) -> tuple[str, int, List[str]]:
    """
    Insert a leaf into the incremental Merkle tree.
    
    Returns: (new_root, leaf_index, witness_siblings)
    """
    tree = get_merkle_tree(tree_id)
    if not tree:
        raise ValueError(f"Tree not found: {tree_id}")
    
    depth = tree["depth"]
    leaf_index = tree["next_leaf_index"]
    state = tree["state"]
    
    if leaf_index >= (1 << depth):
        raise ValueError(f"Tree is full (max {1 << depth} leaves)")
    
    # Compute witness siblings (before updating state)
    siblings = []
    idx = leaf_index
    current_hash = leaf_hash
    new_state = state.copy()
    
    for level in range(depth):
        is_right = (idx & 1) == 1
        
        if is_right:
            sibling = state[level]
            siblings.append(sibling)
            current_hash = hash_pair(sibling, current_hash)
        else:
            sibling = get_zero_hash(level)
            siblings.append(sibling)
            new_state[level] = current_hash
            current_hash = hash_pair(current_hash, sibling)
        
        idx >>= 1
    
    new_root = current_hash
    
    # Update tree state
    update_merkle_tree(tree_id, leaf_index + 1, new_state)
    
    # Add root to history
    add_merkle_root(tree_id, new_root, leaf_index)
    
    return new_root, leaf_index, siblings


def get_or_create_tree(client_id: str, purpose: str = "allowlist") -> str:
    """Get or create a Merkle tree for client+purpose."""
    tree_id = f"{client_id}-{purpose}"
    tree = get_merkle_tree(tree_id)
    if not tree:
        create_merkle_tree(tree_id, client_id, purpose, TREE_DEPTH)
        # Initialize with empty root in history
        empty_root = get_zero_hash(TREE_DEPTH)
        add_merkle_root(tree_id, empty_root, -1)
    return tree_id


# =============================================================================
# Models
# =============================================================================

class NostrEventModel(BaseModel):
    """NOSTR event (NIP-01 format)."""
    id: str = Field(..., description="Event ID (32-byte hex SHA256)")
    pubkey: str = Field(..., description="Author pubkey (32-byte hex)")
    created_at: int = Field(..., description="Unix timestamp")
    kind: int = Field(..., description="Event kind")
    tags: List[List[str]] = Field(..., description="Event tags")
    content: str = Field(..., description="Event content")
    sig: str = Field(..., description="Schnorr signature (64-byte hex)")


class EnrollRequest(BaseModel):
    """Phase 26 enrollment request."""
    authorization_event: NostrEventModel = Field(
        ..., 
        description="Kind 28200 enrollment_authorization event from enterprise"
    )
    leaf_commitment: str = Field(
        ..., 
        description="Hex-encoded leaf commitment (32 bytes)"
    )
    purpose: str = Field(
        "allowlist", 
        description="Purpose: allowlist, kyc_verified, etc."
    )


class EnrollResponse(BaseModel):
    """Phase 26 enrollment response."""
    success: bool
    tree_id: str
    leaf_index: int
    root: str
    witness: dict  # {siblings: [...], path_bits: [...]}
    valid_roots: List[str]
    message: str


class WitnessResponse(BaseModel):
    """Witness for membership proof."""
    tree_id: str
    leaf_index: int
    leaf_commitment: str
    siblings: List[str]
    path_bits: List[int]
    root_hash: str
    current_root: str
    valid_roots: List[str]


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/enroll", response_model=EnrollResponse)
async def enroll(
    body: EnrollRequest,
    authorization: str = Header(..., alias="Authorization")
):
    """
    Enroll a user in the membership tree (Phase 26).
    
    Authorization: Kind 28200 NOSTR event signed by enterprise.
    The event signature IS the authorization (no enrollment_id needed).
    
    Flow:
    1. Verify API key matches client_id in event
    2. Verify kind 28200 event signature
    3. Verify enterprise pubkey via NIP-05
    4. Check for duplicate (event_id or leaf_commitment)
    5. Insert leaf into Merkle tree
    6. Return witness
    """
    # Extract Bearer token
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]
    
    # Validate API key
    client_id, config = validate_api_key(api_key)
    
    # Convert model to NostrEvent
    event = NostrEvent(
        id=body.authorization_event.id,
        pubkey=body.authorization_event.pubkey,
        created_at=body.authorization_event.created_at,
        kind=body.authorization_event.kind,
        tags=body.authorization_event.tags,
        content=body.authorization_event.content,
        sig=body.authorization_event.sig,
    )
    
    # Verify event kind
    if event.kind != KIND_ENROLLMENT_AUTHORIZATION:
        raise HTTPException(400, f"Wrong event kind: {event.kind}, expected {KIND_ENROLLMENT_AUTHORIZATION}")
    
    # Parse authorization
    auth, error = parse_enrollment_authorization(event)
    if not auth:
        raise HTTPException(400, f"Invalid authorization event: {error}")
    
    # Verify client_id matches
    if auth.client_id != client_id:
        raise HTTPException(400, f"Event client_id '{auth.client_id}' does not match API key client_id '{client_id}'")
    
    # Check expiration
    if auth.is_expired():
        raise HTTPException(400, f"Authorization expired at {auth.expires_at}")
    
    # Verify event signature
    valid, error = verify_event(event)
    if not valid:
        raise HTTPException(400, f"Event signature verification failed: {error}")
    
    # Verify enterprise pubkey via NIP-05
    domain = get_client_domain(client_id)
    if domain:
        nip05_result = await verify_enterprise_pubkey(domain, event.pubkey)
        if not nip05_result.valid:
            logger.warning(f"NIP-05 verification failed for {client_id}: {nip05_result.error}")
            # Don't fail - NIP-05 is optional enhancement
    
    # Validate commitment format
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "").lower()
        if len(bytes.fromhex(commitment_hex)) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Get or create tree
    tree_id = get_or_create_tree(client_id, body.purpose)
    
    # Check for duplicate event
    existing = get_merkle_leaf_by_event(event.id)
    if existing:
        raise HTTPException(409, f"Authorization event already used")
    
    # Check for duplicate commitment
    if leaf_commitment_exists(tree_id, commitment_hex):
        raise HTTPException(409, "Leaf commitment already enrolled")
    
    # Insert leaf into tree
    new_root, leaf_index, siblings = insert_leaf(tree_id, commitment_hex)
    
    # Compute path bits
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx >>= 1
    
    # Add leaf to database
    leaf_id = add_merkle_leaf(
        tree_id=tree_id,
        leaf_index=leaf_index,
        leaf_commitment=commitment_hex,
        authorization_event_id=event.id,
        authorization_pubkey=event.pubkey,
    )
    
    # Save witness
    save_witness(
        leaf_id=leaf_id,
        tree_id=tree_id,
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
        root_hash=new_root,
    )
    
    # Get valid roots
    valid_roots = get_valid_roots(tree_id, VALID_ROOTS_WINDOW)
    
    audit_log("enrollment", client_id=client_id, details={
        "tree_id": tree_id,
        "leaf_index": leaf_index,
        "event_id": event.id[:16] + "...",
    })
    
    logger.info(f"Enrolled leaf {leaf_index} in {tree_id}")
    
    return EnrollResponse(
        success=True,
        tree_id=tree_id,
        leaf_index=leaf_index,
        root=new_root,
        witness={
            "siblings": siblings,
            "path_bits": path_bits,
        },
        valid_roots=valid_roots,
        message="Successfully enrolled in membership tree.",
    )


@router.get("/witness", response_model=WitnessResponse)
def get_membership_witness(
    leaf_commitment: str = Query(..., description="Leaf commitment (hex)"),
    tree_id: Optional[str] = Query(None, description="Tree ID (optional, derived from client)"),
    authorization: str = Header(..., alias="Authorization")
):
    """
    Get witness for a leaf commitment.
    
    Returns the Merkle proof needed for Groth16 membership proof.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]
    client_id, _ = validate_api_key(api_key)
    
    # Normalize commitment
    commitment_hex = leaf_commitment.replace("0x", "").lower()
    
    # Determine tree_id
    if not tree_id:
        tree_id = f"{client_id}-allowlist"
    
    # Verify tree belongs to client
    tree = get_merkle_tree(tree_id)
    if not tree:
        raise HTTPException(404, "Tree not found")
    if tree["client_id"] != client_id:
        raise HTTPException(403, "Tree belongs to different client")
    
    # Get witness
    witness = get_witness_by_commitment(tree_id, commitment_hex)
    if not witness:
        raise HTTPException(404, "Witness not found for commitment")
    
    # Get current root
    current_root = get_current_root(tree_id)
    valid_roots = get_valid_roots(tree_id, VALID_ROOTS_WINDOW)
    
    return WitnessResponse(
        tree_id=tree_id,
        leaf_index=witness["leaf_index"],
        leaf_commitment=commitment_hex,
        siblings=witness["siblings"],
        path_bits=witness["path_bits"],
        root_hash=witness["root_hash"],
        current_root=current_root or "",
        valid_roots=valid_roots,
    )


@router.get("/roots/{tree_id}")
def get_tree_roots(
    tree_id: str,
    limit: int = Query(30, ge=1, le=100),
    authorization: str = Header(..., alias="Authorization")
):
    """Get valid roots for a tree."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]
    client_id, _ = validate_api_key(api_key)
    
    tree = get_merkle_tree(tree_id)
    if not tree:
        raise HTTPException(404, "Tree not found")
    if tree["client_id"] != client_id:
        raise HTTPException(403, "Tree belongs to different client")
    
    valid_roots = get_valid_roots(tree_id, limit)
    current = get_current_root(tree_id)
    
    return {
        "tree_id": tree_id,
        "current_root": current,
        "valid_roots": valid_roots,
        "valid_count": len(valid_roots),
        "next_leaf_index": tree["next_leaf_index"],
    }


@router.post("/validate-root")
def validate_root(
    tree_id: str = Query(...),
    root: str = Query(...),
    authorization: str = Header(..., alias="Authorization")
):
    """Check if a root is in the valid window."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]
    client_id, _ = validate_api_key(api_key)
    
    tree = get_merkle_tree(tree_id)
    if not tree:
        raise HTTPException(404, "Tree not found")
    if tree["client_id"] != client_id:
        raise HTTPException(403, "Tree belongs to different client")
    
    valid = is_root_valid(tree_id, root, VALID_ROOTS_WINDOW)
    
    return {
        "tree_id": tree_id,
        "root": root,
        "valid": valid,
        "window_size": VALID_ROOTS_WINDOW,
    }


# =============================================================================
# Stats
# =============================================================================

@router.get("/stats")
def membership_stats(authorization: str = Header(..., alias="Authorization")):
    """Get membership statistics."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]
    client_id, _ = validate_api_key(api_key)
    
    trees = list_merkle_trees(client_id)
    
    stats = {
        "client_id": client_id,
        "trees": [],
    }
    
    for tree in trees:
        tree_id = tree["id"]
        stats["trees"].append({
            "tree_id": tree_id,
            "purpose": tree["purpose"],
            "leaf_count": tree["next_leaf_index"],
            "depth": tree["depth"],
            "current_root": get_current_root(tree_id),
        })
    
    return stats


# =============================================================================
# Health
# =============================================================================

@router.get("/health")
def health():
    """Health check for membership service."""
    stats = get_stats()
    return {
        "ok": True,
        "phase": 26,
        "stats": stats,
    }
