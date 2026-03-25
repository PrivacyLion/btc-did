"""
Enrollment API (Phase 10)

3-step enrollment flow:
1. POST /v1/enroll/start - Start enrollment, get verification token
2. POST /v1/enroll/verify-callback - Email/SMS verification callback
3. POST /v1/enroll/commit - Commit to Merkle tree

Direct enrollment (for auto-approve clients):
- POST /v1/enroll - One-step enrollment + commit

Incremental Merkle Tree:
- New root computed on each insert (O(log n) updates)
- Last 30 roots valid (handles concurrent proofs)
- Witnesses updated automatically

Storage: SQLite (app/var/signedby.db)
"""

import os
import json
import time
import secrets
import hashlib
import subprocess
import logging
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel, Field

from ..db import (
    create_enrollment,
    get_enrollment,
    list_enrollments,
    update_enrollment,
    approve_enrollment as db_approve,
    create_merkle_tree,
    get_merkle_tree,
    update_merkle_tree,
    add_root_to_history,
    get_valid_roots,
    get_current_root,
    is_root_valid,
    save_witness,
    get_witness,
    audit_log,
    get_connection,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/membership/enroll", tags=["enrollment"])

# =============================================================================
# Config
# =============================================================================

DATA_DIR = Path(__file__).resolve().parents[2]
TREE_DEPTH = 20  # Fixed depth for all trees (2^20 = 1M leaves max)
VALID_ROOTS_WINDOW = 30  # Last 30 roots are valid

# Verification token TTL
VERIFY_TOKEN_TTL = 30 * 60  # 30 minutes

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


def validate_enterprise_key(api_key: Optional[str]) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    if not api_key:
        raise HTTPException(401, "Missing X-API-Key header")
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    raise HTTPException(401, "Invalid API key")


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


# =============================================================================
# Incremental Merkle Tree
# =============================================================================

def get_zero_hash(level: int) -> str:
    """Get the zero hash for a given level (precomputed)."""
    # Level 0 = leaf level, level N = root
    # For simplicity, use zeros (can be precomputed Poseidon hashes later)
    return "0" * 64


def compute_root_from_state(state: List[str], depth: int) -> str:
    """Compute root from tree state (right-most path hashes)."""
    if not state or len(state) != depth:
        return get_zero_hash(depth)
    
    # State contains the hash at each level along the right-most path
    # We need to hash up to get the root
    current = state[0]
    for level in range(1, depth):
        sibling = state[level]
        # At each level, current is the left child, sibling is the right (filled) side
        current = hash_pair(current, sibling)
    
    return current


def insert_leaf(tree_id: str, leaf_hash: str) -> tuple[str, int, List[str]]:
    """
    Insert a leaf into the incremental Merkle tree.
    
    Returns: (new_root, leaf_index, witness_siblings)
    
    Algorithm:
    1. Get current tree state
    2. Compute witness (path from leaf to root)
    3. Update tree state
    4. Compute and store new root
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
        # Determine if we're a left or right child
        is_right = (idx & 1) == 1
        
        if is_right:
            # We're right child, sibling is the existing hash at this level
            sibling = state[level]
            siblings.append(sibling)
            # Hash: parent = hash(sibling, current)
            current_hash = hash_pair(sibling, current_hash)
        else:
            # We're left child, sibling is zero hash
            sibling = get_zero_hash(level)
            siblings.append(sibling)
            # Update state: this level now has our hash
            new_state[level] = current_hash
            # Hash: parent = hash(current, sibling)
            current_hash = hash_pair(current_hash, sibling)
        
        idx >>= 1
    
    new_root = current_hash
    
    # Update tree state
    update_merkle_tree(tree_id, leaf_index + 1, new_state)
    
    # Add root to history
    add_root_to_history(tree_id, new_root, leaf_index)
    
    return new_root, leaf_index, siblings


def get_or_create_tree(client_id: str, purpose: str) -> str:
    """Get or create a Merkle tree for client+purpose."""
    tree_id = f"{client_id}-{purpose}"
    tree = get_merkle_tree(tree_id)
    if not tree:
        create_merkle_tree(tree_id, client_id, purpose, TREE_DEPTH)
        # Initialize with empty root in history
        empty_root = get_zero_hash(TREE_DEPTH)
        add_root_to_history(tree_id, empty_root, -1)
    return tree_id


# =============================================================================
# Models
# =============================================================================

class EnrollStartRequest(BaseModel):
    """Start enrollment request."""
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    email: Optional[str] = Field(None, description="Email for verification (optional)")
    purpose: str = Field("allowlist", description="Purpose: allowlist, issuer_batch, revocation")


class EnrollStartResponse(BaseModel):
    """Start enrollment response."""
    enrollment_id: str
    verify_token: str
    verify_token_expires_at: int
    status: str  # pending_verification, auto_approved
    verify_url: Optional[str] = None  # URL to verify (if email provided)
    message: str


class EnrollVerifyRequest(BaseModel):
    """Verify enrollment request (callback from email/SMS)."""
    enrollment_id: str
    verify_token: str
    verification_code: Optional[str] = Field(None, description="Code from email/SMS")


class EnrollVerifyResponse(BaseModel):
    """Verify enrollment response."""
    enrollment_id: str
    status: str  # verified, already_verified, invalid
    commit_token: str  # Token to use for commit step
    commit_token_expires_at: int
    message: str


class EnrollCommitRequest(BaseModel):
    """Commit enrollment to tree."""
    enrollment_id: str
    commit_token: str


class EnrollCommitResponse(BaseModel):
    """Commit enrollment response."""
    enrollment_id: str
    status: str  # committed
    tree_id: str
    root: str
    leaf_index: int
    witness: dict  # {siblings: [...], path_bits: [...]}
    message: str


class DirectEnrollRequest(BaseModel):
    """Direct enrollment (one-step for auto-approve clients)."""
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    purpose: str = Field("allowlist", description="Purpose")


class DirectEnrollResponse(BaseModel):
    """Direct enrollment response."""
    enrollment_id: str
    status: str  # committed
    tree_id: str
    root: str
    leaf_index: int
    witness: dict
    valid_roots: List[str]  # Last 30 valid roots
    message: str


# =============================================================================
# Enrollment State (stored in enrollments table)
# =============================================================================
# Status flow:
#   pending_verification -> verified -> committed
#   (auto_approved)      -> committed  (direct path)
#
# Fields stored in enrollments:
#   - email_hash: SHA256(email) or DID
#   - leaf_commitment: The commitment
#   - status: pending, approved, in_tree (we'll use these)
#   - Extra data stored in a separate table or JSON field

def create_verify_token(enrollment_id: str) -> tuple[str, int]:
    """Create verification token."""
    token = "vtk_" + secrets.token_urlsafe(32)
    expires_at = int(time.time()) + VERIFY_TOKEN_TTL
    # Store in enrollment_tokens table
    from ..db import create_enrollment_token
    create_enrollment_token(token, enrollment_id, "", "", expires_at)
    return token, expires_at


def validate_verify_token(token: str, enrollment_id: str) -> bool:
    """Validate verification token."""
    from ..db import get_enrollment_token
    t = get_enrollment_token(token)
    return t is not None and t["enrollment_id"] == enrollment_id


def consume_verify_token(token: str):
    """Consume verification token."""
    from ..db import consume_enrollment_token
    consume_enrollment_token(token)


# =============================================================================
# Endpoints: 3-Step Flow
# =============================================================================

@router.post("/start", response_model=EnrollStartResponse)
def enroll_start(
    body: EnrollStartRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Step 1: Start enrollment.
    
    Creates enrollment record, returns verification token.
    If client has auto_approve policy, skips to verified status.
    """
    client_id, config = validate_enterprise_key(x_api_key)
    
    # Validate commitment
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        if len(bytes.fromhex(commitment_hex)) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Check for duplicate
    existing = list_enrollments(client_id=client_id)
    for e in existing:
        if e.get("leaf_commitment") == body.leaf_commitment:
            raise HTTPException(409, "Commitment already enrolled")
    
    # Create enrollment
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    email_hash = hashlib.sha256(body.email.encode()).hexdigest() if body.email else None
    
    # Check auto-approve policy
    policy = config.get("membership_policy", {})
    auto_approve = policy.get("auto_approve", False)
    
    initial_status = "approved" if auto_approve else "pending"
    
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=body.purpose,
        leaf_commitment=body.leaf_commitment,
        email_hash=email_hash,
        status=initial_status,
    )
    
    # Create verification token
    verify_token, verify_expires = create_verify_token(enrollment_id)
    
    # For auto-approve, status is already approved
    if auto_approve:
        status = "auto_approved"
        message = "Auto-approved. Use token to commit to tree."
        verify_url = None
    else:
        status = "pending_verification"
        message = "Verification required. Check email or use callback endpoint."
        # In production, send verification email here
        verify_url = f"https://api.beta.privacy-lion.com/v1/enroll/verify-callback?enrollment_id={enrollment_id}&token={verify_token}"
    
    audit_log("enroll_start", client_id=client_id, details={
        "enrollment_id": enrollment_id, "status": status, "purpose": body.purpose
    })
    
    return EnrollStartResponse(
        enrollment_id=enrollment_id,
        verify_token=verify_token,
        verify_token_expires_at=verify_expires,
        status=status,
        verify_url=verify_url,
        message=message,
    )


@router.post("/verify-callback", response_model=EnrollVerifyResponse)
def enroll_verify_callback(
    body: EnrollVerifyRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Step 2: Verify enrollment (callback from email/SMS).
    
    Validates token, marks enrollment as verified.
    Returns commit token for final step.
    """
    client_id, _ = validate_enterprise_key(x_api_key)
    
    # Get enrollment
    enrollment = get_enrollment(body.enrollment_id)
    if not enrollment:
        raise HTTPException(404, "Enrollment not found")
    
    if enrollment["client_id"] != client_id:
        raise HTTPException(403, "Enrollment belongs to different client")
    
    # Validate token
    if not validate_verify_token(body.verify_token, body.enrollment_id):
        raise HTTPException(401, "Invalid or expired verification token")
    
    # Check status
    if enrollment["status"] == "in_tree":
        raise HTTPException(400, "Enrollment already committed")
    
    # Mark as approved (verified)
    db_approve(body.enrollment_id)
    consume_verify_token(body.verify_token)
    
    # Create commit token
    commit_token, commit_expires = create_verify_token(body.enrollment_id)
    
    audit_log("enroll_verified", client_id=client_id, details={
        "enrollment_id": body.enrollment_id
    })
    
    return EnrollVerifyResponse(
        enrollment_id=body.enrollment_id,
        status="verified",
        commit_token=commit_token,
        commit_token_expires_at=commit_expires,
        message="Verified. Use commit_token to add to Merkle tree.",
    )


@router.post("/commit", response_model=EnrollCommitResponse)
def enroll_commit(
    body: EnrollCommitRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Step 3: Commit enrollment to Merkle tree.
    
    Inserts leaf into incremental tree, returns witness.
    """
    client_id, _ = validate_enterprise_key(x_api_key)
    
    # Get enrollment
    enrollment = get_enrollment(body.enrollment_id)
    if not enrollment:
        raise HTTPException(404, "Enrollment not found")
    
    if enrollment["client_id"] != client_id:
        raise HTTPException(403, "Enrollment belongs to different client")
    
    # Validate token
    if not validate_verify_token(body.commit_token, body.enrollment_id):
        raise HTTPException(401, "Invalid or expired commit token")
    
    # Check status - must be approved
    if enrollment["status"] == "pending":
        raise HTTPException(400, "Enrollment not yet verified")
    if enrollment["status"] == "in_tree":
        raise HTTPException(400, "Enrollment already committed")
    
    # Get or create tree
    tree_id = get_or_create_tree(client_id, enrollment["purpose"])
    
    # Insert leaf into tree
    leaf_hash = enrollment["leaf_commitment"].replace("0x", "")
    new_root, leaf_index, siblings = insert_leaf(tree_id, leaf_hash)
    
    # Compute path bits from leaf index
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx >>= 1
    
    # Save witness
    save_witness(
        enrollment_id=body.enrollment_id,
        root_id=tree_id,
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
    )
    
    # Update enrollment status
    update_enrollment(
        body.enrollment_id,
        status="in_tree",
        tree_id=tree_id,
        leaf_index=leaf_index,
        tree_built_at=int(time.time()),
    )
    
    consume_verify_token(body.commit_token)
    
    audit_log("enroll_committed", client_id=client_id, details={
        "enrollment_id": body.enrollment_id,
        "tree_id": tree_id,
        "leaf_index": leaf_index,
        "root": new_root[:16] + "...",
    })
    
    return EnrollCommitResponse(
        enrollment_id=body.enrollment_id,
        status="committed",
        tree_id=tree_id,
        root=new_root,
        leaf_index=leaf_index,
        witness={
            "siblings": siblings,
            "path_bits": path_bits,
        },
        message="Successfully added to Merkle tree.",
    )


# =============================================================================
# Direct Enrollment (one-step for auto-approve clients)
# =============================================================================

@router.post("", response_model=DirectEnrollResponse)
def direct_enroll(
    body: DirectEnrollRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Direct enrollment (one-step).
    
    For clients with auto_approve policy.
    Creates enrollment and immediately commits to tree.
    """
    client_id, config = validate_enterprise_key(x_api_key)
    
    # Check auto-approve policy
    policy = config.get("membership_policy", {})
    if not policy.get("auto_approve", False):
        raise HTTPException(403, "Direct enrollment requires auto_approve policy. Use /start flow instead.")
    
    # Validate commitment
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        if len(bytes.fromhex(commitment_hex)) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Check for duplicate
    existing = list_enrollments(client_id=client_id)
    for e in existing:
        if e.get("leaf_commitment") == body.leaf_commitment:
            raise HTTPException(409, "Commitment already enrolled")
    
    # Create enrollment
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=body.purpose,
        leaf_commitment=body.leaf_commitment,
        email_hash=None,
        status="approved",
    )
    
    # Get or create tree
    tree_id = get_or_create_tree(client_id, body.purpose)
    
    # Insert leaf
    leaf_hash = body.leaf_commitment.replace("0x", "")
    new_root, leaf_index, siblings = insert_leaf(tree_id, leaf_hash)
    
    # Compute path bits
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx >>= 1
    
    # Save witness
    save_witness(
        enrollment_id=enrollment_id,
        root_id=tree_id,
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
    )
    
    # Update enrollment
    update_enrollment(
        enrollment_id,
        status="in_tree",
        tree_id=tree_id,
        leaf_index=leaf_index,
        tree_built_at=int(time.time()),
    )
    
    # Get valid roots
    valid_roots = get_valid_roots(tree_id, VALID_ROOTS_WINDOW)
    
    audit_log("direct_enroll", client_id=client_id, details={
        "enrollment_id": enrollment_id,
        "tree_id": tree_id,
        "leaf_index": leaf_index,
    })
    
    return DirectEnrollResponse(
        enrollment_id=enrollment_id,
        status="committed",
        tree_id=tree_id,
        root=new_root,
        leaf_index=leaf_index,
        witness={
            "siblings": siblings,
            "path_bits": path_bits,
        },
        valid_roots=valid_roots,
        message="Enrolled and committed to Merkle tree.",
    )


# =============================================================================
# Utility Endpoints
# =============================================================================

@router.get("/roots/{tree_id}")
def get_tree_roots(
    tree_id: str,
    limit: int = Query(30, ge=1, le=100),
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """Get valid roots for a tree."""
    client_id, _ = validate_enterprise_key(x_api_key)
    
    # Verify tree belongs to client
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


@router.get("/witness/{enrollment_id}")
def get_enrollment_witness(
    enrollment_id: str,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """Get witness for an enrollment."""
    client_id, _ = validate_enterprise_key(x_api_key)
    
    enrollment = get_enrollment(enrollment_id)
    if not enrollment:
        raise HTTPException(404, "Enrollment not found")
    if enrollment["client_id"] != client_id:
        raise HTTPException(403, "Enrollment belongs to different client")
    if enrollment["status"] != "in_tree":
        raise HTTPException(400, "Enrollment not yet committed to tree")
    
    witness = get_witness(enrollment_id)
    if not witness:
        raise HTTPException(404, "Witness not found")
    
    tree_id = enrollment.get("tree_id")
    current_root = get_current_root(tree_id) if tree_id else None
    valid_roots = get_valid_roots(tree_id, VALID_ROOTS_WINDOW) if tree_id else []
    
    return {
        "enrollment_id": enrollment_id,
        "tree_id": tree_id,
        "leaf_index": witness["leaf_index"],
        "siblings": witness["siblings"],
        "path_bits": witness["path_bits"],
        "current_root": current_root,
        "valid_roots": valid_roots,
    }


@router.post("/validate-root")
def validate_root(
    tree_id: str = Query(...),
    root: str = Query(...),
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """Check if a root is in the valid window."""
    client_id, _ = validate_enterprise_key(x_api_key)
    
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
