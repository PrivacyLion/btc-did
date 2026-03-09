"""
Membership enrollment, witness retrieval, and tree management.

3-STEP ENROLLMENT FLOW (Bible Section 4.3):
- POST /v1/membership/enroll/start - Enterprise creates enrollment session
- POST /v1/membership/enroll/verify-callback - Webhook from Persona/Jumio
- POST /v1/membership/enroll/commit - App submits leaf_commitment

DIRECT ENROLLMENT (Step 10.4 - enterprises without verification):
- POST /v1/membership/enroll - Submit enrollment directly (requires auto_approve policy)

WITNESS RETRIEVAL:
- GET /v1/membership/witness - Fetch witness for membership proof

ADMIN ENDPOINTS (gated behind SBM_INTERNAL_ADMIN=true):
- GET /v1/membership/enrollments - List all enrollments
- POST /v1/membership/approve - Manual approval override
- POST /v1/membership/build-tree - Force tree rebuild
- DELETE /v1/membership/enrollments/{id} - Delete enrollment

Storage: SQLite (persistent across restarts)
Hashing: Poseidon2 via Rust CLI (BN254 compatible with circuit)
"""

import os
import json
import time
import secrets
import subprocess
import logging
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..db import (
    # Enrollments
    create_enrollment,
    get_enrollment,
    list_enrollments,
    update_enrollment,
    approve_enrollment,
    reject_enrollment,
    # Enrollment sessions (3-step flow)
    create_enrollment_session,
    get_enrollment_session,
    mark_session_verified,
    commit_enrollment_session,
    delete_enrollment_session,
    cleanup_expired_sessions,
    # Roots & witnesses
    create_root,
    get_active_root,
    get_root_by_id,
    save_witness,
    get_witness,
    # Tokens & challenges
    create_enrollment_token as db_create_token,
    get_enrollment_token,
    consume_enrollment_token as db_consume_token,
    create_challenge as db_create_challenge,
    get_challenge as db_get_challenge,
    delete_challenge as db_delete_challenge,
    # Trees
    create_merkle_tree,
    get_merkle_tree,
    update_merkle_tree,
    add_root_to_history,
    get_current_root,
    # Audit
    audit_log,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["membership"])

# =============================================================================
# Poseidon2 Hashing via Rust CLI
# =============================================================================

POSEIDON_HASH_BIN = os.getenv(
    "POSEIDON_HASH_BIN",
    str(Path(__file__).resolve().parents[2] / "server" / "groth16-verifier" / "target" / "release" / "poseidon_hash")
)


def _call_poseidon_hash(args: list) -> bytes:
    """Call the poseidon_hash Rust CLI binary."""
    cmd = [POSEIDON_HASH_BIN] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError(f"poseidon_hash failed: {result.stderr.strip()}")
        return bytes.fromhex(result.stdout.strip())
    except FileNotFoundError:
        raise RuntimeError(f"poseidon_hash binary not found at {POSEIDON_HASH_BIN}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("poseidon_hash timed out")


def poseidon_hash_pair(left: bytes, right: bytes) -> bytes:
    """Compute Merkle tree internal node hash using Poseidon2."""
    return _call_poseidon_hash(["pair", left.hex(), right.hex()])


def poseidon_zero_hash() -> bytes:
    """Get the zero hash for empty leaves."""
    return _call_poseidon_hash(["zero"])


# =============================================================================
# Config
# =============================================================================

INTERNAL_ADMIN_ONLY = os.getenv("SBM_INTERNAL_ADMIN", "").lower() in ("true", "1", "yes")
ADMIN_API_KEY = os.getenv("SBM_ADMIN_KEY")
DATA_DIR = Path(__file__).resolve().parents[2]

ENROLLMENT_SESSION_TTL_SECONDS = 60 * 60  # 1 hour
ENROLLMENT_TOKEN_TTL_SECONDS = 30 * 60  # 30 minutes
CHALLENGE_TTL_SECONDS = 5 * 60  # 5 minutes
TREE_DEPTH = 20  # Standard depth for all trees

_rate_limit_cache: dict = {}
RATE_LIMIT_PER_HOUR = 100

PURPOSE_IDS = {"none": 0, "allowlist": 1, "issuer_batch": 2, "revocation": 3}


def get_purpose_id(purpose: str) -> int:
    return PURPOSE_IDS.get(purpose, 0)


def load_clients() -> dict:
    """Load enterprise client configs."""
    clients_file = DATA_DIR / "clients.json"
    if clients_file.exists():
        return json.loads(clients_file.read_text())
    return {}


# =============================================================================
# Auth helpers
# =============================================================================

def validate_enterprise_key(api_key: Optional[str]) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    if not api_key:
        raise HTTPException(401, "Missing X-API-Key header")
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    raise HTTPException(401, "Invalid API key")


def validate_admin_key(api_key: str):
    """Validate admin API key."""
    if not ADMIN_API_KEY:
        raise HTTPException(503, "Admin endpoints disabled - SBM_ADMIN_KEY not configured")
    if not api_key:
        raise HTTPException(401, "Missing admin API key")
    if api_key != ADMIN_API_KEY:
        raise HTTPException(401, "Invalid admin key")


def require_internal_enabled():
    """Check if internal admin endpoints are enabled."""
    if not INTERNAL_ADMIN_ONLY:
        raise HTTPException(403, "Admin endpoints disabled. Set SBM_INTERNAL_ADMIN=true to enable.")


def check_rate_limit(client_id: str):
    """Simple rate limiting per client."""
    now = time.time()
    hour_ago = now - 3600
    if client_id in _rate_limit_cache:
        _rate_limit_cache[client_id] = [t for t in _rate_limit_cache[client_id] if t > hour_ago]
    else:
        _rate_limit_cache[client_id] = []
    if len(_rate_limit_cache[client_id]) >= RATE_LIMIT_PER_HOUR:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")
    _rate_limit_cache[client_id].append(now)


# =============================================================================
# Models - 3-Step Enrollment Flow
# =============================================================================

class EnrollStartRequest(BaseModel):
    """Request to start an enrollment session."""
    verification_type: str = Field(..., description="What to verify: age_18_plus, kyc_basic, etc.")
    verification_provider: str = Field("persona", description="Verifier: persona, jumio, idme")
    callback_url: Optional[str] = Field(None, description="Webhook URL for completion notification")


class EnrollStartResponse(BaseModel):
    """Response from enrollment start."""
    enrollment_session_id: str
    verification_url: str
    expires_at: int


class VerifyCallbackRequest(BaseModel):
    """Webhook from verification provider."""
    enrollment_session_id: str
    passed: bool
    attribute: Optional[str] = None  # e.g., "age_18_plus"
    provider_signature: Optional[str] = None  # Cryptographic attestation


class VerifyCallbackResponse(BaseModel):
    """Response to verification webhook."""
    ok: bool
    enrollment_session_id: str
    verification_passed: bool


class EnrollCommitRequest(BaseModel):
    """Request to commit leaf_commitment to verified session."""
    enrollment_session_id: str
    leaf_commitment: str = Field(..., description="Hex-encoded commitment (32 bytes)")


class EnrollCommitResponse(BaseModel):
    """Response from enrollment commit."""
    ok: bool
    enrollment_id: str
    leaf_index: int
    merkle_root: str
    message: str


# =============================================================================
# Models - Direct Enrollment (Step 10.4)
# =============================================================================

class DirectEnrollRequest(BaseModel):
    """Direct enrollment without verification (for enterprises with auto_approve)."""
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    purpose: str = Field("allowlist", description="Purpose: allowlist, issuer_batch, revocation")


class DirectEnrollResponse(BaseModel):
    """Response from direct enrollment."""
    enrollment_id: str
    status: str
    purpose: str
    client_id: str
    leaf_index: Optional[int] = None
    merkle_root: Optional[str] = None
    message: str


# =============================================================================
# Models - Witness & Admin
# =============================================================================

class WitnessResponse(BaseModel):
    root_id: str
    root: str
    leaf_index: int
    siblings: List[str]
    purpose: str


class ApproveRequest(BaseModel):
    enrollment_ids: List[str]


class BuildTreeRequest(BaseModel):
    purpose: str = Field(..., description="Purpose: allowlist, issuer_batch, revocation")
    client_id: Optional[str] = Field(None, description="Client ID (required for allowlist)")


class BuildTreeResponse(BaseModel):
    root_id: str
    root: str
    purpose: str
    leaf_count: int
    created_at: int


class ListEnrollmentsResponse(BaseModel):
    pending: List[dict]
    approved: List[dict]
    in_tree: List[dict]


# =============================================================================
# Incremental Merkle Tree
# =============================================================================

def get_or_create_tree(client_id: str, purpose: str) -> dict:
    """Get or create an incremental Merkle tree for client+purpose."""
    tree_id = f"{client_id}-{purpose}"
    tree = get_merkle_tree(tree_id)
    if not tree:
        create_merkle_tree(tree_id, client_id, purpose, TREE_DEPTH)
        tree = get_merkle_tree(tree_id)
        
        # Initialize with precomputed zero hashes
        zeros_output = subprocess.run(
            [POSEIDON_HASH_BIN, "zeros", str(TREE_DEPTH)],
            capture_output=True, text=True, timeout=10
        )
        if zeros_output.returncode != 0:
            raise RuntimeError(f"Failed to compute zero hashes: {zeros_output.stderr}")
        
        # Parse zeros (format: "level:hash\n")
        zeros = []
        for line in zeros_output.stdout.strip().split("\n"):
            _, hash_hex = line.split(":")
            zeros.append(hash_hex)
        
        update_merkle_tree(tree_id, 0, zeros)
        tree = get_merkle_tree(tree_id)
    
    return tree


def insert_leaf_incremental(client_id: str, purpose: str, leaf_commitment: str) -> tuple[int, str, list]:
    """
    Insert a leaf into the incremental Merkle tree.
    
    Returns: (leaf_index, new_root, siblings)
    """
    tree = get_or_create_tree(client_id, purpose)
    tree_id = tree["id"]
    leaf_index = tree["next_leaf_index"]
    state = tree["state"]  # Current right-most path
    
    # Validate leaf commitment format
    commitment_hex = leaf_commitment.replace("0x", "")
    if len(commitment_hex) != 64:
        raise ValueError(f"leaf_commitment must be 32 bytes (64 hex chars)")
    commitment_bytes = bytes.fromhex(commitment_hex)
    
    # Compute new path from leaf to root
    current = commitment_bytes
    new_state = [commitment_hex]
    siblings = []
    
    idx = leaf_index
    for level in range(TREE_DEPTH):
        if idx & 1 == 0:
            # New leaf is on the left, sibling is from state (default zero)
            sibling_hex = state[level] if level < len(state) else "00" * 32
            sibling = bytes.fromhex(sibling_hex)
            parent = poseidon_hash_pair(current, sibling)
        else:
            # New leaf is on the right, sibling is from state
            sibling_hex = state[level] if level < len(state) else "00" * 32
            sibling = bytes.fromhex(sibling_hex)
            parent = poseidon_hash_pair(sibling, current)
        
        siblings.append("0x" + sibling_hex)
        new_state.append(parent.hex())
        current = parent
        idx //= 2
    
    new_root = "0x" + current.hex()
    
    # Update tree state
    update_merkle_tree(tree_id, leaf_index + 1, new_state[:TREE_DEPTH])
    
    # Add root to history
    add_root_to_history(tree_id, new_root, leaf_index)
    
    return leaf_index, new_root, siblings


# =============================================================================
# 3-STEP ENROLLMENT ENDPOINTS
# =============================================================================

@router.post("/v1/membership/enroll/start", response_model=EnrollStartResponse)
def enroll_start(
    body: EnrollStartRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Step 1: Enterprise creates an enrollment session.
    
    Returns enrollment_session_id and verification_url for the user to complete
    verification with the third-party provider (Persona, Jumio, etc.).
    """
    client_id, config = validate_enterprise_key(x_api_key)
    check_rate_limit(client_id)
    
    # Generate session ID
    session_id = "enr_" + secrets.token_urlsafe(24)
    expires_at = int(time.time()) + ENROLLMENT_SESSION_TTL_SECONDS
    
    # Create session in database
    create_enrollment_session(
        session_id=session_id,
        client_id=client_id,
        verification_type=body.verification_type,
        verification_provider=body.verification_provider,
        callback_url=body.callback_url,
        expires_at=expires_at,
    )
    
    # Generate verification URL (provider-specific)
    # In production, this would integrate with Persona/Jumio API
    verification_url = f"https://{body.verification_provider}.com/verify?session={session_id}"
    
    audit_log("enrollment_session_created", client_id=client_id, details={
        "session_id": session_id,
        "verification_type": body.verification_type,
        "verification_provider": body.verification_provider,
    })
    
    return EnrollStartResponse(
        enrollment_session_id=session_id,
        verification_url=verification_url,
        expires_at=expires_at,
    )


@router.post("/v1/membership/enroll/verify-callback", response_model=VerifyCallbackResponse)
def enroll_verify_callback(body: VerifyCallbackRequest):
    """
    Step 2: Webhook from verification provider (Persona, Jumio).
    
    Receives pass/fail result. NO PII - only the verification result.
    This endpoint should be called by the verification provider, not the user.
    """
    session = get_enrollment_session(body.enrollment_session_id)
    if not session:
        raise HTTPException(404, "Enrollment session not found")
    
    if session["expires_at"] < int(time.time()):
        raise HTTPException(410, "Enrollment session expired")
    
    if session["used"]:
        raise HTTPException(409, "Enrollment session already used")
    
    if body.passed:
        success = mark_session_verified(
            body.enrollment_session_id,
            provider_signature=body.provider_signature,
        )
        if not success:
            raise HTTPException(500, "Failed to mark session as verified")
    
    audit_log("verification_callback", client_id=session["client_id"], details={
        "session_id": body.enrollment_session_id,
        "passed": body.passed,
        "attribute": body.attribute,
    })
    
    return VerifyCallbackResponse(
        ok=True,
        enrollment_session_id=body.enrollment_session_id,
        verification_passed=body.passed,
    )


@router.post("/v1/membership/enroll/commit", response_model=EnrollCommitResponse)
def enroll_commit(body: EnrollCommitRequest):
    """
    Step 3: User submits leaf_commitment after verification passed.
    
    Validates:
    - Session exists
    - Verification passed
    - Session not already used
    - Commitment format valid
    
    Appends commitment to incremental Merkle tree immediately.
    Per Bible Section 13.6: After commit, enrollment_session_id is permanently deleted.
    """
    # Validate commitment format
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        if len(commitment_hex) != 64:
            raise ValueError("Must be 32 bytes")
        bytes.fromhex(commitment_hex)
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Commit to session (validates all conditions)
    session = commit_enrollment_session(body.enrollment_session_id, body.leaf_commitment)
    if not session:
        # Need to determine why it failed
        s = get_enrollment_session(body.enrollment_session_id)
        if not s:
            raise HTTPException(404, "Enrollment session not found")
        if s["expires_at"] < int(time.time()):
            raise HTTPException(410, "Enrollment session expired")
        if s["used"]:
            raise HTTPException(409, "Enrollment session already used")
        if not s["verification_passed"]:
            raise HTTPException(403, "Verification not yet passed")
        raise HTTPException(500, "Failed to commit enrollment")
    
    client_id = session["client_id"]
    purpose = "allowlist"  # Default purpose for 3-step flow
    
    # Insert into incremental Merkle tree
    try:
        leaf_index, new_root, siblings = insert_leaf_incremental(
            client_id, purpose, body.leaf_commitment
        )
    except Exception as e:
        logger.error(f"Failed to insert leaf: {e}")
        raise HTTPException(500, f"Failed to insert into Merkle tree: {e}")
    
    # Create enrollment record (only commitment, client_id, timestamp - NO session_id)
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=purpose,
        leaf_commitment=body.leaf_commitment,
        status="in_tree",
    )
    
    # Update enrollment with tree position
    update_enrollment(
        enrollment_id,
        tree_id=f"{client_id}-{purpose}",
        leaf_index=leaf_index,
        tree_built_at=int(time.time()),
    )
    
    # Save witness
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx //= 2
    
    save_witness(
        enrollment_id=enrollment_id,
        root_id=f"{client_id}-{purpose}",
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
    )
    
    # Delete enrollment session (Section 13.6 - destroy correlation chain)
    delete_enrollment_session(body.enrollment_session_id)
    
    audit_log("enrollment_committed", client_id=client_id, details={
        "enrollment_id": enrollment_id,
        "leaf_index": leaf_index,
        "root": new_root,
    })
    
    return EnrollCommitResponse(
        ok=True,
        enrollment_id=enrollment_id,
        leaf_index=leaf_index,
        merkle_root=new_root,
        message="Enrolled successfully. You can now log in.",
    )


# =============================================================================
# DIRECT ENROLLMENT (Step 10.4)
# =============================================================================

@router.post("/v1/membership/enroll", response_model=DirectEnrollResponse)
def direct_enroll(
    body: DirectEnrollRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Direct enrollment without verification.
    
    For enterprises with auto_approve policy that don't require third-party
    verification. Commitment is immediately added to the Merkle tree.
    
    NOTE: This endpoint does NOT accept DID. Only the commitment hash is sent.
    """
    client_id, config = validate_enterprise_key(x_api_key)
    check_rate_limit(client_id)
    
    # Check if direct enrollment is allowed
    policy = config.get("membership_policy", {})
    if not policy.get("auto_approve", False):
        raise HTTPException(
            403,
            "Direct enrollment requires auto_approve policy. Use /v1/membership/enroll/start for verification flow."
        )
    
    # Validate commitment
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        if len(commitment_hex) != 64:
            raise ValueError("Must be 32 bytes")
        bytes.fromhex(commitment_hex)
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Validate purpose
    if body.purpose not in PURPOSE_IDS:
        raise HTTPException(400, f"Invalid purpose: {body.purpose}")
    
    # Check for duplicate commitment
    existing = list_enrollments(client_id=client_id, purpose=body.purpose)
    for e in existing:
        if e.get("leaf_commitment") == body.leaf_commitment:
            raise HTTPException(409, "Commitment already enrolled")
    
    # Insert into incremental Merkle tree
    try:
        leaf_index, new_root, siblings = insert_leaf_incremental(
            client_id, body.purpose, body.leaf_commitment
        )
    except Exception as e:
        logger.error(f"Failed to insert leaf: {e}")
        raise HTTPException(500, f"Failed to insert into Merkle tree: {e}")
    
    # Create enrollment record
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=body.purpose,
        leaf_commitment=body.leaf_commitment,
        status="in_tree",
    )
    
    # Update enrollment with tree position
    update_enrollment(
        enrollment_id,
        tree_id=f"{client_id}-{body.purpose}",
        leaf_index=leaf_index,
        tree_built_at=int(time.time()),
    )
    
    # Save witness
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx //= 2
    
    save_witness(
        enrollment_id=enrollment_id,
        root_id=f"{client_id}-{body.purpose}",
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
    )
    
    audit_log("direct_enrollment", client_id=client_id, details={
        "enrollment_id": enrollment_id,
        "leaf_index": leaf_index,
        "purpose": body.purpose,
        "root": new_root,
    })
    
    return DirectEnrollResponse(
        enrollment_id=enrollment_id,
        status="in_tree",
        purpose=body.purpose,
        client_id=client_id,
        leaf_index=leaf_index,
        merkle_root=new_root,
        message="Enrolled directly. You can log in immediately.",
    )


# =============================================================================
# WITNESS RETRIEVAL
# =============================================================================

@router.get("/v1/membership/witness", response_model=WitnessResponse)
def get_member_witness(
    enrollment_id: str = Query(..., description="Enrollment ID"),
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Fetch witness for membership proof.
    
    Returns the Merkle path (siblings) needed to prove membership.
    """
    client_id, _ = validate_enterprise_key(x_api_key)
    
    # Get enrollment
    enrollment = get_enrollment(enrollment_id)
    if not enrollment:
        raise HTTPException(404, "Enrollment not found")
    
    # Verify client_id matches
    if enrollment["client_id"] != client_id:
        raise HTTPException(403, "Enrollment belongs to different client")
    
    if enrollment["status"] != "in_tree":
        raise HTTPException(400, f"Enrollment not in tree (status: {enrollment['status']})")
    
    # Get witness
    witness = get_witness(enrollment_id)
    if not witness:
        raise HTTPException(404, "Witness not found")
    
    # Get current root
    tree_id = enrollment["tree_id"]
    current_root = get_current_root(tree_id)
    
    return WitnessResponse(
        root_id=tree_id,
        root=current_root or "0x" + "00" * 32,
        leaf_index=witness["leaf_index"],
        siblings=witness["siblings"],
        purpose=enrollment["purpose"],
    )


# =============================================================================
# ADMIN ENDPOINTS
# =============================================================================

@router.get("/v1/membership/enrollments", response_model=ListEnrollmentsResponse)
def list_all_enrollments(
    x_admin_key: str = Header(None, alias="X-Admin-Key")
):
    """List all enrollments (admin)."""
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    pending = list_enrollments(status="pending")
    approved = list_enrollments(status="approved")
    in_tree = list_enrollments(status="in_tree")
    
    return ListEnrollmentsResponse(
        pending=pending,
        approved=approved,
        in_tree=in_tree,
    )


@router.post("/v1/membership/approve", response_model=dict)
def approve_enrollments(
    body: ApproveRequest,
    x_admin_key: str = Header(None, alias="X-Admin-Key")
):
    """Manually approve enrollments (admin)."""
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    approved_count = 0
    for enrollment_id in body.enrollment_ids:
        enrollment = get_enrollment(enrollment_id)
        if enrollment and enrollment["status"] == "pending":
            approve_enrollment(enrollment_id)
            approved_count += 1
    
    audit_log("enrollments_approved", details={"count": approved_count})
    
    return {"ok": True, "approved": approved_count}


@router.post("/v1/membership/build-tree", response_model=BuildTreeResponse)
def build_tree(
    body: BuildTreeRequest,
    x_admin_key: str = Header(None, alias="X-Admin-Key")
):
    """
    Force tree rebuild (admin).
    
    Note: With incremental trees, this is rarely needed. The tree is updated
    on each enrollment commit.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    client_id = body.client_id
    if not client_id:
        raise HTTPException(400, "client_id required")
    
    # Just return current tree state
    tree = get_or_create_tree(client_id, body.purpose)
    current_root = get_current_root(tree["id"])
    
    return BuildTreeResponse(
        root_id=tree["id"],
        root=current_root or "0x" + "00" * 32,
        purpose=body.purpose,
        leaf_count=tree["next_leaf_index"],
        created_at=tree["created_at"],
    )


@router.delete("/v1/membership/enrollments/{enrollment_id}", response_model=dict)
def delete_member_enrollment(
    enrollment_id: str,
    x_admin_key: str = Header(None, alias="X-Admin-Key")
):
    """Delete an enrollment (admin)."""
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    enrollment = get_enrollment(enrollment_id)
    if not enrollment:
        raise HTTPException(404, "Enrollment not found")
    
    from ..db import get_connection
    conn = get_connection()
    conn.execute("DELETE FROM enrollments WHERE id = ?", (enrollment_id,))
    conn.execute("DELETE FROM merkle_witnesses WHERE enrollment_id = ?", (enrollment_id,))
    conn.commit()
    
    audit_log("enrollment_deleted", details={"enrollment_id": enrollment_id})
    
    return {"ok": True, "deleted": enrollment_id}


@router.get("/v1/membership/session/{session_id}")
def get_session_status(
    session_id: str,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Get enrollment session status (for app polling).
    
    App polls this to check if verification has passed.
    """
    client_id, _ = validate_enterprise_key(x_api_key)
    
    session = get_enrollment_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    
    if session["client_id"] != client_id:
        raise HTTPException(403, "Session belongs to different client")
    
    return {
        "enrollment_session_id": session_id,
        "verification_passed": bool(session["verification_passed"]),
        "used": bool(session["used"]),
        "expires_at": session["expires_at"],
    }
