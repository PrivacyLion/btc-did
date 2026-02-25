"""
Membership enrollment, witness retrieval, and tree management.

PUBLIC ENDPOINTS (RP-authenticated via X-API-Key):
- POST /v1/membership/enroll - Submit enrollment (auto-approve based on policy)
- POST /v1/membership/challenge - Get DID signature challenge
- GET /v1/membership/witness - Fetch witness (requires token or DID signature)

ADMIN ENDPOINTS (gated behind SBM_INTERNAL_ADMIN=true):
- GET /v1/membership/enrollments - List all enrollments
- POST /v1/membership/approve - Manual approval override
- POST /v1/membership/build-tree - Force tree rebuild
- DELETE /v1/membership/enrollments/{id} - Delete enrollment

Storage: SQLite (persistent across restarts)
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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..db import (
    create_enrollment,
    get_enrollment,
    list_enrollments,
    update_enrollment,
    approve_enrollment,
    reject_enrollment,
    create_root,
    get_active_root,
    get_root_by_id,
    save_witness,
    get_witness,
    create_enrollment_token as db_create_token,
    get_enrollment_token,
    consume_enrollment_token as db_consume_token,
    create_challenge as db_create_challenge,
    get_challenge as db_get_challenge,
    delete_challenge as db_delete_challenge,
    audit_log,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["membership"])

# =============================================================================
# Poseidon2 Hashing via Rust CLI
# =============================================================================

POSEIDON_HASH_BIN = os.getenv(
    "POSEIDON_HASH_BIN", 
    str(Path(__file__).resolve().parents[2] / "native" / "signedby_core" / "target" / "release" / "poseidon_hash")
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


def compute_leaf_commitment(leaf_secret: bytes) -> bytes:
    """Compute leaf commitment from secret using Poseidon2."""
    if len(leaf_secret) != 32:
        raise ValueError(f"leaf_secret must be 32 bytes, got {len(leaf_secret)}")
    result = _call_poseidon_hash(["leaf_commit", leaf_secret.hex()])
    return result.ljust(32, b'\x00')


def compute_nullifier(leaf_secret: bytes, session_id: bytes) -> bytes:
    """Compute session-specific nullifier using Poseidon2."""
    if len(leaf_secret) != 32:
        raise ValueError(f"leaf_secret must be 32 bytes")
    if len(session_id) != 32:
        raise ValueError(f"session_id must be 32 bytes")
    result = _call_poseidon_hash(["nullifier", leaf_secret.hex(), session_id.hex()])
    return result.ljust(32, b'\x00')


# =============================================================================
# Config
# =============================================================================

INTERNAL_ADMIN_ONLY = os.getenv("SBM_INTERNAL_ADMIN", "").lower() in ("true", "1", "yes")
ADMIN_API_KEY = os.getenv("SBM_ADMIN_KEY")
DATA_DIR = Path(__file__).resolve().parents[2]

ENROLLMENT_TOKEN_TTL_SECONDS = 30 * 60  # 30 minutes
CHALLENGE_TTL_SECONDS = 5 * 60  # 5 minutes

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
# Models
# =============================================================================

class EnrollRequest(BaseModel):
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    did: str = Field(..., description="User's DID (did:key:z6Mk...)")
    purpose: str = Field("allowlist", description="Purpose: allowlist, issuer_batch, revocation")


class EnrollResponse(BaseModel):
    enrollment_id: str
    enrollment_token: str
    enrollment_token_expires_at: int
    status: str
    purpose: str
    client_id: str
    message: str


class ChallengeRequest(BaseModel):
    did: str = Field(..., description="User's DID")


class ChallengeResponse(BaseModel):
    challenge: str
    challenge_expires_at: int


class WitnessResponse(BaseModel):
    root_id: str
    root: str
    leaf_index: int
    siblings: List[str]
    purpose: str
    expires_at: int


class ApproveRequest(BaseModel):
    enrollment_ids: List[str]


class BuildTreeRequest(BaseModel):
    purpose: str = Field(..., description="Purpose: allowlist, issuer_batch, revocation")
    client_id: Optional[str] = Field(None, description="Client ID (required for allowlist)")
    root_id: Optional[str] = Field(None, description="Custom root ID")
    description: Optional[str] = Field(None)
    expires_days: int = Field(365)


class BuildTreeResponse(BaseModel):
    root_id: str
    root: str
    purpose: str
    leaf_count: int
    created_at: int
    expires_at: int


class ListEnrollmentsResponse(BaseModel):
    pending: List[dict]
    approved: List[dict]
    in_tree: List[dict]


# =============================================================================
# Tree building
# =============================================================================

def merkle_hash_pair(left: bytes, right: bytes) -> bytes:
    """Compute Merkle tree internal node hash using Poseidon2."""
    left_m31 = left[:4].hex() if len(left) >= 4 else left.ljust(4, b'\x00').hex()
    right_m31 = right[:4].hex() if len(right) >= 4 else right.ljust(4, b'\x00').hex()
    result = _call_poseidon_hash(["pair", left_m31, right_m31])
    return result.ljust(32, b'\x00')


def build_merkle_tree_with_witnesses(leaves: List[bytes]) -> tuple[bytes, List[dict]]:
    """Build a Merkle tree and return (root, witnesses)."""
    if not leaves:
        return bytes(32), []
    
    # Ensure power of 2
    n = len(leaves)
    next_pow2 = 1
    while next_pow2 < n:
        next_pow2 *= 2
    
    padded = leaves + [bytes(32)] * (next_pow2 - n)
    
    # Build layers
    layers = [padded]
    current = padded
    
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else bytes(32)
            parent = merkle_hash_pair(left, right)
            next_layer.append(parent)
        layers.append(next_layer)
        current = next_layer
    
    root = current[0] if current else bytes(32)
    
    # Generate witnesses
    witnesses = []
    for leaf_index in range(n):
        siblings = []
        path_bits = []
        idx = leaf_index
        for layer in layers[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(layer):
                siblings.append("0x" + layer[sibling_idx].hex())
            else:
                siblings.append("0x" + ("00" * 32))
            path_bits.append(idx & 1)
            idx //= 2
        witnesses.append({
            "leaf_index": leaf_index,
            "siblings": siblings,
            "path_bits": path_bits,
        })
    
    return root, witnesses


def do_build_tree(client_id: str, purpose: str) -> Optional[dict]:
    """Build tree from approved enrollments for client_id + purpose."""
    # Get approved enrollments
    enrollments = list_enrollments(client_id=client_id, purpose=purpose, status="approved")
    
    if not enrollments:
        return None
    
    # Extract leaves
    leaves = []
    enrollment_ids = []
    for e in enrollments:
        try:
            leaf = bytes.fromhex(e["leaf_commitment"].replace("0x", ""))
            leaves.append(leaf)
            enrollment_ids.append(e["id"])
        except:
            pass
    
    if not leaves:
        return None
    
    # Build tree
    root, witnesses = build_merkle_tree_with_witnesses(leaves)
    root_hex = "0x" + root.hex()
    
    now = int(time.time())
    root_id = f"{client_id}-{purpose}-{now}"
    
    # Save root to SQLite
    tree_depth = len(witnesses[0]["siblings"]) if witnesses else 0
    create_root(
        root_id=root_id,
        client_id=client_id,
        purpose=purpose,
        root_hash=root_hex,
        leaf_count=len(leaves),
        tree_depth=tree_depth,
    )
    
    # Save witnesses and update enrollments
    for i, enrollment_id in enumerate(enrollment_ids):
        w = witnesses[i]
        save_witness(
            enrollment_id=enrollment_id,
            root_id=root_id,
            siblings=w["siblings"],
            path_bits=w["path_bits"],
            leaf_index=w["leaf_index"],
        )
        update_enrollment(
            enrollment_id,
            status="in_tree",
            tree_id=root_id,
            leaf_index=w["leaf_index"],
            tree_built_at=now,
        )
    
    audit_log("tree_built", client_id=client_id, details={
        "root_id": root_id, "leaf_count": len(leaves), "purpose": purpose
    })
    
    return {
        "root_id": root_id,
        "root": root_hex,
        "purpose": purpose,
        "leaf_count": len(leaves),
        "created_at": now,
    }


def maybe_build_tree(client_id: str, purpose: str = "allowlist") -> bool:
    """Opportunistically build tree if threshold trigger fires."""
    clients = load_clients()
    config = clients.get(client_id, {})
    policy = config.get("membership_policy", {})
    
    if not policy.get("auto_approve"):
        return False
    
    # Count approved enrollments
    enrollments = list_enrollments(client_id=client_id, purpose=purpose, status="approved")
    pending_count = len(enrollments)
    
    if pending_count == 0:
        return False
    
    threshold = policy.get("auto_build_threshold", 999999)
    
    if pending_count >= threshold:
        do_build_tree(client_id, purpose)
        return True
    
    return False


# =============================================================================
# Token/Challenge helpers
# =============================================================================

def create_enrollment_token(enrollment_id: str, client_id: str, did: str) -> tuple[str, int]:
    """Create enrollment token. Returns (token, expires_at)."""
    token = "etk_" + secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ENROLLMENT_TOKEN_TTL_SECONDS
    db_create_token(token, enrollment_id, client_id, did, expires_at)
    return token, expires_at


def validate_enrollment_token(token: str, client_id: str, did: str) -> bool:
    """Validate token. Returns True if valid."""
    t = get_enrollment_token(token)
    if t and t["client_id"] == client_id and t["did"] == did:
        return True
    return False


def consume_enrollment_token(token: str):
    """Mark token as consumed."""
    db_consume_token(token)


def create_challenge(client_id: str, did: str) -> tuple[str, int]:
    """Create DID signature challenge. Returns (challenge, expires_at)."""
    challenge = "ch_" + secrets.token_urlsafe(24)
    expires_at = int(time.time()) + CHALLENGE_TTL_SECONDS
    db_create_challenge(challenge, client_id, did, expires_at)
    return challenge, expires_at


def validate_challenge(challenge: str, client_id: str, did: str) -> bool:
    """Validate challenge exists and is not expired."""
    return db_get_challenge(challenge, client_id, did) is not None


def consume_challenge(challenge: str):
    """Remove challenge after use (single-use)."""
    db_delete_challenge(challenge)


def verify_did_signature(did: str, challenge: str, client_id: str, purpose: str, 
                         root_id: str, signature: str) -> bool:
    """Verify DID signature over challenge payload."""
    if not validate_challenge(challenge, client_id, did):
        return False
    
    payload = f"{challenge}|{client_id}|{did}|{purpose}|{root_id}"
    
    try:
        if not did.startswith("did:key:"):
            return False
        
        multibase_key = did[8:]
        
        if multibase_key.startswith("z6Mk"):
            import base64
            import base58
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            
            try:
                sig_bytes = base64.b64decode(signature)
                if len(sig_bytes) != 64:
                    return False
            except:
                return False
            
            try:
                multicodec_key = base58.b58decode(multibase_key[1:])
                if len(multicodec_key) < 34 or multicodec_key[0:2] != bytes([0xed, 0x01]):
                    return False
                raw_pubkey = multicodec_key[2:34]
                pubkey = Ed25519PublicKey.from_public_bytes(raw_pubkey)
                pubkey.verify(sig_bytes, payload.encode('utf-8'))
                return True
            except InvalidSignature:
                return False
            except:
                return False
        
        return False
    except:
        return False


# =============================================================================
# PUBLIC ENDPOINTS
# =============================================================================

@router.post("/v1/membership/enroll", response_model=EnrollResponse)
def enroll_member(
    body: EnrollRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """Submit enrollment for membership."""
    client_id, config = validate_enterprise_key(x_api_key)
    check_rate_limit(client_id)
    
    # Validate commitment
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        commitment_bytes = bytes.fromhex(commitment_hex)
        if len(commitment_bytes) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Validate DID
    if not (body.did.startswith("did:key:") or body.did.startswith("did:btcr:")):
        raise HTTPException(400, "Invalid DID format")
    
    # Validate purpose
    if body.purpose not in PURPOSE_IDS:
        raise HTTPException(400, f"Invalid purpose")
    
    # Check for duplicate
    existing = list_enrollments(client_id=client_id)
    for e in existing:
        if e.get("email_hash") == body.did and e.get("purpose") == body.purpose:
            raise HTTPException(409, "DID already enrolled")
    
    # Create enrollment
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    now = int(time.time())
    
    policy = config.get("membership_policy", {})
    auto_approve = policy.get("auto_approve", False)
    
    status = "approved" if (auto_approve or body.purpose == "issuer_batch") else "pending"
    
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=body.purpose,
        leaf_commitment=body.leaf_commitment,
        email_hash=body.did,  # Store DID in email_hash field
        status=status,
    )
    
    if status == "approved":
        approve_enrollment(enrollment_id)
    
    # Create token
    token, token_expires = create_enrollment_token(enrollment_id, client_id, body.did)
    
    # Opportunistic tree build
    if status == "approved":
        maybe_build_tree(client_id, body.purpose)
    
    audit_log("enrollment_created", client_id=client_id, details={
        "enrollment_id": enrollment_id, "status": status, "purpose": body.purpose
    })
    
    message = "Auto-approved" if status == "approved" else "Pending approval"
    
    return EnrollResponse(
        enrollment_id=enrollment_id,
        enrollment_token=token,
        enrollment_token_expires_at=token_expires,
        status=status,
        purpose=body.purpose,
        client_id=client_id,
        message=message,
    )


@router.post("/v1/membership/challenge", response_model=ChallengeResponse)
def get_did_challenge(
    body: ChallengeRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """Get a challenge for DID signature."""
    client_id, _ = validate_enterprise_key(x_api_key)
    challenge, expires_at = create_challenge(client_id, body.did)
    return ChallengeResponse(challenge=challenge, challenge_expires_at=expires_at)


@router.get("/v1/membership/witness", response_model=WitnessResponse)
def get_member_witness(
    did: str = Query(...),
    purpose: str = Query("allowlist"),
    root_id: Optional[str] = Query(None),
    enrollment_token: Optional[str] = Query(None),
    challenge: Optional[str] = Query(None),
    signature: Optional[str] = Query(None),
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """Fetch witness for membership proof."""
    client_id, _ = validate_enterprise_key(x_api_key)
    
    # Auth: token OR signature
    if enrollment_token:
        if not validate_enrollment_token(enrollment_token, client_id, did):
            raise HTTPException(401, "Invalid or expired enrollment token")
    elif challenge and signature:
        if not root_id:
            raise HTTPException(400, "root_id required for signature auth")
        if not verify_did_signature(did, challenge, client_id, purpose, root_id, signature):
            raise HTTPException(401, "Invalid signature")
        consume_challenge(challenge)
    else:
        raise HTTPException(401, "enrollment_token OR (challenge+signature) required")
    
    # Find enrollment
    enrollments = list_enrollments(client_id=client_id, status="in_tree")
    enrollment = None
    for e in enrollments:
        if e.get("email_hash") == did and e.get("purpose") == purpose:
            enrollment = e
            break
    
    if not enrollment:
        raise HTTPException(404, "No membership found")
    
    # Get witness
    witness = get_witness(enrollment["id"])
    if not witness:
        raise HTTPException(404, "Witness not found")
    
    # Get root
    root = get_root_by_id(witness["root_id"])
    if not root:
        raise HTTPException(404, "Root not found")
    
    return WitnessResponse(
        root_id=root["id"],
        root=root["root_hash"],
        leaf_index=witness["leaf_index"],
        siblings=witness["siblings"],
        purpose=purpose,
        expires_at=root.get("superseded_at") or 2000000000,
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
    """Force tree rebuild (admin)."""
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    client_id = body.client_id
    if not client_id:
        raise HTTPException(400, "client_id required")
    
    result = do_build_tree(client_id, body.purpose)
    
    if not result:
        raise HTTPException(400, "No approved enrollments to build tree from")
    
    return BuildTreeResponse(
        root_id=result["root_id"],
        root=result["root"],
        purpose=result["purpose"],
        leaf_count=result["leaf_count"],
        created_at=result["created_at"],
        expires_at=result["created_at"] + (body.expires_days * 86400),
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
    conn.commit()
    
    audit_log("enrollment_deleted", details={"enrollment_id": enrollment_id})
    
    return {"ok": True, "deleted": enrollment_id}
