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
"""

import os
import json
import time
import secrets
import hashlib
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

router = APIRouter(tags=["membership"])

# =============================================================================
# Poseidon2 Hashing via Rust CLI
# =============================================================================
#
# ⚠️  ALL HASHING USES RUST CLI (poseidon_hash) ⚠️
# This is the SINGLE SOURCE OF TRUTH. Do not implement hashing in Python.
#
# The Rust binary uses Plonky3's verified Poseidon2-M31 implementation.
# State layout: [domain, inputs..., padding...], output from position 1.
#
# Domain separators (defined in Rust, referenced here for documentation):
#   LEAF: 0x4C454146  NULLIFIER: 0x4E554C4C  MERKLE: 0x4D45524B

import subprocess
import logging

logger = logging.getLogger(__name__)

# Path to poseidon_hash binary (built from signedby_core)
# In production, this should be an absolute path or in PATH
POSEIDON_HASH_BIN = os.getenv(
    "POSEIDON_HASH_BIN", 
    str(Path(__file__).resolve().parents[2] / "native" / "signedby_core" / "target" / "release" / "poseidon_hash")
)


def _call_poseidon_hash(args: list) -> bytes:
    """
    Call the poseidon_hash Rust CLI binary.
    
    Returns the hex-decoded output (4 bytes for M31).
    Raises RuntimeError on failure.
    """
    cmd = [POSEIDON_HASH_BIN] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Unknown error"
            raise RuntimeError(f"poseidon_hash failed: {error_msg}")
        
        output_hex = result.stdout.strip()
        return bytes.fromhex(output_hex)
        
    except FileNotFoundError:
        raise RuntimeError(
            f"poseidon_hash binary not found at {POSEIDON_HASH_BIN}. "
            "Build with: cd native/signedby_core && cargo build --release"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("poseidon_hash timed out")


def compute_leaf_commitment(leaf_secret: bytes) -> bytes:
    """
    Compute leaf commitment from secret using Poseidon2.
    
    Calls: poseidon_hash leaf_commit <secret_hex>
    
    Input: 32-byte secret
    Output: 4-byte M31 commitment (zero-padded to 32 bytes for compatibility)
    """
    if len(leaf_secret) != 32:
        raise ValueError(f"leaf_secret must be 32 bytes, got {len(leaf_secret)}")
    
    secret_hex = leaf_secret.hex()
    result = _call_poseidon_hash(["leaf_commit", secret_hex])
    
    # Zero-pad to 32 bytes for compatibility with existing code
    return result.ljust(32, b'\x00')


def compute_nullifier(leaf_secret: bytes, session_id: bytes) -> bytes:
    """
    Compute session-specific nullifier using Poseidon2.
    
    Calls: poseidon_hash nullifier <secret_hex> <session_hex>
    
    Different sessions produce different nullifiers, preventing
    cross-session linkability while allowing replay detection
    within a session.
    
    Output: 16-byte nullifier (4 M31 elements = 124 bits), zero-padded to 32 bytes
    """
    if len(leaf_secret) != 32:
        raise ValueError(f"leaf_secret must be 32 bytes, got {len(leaf_secret)}")
    if len(session_id) != 32:
        raise ValueError(f"session_id must be 32 bytes, got {len(session_id)}")
    
    secret_hex = leaf_secret.hex()
    session_hex = session_id.hex()
    result = _call_poseidon_hash(["nullifier", secret_hex, session_hex])
    
    # Result is 16 bytes, zero-pad to 32 bytes for compatibility
    return result.ljust(32, b'\x00')


# Feature flag - admin endpoints require this
INTERNAL_ADMIN_ONLY = os.getenv("SBM_INTERNAL_ADMIN", "").lower() in ("true", "1", "yes")

# Storage paths
DATA_DIR = Path(__file__).resolve().parents[2]
ENROLLMENTS_FILE = DATA_DIR / "enrollments.json"
ROOTS_FILE = DATA_DIR / "roots.json"
CHALLENGES_FILE = DATA_DIR / "challenges.json"
TOKENS_FILE = DATA_DIR / "enrollment_tokens.json"
TREES_FILE = DATA_DIR / "trees.json"  # Stores tree data with witnesses
BUILD_STATE_FILE = DATA_DIR / "build_state.json"  # Tracks last build times

# Admin API key (separate from enterprise keys)
# SECURITY: No default - must be set in production
ADMIN_API_KEY = os.getenv("SBM_ADMIN_KEY")
if not ADMIN_API_KEY:
    import logging
    logging.getLogger(__name__).warning(
        "SBM_ADMIN_KEY not set - admin endpoints will be disabled"
    )

# Token/challenge config
ENROLLMENT_TOKEN_TTL_SECONDS = 30 * 60  # 30 minutes
CHALLENGE_TTL_SECONDS = 5 * 60  # 5 minutes

# Rate limiting (simple in-memory for beta)
_rate_limit_cache: dict = {}
RATE_LIMIT_PER_HOUR = 100


# =============================================================================
# Storage helpers
# =============================================================================

def load_json(path: Path, default: dict) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except:
            return default
    return default


def save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2))


def load_enrollments() -> dict:
    return load_json(ENROLLMENTS_FILE, {"pending": [], "approved": [], "in_tree": []})


def save_enrollments(data: dict):
    save_json(ENROLLMENTS_FILE, data)


def load_roots() -> dict:
    return load_json(ROOTS_FILE, {"roots": []})


def save_roots(data: dict):
    save_json(ROOTS_FILE, data)


def load_challenges() -> dict:
    return load_json(CHALLENGES_FILE, {"challenges": []})


def save_challenges(data: dict):
    save_json(CHALLENGES_FILE, data)


def load_tokens() -> dict:
    return load_json(TOKENS_FILE, {"tokens": []})


def save_tokens(data: dict):
    save_json(TOKENS_FILE, data)


def load_trees() -> dict:
    return load_json(TREES_FILE, {"trees": {}})


def save_trees(data: dict):
    save_json(TREES_FILE, data)


def load_build_state() -> dict:
    return load_json(BUILD_STATE_FILE, {"clients": {}})


def save_build_state(data: dict):
    save_json(BUILD_STATE_FILE, data)


def load_clients() -> dict:
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
    """
    Validate admin API key.
    
    SECURITY: Fails if SBM_ADMIN_KEY is not set in environment.
    """
    if not ADMIN_API_KEY:
        raise HTTPException(
            503, 
            "Admin endpoints disabled - SBM_ADMIN_KEY not configured"
        )
    if not api_key:
        raise HTTPException(401, "Missing admin API key")
    if api_key != ADMIN_API_KEY:
        raise HTTPException(401, "Invalid admin key")


def require_internal_enabled():
    """Check if internal admin endpoints are enabled."""
    if not INTERNAL_ADMIN_ONLY:
        raise HTTPException(
            403,
            "Admin endpoints disabled. Set SBM_INTERNAL_ADMIN=true to enable."
        )


def check_rate_limit(client_id: str):
    """Simple rate limiting per client."""
    now = time.time()
    hour_ago = now - 3600
    
    # Clean old entries
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

PURPOSE_IDS = {
    "none": 0,
    "allowlist": 1,
    "issuer_batch": 2,
    "revocation": 3,
}


def get_purpose_id(purpose: str) -> int:
    return PURPOSE_IDS.get(purpose, 0)


class EnrollRequest(BaseModel):
    """User enrollment request."""
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    did: str = Field(..., description="User's DID (did:key:z6Mk...)")
    purpose: str = Field("allowlist", description="Purpose: allowlist, issuer_batch, revocation")


class EnrollResponse(BaseModel):
    """Enrollment response."""
    enrollment_id: str
    enrollment_token: str
    enrollment_token_expires_at: int
    status: str
    purpose: str
    client_id: str
    message: str


class ChallengeRequest(BaseModel):
    """Request for DID signature challenge."""
    did: str = Field(..., description="User's DID")


class ChallengeResponse(BaseModel):
    """Challenge response."""
    challenge: str
    challenge_expires_at: int


class WitnessResponse(BaseModel):
    """Witness response."""
    root_id: str
    root: str
    leaf_index: int
    siblings: List[str]
    purpose: str
    expires_at: int


class ApproveRequest(BaseModel):
    """Admin approval request."""
    enrollment_ids: List[str]


class BuildTreeRequest(BaseModel):
    """Request to build a Merkle tree."""
    purpose: str = Field(..., description="Purpose: allowlist, issuer_batch, revocation")
    client_id: Optional[str] = Field(None, description="Client ID (required for allowlist)")
    root_id: Optional[str] = Field(None, description="Custom root ID")
    description: Optional[str] = Field(None)
    expires_days: int = Field(365)


class BuildTreeResponse(BaseModel):
    """Tree build response."""
    root_id: str
    root: str
    purpose: str
    leaf_count: int
    created_at: int
    expires_at: int


class ListEnrollmentsResponse(BaseModel):
    """List enrollments response."""
    pending: List[dict]
    approved: List[dict]
    in_tree: List[dict]


# =============================================================================
# Tree building
# =============================================================================

def merkle_hash_pair(left: bytes, right: bytes) -> bytes:
    """
    Compute Merkle tree internal node hash using Poseidon2.
    
    Calls: poseidon_hash pair <left_hex> <right_hex>
    
    Input: Two values (first 4 bytes of each used as M31)
    Output: 4-byte M31 hash (zero-padded to 32 bytes)
    
    ⚠️  Uses Poseidon2, not SHA-256. All tree operations must use this.
    """
    # Extract first 4 bytes as M31 values
    left_m31 = left[:4].hex() if len(left) >= 4 else left.ljust(4, b'\x00').hex()
    right_m31 = right[:4].hex() if len(right) >= 4 else right.ljust(4, b'\x00').hex()
    
    result = _call_poseidon_hash(["pair", left_m31, right_m31])
    
    # Zero-pad to 32 bytes for compatibility
    return result.ljust(32, b'\x00')


def build_merkle_tree_with_witnesses(leaves: List[bytes]) -> tuple[bytes, List[dict]]:
    """
    Build a Merkle tree and return (root, witnesses).
    Each witness contains leaf_index and siblings for proving membership.
    """
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
    
    # Generate witnesses for each original leaf
    witnesses = []
    for leaf_index in range(n):
        siblings = []
        idx = leaf_index
        for layer in layers[:-1]:
            sibling_idx = idx ^ 1  # XOR with 1 to get sibling
            if sibling_idx < len(layer):
                siblings.append("0x" + layer[sibling_idx].hex())
            else:
                siblings.append("0x" + ("00" * 32))
            idx //= 2
        witnesses.append({
            "leaf_index": leaf_index,
            "siblings": siblings,
        })
    
    return root, witnesses


def do_build_tree(client_id: str, purpose: str) -> Optional[dict]:
    """
    Build tree from approved enrollments for client_id + purpose.
    Returns root entry or None if no enrollments.
    """
    data = load_enrollments()
    approved = data.get("approved", [])
    
    # Find matching enrollments
    matching = []
    remaining = []
    
    for e in approved:
        if e.get("purpose") == purpose and e.get("client_id") == client_id:
            matching.append(e)
        else:
            remaining.append(e)
    
    if not matching:
        return None
    
    # Extract leaves and track enrollment IDs
    leaves = []
    enrollment_map = []  # Maps leaf_index to enrollment
    
    for e in matching:
        try:
            leaf = bytes.fromhex(e["leaf_commitment"].replace("0x", ""))
            leaves.append(leaf)
            enrollment_map.append(e)
        except:
            pass
    
    if not leaves:
        return None
    
    # Build tree
    root, witnesses = build_merkle_tree_with_witnesses(leaves)
    root_hex = "0x" + root.hex()
    
    now = int(time.time())
    root_id = f"{client_id}-{purpose}-{now}"
    expires_at = now + (365 * 86400)
    
    # Create root entry
    root_entry = {
        "root_id": root_id,
        "purpose": purpose,
        "purpose_id": get_purpose_id(purpose),
        "root": root_hex,
        "hash_alg": "poseidon2-m31",
        "depth": len(witnesses[0]["siblings"]) if witnesses else 0,
        "leaf_count": len(leaves),
        "client_id": client_id,
        "not_before": now,
        "expires_at": expires_at,
        "created_at": now,
    }
    
    # Save root
    roots_data = load_roots()
    roots_data["roots"].append(root_entry)
    save_roots(roots_data)
    
    # Save tree with witnesses (keyed by root_id)
    trees_data = load_trees()
    tree_entry = {
        "root_id": root_id,
        "client_id": client_id,
        "purpose": purpose,
        "root": root_hex,
        "expires_at": expires_at,
        "leaves": [],  # Maps leaf_index to (did, leaf_commitment) - NO logging of commitment
    }
    
    # Store witness data per DID (for retrieval)
    for i, e in enumerate(enrollment_map):
        tree_entry["leaves"].append({
            "leaf_index": i,
            "did": e["did"],
            "siblings": witnesses[i]["siblings"],
            # Note: leaf_commitment intentionally NOT stored here
        })
    
    trees_data["trees"][root_id] = tree_entry
    save_trees(trees_data)
    
    # Move enrollments from approved to in_tree
    in_tree = data.get("in_tree", [])
    for e in matching:
        e["root_id"] = root_id
        e["tree_built_at"] = now
        in_tree.append(e)
    
    data["approved"] = remaining
    data["in_tree"] = in_tree
    save_enrollments(data)
    
    # Update build state
    build_state = load_build_state()
    if client_id not in build_state["clients"]:
        build_state["clients"][client_id] = {}
    build_state["clients"][client_id][purpose] = {
        "last_build_time": now,
        "last_root_id": root_id,
    }
    save_build_state(build_state)
    
    return root_entry


def maybe_build_tree(client_id: str, purpose: str = "allowlist") -> bool:
    """
    Opportunistically build tree if threshold or interval trigger fires.
    Returns True if tree was built.
    """
    clients = load_clients()
    config = clients.get(client_id, {})
    policy = config.get("membership_policy", {})
    
    if not policy.get("auto_approve"):
        return False
    
    # Count approved enrollments not yet in tree
    data = load_enrollments()
    approved = data.get("approved", [])
    pending_count = sum(
        1 for e in approved
        if e.get("purpose") == purpose and e.get("client_id") == client_id
    )
    
    if pending_count == 0:
        return False
    
    # Get build state
    build_state = load_build_state()
    client_state = build_state.get("clients", {}).get(client_id, {}).get(purpose, {})
    last_build = client_state.get("last_build_time", 0)
    
    now = time.time()
    hours_since = (now - last_build) / 3600
    
    threshold = policy.get("auto_build_threshold", 999999)
    interval_hours = policy.get("auto_build_interval_hours", 24)
    
    # Threshold trigger (accelerator)
    if pending_count >= threshold:
        do_build_tree(client_id, purpose)
        return True
    
    # Interval trigger (guarantee)
    if hours_since >= interval_hours:
        do_build_tree(client_id, purpose)
        return True
    
    return False


def get_current_root(client_id: str, purpose: str = "allowlist") -> Optional[dict]:
    """Get the current (most recent, non-expired) root for client + purpose."""
    roots_data = load_roots()
    now = time.time()
    
    matching = [
        r for r in roots_data.get("roots", [])
        if r.get("client_id") == client_id
        and r.get("purpose") == purpose
        and r.get("expires_at", 0) > now
    ]
    
    if not matching:
        return None
    
    # Return most recent
    return max(matching, key=lambda r: r.get("created_at", 0))


# =============================================================================
# Token and challenge management
# =============================================================================

def create_enrollment_token(enrollment_id: str, client_id: str, did: str) -> tuple[str, int]:
    """Create enrollment token. Returns (token, expires_at)."""
    token = "etk_" + secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ENROLLMENT_TOKEN_TTL_SECONDS
    
    tokens_data = load_tokens()
    tokens_data["tokens"].append({
        "token": token,
        "enrollment_id": enrollment_id,
        "client_id": client_id,
        "did": did,
        "expires_at": expires_at,
        "consumed": False,
    })
    save_tokens(tokens_data)
    
    return token, expires_at


def validate_enrollment_token(token: str, client_id: str, did: str) -> bool:
    """Validate token. Returns True if valid."""
    tokens_data = load_tokens()
    now = time.time()
    
    for t in tokens_data["tokens"]:
        if (t["token"] == token
            and t["client_id"] == client_id
            and t["did"] == did
            and t["expires_at"] > now
            and not t["consumed"]):
            return True
    
    return False


def consume_enrollment_token(token: str):
    """Mark token as consumed."""
    tokens_data = load_tokens()
    for t in tokens_data["tokens"]:
        if t["token"] == token:
            t["consumed"] = True
            break
    save_tokens(tokens_data)


def create_challenge(client_id: str, did: str) -> tuple[str, int]:
    """Create DID signature challenge. Returns (challenge, expires_at)."""
    challenge = "ch_" + secrets.token_urlsafe(24)
    expires_at = int(time.time()) + CHALLENGE_TTL_SECONDS
    
    challenges_data = load_challenges()
    # Remove old challenges for same (client_id, did)
    challenges_data["challenges"] = [
        c for c in challenges_data["challenges"]
        if not (c["client_id"] == client_id and c["did"] == did)
    ]
    challenges_data["challenges"].append({
        "challenge": challenge,
        "client_id": client_id,
        "did": did,
        "expires_at": expires_at,
    })
    save_challenges(challenges_data)
    
    return challenge, expires_at


def validate_challenge(challenge: str, client_id: str, did: str) -> bool:
    """Validate challenge exists and is not expired."""
    challenges_data = load_challenges()
    now = time.time()
    
    for c in challenges_data["challenges"]:
        if (c["challenge"] == challenge
            and c["client_id"] == client_id
            and c["did"] == did
            and c["expires_at"] > now):
            return True
    
    return False


def consume_challenge(challenge: str):
    """Remove challenge after use (single-use)."""
    challenges_data = load_challenges()
    challenges_data["challenges"] = [
        c for c in challenges_data["challenges"]
        if c["challenge"] != challenge
    ]
    save_challenges(challenges_data)


def verify_did_signature(did: str, challenge: str, client_id: str, purpose: str, 
                         root_id: str, signature: str) -> bool:
    """
    Verify DID signature over challenge payload.
    
    Payload format: challenge|client_id|did|purpose|root_id
    
    Supports did:key with Ed25519 (z6Mk prefix).
    """
    # First verify the challenge exists and is valid
    if not validate_challenge(challenge, client_id, did):
        return False
    
    # Construct expected payload
    payload = f"{challenge}|{client_id}|{did}|{purpose}|{root_id}"
    
    try:
        # Extract public key from did:key
        if not did.startswith("did:key:"):
            return False
        
        multibase_key = did[8:]  # Remove "did:key:" prefix
        
        # For Ed25519 keys (z6Mk prefix), decode and verify
        if multibase_key.startswith("z6Mk"):
            import base64
            import base58
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            
            # Decode signature from base64
            try:
                sig_bytes = base64.b64decode(signature)
                if len(sig_bytes) != 64:
                    return False
            except Exception:
                return False
            
            # Decode public key from multibase (z = base58btc)
            # z6Mk... is base58btc-encoded multicodec (0xed01 = Ed25519 public key)
            try:
                # Remove 'z' prefix (base58btc indicator)
                multicodec_key = base58.b58decode(multibase_key[1:])
                
                # First two bytes are multicodec prefix for Ed25519 (0xed01)
                if len(multicodec_key) < 34:
                    return False
                if multicodec_key[0:2] != bytes([0xed, 0x01]):
                    return False
                
                # Remaining 32 bytes are the raw public key
                raw_pubkey = multicodec_key[2:34]
                if len(raw_pubkey) != 32:
                    return False
                
                # Create Ed25519 public key object
                pubkey = Ed25519PublicKey.from_public_bytes(raw_pubkey)
                
                # Verify signature over payload
                payload_bytes = payload.encode('utf-8')
                pubkey.verify(sig_bytes, payload_bytes)
                
                return True
                
            except InvalidSignature:
                return False
            except Exception:
                return False
        
        return False
        
    except Exception:
        return False


# =============================================================================
# PUBLIC ENDPOINTS (RP-authenticated)
# =============================================================================

@router.post("/v1/membership/enroll", response_model=EnrollResponse)
def enroll_member(
    body: EnrollRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Submit enrollment for membership.
    
    Requires X-API-Key (RP client key).
    Auto-approves based on client's membership_policy.
    """
    # Validate RP key
    client_id, config = validate_enterprise_key(x_api_key)
    
    # Rate limit
    check_rate_limit(client_id)
    
    # Validate commitment format
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        commitment_bytes = bytes.fromhex(commitment_hex)
        if len(commitment_bytes) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Validate DID format (accept did:key: or did:btcr:)
    if not (body.did.startswith("did:key:") or body.did.startswith("did:btcr:")):
        raise HTTPException(400, "Invalid DID format. Must be did:key: or did:btcr:")
    
    # Validate purpose
    if body.purpose not in PURPOSE_IDS:
        raise HTTPException(400, f"Invalid purpose. Must be one of: {list(PURPOSE_IDS.keys())}")
    
    # Check for duplicate enrollment
    data = load_enrollments()
    for e in data.get("approved", []) + data.get("pending", []) + data.get("in_tree", []):
        if e.get("did") == body.did and e.get("client_id") == client_id and e.get("purpose") == body.purpose:
            raise HTTPException(409, "DID already enrolled for this client and purpose")
    
    # Create enrollment
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    now = int(time.time())
    
    enrollment = {
        "enrollment_id": enrollment_id,
        "leaf_commitment": body.leaf_commitment,
        "did": body.did,
        "purpose": body.purpose,
        "client_id": client_id,
        "created_at": now,
    }
    
    # Check auto-approve policy
    policy = config.get("membership_policy", {})
    auto_approve = policy.get("auto_approve", False)
    
    if auto_approve or body.purpose == "issuer_batch":
        enrollment["status"] = "approved"
        enrollment["approved_at"] = now
        data["approved"].append(enrollment)
        status = "approved"
        message = "Auto-approved based on client policy"
    else:
        enrollment["status"] = "pending"
        data["pending"].append(enrollment)
        status = "pending"
        message = "Pending admin approval"
    
    save_enrollments(data)
    
    # Create enrollment token
    token, token_expires = create_enrollment_token(enrollment_id, client_id, body.did)
    
    # Opportunistic tree build
    if status == "approved":
        maybe_build_tree(client_id, body.purpose)
    
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
def get_challenge(
    body: ChallengeRequest,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Get a challenge for DID signature (for witness retrieval when token expired).
    
    Requires X-API-Key (RP client key).
    """
    client_id, _ = validate_enterprise_key(x_api_key)
    
    # Validate DID format
    if not body.did.startswith("did:key:"):
        raise HTTPException(400, "Invalid DID format")
    
    challenge, expires_at = create_challenge(client_id, body.did)
    
    return ChallengeResponse(
        challenge=challenge,
        challenge_expires_at=expires_at,
    )


@router.get("/v1/membership/witness")
def get_witness(
    did: str = Query(..., description="User's DID"),
    purpose: str = Query("allowlist", description="Purpose"),
    root_id: Optional[str] = Query(None, description="Specific root ID (defaults to current)"),
    x_api_key: str = Header(None, alias="X-API-Key"),
    x_enrollment_token: Optional[str] = Header(None, alias="X-Enrollment-Token"),
    x_did_challenge: Optional[str] = Header(None, alias="X-DID-Challenge"),
    x_did_signature: Optional[str] = Header(None, alias="X-DID-Signature"),
):
    """
    Fetch witness for membership proof.
    
    Requires X-API-Key (RP client key) + user authorization via:
    - X-Enrollment-Token (valid, unexpired, unconsumed), OR
    - X-DID-Challenge + X-DID-Signature (proof of DID ownership)
    
    client_id is derived from X-API-Key (not in query params).
    """
    # Validate RP key
    client_id, config = validate_enterprise_key(x_api_key)
    
    # Run opportunistic tree build BEFORE lookup
    maybe_build_tree(client_id, purpose)
    
    # Determine root_id
    if root_id:
        target_root_id = root_id
    else:
        current_root = get_current_root(client_id, purpose)
        if not current_root:
            # Check if enrollment exists but tree not built yet
            data = load_enrollments()
            for e in data.get("approved", []):
                if e.get("did") == did and e.get("client_id") == client_id and e.get("purpose") == purpose:
                    return JSONResponse(
                        status_code=202,
                        content={
                            "status": "pending_tree_build",
                            "message": "Enrollment approved but tree not yet built",
                            "retry_after_seconds": 60,
                        }
                    )
            raise HTTPException(404, "No active root found for this client and purpose")
        target_root_id = current_root["root_id"]
    
    # Validate user authorization
    auth_valid = False
    used_token = None
    
    # Try token first
    if x_enrollment_token:
        if validate_enrollment_token(x_enrollment_token, client_id, did):
            auth_valid = True
            used_token = x_enrollment_token
    
    # Try DID signature if token not valid
    if not auth_valid and x_did_challenge and x_did_signature:
        if verify_did_signature(did, x_did_challenge, client_id, purpose, target_root_id, x_did_signature):
            auth_valid = True
            consume_challenge(x_did_challenge)
    
    if not auth_valid:
        raise HTTPException(
            401,
            "Unauthorized. Provide valid X-Enrollment-Token or X-DID-Challenge + X-DID-Signature"
        )
    
    # Find witness in tree
    trees_data = load_trees()
    tree = trees_data.get("trees", {}).get(target_root_id)
    
    if not tree:
        raise HTTPException(404, f"Tree not found for root_id: {target_root_id}")
    
    # Find leaf for this DID
    witness_data = None
    for leaf in tree.get("leaves", []):
        if leaf.get("did") == did:
            witness_data = leaf
            break
    
    if not witness_data:
        raise HTTPException(404, "DID not found in tree")
    
    # Consume token on successful retrieval
    if used_token:
        consume_enrollment_token(used_token)
    
    return WitnessResponse(
        root_id=target_root_id,
        root=tree["root"],
        leaf_index=witness_data["leaf_index"],
        siblings=witness_data["siblings"],
        purpose=purpose,
        expires_at=tree["expires_at"],
    )


# =============================================================================
# ADMIN ENDPOINTS (gated behind SBM_INTERNAL_ADMIN=true)
# =============================================================================

@router.get("/v1/membership/enrollments", response_model=ListEnrollmentsResponse)
def list_enrollments(
    purpose: Optional[str] = None,
    status: Optional[str] = None,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    List enrollments (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    data = load_enrollments()
    
    pending = data.get("pending", [])
    approved = data.get("approved", [])
    in_tree = data.get("in_tree", [])
    
    if purpose:
        pending = [e for e in pending if e.get("purpose") == purpose]
        approved = [e for e in approved if e.get("purpose") == purpose]
        in_tree = [e for e in in_tree if e.get("purpose") == purpose]
    
    if status == "pending":
        approved = []
        in_tree = []
    elif status == "approved":
        pending = []
        in_tree = []
    elif status == "in_tree":
        pending = []
        approved = []
    
    return ListEnrollmentsResponse(pending=pending, approved=approved, in_tree=in_tree)


@router.post("/v1/membership/approve")
def approve_enrollments(
    body: ApproveRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    Manually approve pending enrollments (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    data = load_enrollments()
    
    approved_count = 0
    not_found = []
    
    for enrollment_id in body.enrollment_ids:
        found = None
        for i, e in enumerate(data["pending"]):
            if e["enrollment_id"] == enrollment_id:
                found = (i, e)
                break
        
        if found:
            idx, enrollment = found
            enrollment["status"] = "approved"
            enrollment["approved_at"] = int(time.time())
            data["approved"].append(enrollment)
            data["pending"].pop(idx)
            approved_count += 1
        else:
            not_found.append(enrollment_id)
    
    save_enrollments(data)
    
    return {
        "approved": approved_count,
        "not_found": not_found,
    }


@router.post("/v1/membership/build-tree", response_model=BuildTreeResponse)
def build_tree_admin(
    body: BuildTreeRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    Force build a Merkle tree (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    if body.purpose not in PURPOSE_IDS:
        raise HTTPException(400, f"Invalid purpose: {body.purpose}")
    
    if body.purpose == "allowlist" and not body.client_id:
        raise HTTPException(400, "client_id required for allowlist purpose")
    
    client_id = body.client_id or "sbm"
    
    result = do_build_tree(client_id, body.purpose)
    
    if not result:
        raise HTTPException(400, "No approved enrollments found for this purpose/client")
    
    return BuildTreeResponse(
        root_id=result["root_id"],
        root=result["root"],
        purpose=result["purpose"],
        leaf_count=result["leaf_count"],
        created_at=result["created_at"],
        expires_at=result["expires_at"],
    )


@router.delete("/v1/membership/enrollments/{enrollment_id}")
def delete_enrollment(
    enrollment_id: str,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    Delete an enrollment (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    data = load_enrollments()
    
    for list_name in ["pending", "approved", "in_tree"]:
        for i, e in enumerate(data.get(list_name, [])):
            if e["enrollment_id"] == enrollment_id:
                data[list_name].pop(i)
                save_enrollments(data)
                return {"deleted": enrollment_id, "was_status": list_name}
    
    raise HTTPException(404, "Enrollment not found")
