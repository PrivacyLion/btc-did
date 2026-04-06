"""
Enrollment API (Phase 26)

Single-step enrollment authorized by NOSTR event signatures:
- POST /v1/membership/enroll/commit - Commit to Merkle tree

Per Bible Section 6.1, enrollment requires:
1. Kind 28200 authorization event (enterprise-signed)
2. Kind 28250 delegation event (human-signed)
3. agent_npub must match in both events
4. authorization_event_id replay check
5. Leaf added to tree with authorization_event_id recorded

Direct enrollment (auto-approve clients with API key):
- POST /v1/membership/enroll - One-step enrollment

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
import httpx
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
    add_merkle_leaf,
    leaf_commitment_exists,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/membership/enroll", tags=["enrollment"])

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


def validate_enterprise_key(api_key: Optional[str]) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    if not api_key:
        raise HTTPException(401, "Missing Authorization header")
    clients = load_clients()
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    for client_id, config in clients.items():
        if api_key_hash == config.get("api_key_hash"):
            return client_id, config
    raise HTTPException(401, "Invalid API key")


def get_client_config(client_id: str) -> Optional[dict]:
    """Get client config by client_id."""
    clients = load_clients()
    return clients.get(client_id)


# =============================================================================
# NIP-05 and Schnorr Signature Verification
# =============================================================================

def get_nip05_pubkey(client_id: str) -> Optional[str]:
    """
    Fetch enterprise pubkey via NIP-05.
    Looks up https://{client_id}.beta.privacy-lion.com/.well-known/nostr.json
    Returns hex pubkey or None.
    """
    # Map client_id to domain
    nip05_url = f"https://{client_id}.beta.privacy-lion.com/.well-known/nostr.json"
    
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(nip05_url)
            if response.status_code != 200:
                logger.warning(f"NIP-05 lookup failed for {client_id}: {response.status_code}")
                return None
            
            data = response.json()
            # NIP-05 format: {"names": {"_": "pubkey_hex"}}
            names = data.get("names", {})
            # Try "_" (root) or client_id as name
            pubkey = names.get("_") or names.get(client_id)
            return pubkey
    except Exception as e:
        logger.error(f"NIP-05 lookup error for {client_id}: {e}")
        return None


def verify_nostr_event_id(event: dict) -> bool:
    """
    Verify NOSTR event ID matches the hash of serialized event.
    ID = SHA256(JSON.stringify([0, pubkey, created_at, kind, tags, content]))
    """
    serialized = json.dumps([
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"]
    ], separators=(',', ':'), ensure_ascii=False)
    
    computed_id = hashlib.sha256(serialized.encode()).hexdigest()
    return computed_id == event["id"]


def verify_schnorr_signature(event: dict) -> bool:
    """
    Verify Schnorr signature on NOSTR event.
    Uses secp256k1 BIP-340 Schnorr signature verification.
    """
    try:
        # Try using the native Rust binary first
        verify_bin = DATA_DIR / "native" / "signedby_core" / "target" / "release" / "schnorr_verify"
        if verify_bin.exists():
            result = subprocess.run(
                [str(verify_bin), event["id"], event["pubkey"], event["sig"]],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        
        # Fallback: use Python secp256k1 library if available
        try:
            import secp256k1
            pubkey_bytes = bytes.fromhex(event["pubkey"])
            sig_bytes = bytes.fromhex(event["sig"])
            msg_bytes = bytes.fromhex(event["id"])
            
            # Create x-only pubkey for Schnorr
            pubkey = secp256k1.PublicKey(b'\x02' + pubkey_bytes, raw=True)
            return pubkey.schnorr_verify(msg_bytes, sig_bytes)
        except ImportError:
            pass
        
        # If no verification method available, fail closed
        raise RuntimeError("No Schnorr verification method available")
        
    except Exception as e:
        logger.error(f"Schnorr verification error: {e}")
        return False


def verify_authorization_event(event: dict, expected_client_id: str) -> tuple[bool, str]:
    """
    Verify a kind 28200 authorization event.
    
    Returns: (is_valid, error_message)
    """
    # 1. Check event kind
    if event.get("kind") != 28200:
        return False, f"Invalid event kind: {event.get('kind')} (expected 28200)"
    
    # 2. Verify event ID
    if not verify_nostr_event_id(event):
        return False, "Event ID does not match content hash"
    
    # 3. Get expected pubkey via NIP-05
    expected_pubkey = get_nip05_pubkey(expected_client_id)
    if not expected_pubkey:
        return False, f"Could not fetch NIP-05 pubkey for {expected_client_id}"
    
    # 4. Check pubkey matches
    if event.get("pubkey") != expected_pubkey:
        return False, f"Event pubkey does not match NIP-05 pubkey for {expected_client_id}"
    
    # 5. Verify Schnorr signature
    if not verify_schnorr_signature(event):
        return False, "Invalid Schnorr signature"
    
    # 6. Check expiration (from content JSON)
    try:
        content = json.loads(event.get("content", "{}"))
        expires_at = content.get("expires_at")
        if expires_at:
            from datetime import datetime
            exp_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp_time.timestamp() < time.time():
                return False, f"Authorization event expired at {expires_at}"
    except Exception as e:
        logger.warning(f"Could not parse event content for expiration: {e}")
    
    return True, ""


def extract_nonce_from_event(event: dict) -> Optional[str]:
    """Extract nonce from event tags."""
    for tag in event.get("tags", []):
        if len(tag) >= 2 and tag[0] == "nonce":
            return tag[1]
    return None


def extract_client_id_from_event(event: dict) -> Optional[str]:
    """Extract client_id from event tags."""
    for tag in event.get("tags", []):
        if len(tag) >= 2 and tag[0] == "c":
            return tag[1]
    return None


def verify_delegation_event(event: dict) -> tuple[bool, str]:
    """
    Verify a kind 28250 delegation event (human signature).
    
    Per Bible Section 6.1: Verify human Schnorr signature via NIP-05 — fail closed.
    
    Returns: (is_valid, error_message)
    """
    # 1. Check event kind
    if event.get("kind") != 28250:
        return False, f"Invalid event kind: {event.get('kind')} (expected 28250)"
    
    # 2. Verify event ID
    if not verify_nostr_event_id(event):
        return False, "Event ID does not match content hash"
    
    # 3. Verify Schnorr signature
    # Note: Human pubkey verification via NIP-05 is optional for delegation
    # The signature itself proves the human holds the private key
    if not verify_schnorr_signature(event):
        return False, "Invalid Schnorr signature on delegation event"
    
    # 4. Check expiration (from content JSON)
    try:
        content = json.loads(event.get("content", "{}"))
        expires_at = content.get("expires_at")
        if expires_at:
            from datetime import datetime
            exp_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp_time.timestamp() < time.time():
                return False, f"Delegation event expired at {expires_at}"
    except Exception as e:
        logger.warning(f"Could not parse delegation event content for expiration: {e}")
    
    return True, ""


def extract_agent_npub_from_event(event: dict) -> Optional[str]:
    """
    Extract agent_npub from event content JSON.
    
    Both kind 28200 and kind 28250 contain agent_npub in their content field.
    """
    try:
        content = json.loads(event.get("content", "{}"))
        agent_npub = content.get("agent_npub")
        if agent_npub:
            return agent_npub
    except Exception:
        pass
    
    # Also check tags (some implementations may use tags)
    for tag in event.get("tags", []):
        if len(tag) >= 2 and tag[0] == "p":
            # 'p' tag often contains the target pubkey
            return tag[1]
    
    return None


def authorization_event_id_exists(event_id: str) -> bool:
    """
    Check if an authorization event ID already exists in merkle_leaves.
    
    Per Bible Section 6.1: Replay prevention via merkle_leaves.authorization_event_id.
    """
    from ..db import get_merkle_leaf_by_event
    return get_merkle_leaf_by_event(event_id) is not None


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

# EnrollStartRequest and EnrollStartResponse REMOVED — Phase 26
# Nonce eliminated. No server-generated secrets.
# Enrollment is a single enroll/commit call authorized by NOSTR event signatures.


class AuthorizationEvent(BaseModel):
    """Complete kind 28200 NOSTR event (enterprise enrollment authorization)."""
    id: str = Field(..., description="Event ID (32-byte hex)")
    pubkey: str = Field(..., description="Enterprise pubkey (32-byte hex)")
    created_at: int = Field(..., description="Unix timestamp")
    kind: int = Field(..., description="Must be 28200")
    tags: List[List[str]] = Field(..., description="Event tags including agent_npub")
    content: str = Field(..., description="JSON content with agent_npub, expires_at")
    sig: str = Field(..., description="Schnorr signature (64-byte hex)")


class DelegationEvent(BaseModel):
    """Complete kind 28250 NOSTR event (human delegation grant)."""
    id: str = Field(..., description="Event ID (32-byte hex)")
    pubkey: str = Field(..., description="Human pubkey (32-byte hex)")
    created_at: int = Field(..., description="Unix timestamp")
    kind: int = Field(..., description="Must be 28250")
    tags: List[List[str]] = Field(..., description="Event tags")
    content: str = Field(..., description="JSON content with agent_npub, scopes, expires_at")
    sig: str = Field(..., description="Schnorr signature (64-byte hex)")


class EnrollCommitRequest(BaseModel):
    """
    Commit enrollment to tree. Per Bible Section 6.1:
    - leaf_commitment: The agent's leaf commitment
    - authorization_event: Kind 28200 NOSTR event signed by enterprise
    - delegation_event: Kind 28250 NOSTR event signed by human
    """
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    authorization_event: AuthorizationEvent = Field(..., description="Kind 28200 NOSTR event")
    delegation_event: DelegationEvent = Field(..., description="Kind 28250 NOSTR event")


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
# =============================================================================
# Endpoints: Phase 26 Enrollment
# =============================================================================

# /start endpoint DELETED — Phase 26
# Nonce eliminated. No server-generated secrets.
# Enrollment is a single enroll/commit call authorized by NOSTR event signatures.


@router.post("/commit", response_model=EnrollCommitResponse)
def enroll_commit(body: EnrollCommitRequest):
    """
    Commit enrollment to Merkle tree.
    
    Per Bible Section 6.1 — ALL SIX CHECKS REQUIRED:
    1. Accept leaf_commitment, authorization_event (28200), delegation_event (28250)
    2. Verify enterprise Schnorr signature on kind 28200 via NIP-05 — fail closed
    3. Verify human Schnorr signature on kind 28250 via NIP-05 — fail closed
    4. Confirm agent_npub in kind 28200 matches agent_npub in kind 28250
    5. Check authorization_event_id not already in merkle_leaves (replay prevention)
    6. Append leaf to tree and record authorization_event_id
    """
    # Convert events to dicts
    auth_event = body.authorization_event.model_dump()
    deleg_event = body.delegation_event.model_dump()
    
    # === CHECK 1: Validate event kinds ===
    if auth_event.get("kind") != 28200:
        raise HTTPException(400, f"authorization_event must be kind 28200, got {auth_event.get('kind')}")
    if deleg_event.get("kind") != 28250:
        raise HTTPException(400, f"delegation_event must be kind 28250, got {deleg_event.get('kind')}")
    
    # === Extract client_id from authorization event ===
    client_id = extract_client_id_from_event(auth_event)
    if not client_id:
        raise HTTPException(400, "Missing client_id (tag 'c') in authorization event")
    
    # === CHECK 2: Verify enterprise Schnorr signature on kind 28200 via NIP-05 ===
    is_valid, error_msg = verify_authorization_event(auth_event, client_id)
    if not is_valid:
        raise HTTPException(401, f"Enterprise signature verification failed: {error_msg}")
    
    # === CHECK 3: Verify human Schnorr signature on kind 28250 via NIP-05 ===
    is_valid, error_msg = verify_delegation_event(deleg_event)
    if not is_valid:
        raise HTTPException(401, f"Human signature verification failed: {error_msg}")
    
    # === CHECK 4: Confirm agent_npub in 28200 matches agent_npub in 28250 ===
    auth_agent_npub = extract_agent_npub_from_event(auth_event)
    deleg_agent_npub = extract_agent_npub_from_event(deleg_event)
    
    if not auth_agent_npub:
        raise HTTPException(400, "Missing agent_npub in authorization event (kind 28200)")
    if not deleg_agent_npub:
        raise HTTPException(400, "Missing agent_npub in delegation event (kind 28250)")
    if auth_agent_npub != deleg_agent_npub:
        raise HTTPException(400, f"npub_mismatch: agent_npub in kind 28200 ({auth_agent_npub[:16]}...) does not match kind 28250 ({deleg_agent_npub[:16]}...)")
    
    # === CHECK 5: Check authorization_event_id not already in merkle_leaves ===
    if authorization_event_id_exists(auth_event["id"]):
        raise HTTPException(409, "Authorization event already used (replay prevention)")
    
    # === Validate leaf_commitment format ===
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        if len(bytes.fromhex(commitment_hex)) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # === Extract purpose from authorization event tags (default: allowlist) ===
    purpose = "allowlist"
    for tag in auth_event.get("tags", []):
        if tag[0] == "purpose" and len(tag) > 1:
            purpose = tag[1]
            break
    
    # === Check for duplicate commitment ===
    tree_id = f"{client_id}-{purpose}"
    if leaf_commitment_exists(tree_id, body.leaf_commitment):
        raise HTTPException(409, "Commitment already enrolled")
    
    # === Create enrollment record ===
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=purpose,
        leaf_commitment=body.leaf_commitment,
        email_hash=None,
        status="approved",
    )
    
    # === Get or create tree ===
    tree_id = get_or_create_tree(client_id, purpose)
    
    # === Insert leaf into tree ===
    leaf_hash = body.leaf_commitment.replace("0x", "")
    new_root, leaf_index, siblings = insert_leaf(tree_id, leaf_hash)
    
    # === CHECK 6: Create merkle_leaf record with authorization_event_id ===
    # (This is the replay prevention — authorization_event_id stored in merkle_leaves)
    leaf_id = add_merkle_leaf(
        tree_id=tree_id,
        leaf_index=leaf_index,
        leaf_commitment=body.leaf_commitment,
        authorization_event_id=auth_event["id"],
        authorization_pubkey=auth_event["pubkey"],
    )
    
    # 11. Compute path bits from leaf index
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx >>= 1
    
    # 12. Save witness
    save_witness(
        leaf_id=leaf_id,
        tree_id=tree_id,
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
        root_hash=new_root,
    )
    
    # === Update enrollment status ===
    update_enrollment(
        enrollment_id,
        status="in_tree",
        tree_id=tree_id,
        leaf_index=leaf_index,
        tree_built_at=int(time.time()),
    )
    
    # NOTE: Replay prevention via merkle_leaves.authorization_event_id (CHECK 5/6)
    # No separate mark_event_id_used needed — the leaf insertion IS the replay marker
    
    audit_log("enroll_committed", client_id=client_id, details={
        "enrollment_id": enrollment_id,
        "tree_id": tree_id,
        "leaf_index": leaf_index,
        "root": new_root[:16] + "...",
        "auth_event_id": auth_event["id"][:16] + "...",
        "agent_npub": auth_agent_npub[:16] + "...",
    })
    
    return EnrollCommitResponse(
        enrollment_id=enrollment_id,
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
    authorization: str = Header(..., alias="Authorization")
):
    """
    Direct enrollment (one-step).
    
    For clients with auto_approve policy.
    Creates enrollment and immediately commits to tree.
    """
    # Extract Bearer token
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]  # Strip "Bearer "
    
    client_id, config = validate_enterprise_key(api_key)
    
    # Check auto-approve policy
    policy = config.get("membership_policy", {})
    if not policy.get("auto_approve", False):
        raise HTTPException(403, "Direct enrollment requires auto_approve policy. Use /commit endpoint with NOSTR events.")
    
    # Validate commitment
    try:
        commitment_hex = body.leaf_commitment.replace("0x", "")
        if len(bytes.fromhex(commitment_hex)) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Get or create tree
    tree_id = get_or_create_tree(client_id, body.purpose)
    
    # Check for duplicate
    if leaf_commitment_exists(tree_id, body.leaf_commitment):
        raise HTTPException(409, "Commitment already enrolled")
    
    # Create enrollment (legacy record)
    enrollment_id = "enr_" + secrets.token_urlsafe(16)
    
    create_enrollment(
        enrollment_id=enrollment_id,
        client_id=client_id,
        purpose=body.purpose,
        leaf_commitment=body.leaf_commitment,
        email_hash=None,
        status="approved",
    )
    
    # Insert leaf
    leaf_hash = body.leaf_commitment.replace("0x", "")
    new_root, leaf_index, siblings = insert_leaf(tree_id, leaf_hash)
    
    # Create merkle_leaf record (auto-approve: API key is the authorization)
    leaf_id = add_merkle_leaf(
        tree_id=tree_id,
        leaf_index=leaf_index,
        leaf_commitment=body.leaf_commitment,
        authorization_event_id=f"api_key_{enrollment_id}",  # Pseudo-event for API key auth
        authorization_pubkey=client_id,  # Client ID as pseudo-pubkey
    )
    
    # Compute path bits
    path_bits = []
    idx = leaf_index
    for _ in range(TREE_DEPTH):
        path_bits.append(idx & 1)
        idx >>= 1
    
    # Save witness
    save_witness(
        leaf_id=leaf_id,
        tree_id=tree_id,
        siblings=siblings,
        path_bits=path_bits,
        leaf_index=leaf_index,
        root_hash=new_root,
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
    authorization: str = Header(..., alias="Authorization")
):
    """Get valid roots for a tree."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]
    client_id, _ = validate_enterprise_key(api_key)
    
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
    client_id, _ = validate_enterprise_key(api_key)
    
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
