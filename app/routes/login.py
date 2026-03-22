"""
SignedByMe Login Verification API (Phase 26)

POST /v1/login/verify - Stateless endpoint. No sessions.

3 checks:
1. SHA256(user_preimage) == user_payment_hash
2. SHA256(operator_preimage) == operator_payment_hash
3. merkle_root in last 30 roots

npub extraction: From NOSTR event signature (proves ownership).

All pass → return id_token
Any fail → reject

No database write for auth. Verification logged for audit.
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import json
import base64
import logging
from pathlib import Path

from ..lib.verifier import verify_preimage, pubkey_hex_to_npub
from ..lib.nostr import NostrEvent, verify_event
from ..db import is_root_valid_for_client, log_verification

logger = logging.getLogger("login")
router = APIRouter(tags=["login"])

# Config
ISSUER = "https://api.beta.privacy-lion.com"
KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"
CLIENTS_PATH = Path(__file__).resolve().parents[2] / "clients.json"

# Root validity window
ROOT_VALIDITY_WINDOW = 30


def load_clients() -> dict:
    """Load client configuration."""
    if CLIENTS_PATH.exists():
        try:
            return json.loads(CLIENTS_PATH.read_text())
        except Exception as e:
            logger.warning(f"Could not load clients.json: {e}")
    return {}


def validate_api_key(api_key: str) -> tuple[str, dict]:
    """Validate API key and return (client_id, client_config)."""
    if not api_key:
        raise HTTPException(401, "Missing API key")
    
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    
    raise HTTPException(401, "Invalid API key")


def _b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_rs256(payload: dict, kid: str, pem_path: Path) -> str:
    """Sign JWT with RS256."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    
    private_key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    s_b64 = _b64url(sig)
    
    return f"{h_b64}.{p_b64}.{s_b64}"


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


class LoginVerifyRequest(BaseModel):
    """Login verification request (Phase 26)."""
    # NOSTR event containing proof (npub extracted from signature)
    event: NostrEventModel = Field(..., description="NOSTR event signed by user")
    
    # Merkle root for validation
    merkle_root: str = Field(..., description="Merkle root (64 hex chars)")
    
    # Client identification
    client_id: str = Field(..., description="Client ID")
    nonce: Optional[str] = Field(None, description="Optional nonce for replay protection")
    
    # Payment verification (REQUIRED)
    user_payment_hash: str = Field(..., description="Payment hash from user invoice (64 hex)")
    user_preimage: str = Field(..., description="Preimage proving user payment (64 hex)")
    operator_payment_hash: str = Field(..., description="Payment hash from operator invoice (64 hex)")
    operator_preimage: str = Field(..., description="Preimage proving operator payment (64 hex)")


class LoginVerifyResponse(BaseModel):
    """Login verification response."""
    ok: bool
    id_token: str
    token_type: str = "Bearer"
    expires_in: int
    sub: str  # npub in bech32
    merkle_root: str
    event_id: str  # For dedup/audit


class LoginVerifyError(BaseModel):
    """Error response."""
    ok: bool = False
    error: str
    error_code: str


# =============================================================================
# Endpoint
# =============================================================================

@router.post(
    "/v1/login/verify",
    response_model=LoginVerifyResponse,
    responses={
        400: {"model": LoginVerifyError, "description": "Verification failed"},
        401: {"model": LoginVerifyError, "description": "Invalid API key"},
    }
)
def verify_login(
    body: LoginVerifyRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Verify login and return OIDC id_token.
    
    ## 3 Checks
    
    1. **User payment verified** - SHA256(user_preimage) == user_payment_hash
    2. **Operator payment verified** - SHA256(operator_preimage) == operator_payment_hash
    3. **merkle_root valid** - Must be in last 30 roots for this client
    
    npub is extracted from the NOSTR event signature (proves ownership).
    
    All 3 pass → id_token returned
    Any fail → 400 error
    """
    # Validate API key
    client_id, client_config = validate_api_key(x_api_key)
    
    # Verify client_id matches
    if body.client_id != client_id:
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"client_id mismatch: expected {client_id}",
            "error_code": "client_id_mismatch"
        })
    
    # Validate input formats
    for field, value in [
        ("user_payment_hash", body.user_payment_hash),
        ("user_preimage", body.user_preimage),
        ("operator_payment_hash", body.operator_payment_hash),
        ("operator_preimage", body.operator_preimage),
        ("merkle_root", body.merkle_root),
    ]:
        if len(value) != 64 or not all(c in "0123456789abcdefABCDEF" for c in value):
            raise HTTPException(400, detail={
                "ok": False,
                "error": f"{field} must be 64 hex characters",
                "error_code": "invalid_format"
            })
    
    # Convert event model to NostrEvent
    event = NostrEvent(
        id=body.event.id,
        pubkey=body.event.pubkey,
        created_at=body.event.created_at,
        kind=body.event.kind,
        tags=body.event.tags,
        content=body.event.content,
        sig=body.event.sig,
    )
    
    # Verify NOSTR event signature (proves npub ownership)
    valid, error = verify_event(event)
    if not valid:
        logger.warning(f"NOSTR event verification failed: {error}")
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"Event signature invalid: {error}",
            "error_code": "invalid_event"
        })
    
    # Extract npub from event pubkey
    try:
        npub_bech32 = pubkey_hex_to_npub(event.pubkey)
    except Exception as e:
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"Failed to extract npub: {e}",
            "error_code": "npub_extraction_failed"
        })
    
    # =========================================================================
    # CHECK 1: SHA256(user_preimage) == user_payment_hash
    # =========================================================================
    if not verify_preimage(body.user_preimage.lower(), body.user_payment_hash.lower()):
        logger.warning("User preimage verification failed")
        raise HTTPException(400, detail={
            "ok": False,
            "error": "User preimage does not match payment hash",
            "error_code": "user_preimage_mismatch"
        })
    
    # =========================================================================
    # CHECK 2: SHA256(operator_preimage) == operator_payment_hash
    # =========================================================================
    if not verify_preimage(body.operator_preimage.lower(), body.operator_payment_hash.lower()):
        logger.warning("Operator preimage verification failed")
        raise HTTPException(400, detail={
            "ok": False,
            "error": "Operator preimage does not match payment hash",
            "error_code": "operator_preimage_mismatch"
        })
    
    # =========================================================================
    # CHECK 3: merkle_root in last 30 roots
    # =========================================================================
    if not is_root_valid_for_client(client_id, body.merkle_root.lower(), limit=ROOT_VALIDITY_WINDOW):
        logger.warning(f"Stale merkle_root: {body.merkle_root[:16]}...")
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"merkle_root not in valid root set (last {ROOT_VALIDITY_WINDOW} roots)",
            "error_code": "stale_merkle_root"
        })
    
    # =========================================================================
    # ALL 3 CHECKS PASSED → Log + Issue id_token
    # =========================================================================
    
    now = int(time.time())
    
    # Log verification
    log_verification(
        npub=npub_bech32,
        client_id=client_id,
        merkle_root=body.merkle_root.lower(),
        payment_hash_user=body.user_payment_hash.lower(),
        payment_hash_operator=body.operator_payment_hash.lower(),
        verified_at=now,
        login_event_id=event.id,
    )
    
    # Load signing keys
    jwks_path = KEYS_DIR / "jwks.json"
    priv_path = KEYS_DIR / "oidc_rs256.pem"
    
    if not jwks_path.exists() or not priv_path.exists():
        raise HTTPException(500, detail={
            "ok": False,
            "error": "Signing keys not configured",
            "error_code": "keys_missing"
        })
    
    jwks = json.loads(jwks_path.read_text())
    if "keys" not in jwks or not jwks["keys"]:
        raise HTTPException(500, detail={
            "ok": False,
            "error": "Empty JWKS",
            "error_code": "jwks_empty"
        })
    
    kid = jwks["keys"][0].get("kid", "signedby-1")
    exp = now + 3600  # 1 hour
    
    # Build OIDC claims
    claims = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": npub_bech32,
        "iat": now,
        "exp": exp,
        "amr": ["nostr_sig", "merkle", "lightning"],
        
        # SignedByMe-specific claims
        "https://signedby.me/claims/merkle_root": body.merkle_root.lower(),
        "https://signedby.me/claims/event_id": event.id,
    }
    
    if body.nonce:
        claims["nonce"] = body.nonce
    
    # Sign token
    id_token = _jwt_rs256(claims, kid, priv_path)
    
    logger.info(f"Login verified: sub={npub_bech32[:20]}... client={client_id}")
    
    return LoginVerifyResponse(
        ok=True,
        id_token=id_token,
        token_type="Bearer",
        expires_in=exp - now,
        sub=npub_bech32,
        merkle_root=body.merkle_root.lower(),
        event_id=event.id,
    )


# =============================================================================
# Login Start (Phase 26.4) — Returns enrollment_policy if verification required
# =============================================================================

class EnrollmentPolicy(BaseModel):
    """Enrollment policy returned in login/start response."""
    verification_required: bool = False
    verification_provider: Optional[str] = None  # "persona" | "jumio" | "none"
    verification_type: Optional[str] = None  # "age_18_plus" | "identity_verified" | "none"


class LoginStartRequest(BaseModel):
    """Login start request."""
    client_id: str = Field(..., description="Client ID")
    nonce: Optional[str] = Field(None, description="Session nonce")


class LoginStartResponse(BaseModel):
    """Login start response."""
    ok: bool
    client_id: str
    client_name: Optional[str] = None
    enrollment_policy: Optional[EnrollmentPolicy] = None
    require_membership: bool = False


@router.post("/v1/login/start", response_model=LoginStartResponse)
def login_start(
    body: LoginStartRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Check login requirements for a client (Phase 26.4).
    
    Returns enrollment_policy if verification_required = true.
    App uses this to determine if KYC flow is needed before proof generation.
    
    This endpoint does NOT create a session (per Bible Decision 10).
    Enterprise generates QR locally. This just returns client config.
    """
    # Validate API key
    api_client_id, _ = validate_api_key(x_api_key)
    
    # Get target client config
    clients = load_clients()
    client_config = clients.get(body.client_id)
    
    if not client_config:
        raise HTTPException(404, detail={
            "ok": False,
            "error": f"Client not found: {body.client_id}",
            "error_code": "client_not_found"
        })
    
    # Build enrollment_policy from config
    enrollment_config = client_config.get("enrollment_policy", {})
    enrollment_policy = None
    
    if enrollment_config.get("verification_required", False):
        enrollment_policy = EnrollmentPolicy(
            verification_required=True,
            verification_provider=enrollment_config.get("verification_provider"),
            verification_type=enrollment_config.get("verification_type"),
        )
    
    return LoginStartResponse(
        ok=True,
        client_id=body.client_id,
        client_name=client_config.get("name"),
        enrollment_policy=enrollment_policy,
        require_membership=client_config.get("require_membership", False),
    )


@router.get("/v1/login/verify/health")
def verify_health():
    """Health check for login verification."""
    return {
        "ok": True,
        "phase": 26,
        "checks": ["user_preimage", "operator_preimage", "merkle_root"],
    }
