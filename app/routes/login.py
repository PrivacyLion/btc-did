"""
SignedByMe Login Verification API (Phase 8 → Phase 26)

POST /v1/login/verify - Stateless endpoint. No sessions.

Phase 26 changes:
- Server-side Groth16 verification REMOVED (cryptographically redundant)
- NOSTR event signature proves npub ownership
- Payment preimage verification still required

3 checks (Phase 26):
1. NOSTR event signature valid (proves npub ownership)
2. merkle_root is in the valid root set (last 30 roots)
3. SHA256(preimage) == payment_hash (user + operator)

All pass → return id_token
Any fail → reject

No database write. No session stored.
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
import time
import json
import base64
import logging
from pathlib import Path

from ..lib.verifier import verify_preimage, is_verifier_ready, pubkey_hex_to_npub
from ..lib.nostr import NostrEvent, verify_event, bech32_encode
from ..db import is_root_valid_for_client, log_verification

logger = logging.getLogger("login")
router = APIRouter(tags=["login"])

# Config
ISSUER = "https://api.beta.privacy-lion.com"
KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"
CLIENTS_PATH = Path(__file__).resolve().parents[2] / "clients.json"

# Root validity window
ROOT_VALIDITY_WINDOW = 30  # Last 30 roots are valid


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


# === Models ===

from typing import List

class NostrEventModel(BaseModel):
    """NOSTR event (NIP-01 format)."""
    id: str = Field(..., description="Event ID (32-byte hex SHA256)")
    pubkey: str = Field(..., description="Author pubkey (32-byte hex)")
    created_at: int = Field(..., description="Unix timestamp")
    kind: int = Field(..., description="Event kind")
    tags: List[List[str]] = Field(..., description="Event tags")
    content: str = Field(..., description="Event content")
    sig: str = Field(..., description="Schnorr signature (64-byte hex)")


class Groth16Proof(BaseModel):
    """snarkjs/rapidsnark Groth16 proof format (legacy)."""
    pi_a: list[str]
    pi_b: list[list[str]]
    pi_c: list[str]
    protocol: str = "groth16"
    curve: str = "bn128"


class LoginVerifyRequest(BaseModel):
    """
    Request to verify login and issue id_token.
    
    Phase 26: Enterprise submits NOSTR event + payment preimages.
    Legacy: Groth16 proof + public_inputs (deprecated).
    """
    # Phase 26: NOSTR event
    event: Optional[NostrEventModel] = Field(None, description="NOSTR event containing proof (Phase 26)")
    merkle_root: Optional[str] = Field(None, description="Merkle root for validation (from event tags)")
    
    # Legacy: Groth16 proof (deprecated)
    proof: Optional[Groth16Proof] = Field(None, description="Groth16 proof (legacy, deprecated)")
    public_inputs: Optional[list[str]] = Field(None, description="Public outputs (legacy, deprecated)")
    
    # Client identification
    client_id: str = Field(..., description="Client ID for the relying party")
    nonce: Optional[str] = Field(None, description="Optional nonce for replay protection")
    
    # Payment verification (REQUIRED)
    user_invoice: str = Field(..., description="User's BOLT11 invoice (shows they got paid)")
    user_payment_hash: str = Field(..., description="Payment hash from user invoice (64 hex)")
    user_preimage: str = Field(..., description="Preimage proving user payment (64 hex)")
    
    operator_invoice: str = Field(..., description="Operator's BOLT11 invoice (operator fee)")
    operator_payment_hash: str = Field(..., description="Payment hash from operator invoice (64 hex)")
    operator_preimage: str = Field(..., description="Preimage proving operator payment (64 hex)")


class LoginVerifyResponse(BaseModel):
    """Response with OIDC id_token."""
    ok: bool
    id_token: str
    token_type: str = "Bearer"
    expires_in: int
    
    # Extracted values
    sub: str  # npub in bech32
    merkle_root: str
    verify_time_ms: Optional[float] = None


class LoginVerifyError(BaseModel):
    """Error response."""
    ok: bool = False
    error: str
    error_code: str


# === Endpoint ===

@router.post(
    "/v1/login/verify",
    response_model=LoginVerifyResponse,
    responses={
        400: {"model": LoginVerifyError, "description": "Verification failed"},
        401: {"model": LoginVerifyError, "description": "Invalid API key"},
        503: {"model": LoginVerifyError, "description": "Verifier unavailable"},
    }
)
def verify_login(
    body: LoginVerifyRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Verify Groth16 membership proof and return OIDC id_token.
    
    **Stateless endpoint.** No sessions. No database writes. No NOSTR on server.
    
    ## 4 Checks (in order)
    
    1. **Groth16 proof valid** - Calls Rust verifier (~5ms)
    2. **merkle_root valid** - Must be in last 30 roots for this client
    3. **User payment verified** - SHA256(user_preimage) == user_payment_hash
    4. **Operator payment verified** - SHA256(operator_preimage) == operator_payment_hash
    
    All 4 pass → id_token returned  
    Any fail → 400 error with specific reason
    
    ## Returns
    
    OIDC id_token (RS256 signed JWT) with:
    - `sub`: npub (bech32 format)
    - `aud`: client_id
    - `amr`: ["groth16", "merkle", "lightning"]
    - SignedByMe-specific claims for merkle_root, payment hashes
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
    
    # Check verifier readiness
    ready, msg = is_verifier_ready()
    if not ready:
        raise HTTPException(503, detail={
            "ok": False,
            "error": msg,
            "error_code": "verifier_unavailable"
        })
    
    # Validate input formats
    if len(body.public_inputs) != 9:
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"Expected 9 public inputs, got {len(body.public_inputs)}",
            "error_code": "invalid_public_inputs"
        })
    
    for field, value in [
        ("user_payment_hash", body.user_payment_hash),
        ("user_preimage", body.user_preimage),
        ("operator_payment_hash", body.operator_payment_hash),
        ("operator_preimage", body.operator_preimage),
    ]:
        if len(value) != 64 or not all(c in "0123456789abcdefABCDEF" for c in value):
            raise HTTPException(400, detail={
                "ok": False,
                "error": f"{field} must be 64 hex characters",
                "error_code": "invalid_format"
            })
    
    # =========================================================================
    # CHECK 1: NOSTR event signature valid (Phase 26) or legacy proof
    # =========================================================================
    
    npub_bech32 = None
    merkle_root = None
    
    if body.event:
        # Phase 26: NOSTR event verification
        event = NostrEvent(
            id=body.event.id,
            pubkey=body.event.pubkey,
            created_at=body.event.created_at,
            kind=body.event.kind,
            tags=body.event.tags,
            content=body.event.content,
            sig=body.event.sig,
        )
        
        valid, error = verify_event(event)
        if not valid:
            logger.warning(f"NOSTR event verification failed: {error}")
            raise HTTPException(400, detail={
                "ok": False,
                "error": f"Event verification failed: {error}",
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
        
        # Get merkle_root from event tags or request body
        merkle_root = event.get_tag("merkle_root") or body.merkle_root
        
    elif body.proof and body.public_inputs:
        # Legacy: Extract from public inputs (DEPRECATED)
        logger.warning("Legacy proof verification used - migrate to NOSTR event flow")
        
        if len(body.public_inputs) != 9:
            raise HTTPException(400, detail={
                "ok": False,
                "error": f"Expected 9 public inputs, got {len(body.public_inputs)}",
                "error_code": "invalid_public_inputs"
            })
        
        merkle_root = body.public_inputs[0]
        
        # Extract npub from public inputs (trust without proof verification)
        try:
            npub_x_limbs = [int(body.public_inputs[i]) for i in range(1, 5)]
            x = sum(limb << (64 * i) for i, limb in enumerate(npub_x_limbs))
            x_hex = format(x, '064x')
            npub_bech32 = bech32_encode("npub", bytes.fromhex(x_hex))
        except Exception as e:
            raise HTTPException(400, detail={
                "ok": False,
                "error": f"Failed to extract npub: {e}",
                "error_code": "npub_extraction_failed"
            })
    else:
        raise HTTPException(400, detail={
            "ok": False,
            "error": "Must provide 'event' (Phase 26) or 'proof'+'public_inputs' (legacy)",
            "error_code": "missing_auth"
        })
    
    # =========================================================================
    # CHECK 2: merkle_root in valid root set (last 30 roots)
    # =========================================================================
    if not is_root_valid_for_client(client_id, merkle_root, limit=ROOT_VALIDITY_WINDOW):
        logger.warning(f"Stale merkle_root: {merkle_root[:16]}... not in last {ROOT_VALIDITY_WINDOW} roots for {client_id}")
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"merkle_root not in valid root set (last {ROOT_VALIDITY_WINDOW} roots)",
            "error_code": "stale_merkle_root"
        })
    
    # =========================================================================
    # CHECK 3: SHA256(user_preimage) == user_payment_hash
    # =========================================================================
    if not verify_preimage(body.user_preimage.lower(), body.user_payment_hash.lower()):
        logger.warning("User preimage verification failed")
        raise HTTPException(400, detail={
            "ok": False,
            "error": "User preimage does not match payment hash",
            "error_code": "user_preimage_mismatch"
        })
    
    # =========================================================================
    # CHECK 4: SHA256(operator_preimage) == operator_payment_hash
    # =========================================================================
    if not verify_preimage(body.operator_preimage.lower(), body.operator_payment_hash.lower()):
        logger.warning("Operator preimage verification failed")
        raise HTTPException(400, detail={
            "ok": False,
            "error": "Operator preimage does not match payment hash",
            "error_code": "operator_preimage_mismatch"
        })
    
    # =========================================================================
    # ALL 4 CHECKS PASSED → Log verification + Issue id_token
    # =========================================================================
    
    # Log successful verification to SQLite (before issuing token)
    now = int(time.time())
    log_verification(
        npub=npub_bech32,
        client_id=client_id,
        merkle_root=merkle_root,
        payment_hash_user=body.user_payment_hash.lower(),
        payment_hash_operator=body.operator_payment_hash.lower(),
        verified_at=now,
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
    
    # Build OIDC claims
    exp = now + 3600  # 1 hour (now defined above when logging)
    
    # Determine auth method for amr claim
    amr = ["nostr_sig", "merkle", "lightning"] if body.event else ["legacy", "merkle", "lightning"]
    
    claims = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": npub_bech32,  # THE KEY: npub as subject
        "iat": now,
        "exp": exp,
        "amr": amr,  # Authentication methods
        
        # SignedByMe-specific claims
        "https://signedby.me/claims/merkle_root": merkle_root,
        "https://signedby.me/claims/user_payment_hash": body.user_payment_hash.lower(),
        "https://signedby.me/claims/operator_payment_hash": body.operator_payment_hash.lower(),
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
        merkle_root=merkle_root,
        verify_time_ms=None,  # No longer tracking proof verification time
    )


@router.get("/v1/login/verify/health")
def verify_health():
    """Health check for the Groth16 verifier."""
    ready, msg = is_verifier_ready()
    return {
        "ok": ready,
        "message": msg,
    }
