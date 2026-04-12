"""
SignedByMe Login Verification API (Phase 26)

POST /v1/login/verify - Stateless endpoint. No sessions.

Per Bible Section 2.4 — ONE CHECK ONLY:
  merkle_root in last 30 valid roots

No preimage checks. No payment verification on server.
Groth16 proof verified by circuit (npub is public output).

All pass → return id_token
Fail → reject
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
import time
import json
import base64
import logging
from pathlib import Path

from ..db import is_root_valid_for_client, log_verification
from ..lib.verifier import pubkey_hex_to_npub

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
    from hashlib import sha256
    
    if not api_key:
        raise HTTPException(401, "Missing API key")
    
    clients = load_clients()
    api_key_hash = sha256(api_key.encode()).hexdigest()
    for client_id, config in clients.items():
        if api_key_hash == config.get("api_key_hash"):
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
# Models (Per Bible Section 2.4)
# =============================================================================

class PublicOutputs(BaseModel):
    """Groth16 proof public outputs."""
    merkle_root: str = Field(..., description="Merkle root (64 hex chars)")
    npub: str = Field(..., description="Agent npub (64 hex chars)")


class LoginVerifyRequest(BaseModel):
    """
    Login verification request.
    
    Per Bible Section 2.4:
    { proof, public_outputs: { merkle_root, npub }, client_id }
    """
    proof: str = Field(..., description="Groth16 proof (hex)")
    public_outputs: PublicOutputs = Field(..., description="Public outputs from circuit")
    client_id: str = Field(..., description="Client ID")
    nonce: Optional[str] = Field(None, description="Optional nonce for replay protection")


class LoginVerifyResponse(BaseModel):
    """Login verification response."""
    ok: bool
    id_token: str
    token_type: str = "Bearer"
    expires_in: int
    sub: str  # npub in bech32


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
    authorization: str = Header(..., alias="Authorization")
):
    # Extract Bearer token
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <token>")
    api_key = authorization[7:]  # Strip "Bearer "
    """
    Verify login and return OIDC id_token.
    
    ## Per Bible Section 2.4 — ONE CHECK ONLY
    
    **merkle_root in last 30 valid roots**
    
    No preimage checks. No Groth16 server-side verification.
    npub is a public output from the Groth16 circuit (proven by the circuit).
    
    Pass → id_token returned with sub=npub
    Fail → 400 error
    """
    # Validate API key
    client_id, client_config = validate_api_key(api_key)
    
    # Verify client_id matches
    if body.client_id != client_id:
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"client_id mismatch: expected {client_id}",
            "error_code": "client_id_mismatch"
        })
    
    # Validate merkle_root format
    merkle_root = body.public_outputs.merkle_root.lower()
    if len(merkle_root) != 64 or not all(c in "0123456789abcdef" for c in merkle_root):
        raise HTTPException(400, detail={
            "ok": False,
            "error": "merkle_root must be 64 hex characters",
            "error_code": "invalid_format"
        })
    
    # Validate npub format
    npub_hex = body.public_outputs.npub.lower()
    if len(npub_hex) != 64 or not all(c in "0123456789abcdef" for c in npub_hex):
        raise HTTPException(400, detail={
            "ok": False,
            "error": "npub must be 64 hex characters",
            "error_code": "invalid_format"
        })
    
    # Convert npub to bech32
    try:
        npub_bech32 = pubkey_hex_to_npub(npub_hex)
    except Exception as e:
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"Failed to convert npub: {e}",
            "error_code": "npub_conversion_failed"
        })
    
    # =========================================================================
    # THE ONE CHECK: merkle_root in last 30 roots
    # =========================================================================
    if not is_root_valid_for_client(client_id, merkle_root, limit=ROOT_VALIDITY_WINDOW):
        logger.warning(f"Stale merkle_root: {merkle_root[:16]}...")
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"merkle_root not in valid root set (last {ROOT_VALIDITY_WINDOW} roots)",
            "error_code": "stale_merkle_root"
        })
    
    # =========================================================================
    # CHECK PASSED → Log + Issue id_token
    # =========================================================================
    
    now = int(time.time())
    
    # Log verification (no payment fields)
    log_verification(
        npub=npub_bech32,
        client_id=client_id,
        merkle_root=merkle_root,
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
    exp = now + 3600  # 1 hour
    
    # Build OIDC claims
    # Per Bible: amr = ["zk_membership"] — no "lightning"
    claims = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": npub_bech32,
        "iat": now,
        "exp": exp,
        "amr": ["zk_membership"],
        
        # SignedByMe-specific claims
        "https://signedby.me/claims/merkle_root": merkle_root,
        "https://signedby.me/claims/membership_verified": True,
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
    )


# =============================================================================
# Health Check
# =============================================================================

@router.get("/v1/login/verify/health")
def verify_health():
    """Health check for login verification."""
    return {
        "ok": True,
        "phase": 26,
        "checks": ["merkle_root"],
    }
