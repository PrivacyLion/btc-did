"""
SignedByMe Login Verification API (Phase 8)

POST /v1/login/verify - Stateless endpoint. No sessions. No NOSTR on server.

4 checks in order:
1. Groth16 proof valid (calls Rust verifier from Phase 23)
2. merkle_root is in the valid root set (last 30 roots)
3. SHA256(user_preimage) == user_payment_hash
4. SHA256(operator_preimage) == operator_payment_hash

All 4 pass → return id_token
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

from ..lib.verifier import verify_groth16_proof, verify_preimage, is_verifier_ready
from ..db import is_root_valid_for_client

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

class Groth16Proof(BaseModel):
    """snarkjs/rapidsnark Groth16 proof format."""
    pi_a: list[str]
    pi_b: list[list[str]]
    pi_c: list[str]
    protocol: str = "groth16"
    curve: str = "bn128"


class LoginVerifyRequest(BaseModel):
    """
    Request to verify Groth16 proof and issue id_token.
    
    Enterprise submits: Groth16 proof + npub + both BOLT11 invoices + both preimages.
    """
    # Groth16 proof
    proof: Groth16Proof = Field(..., description="Groth16 proof from snarkjs/rapidsnark")
    public_inputs: list[str] = Field(..., description="9 public outputs: [merkle_root, npub_x[4], npub_y[4]]")
    
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
    # CHECK 1: Groth16 proof valid
    # =========================================================================
    proof_json = body.proof.model_dump_json()
    public_json = json.dumps(body.public_inputs)
    
    result = verify_groth16_proof(proof_json, public_json)
    
    if not result.valid:
        logger.warning(f"Proof verification failed: {result.error}")
        raise HTTPException(400, detail={
            "ok": False,
            "error": f"Proof verification failed: {result.error}",
            "error_code": "invalid_proof"
        })
    
    if not result.npub_bech32:
        raise HTTPException(400, detail={
            "ok": False,
            "error": "Failed to extract npub from proof",
            "error_code": "npub_extraction_failed"
        })
    
    merkle_root = result.merkle_root or body.public_inputs[0]
    
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
    # ALL 4 CHECKS PASSED → Issue id_token
    # =========================================================================
    
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
    now = int(time.time())
    exp = now + 3600  # 1 hour
    
    claims = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": result.npub_bech32,  # THE KEY: npub as subject
        "iat": now,
        "exp": exp,
        "amr": ["groth16", "merkle", "lightning"],  # Authentication methods
        
        # SignedByMe-specific claims
        "https://signedby.me/claims/merkle_root": merkle_root,
        "https://signedby.me/claims/user_payment_hash": body.user_payment_hash.lower(),
        "https://signedby.me/claims/operator_payment_hash": body.operator_payment_hash.lower(),
        "https://signedby.me/claims/proof_verified": True,
    }
    
    if body.nonce:
        claims["nonce"] = body.nonce
    
    # Sign token
    id_token = _jwt_rs256(claims, kid, priv_path)
    
    logger.info(f"Login verified: sub={result.npub_bech32[:20]}... client={client_id}")
    
    return LoginVerifyResponse(
        ok=True,
        id_token=id_token,
        token_type="Bearer",
        expires_in=exp - now,
        sub=result.npub_bech32,
        merkle_root=merkle_root,
        verify_time_ms=result.verify_time_ms,
    )


@router.get("/v1/login/verify/health")
def verify_health():
    """Health check for the Groth16 verifier."""
    ready, msg = is_verifier_ready()
    return {
        "ok": ready,
        "message": msg,
    }
