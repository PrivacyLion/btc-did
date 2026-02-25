"""
SignedByMe Groth16 Login API

Stateless endpoint: proof in, id_token out.
No sessions, no database, no polling.

POST /v1/login/verify
  - Receives Groth16 proof + public inputs
  - Verifies proof (ark-groth16, ~5ms)
  - Extracts npub from public outputs
  - Returns OIDC id_token with sub = npub (bech32)
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
import time
import json
import hashlib
import base64
import logging
from pathlib import Path

from ..lib.groth16_verify import verify_proof, npub_to_bech32, has_verifier, has_vk
from ..db import get_session as db_get_session, audit_log
from . import session as session_module

logger = logging.getLogger("groth16_login")
router = APIRouter(tags=["login"])

# Config
ISSUER = "https://api.beta.privacy-lion.com"
KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"

# Load clients config
CLIENTS_PATH = Path(__file__).resolve().parents[2] / "clients.json"


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
    
    header = {"kid": kid, "alg": "RS256", "typ": "JWT"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    
    private_key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    s_b64 = _b64url(sig)
    
    return f"{h_b64}.{p_b64}.{s_b64}"


class Groth16Proof(BaseModel):
    """snarkjs Groth16 proof format"""
    pi_a: list[str]
    pi_b: list[list[str]]
    pi_c: list[str]
    protocol: str = "groth16"
    curve: str = "bn128"


class LoginVerifyRequest(BaseModel):
    """Request to verify Groth16 proof and get id_token"""
    proof: Groth16Proof = Field(..., description="Groth16 proof from snarkjs/rapidsnark")
    public_inputs: list[str] = Field(..., description="9 public outputs: [merkle_root, npub_x[4], npub_y[4]]")
    client_id: str = Field(..., description="Client ID for the relying party")
    nonce: Optional[str] = Field(None, description="Optional nonce for replay protection")
    # Session binding (for RP polling flow)
    session_id: Optional[str] = Field(None, description="Session ID from /v1/session (for RP polling flow)")
    # Payment preimages (required for id_token issuance once payment phases are built)
    preimage_user: Optional[str] = Field(None, description="User payment preimage (32 bytes hex) - verifies user got paid")
    preimage_operator: Optional[str] = Field(None, description="Operator payment preimage (32 bytes hex) - verifies operator fee paid")


class LoginVerifyResponse(BaseModel):
    """Response with id_token"""
    ok: bool
    id_token: str
    token_type: str = "Bearer"
    expires_in: int
    # Extracted values (for debugging/display)
    sub: str  # npub in bech32
    merkle_root: str
    npub_compressed: str
    verify_time_ms: Optional[float] = None


@router.post("/v1/login/verify", response_model=LoginVerifyResponse)
def verify_login(
    body: LoginVerifyRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Verify Groth16 membership proof and return OIDC id_token.
    
    This is the core SignedByMe login endpoint:
    1. Verifies the Groth16 proof (~5ms)
    2. Extracts npub from public outputs
    3. Returns signed id_token with sub = npub (bech32)
    
    The proof cryptographically binds:
    - User's identity (npub derived from secret inside ZKP)
    - Merkle membership (user is in the allowed set)
    
    No sessions, no database, no polling. Stateless.
    """
    # Validate API key
    client_id, client_config = validate_api_key(x_api_key)
    
    # Verify client_id matches
    if body.client_id != client_id:
        raise HTTPException(400, f"client_id mismatch: expected {client_id}, got {body.client_id}")
    
    # Check verifier availability
    if not has_verifier():
        raise HTTPException(503, "Groth16 verifier not available")
    if not has_vk():
        raise HTTPException(503, "Verification key not found")
    
    # Validate public inputs count
    if len(body.public_inputs) != 9:
        raise HTTPException(400, f"Expected 9 public inputs, got {len(body.public_inputs)}")
    
    # Convert to JSON strings for verifier
    proof_json = body.proof.model_dump_json()
    public_json = json.dumps(body.public_inputs)
    
    # Verify proof
    result = verify_proof(proof_json, public_json)
    
    if not result.valid:
        logger.warning(f"Proof verification failed: {result.error}")
        raise HTTPException(400, f"Proof verification failed: {result.error}")
    
    # Extract npub
    if not result.npub_compressed:
        raise HTTPException(500, "Failed to extract npub from proof")
    
    # Convert to bech32 npub
    try:
        npub_bech32 = npub_to_bech32(result.npub_compressed)
    except Exception as e:
        logger.error(f"Failed to encode npub to bech32: {e}")
        raise HTTPException(500, f"Failed to encode npub: {e}")
    
    # Build id_token
    now = int(time.time())
    exp = now + 3600  # 1 hour
    
    # Load signing keys
    jwks_path = KEYS_DIR / "jwks.json"
    priv_path = KEYS_DIR / "oidc_rs256.pem"
    
    if not jwks_path.exists() or not priv_path.exists():
        raise HTTPException(500, "Missing signing keys")
    
    jwks = json.loads(jwks_path.read_text())
    if "keys" not in jwks or not jwks["keys"]:
        raise HTTPException(500, "Empty JWKS")
    kid = jwks["keys"][0].get("kid", "")
    
    # OIDC claims
    claims = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": npub_bech32,  # THE KEY: npub as subject
        "iat": now,
        "exp": exp,
        "amr": ["groth16", "merkle"],  # Authentication methods
        # SignedByMe-specific claims
        "https://signedby.me/claims/merkle_root": result.merkle_root,
        "https://signedby.me/claims/npub_compressed": result.npub_compressed,
        "https://signedby.me/claims/proof_verified": True,
    }
    
    # Add nonce if provided
    if body.nonce:
        claims["nonce"] = body.nonce
    
    # Sign token
    id_token = _jwt_rs256(claims, kid, priv_path)
    
    # Update session if provided (for RP polling flow)
    if body.session_id:
        session = db_get_session(body.session_id)
        if session:
            if session["client_id"] != client_id:
                raise HTTPException(400, "Session client_id mismatch")
            session_module.complete_session(
                session_id=body.session_id,
                npub=npub_bech32,
                merkle_root=result.merkle_root or "",
            )
            logger.info(f"Session {body.session_id} completed")
    
    # Audit log
    audit_log(
        "login_verified",
        session_id=body.session_id,
        client_id=client_id,
        details={"npub": npub_bech32[:20] + "...", "verify_ms": result.verify_time_ms}
    )
    
    logger.info(f"Login verified: sub={npub_bech32[:20]}... client={client_id}")
    
    return LoginVerifyResponse(
        ok=True,
        id_token=id_token,
        token_type="Bearer",
        expires_in=exp - now,
        sub=npub_bech32,
        merkle_root=result.merkle_root or "",
        npub_compressed=result.npub_compressed,
        verify_time_ms=result.verify_time_ms,
    )


@router.get("/v1/login/verify/health")
def verify_health():
    """Health check for the Groth16 verifier."""
    return {
        "ok": True,
        "verifier_available": has_verifier(),
        "vk_available": has_vk(),
    }
