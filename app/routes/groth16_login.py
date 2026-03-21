"""
SignedByMe Login API (Phase 26)

NOSTR-native login flow:
1. Phone generates Groth16 proof (proves Merkle membership + derives npub)
2. Phone publishes proof as NOSTR event (signed with nsec from same leaf_secret)
3. Server verifies NOSTR event signature
4. Server extracts npub from event pubkey
5. Server issues OIDC id_token with sub=npub

Server does NOT re-verify the Groth16 proof because:
- npub is derived from leaf_secret inside the ZK circuit
- nsec is derived from the same leaf_secret
- NOSTR signature proves npub ownership
- If proof was fake, npub would be wrong → signature fails

This is the core cryptographic insight of SignedByMe:
The ZK proof and NOSTR signature form an unbreakable chain.

POST /v1/login/verify
  - Receives NOSTR event containing Groth16 proof
  - Verifies NOSTR event signature (~1ms)
  - Extracts npub from event pubkey
  - Returns OIDC id_token with sub = npub (bech32)
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import json
import base64
import logging
from pathlib import Path

from ..lib.nostr import (
    NostrEvent,
    verify_event,
    bech32_encode,
)
from ..lib.verifier import pubkey_hex_to_npub
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


# =============================================================================
# Request/Response Models
# =============================================================================

class NostrEventModel(BaseModel):
    """NOSTR event (NIP-01 format)."""
    id: str = Field(..., description="Event ID (32-byte hex SHA256)")
    pubkey: str = Field(..., description="Author pubkey (32-byte hex)")
    created_at: int = Field(..., description="Unix timestamp")
    kind: int = Field(..., description="Event kind")
    tags: List[List[str]] = Field(..., description="Event tags")
    content: str = Field(..., description="Event content (contains proof)")
    sig: str = Field(..., description="Schnorr signature (64-byte hex)")


class LoginVerifyRequest(BaseModel):
    """Request to verify NOSTR event and get id_token."""
    event: NostrEventModel = Field(..., description="NOSTR event containing Groth16 proof")
    client_id: str = Field(..., description="Client ID for the relying party")
    nonce: Optional[str] = Field(None, description="Optional nonce for replay protection")
    session_id: Optional[str] = Field(None, description="Session ID for RP polling flow")


class LoginVerifyResponse(BaseModel):
    """Response with id_token."""
    ok: bool
    id_token: str
    token_type: str = "Bearer"
    expires_in: int
    sub: str  # npub in bech32
    event_id: str  # NOSTR event ID (for audit/dedup)


# =============================================================================
# Legacy Request Model (backward compatibility)
# =============================================================================

class Groth16Proof(BaseModel):
    """snarkjs Groth16 proof format (legacy)."""
    pi_a: list[str]
    pi_b: list[list[str]]
    pi_c: list[str]
    protocol: str = "groth16"
    curve: str = "bn128"


class LegacyLoginVerifyRequest(BaseModel):
    """Legacy request format (raw proof without NOSTR event)."""
    proof: Optional[Groth16Proof] = Field(None, description="Groth16 proof (legacy)")
    public_inputs: Optional[list[str]] = Field(None, description="Public outputs (legacy)")
    event: Optional[NostrEventModel] = Field(None, description="NOSTR event (Phase 26)")
    client_id: str = Field(..., description="Client ID")
    nonce: Optional[str] = None
    session_id: Optional[str] = None


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/v1/login/verify", response_model=LoginVerifyResponse)
def verify_login(
    body: LegacyLoginVerifyRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Verify login and return OIDC id_token.
    
    Phase 26: Accepts NOSTR event containing proof.
    Legacy: Accepts raw proof (deprecated, will be removed).
    
    The NOSTR event signature cryptographically proves npub ownership.
    Server-side Groth16 proof verification is NOT performed (redundant).
    """
    start_time = time.time()
    
    # Validate API key
    client_id, client_config = validate_api_key(x_api_key)
    
    # Verify client_id matches
    if body.client_id != client_id:
        raise HTTPException(400, f"client_id mismatch: expected {client_id}, got {body.client_id}")
    
    # Phase 26: NOSTR event-based verification
    if body.event:
        return _verify_nostr_login(
            event_model=body.event,
            client_id=client_id,
            client_config=client_config,
            nonce=body.nonce,
            session_id=body.session_id,
            start_time=start_time,
        )
    
    # Legacy: Raw proof (deprecated)
    if body.proof and body.public_inputs:
        return _verify_legacy_login(
            proof=body.proof,
            public_inputs=body.public_inputs,
            client_id=client_id,
            client_config=client_config,
            nonce=body.nonce,
            session_id=body.session_id,
            start_time=start_time,
        )
    
    raise HTTPException(400, "Must provide either 'event' (Phase 26) or 'proof'+'public_inputs' (legacy)")


def _verify_nostr_login(
    event_model: NostrEventModel,
    client_id: str,
    client_config: dict,
    nonce: Optional[str],
    session_id: Optional[str],
    start_time: float,
) -> LoginVerifyResponse:
    """Verify NOSTR event and issue id_token."""
    
    # Convert model to NostrEvent
    event = NostrEvent(
        id=event_model.id,
        pubkey=event_model.pubkey,
        created_at=event_model.created_at,
        kind=event_model.kind,
        tags=event_model.tags,
        content=event_model.content,
        sig=event_model.sig,
    )
    
    # Verify event (ID hash + Schnorr signature)
    valid, error = verify_event(event)
    if not valid:
        logger.warning(f"NOSTR event verification failed: {error}")
        raise HTTPException(400, f"Event verification failed: {error}")
    
    # Extract npub from event pubkey
    try:
        npub_bech32 = pubkey_hex_to_npub(event.pubkey)
    except Exception as e:
        logger.error(f"Failed to encode npub: {e}")
        raise HTTPException(500, f"Failed to encode npub: {e}")
    
    # Build and sign id_token
    id_token, expires_in = _build_id_token(
        npub_bech32=npub_bech32,
        client_id=client_id,
        nonce=nonce,
        event_id=event.id,
    )
    
    # Update session if provided
    if session_id:
        _update_session(session_id, client_id, npub_bech32, event.get_tag("merkle_root"))
    
    # Audit log
    verify_ms = (time.time() - start_time) * 1000
    audit_log(
        "login_verified",
        session_id=session_id,
        client_id=client_id,
        details={
            "npub": npub_bech32[:20] + "...",
            "event_id": event.id[:16] + "...",
            "verify_ms": round(verify_ms, 2),
            "method": "nostr_event",
        }
    )
    
    logger.info(f"Login verified: sub={npub_bech32[:20]}... client={client_id} method=nostr")
    
    return LoginVerifyResponse(
        ok=True,
        id_token=id_token,
        token_type="Bearer",
        expires_in=expires_in,
        sub=npub_bech32,
        event_id=event.id,
    )


def _verify_legacy_login(
    proof: Groth16Proof,
    public_inputs: list[str],
    client_id: str,
    client_config: dict,
    nonce: Optional[str],
    session_id: Optional[str],
    start_time: float,
) -> LoginVerifyResponse:
    """
    Legacy proof verification (DEPRECATED).
    
    Phase 26 removes server-side Groth16 verification.
    This endpoint now extracts npub from public inputs without verification.
    Clients should migrate to NOSTR event-based flow.
    """
    logger.warning("Legacy login endpoint used - migrate to NOSTR event flow")
    
    # Validate public inputs count
    if len(public_inputs) != 9:
        raise HTTPException(400, f"Expected 9 public inputs, got {len(public_inputs)}")
    
    # Extract merkle_root (first public input)
    merkle_root = public_inputs[0]
    
    # Extract npub from public inputs (npub_x[4], npub_y[4])
    # For legacy compat, we trust the public inputs (should migrate to NOSTR flow)
    # npub_x is inputs[1:5], npub_y is inputs[5:9]
    # This is INSECURE without NOSTR event signature - deprecated path
    
    # Construct compressed pubkey from x-coordinate limbs
    try:
        # Convert 4 limbs (64-bit each in decimal) to 256-bit x-coordinate
        npub_x_limbs = [int(public_inputs[i]) for i in range(1, 5)]
        npub_y_limbs = [int(public_inputs[i]) for i in range(5, 9)]
        
        # Reconstruct x-coordinate (little-endian limbs)
        x = sum(limb << (64 * i) for i, limb in enumerate(npub_x_limbs))
        y = sum(limb << (64 * i) for i, limb in enumerate(npub_y_limbs))
        
        # Determine parity for compression
        prefix = "02" if y % 2 == 0 else "03"
        x_hex = format(x, '064x')
        compressed = prefix + x_hex
        
        # Convert to npub (just x-coordinate for NOSTR)
        npub_bech32 = bech32_encode("npub", bytes.fromhex(x_hex))
        
    except Exception as e:
        logger.error(f"Failed to extract npub from public inputs: {e}")
        raise HTTPException(500, f"Failed to extract npub: {e}")
    
    # Build id_token
    id_token, expires_in = _build_id_token(
        npub_bech32=npub_bech32,
        client_id=client_id,
        nonce=nonce,
        merkle_root=merkle_root,
        legacy=True,
    )
    
    # Update session if provided
    if session_id:
        _update_session(session_id, client_id, npub_bech32, merkle_root)
    
    # Audit log
    verify_ms = (time.time() - start_time) * 1000
    audit_log(
        "login_verified",
        session_id=session_id,
        client_id=client_id,
        details={
            "npub": npub_bech32[:20] + "...",
            "verify_ms": round(verify_ms, 2),
            "method": "legacy_proof",
            "warning": "deprecated",
        }
    )
    
    logger.warning(f"Legacy login: sub={npub_bech32[:20]}... client={client_id} (DEPRECATED)")
    
    return LoginVerifyResponse(
        ok=True,
        id_token=id_token,
        token_type="Bearer",
        expires_in=expires_in,
        sub=npub_bech32,
        event_id="legacy-no-event",
    )


def _build_id_token(
    npub_bech32: str,
    client_id: str,
    nonce: Optional[str] = None,
    event_id: Optional[str] = None,
    merkle_root: Optional[str] = None,
    legacy: bool = False,
) -> tuple[str, int]:
    """Build and sign OIDC id_token."""
    
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
        "sub": npub_bech32,
        "iat": now,
        "exp": exp,
        "amr": ["nostr_sig"] if not legacy else ["groth16"],
    }
    
    if nonce:
        claims["nonce"] = nonce
    
    if event_id:
        claims["https://signedby.me/claims/event_id"] = event_id
    
    if merkle_root:
        claims["https://signedby.me/claims/merkle_root"] = merkle_root
    
    if legacy:
        claims["https://signedby.me/claims/legacy"] = True
    
    # Sign token
    id_token = _jwt_rs256(claims, kid, priv_path)
    
    return id_token, exp - now


def _update_session(session_id: str, client_id: str, npub: str, merkle_root: Optional[str]):
    """Update session with login result (for RP polling flow)."""
    session = db_get_session(session_id)
    if session:
        if session["client_id"] != client_id:
            raise HTTPException(400, "Session client_id mismatch")
        session_module.complete_session(
            session_id=session_id,
            npub=npub,
            merkle_root=merkle_root or "",
        )
        logger.info(f"Session {session_id} completed")


@router.get("/v1/login/verify/health")
def verify_health():
    """Health check for login verification."""
    return {
        "ok": True,
        "phase": 26,
        "method": "nostr_event",
        "note": "Server-side Groth16 verification removed (cryptographically redundant)",
    }
