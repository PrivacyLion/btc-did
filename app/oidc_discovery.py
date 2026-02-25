"""
OIDC Discovery Endpoints

Standard OpenID Connect discovery:
- GET /.well-known/openid-configuration
- GET /oidc/jwks.json

SignedByMe extends OIDC with:
- Groth16 proof verification
- Merkle membership claims
- npub (Nostr public key) as subject
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import json

router = APIRouter(tags=["oidc"])

ISSUER = "https://api.beta.privacy-lion.com"

# Standard OIDC endpoints
AUTHZ = f"{ISSUER}/oidc/authorize"
TOKEN = f"{ISSUER}/oidc/token"
JWKS = f"{ISSUER}/oidc/jwks.json"
USERINFO = f"{ISSUER}/oidc/userinfo"

# SignedByMe-specific endpoints
LOGIN_VERIFY = f"{ISSUER}/v1/login/verify"
ENROLL = f"{ISSUER}/v1/enroll"
SESSION = f"{ISSUER}/v1/session"

# Keys directory
KEYS_DIR = Path(__file__).resolve().parents[1] / "keys"


@router.get("/.well-known/openid-configuration")
def openid_configuration():
    """
    OpenID Connect Discovery Document.
    
    Standard OIDC with SignedByMe extensions:
    - Groth16 ZKP verification
    - Merkle membership proofs
    - npub (Nostr) as subject identifier
    """
    doc = {
        # Standard OIDC
        "issuer": ISSUER,
        "authorization_endpoint": AUTHZ,
        "token_endpoint": TOKEN,
        "jwks_uri": JWKS,
        "userinfo_endpoint": USERINFO,
        
        # Supported flows
        "response_types_supported": ["code", "id_token"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        
        # Signing
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        
        # PKCE
        "code_challenge_methods_supported": ["S256"],
        
        # Scopes
        "scopes_supported": [
            "openid",
            "profile",
        ],
        
        # Standard claims
        "claims_supported": [
            # Standard OIDC
            "sub",      # npub (bech32 Nostr public key)
            "aud",      # client_id
            "iss",      # issuer
            "exp",      # expiration
            "iat",      # issued at
            "nonce",    # replay protection
            "amr",      # authentication methods
            "sid",      # session id
            
            # SignedByMe-specific (namespaced)
            "https://signedby.me/claims/merkle_root",
            "https://signedby.me/claims/npub_compressed",
            "https://signedby.me/claims/proof_verified",
            "https://signedby.me/claims/membership_verified",
            "https://signedby.me/claims/membership_purpose",
            "https://signedby.me/claims/payment_verified",
            "https://signedby.me/claims/payment_hash",
            "https://signedby.me/claims/amount_sats",
        ],
        
        # SignedByMe extensions (non-standard, for documentation)
        "x_signedby_extensions": {
            "login_verify_endpoint": LOGIN_VERIFY,
            "enroll_endpoint": ENROLL,
            "session_endpoint": SESSION,
            "proof_system": "groth16",
            "curve": "bn254",
            "subject_type": "npub",
            "subject_format": "bech32",
            "authentication_methods": [
                "groth16",  # ZKP verified
                "merkle",   # Merkle membership
            ],
        },
    }
    return JSONResponse(doc)


@router.get("/oidc/jwks.json")
def jwks():
    """
    JSON Web Key Set for verifying SignedByMe JWTs.
    
    Keys are RS256 (RSA with SHA-256).
    """
    jwks_path = KEYS_DIR / "jwks.json"
    
    if not jwks_path.exists():
        # Return empty keyset during first boot
        # Generate keys with: python scripts/generate_oidc_keys.py
        return JSONResponse(
            {"keys": []},
            headers={"Cache-Control": "no-cache"},
        )
    
    try:
        data = json.loads(jwks_path.read_text())
        
        # Validate structure
        if not isinstance(data, dict) or "keys" not in data:
            raise ValueError("Invalid JWKS format")
        
        return JSONResponse(
            data,
            headers={"Cache-Control": "public, max-age=3600"},  # Cache for 1 hour
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"JWKS load error: {e}")


@router.get("/oidc/health")
def oidc_health():
    """Health check for OIDC endpoints."""
    jwks_path = KEYS_DIR / "jwks.json"
    pem_path = KEYS_DIR / "oidc_rs256.pem"
    
    return {
        "ok": True,
        "issuer": ISSUER,
        "jwks_available": jwks_path.exists(),
        "signing_key_available": pem_path.exists(),
    }
