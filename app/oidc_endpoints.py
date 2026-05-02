from fastapi import APIRouter, HTTPException, Query, Form
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from urllib.parse import urlparse
from pathlib import Path
from fastapi import Header, status
import time, json, hashlib, base64, secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .db import create_oidc_code, get_oidc_code, use_oidc_code

router = APIRouter()

ISSUER = "https://api.signedbyme.com"

def oauth_err(code: str, desc: str, http=status.HTTP_400_BAD_REQUEST):
    return JSONResponse({"error": code, "error_description": desc}, status_code=http)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _jwt_rs256(payload: dict, kid: str, pem_path: Path) -> str:
    header = {"kid": kid, "alg": "RS256", "typ": "JWT"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    private_key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    s_b64 = _b64url(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"

CLIENTS_PATH = Path(__file__).resolve().parents[1] / "clients.json"

def load_clients() -> dict:
    try:
        return json.loads(CLIENTS_PATH.read_text())
    except Exception:
        return {}

def is_allowed_redirect(client_id: str, redirect_uri: str) -> bool:
    cfg = load_clients().get(client_id)
    if not cfg:
        return False
    return redirect_uri in cfg.get("redirect_uris", [])

import re
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")  # base64url-safe, max 128 chars

def _valid_nonce(n: str | None) -> bool:
    return n is None or bool(_NONCE_RE.fullmatch(n))

# ========== AUTHORIZE: standard redirect with ?code=...&state=... ==========
@router.get("/oidc/authorize")
def oidc_authorize(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    state: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
    nonce: str | None = Query(None),
    response_type: str = Query("code"),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="unsupported response_type")
        
    if not _valid_nonce(nonce):
        raise HTTPException(status_code=400, detail="invalid nonce")

    parsed = urlparse(redirect_uri)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="invalid redirect_uri")
    if parsed.scheme not in ("https",):
        raise HTTPException(status_code=400, detail="redirect_uri must be https")

    rp_domain = parsed.hostname or ""
    if not rp_domain:
        raise HTTPException(status_code=400, detail="invalid redirect_uri")

    if not is_allowed_redirect(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="unauthorized redirect_uri for client_id")

    code = secrets.token_urlsafe(32)
    now = int(time.time())
    exp = now + 300

    # Store code in SQLite
    create_oidc_code(
        code=code,
        client_id=client_id,
        iat=now,
        exp=exp,
        redirect_uri=redirect_uri,
        nonce=nonce or secrets.token_urlsafe(16),
        code_challenge=code_challenge,
    )

    sep = '&' if parsed.query else '?'
    loc = f"{redirect_uri}{sep}code={code}"
    if state is not None:
        loc += f"&state={state}"
    return RedirectResponse(url=loc, status_code=302)

# ========== OPTIONAL: JSON "receipt" token endpoint (moved to /oidc/token-receipt) ==========
class LNFields(BaseModel):
    invoice: str | None = None
    payment_hash: str
    preimage: str

class Receipt(BaseModel):
    nonce: str
    rp_domain: str
    did_pubkey: str
    zk_proof: dict | None = None
    ln: LNFields
    timestamps: dict | None = None
    sig: str | None = None

class TokenRequest(BaseModel):
    client_id: str
    receipt: Receipt

@router.post("/oidc/token-receipt")
def oidc_token_receipt(req: TokenRequest):
    # LN preimage binding
    try:
        h = hashlib.sha256(bytes.fromhex(req.receipt.ln.preimage)).hexdigest()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid preimage hex")
    if h.lower() != req.receipt.ln.payment_hash.lower():
        raise HTTPException(status_code=400, detail="preimage does not match payment_hash")

    # Canonical hash of receipt (without sig)
    def canonical(obj):
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)
    receipt_dict = json.loads(req.receipt.model_dump_json())
    rec_for_hash = dict(receipt_dict); rec_for_hash.pop("sig", None)
    plr_hash = hashlib.sha256(canonical(rec_for_hash).encode()).hexdigest()

    sub = hashlib.sha256(req.receipt.did_pubkey.encode()).hexdigest()
    now = int(time.time()); exp = now + 300

    jwks_path = Path("keys/jwks.json")
    priv_path = Path("keys/oidc_rs256.pem")
    if not jwks_path.exists() or not priv_path.exists():
        raise HTTPException(status_code=500, detail="missing signing material (keys/jwks.json or keys/oidc_rs256.pem)")
    jwks = json.loads(jwks_path.read_text())
    if "keys" not in jwks or not jwks["keys"]:
        raise HTTPException(status_code=500, detail="empty JWKS")
    kid = jwks["keys"][0].get("kid") or ""

    claims = {
        "iss": ISSUER,
        "aud": req.client_id,
        "sub": sub,
        "iat": now,
        "exp": exp,
        "nonce": req.receipt.nonce,
        "amr": ["did_sig", "zk", "ln_preimage"],
        "plr_hash": plr_hash,
        "rp_domain": req.receipt.rp_domain,
    }
    id_token = _jwt_rs256(claims, kid, priv_path)
    return JSONResponse(
        {"id_token": id_token, "token_type": "Bearer", "expires_in": exp - now},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )

# ========== TOKEN (OAuth 2.0 code exchange with PKCE) ==========
@router.post("/oidc/token")
async def oidc_token_code_grant(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    code_verifier: str = Form(None),
):
    if grant_type != "authorization_code":
        return oauth_err("unsupported_grant_type", "grant_type must be authorization_code")

    # Get code from SQLite
    rec = get_oidc_code(code)
    if not rec:
        raise HTTPException(status_code=400, detail="invalid or expired code")
    if redirect_uri and redirect_uri != rec["redirect_uri"]:
        return oauth_err("invalid_request", "redirect_uri mismatch")
    if client_id and client_id != rec["client_id"]:
        return oauth_err("invalid_client", "client_id mismatch")

    # PKCE (S256)
    if rec.get("code_challenge"):
        if not code_verifier:
            raise HTTPException(status_code=400, detail="missing code_verifier")
        if (rec.get("code_challenge_method") or "S256") != "S256":
            raise HTTPException(status_code=400, detail="unsupported code_challenge_method")
        digest = hashlib.sha256(code_verifier.encode()).digest()
        derived = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if derived != rec["code_challenge"]:
            raise HTTPException(status_code=400, detail="PKCE verification failed")

    # Mark code as used (one-time use)
    use_oidc_code(code)

    # Sign ID Token
    jwks_path = Path("keys/jwks.json")
    priv_path = Path("keys/oidc_rs256.pem")
    if not jwks_path.exists() or not priv_path.exists():
        raise HTTPException(status_code=500, detail="missing signing material (keys/jwks.json or keys/oidc_rs256.pem)")
    jwks = json.loads(jwks_path.read_text())
    if "keys" not in jwks or not jwks["keys"]:
        raise HTTPException(status_code=500, detail="empty JWKS")
    kid = jwks["keys"][0].get("kid") or ""

    now = int(time.time()); exp = now + 3600  # 1 hour for SignedByMe tokens
    
    # Check if this is a SignedByMe login flow
    if rec.get("signedby"):
        # Build AMR (authentication methods reference)
        amr = ["did_sig", "groth16", "ln_payment"]
        if rec.get("membership_verified"):
            amr.append("merkle")
        
        # SignedByMe flow: use DID as subject, include payment claims
        claims = {
            "iss": ISSUER,
            "aud": rec["client_id"],
            "sub": rec.get("did", ""),  # DID is the subject
            "iat": now,
            "exp": exp,
            "nonce": rec.get("nonce", ""),
            "sid": rec.get("signedby_session_id", ""),
            "amr": amr,
            # SignedByMe-specific claims (namespaced)
            "https://signedby.me/claims/attestation_hash": rec.get("audit_hash", ""),
            "https://signedby.me/claims/payment_verified": True,
            "https://signedby.me/claims/payment_hash": rec.get("payment_hash", ""),
            "https://signedby.me/claims/amount_sats": rec.get("amount_sats", 0),
            # Membership claims (only if verified)
            "https://signedby.me/claims/membership_verified": rec.get("membership_verified", False),
        }
        
        # Add membership details only if verified
        if rec.get("membership_verified"):
            claims["https://signedby.me/claims/membership_purpose"] = rec.get("membership_purpose")
            claims["https://signedby.me/claims/membership_root_id"] = rec.get("membership_root_id")
    else:
        # Standard OIDC flow (existing behavior)
        sub_material = f"{rec['client_id']}|{rec.get('rp_domain', '')}|{rec['nonce']}".encode()
        sub = hashlib.sha256(sub_material).hexdigest()
        claims = {
            "iss": ISSUER,
            "aud": rec["client_id"],
            "sub": sub,
            "iat": now,
            "exp": exp,
            "nonce": rec["nonce"],
            "amr": ["pkce"],
            "rp_domain": rec.get("rp_domain", ""),
        }
    
    id_token = _jwt_rs256(claims, kid, priv_path)

    # OIDC token response
    response_data = {
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": exp - now
    }
    
    # Add access_token for SignedByMe (can be used to fetch attestation later)
    if rec.get("signedby"):
        response_data["access_token"] = secrets.token_urlsafe(32)
    
    return JSONResponse(
        response_data,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )

@router.get("/oidc/userinfo")
def oidc_userinfo(authorization: str | None = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        return oauth_err("invalid_request", "missing bearer token", http=status.HTTP_401_UNAUTHORIZED)
    token = authorization.split(" ", 1)[1].strip()
    claims = _verify_id_token_rs256(token)
    return JSONResponse(
        {"sub": claims.get("sub", ""), "amr": claims.get("amr", [])},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )

def _b64u_dec(s: str | bytes) -> bytes:
    s = s if isinstance(s, bytes) else s.encode()
    s += b'=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)

def _verify_id_token_rs256(jwt: str) -> dict:
    try:
        h_b64, p_b64, s_b64 = jwt.split(".")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")

    try:
        hdr = json.loads(_b64u_dec(h_b64)); claims = json.loads(_b64u_dec(p_b64))
        sig = _b64u_dec(s_b64)
        jwks = json.loads(Path("keys/jwks.json").read_text())
        kid = hdr.get("kid", "")
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if not key:
            raise ValueError("kid not found")

        n = int.from_bytes(_b64u_dec(key["n"]), "big")
        e = int.from_bytes(_b64u_dec(key["e"]), "big")
        from cryptography.hazmat.primitives.asymmetric import rsa
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        pub.verify(sig, f"{h_b64}.{p_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())

        # minimal claim checks + small skew allowance
        now = int(time.time())
        if claims.get("iss") != ISSUER:
            raise ValueError("bad iss")
        if now > int(claims.get("exp", 0)) + 60:
            raise ValueError("expired")

        return claims
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")
