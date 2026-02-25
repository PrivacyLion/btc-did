import time, uuid, os
from fastapi import APIRouter, HTTPException
from ..models.auth import (
    LoginStartRequest, LoginStartResponse, LoginCompleteRequest,
    LoginPRPResponse, LoginStatusResponse
)
from ..models.common import PayTerms, PRP, SettlementRefs
from ..lib.crypto import sha256_hex, verify_secp256k1_signature_stub
from ..lib import store

router = APIRouter(tags=["login"])
PRP_TTL = int(os.getenv("PRP_EXPIRES_SECS", "180"))

@router.post("/login/start", response_model=LoginStartResponse)
def login_start(body: LoginStartRequest):
    login_id = uuid.uuid4().hex[:16]
    nonce = sha256_hex(f"{login_id}:{body.domain}:{time.time_ns()}")
    pay_terms = PayTerms(
        amount_sats=100,
        description=f"SignedByMe login for {body.domain}",
        expires=int(time.time()) + PRP_TTL
    )
    store.LOGINS[login_id] = {
        "status": "pending",
        "nonce": nonce,
        "domain": body.domain,
        "pay_terms": pay_terms.model_dump()
    }
    return LoginStartResponse(login_id=login_id, nonce=nonce, pay_terms=pay_terms)

@router.post("/login/complete", response_model=LoginPRPResponse)
def login_complete(body: LoginCompleteRequest):
    rec = store.LOGINS.get(body.login_id)
    if not rec:
        raise HTTPException(status_code=404, detail="login_id not found")
    ok = verify_secp256k1_signature_stub(
        message=rec["nonce"],
        pubkey_hex=body.did_sig.pubkey_hex,
        signature_hex=body.did_sig.signature_hex
    )
    if not ok:
        raise HTTPException(status_code=400, detail="invalid DID signature")
    prp_id = uuid.uuid4().hex[:16]
    prp = PRP(
        prp_id=prp_id,
        kind="login",
        payload={
            "login_id": body.login_id,
            "dlc": (body.dlc.model_dump() if body.dlc else {"outcome": "auth_verified", "split": [0.9, 0.1]}),
            "zk": (body.zk_proof.model_dump() if body.zk_proof else None)
        },
        expires=int(time.time()) + PRP_TTL
    )
    store.PRPS[prp_id] = prp.model_dump()
    rec["prp_id"] = prp_id
    return LoginPRPResponse(prp=prp)

@router.get("/login/status/{login_id}", response_model=LoginStatusResponse)
def login_status(login_id: str):
    rec = store.LOGINS.get(login_id)
    if not rec:
        raise HTTPException(status_code=404, detail="login_id not found")
    return LoginStatusResponse(
        login_id=login_id,
        status=rec.get("status", "pending"),
        settlement=rec.get("settlement")
    )

@router.post("/login/settle", response_model=LoginStatusResponse)
def login_settle(login_id: str, preimage: str, txid: str | None = None):
    rec = store.LOGINS.get(login_id)
    if not rec:
        raise HTTPException(status_code=404, detail="login_id not found")
    rec["status"] = "paid"
    rec["settlement"] = SettlementRefs(
        preimage=preimage, txid=txid, settled_at=int(time.time())
    ).model_dump()
    return LoginStatusResponse(login_id=login_id, status="paid", settlement=rec["settlement"])
