from pydantic import BaseModel
from typing import Optional
from .common import PayTerms, PRP, DIDSignature, ZKProof, SettlementRefs

class LoginStartRequest(BaseModel):
    domain: str

class LoginStartResponse(BaseModel):
    login_id: str
    nonce: str
    pay_terms: PayTerms

class LoginCompleteRequest(BaseModel):
    """Legacy model - login completion now happens via /v1/login/verify (stateless)."""
    login_id: str
    did_sig: DIDSignature
    zk_proof: Optional[ZKProof] = None
    # DLC field DELETED - server has ZERO DLC awareness (Phase 11 compliance)

class LoginPRPResponse(BaseModel):
    prp: PRP

class LoginStatusResponse(BaseModel):
    login_id: str
    status: str  # pending|paid|expired
    settlement: Optional[SettlementRefs] = None
