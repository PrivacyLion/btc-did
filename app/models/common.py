from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class PayTerms(BaseModel):
    amount_sats: int = Field(ge=1)
    description: str
    expires: int  # unix ts

class PRP(BaseModel):
    prp_id: str
    kind: str  # 'login' or 'unlock'
    payload: Dict[str, Any]
    expires: int

# DLCMetadata DELETED - Phase 11 compliance
# Server has ZERO knowledge of DLCs (Bible Section 7.4)
# DLC logic lives entirely on mobile (native/signedby_core/src/dlc_*.rs)

class ZKProof(BaseModel):
    system: str = "groth16"
    proof: str
    proof_hash: Optional[str] = None
    circuit: Optional[str] = None

class DIDSignature(BaseModel):
    did: str
    pubkey_hex: str
    message: str
    signature_hex: str

class SettlementRefs(BaseModel):
    preimage: Optional[str] = None
    txid: Optional[str] = None
    settled_at: Optional[int] = None
