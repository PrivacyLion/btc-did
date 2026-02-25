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

class DLCMetadata(BaseModel):
    outcome: str = "auth_verified"
    split: List[float] = [0.9, 0.1]
    contract: Optional[str] = None
    oracle_pubkey: Optional[str] = None

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
