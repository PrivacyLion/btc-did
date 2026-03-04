"""
Groth16 Proof Verification (Phase 8 - Step 8.2)

Thin wrapper around the Rust verifier binary (Phase 23).
Accepts proof bytes + public outputs, returns valid/invalid.
"""
import hashlib
from dataclasses import dataclass
from typing import Optional

from .groth16_verify import (
    verify_proof as _verify_proof,
    npub_to_bech32,
    has_verifier,
    has_vk,
    VerifyResult,
)


@dataclass
class VerificationResult:
    """Result of Groth16 proof verification."""
    valid: bool
    merkle_root: Optional[str] = None
    npub_bech32: Optional[str] = None
    npub_compressed: Optional[str] = None
    verify_time_ms: Optional[float] = None
    error: Optional[str] = None


def verify_groth16_proof(proof_json: str, public_json: str) -> VerificationResult:
    """
    Verify a Groth16 proof using the Rust verifier.
    
    Args:
        proof_json: JSON string containing the snarkjs proof
        public_json: JSON string containing the 9 public outputs
        
    Returns:
        VerificationResult with verification status and extracted npub (bech32)
    """
    if not has_verifier():
        return VerificationResult(valid=False, error="Verifier binary not found")
    
    if not has_vk():
        return VerificationResult(valid=False, error="Verification key not found")
    
    result = _verify_proof(proof_json, public_json)
    
    if not result.valid:
        return VerificationResult(valid=False, error=result.error)
    
    # Convert npub to bech32
    npub_bech32 = None
    if result.npub_compressed:
        try:
            npub_bech32 = npub_to_bech32(result.npub_compressed)
        except Exception as e:
            return VerificationResult(valid=False, error=f"Failed to encode npub: {e}")
    
    return VerificationResult(
        valid=True,
        merkle_root=result.merkle_root,
        npub_bech32=npub_bech32,
        npub_compressed=result.npub_compressed,
        verify_time_ms=result.verify_time_ms,
    )


def verify_preimage(preimage_hex: str, payment_hash_hex: str) -> bool:
    """
    Verify that SHA256(preimage) == payment_hash.
    
    Args:
        preimage_hex: 32-byte preimage as 64 hex chars
        payment_hash_hex: 32-byte payment hash as 64 hex chars
        
    Returns:
        True if preimage matches payment_hash
    """
    try:
        preimage_bytes = bytes.fromhex(preimage_hex)
        expected_hash = bytes.fromhex(payment_hash_hex)
        computed_hash = hashlib.sha256(preimage_bytes).digest()
        return computed_hash == expected_hash
    except Exception:
        return False


def is_verifier_ready() -> tuple[bool, str]:
    """
    Check if the Groth16 verifier is ready.
    
    Returns:
        (ready, message)
    """
    if not has_verifier():
        return False, "Rust verifier binary not found"
    if not has_vk():
        return False, "Verification key not found"
    return True, "Verifier ready"
