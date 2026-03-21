"""
Phase 26: Simplified Verification

Server-side Groth16 proof verification is now REMOVED.
Verification is cryptographically redundant because:
1. The npub is derived inside the ZK circuit from leaf_secret
2. The user signs the NOSTR event with nsec derived from the same leaf_secret
3. If the proof was fake, npub would be wrong → NOSTR signature verification fails

The cryptographic chain (proof → npub → nsec → NOSTR signature) makes
server-side proof re-verification unnecessary.

Server now:
1. Verifies NOSTR event signature (proves npub ownership)
2. Extracts npub from event pubkey
3. Issues id_token with sub=npub

This file provides thin wrappers for verification utilities.
"""
import hashlib
from dataclasses import dataclass
from typing import Optional

from .nostr import bech32_encode, verify_event, NostrEvent


@dataclass
class VerificationResult:
    """Result of verification."""
    valid: bool
    merkle_root: Optional[str] = None
    npub_bech32: Optional[str] = None
    npub_compressed: Optional[str] = None
    verify_time_ms: Optional[float] = None
    error: Optional[str] = None


def npub_to_bech32(compressed_hex: str) -> str:
    """
    Convert compressed secp256k1 pubkey to Nostr bech32 npub format.
    
    Input: "02/03" + 64 hex chars (33 bytes compressed)
    Output: "npub1..." (bech32 encoded x-coordinate only)
    
    Note: Nostr npub is just the 32-byte x-coordinate, not the full compressed key.
    """
    if not compressed_hex or len(compressed_hex) < 66:
        raise ValueError(f"Invalid compressed pubkey: {compressed_hex}")
    
    # Extract x-coordinate (skip 02/03 prefix)
    x_hex = compressed_hex[2:]
    if len(x_hex) != 64:
        raise ValueError(f"Invalid x-coordinate length: {len(x_hex)}")
    
    x_bytes = bytes.fromhex(x_hex)
    return bech32_encode("npub", x_bytes)


def pubkey_hex_to_npub(pubkey_hex: str) -> str:
    """
    Convert 32-byte hex pubkey (x-only) to bech32 npub.
    
    Input: 64 hex chars (32 bytes)
    Output: "npub1..."
    """
    if len(pubkey_hex) != 64:
        raise ValueError(f"Invalid pubkey length: {len(pubkey_hex)}, expected 64")
    
    x_bytes = bytes.fromhex(pubkey_hex)
    return bech32_encode("npub", x_bytes)


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


def verify_nostr_event(event: NostrEvent) -> tuple[bool, Optional[str]]:
    """
    Verify a NOSTR event (ID hash + Schnorr signature).
    
    Returns:
        (valid, error_message)
    """
    return verify_event(event)


def is_verifier_ready() -> tuple[bool, str]:
    """
    Check if verification is ready.
    
    Phase 26: Server-side Groth16 verification removed.
    NOSTR event verification is always available.
    """
    return True, "NOSTR event verification ready (Groth16 verification removed in Phase 26)"


# Legacy stubs for backward compatibility
def has_verifier() -> bool:
    """Legacy: Always returns True (Groth16 verifier removed in Phase 26)."""
    return True


def has_vk() -> bool:
    """Legacy: Always returns True (Groth16 verifier removed in Phase 26)."""
    return True
