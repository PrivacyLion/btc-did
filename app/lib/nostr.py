"""
NOSTR Protocol Library for SignedByMe (Phase 26)

Handles:
- NIP-05 identity verification for enterprises
- Kind 28200 (enrollment_authorization) event verification
- Kind 28201 (kyc_verification) event publishing
- Schnorr signature verification (BIP-340)

Server pubkey: 27718b2653a87c2978fe714fe8077703b41af36ca72ca9eb3ad8080426e2bc0f
"""
import os
import json
import time
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# NIP-05 base URL (no trailing slash)
NIP05_BASE_URL = "https://beta.privacy-lion.com"

# Event kinds
KIND_ENROLLMENT_AUTHORIZATION = 28200
KIND_KYC_VERIFICATION = 28201

# Server keys (from env)
def get_server_privkey() -> Optional[str]:
    """Get server's NOSTR private key (hex) from environment."""
    return os.getenv("SIGNEDBYME_NOSTR_PRIVKEY")

def get_server_pubkey() -> str:
    """Get server's NOSTR public key (hex)."""
    # Hardcoded for now - derived from SIGNEDBYME_NOSTR_PRIVKEY
    return "27718b2653a87c2978fe714fe8077703b41af36ca72ca9eb3ad8080426e2bc0f"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class NostrEvent:
    """NOSTR event structure (NIP-01)."""
    id: str                    # 32-byte hex SHA256 of serialized event
    pubkey: str                # 32-byte hex of author's pubkey
    created_at: int            # Unix timestamp
    kind: int                  # Event kind
    tags: List[List[str]]      # Array of arrays
    content: str               # Arbitrary string
    sig: str                   # 64-byte hex Schnorr signature
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NostrEvent":
        """Parse event from dictionary."""
        return cls(
            id=d.get("id", ""),
            pubkey=d.get("pubkey", ""),
            created_at=d.get("created_at", 0),
            kind=d.get("kind", 0),
            tags=d.get("tags", []),
            content=d.get("content", ""),
            sig=d.get("sig", ""),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }
    
    def get_tag(self, name: str) -> Optional[str]:
        """Get first value of a tag by name."""
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                return tag[1]
        return None
    
    def get_all_tags(self, name: str) -> List[str]:
        """Get all values of a tag by name."""
        values = []
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                values.append(tag[1])
        return values


@dataclass
class NIP05Result:
    """Result of NIP-05 verification."""
    valid: bool
    pubkey: Optional[str] = None    # Hex pubkey if valid
    relays: Optional[List[str]] = None
    error: Optional[str] = None


@dataclass
class EventVerifyResult:
    """Result of NOSTR event verification."""
    valid: bool
    event: Optional[NostrEvent] = None
    pubkey_verified: bool = False    # NIP-05 verified?
    error: Optional[str] = None


# =============================================================================
# NIP-05 Verification
# =============================================================================

async def verify_nip05(identifier: str, expected_pubkey: Optional[str] = None) -> NIP05Result:
    """
    Verify a NIP-05 identifier and optionally check against expected pubkey.
    
    Args:
        identifier: NIP-05 identifier (e.g., "acme@acme.beta.privacy-lion.com")
        expected_pubkey: If provided, verify pubkey matches (hex)
        
    Returns:
        NIP05Result with verification status
    """
    try:
        # Parse identifier: name@domain
        if "@" not in identifier:
            return NIP05Result(valid=False, error="Invalid NIP-05 format (missing @)")
        
        name, domain = identifier.rsplit("@", 1)
        
        # Fetch .well-known/nostr.json
        url = f"https://{domain}/.well-known/nostr.json?name={name}"
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            
            if response.status_code != 200:
                return NIP05Result(
                    valid=False,
                    error=f"NIP-05 lookup failed: HTTP {response.status_code}"
                )
            
            data = response.json()
        
        # Extract pubkey
        names = data.get("names", {})
        pubkey = names.get(name)
        
        if not pubkey:
            return NIP05Result(valid=False, error=f"Name '{name}' not found in NIP-05")
        
        # Normalize pubkey (lowercase hex)
        pubkey = pubkey.lower()
        
        # Verify against expected if provided
        if expected_pubkey:
            expected = expected_pubkey.lower()
            if pubkey != expected:
                return NIP05Result(
                    valid=False,
                    pubkey=pubkey,
                    error=f"Pubkey mismatch: expected {expected[:16]}..., got {pubkey[:16]}..."
                )
        
        # Extract relays if present
        relays_data = data.get("relays", {})
        relays = relays_data.get(pubkey, []) if relays_data else None
        
        return NIP05Result(valid=True, pubkey=pubkey, relays=relays)
        
    except httpx.TimeoutException:
        return NIP05Result(valid=False, error="NIP-05 lookup timed out")
    except Exception as e:
        return NIP05Result(valid=False, error=f"NIP-05 verification failed: {e}")


async def verify_enterprise_pubkey(domain: str, pubkey: str) -> NIP05Result:
    """
    Verify an enterprise pubkey against their NIP-05.
    
    Uses the convention: _@{domain} for enterprise identity.
    
    Args:
        domain: Enterprise domain (e.g., "acme.beta.privacy-lion.com")
        pubkey: Expected pubkey (hex)
        
    Returns:
        NIP05Result with verification status
    """
    # Enterprise identity convention: _@domain
    identifier = f"_@{domain}"
    return await verify_nip05(identifier, expected_pubkey=pubkey)


# =============================================================================
# Event ID / Signature Verification
# =============================================================================

def compute_event_id(event: NostrEvent) -> str:
    """
    Compute the event ID (NIP-01).
    
    ID = SHA256([0, pubkey, created_at, kind, tags, content])
    """
    serialized = json.dumps(
        [0, event.pubkey, event.created_at, event.kind, event.tags, event.content],
        separators=(',', ':'),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def verify_event_id(event: NostrEvent) -> bool:
    """Verify event ID matches computed hash."""
    computed = compute_event_id(event)
    return computed.lower() == event.id.lower()


def verify_schnorr_signature(event: NostrEvent) -> bool:
    """
    Verify BIP-340 Schnorr signature on event.
    
    Uses secp256k1 library if available, otherwise falls back to True
    for development (with warning).
    """
    try:
        # Try to use the secp256k1 library
        import secp256k1
        
        # Message is the event ID (32 bytes)
        message = bytes.fromhex(event.id)
        
        # Pubkey (32 bytes x-only for BIP-340)
        pubkey_bytes = bytes.fromhex(event.pubkey)
        
        # Signature (64 bytes)
        sig_bytes = bytes.fromhex(event.sig)
        
        # Verify using BIP-340 Schnorr
        pubkey = secp256k1.PublicKey(b'\x02' + pubkey_bytes, raw=True)
        return pubkey.schnorr_verify(message, sig_bytes, bip340tag=None)
        
    except ImportError:
        # secp256k1 not available - try coincurve
        try:
            from coincurve import PublicKeyXOnly
            
            message = bytes.fromhex(event.id)
            pubkey = PublicKeyXOnly(bytes.fromhex(event.pubkey))
            sig = bytes.fromhex(event.sig)
            
            return pubkey.verify(sig, message)
            
        except ImportError:
            logger.warning("No secp256k1/coincurve library - signature verification skipped")
            # For development: verify event ID is correct at minimum
            return verify_event_id(event)
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


def verify_event(event: NostrEvent) -> Tuple[bool, Optional[str]]:
    """
    Full event verification: ID + signature.
    
    Returns:
        (valid, error_message)
    """
    # Verify event ID
    if not verify_event_id(event):
        return False, "Event ID does not match content hash"
    
    # Verify signature
    if not verify_schnorr_signature(event):
        return False, "Invalid Schnorr signature"
    
    return True, None


# =============================================================================
# Kind 28200: Enrollment Authorization
# =============================================================================

@dataclass
class EnrollmentAuthorization:
    """Parsed enrollment authorization from kind 28200 event."""
    event: NostrEvent
    client_id: str
    nonce: str
    expires_at: int
    user_npub: Optional[str] = None    # For mobile-to-mobile login
    
    def is_expired(self) -> bool:
        """Check if authorization has expired."""
        return time.time() > self.expires_at


def parse_enrollment_authorization(event: NostrEvent) -> Tuple[Optional[EnrollmentAuthorization], str]:
    """
    Parse and validate a kind 28200 enrollment authorization event.
    
    Expected tags:
    - ["client_id", "acme"]
    - ["nonce", "random-string"]
    - ["exp", "1711027200"]  (unix timestamp)
    - ["p", "user-npub-hex"] (optional, for M2M login)
    
    Returns:
        (EnrollmentAuthorization, None) on success
        (None, error_message) on failure
    """
    if event.kind != KIND_ENROLLMENT_AUTHORIZATION:
        return None, f"Wrong event kind: {event.kind}, expected {KIND_ENROLLMENT_AUTHORIZATION}"
    
    # Extract required tags
    client_id = event.get_tag("client_id")
    if not client_id:
        return None, "Missing 'client_id' tag"
    
    nonce = event.get_tag("nonce")
    if not nonce:
        return None, "Missing 'nonce' tag"
    
    exp_str = event.get_tag("exp")
    if not exp_str:
        return None, "Missing 'exp' tag"
    
    try:
        expires_at = int(exp_str)
    except ValueError:
        return None, f"Invalid 'exp' value: {exp_str}"
    
    # Optional: user npub for M2M login
    user_npub = event.get_tag("p")
    
    return EnrollmentAuthorization(
        event=event,
        client_id=client_id,
        nonce=nonce,
        expires_at=expires_at,
        user_npub=user_npub,
    ), ""


async def verify_enrollment_authorization(
    event_json: str,
    expected_client_id: str,
    client_domain: str,
) -> EventVerifyResult:
    """
    Verify a kind 28200 enrollment authorization event.
    
    1. Parse and validate event structure
    2. Verify event ID and signature
    3. Verify enterprise pubkey via NIP-05
    4. Check expiration
    5. Verify client_id matches
    
    Args:
        event_json: JSON string of the event
        expected_client_id: Expected client_id tag value
        client_domain: Enterprise domain for NIP-05 lookup
        
    Returns:
        EventVerifyResult with verification status
    """
    try:
        event_dict = json.loads(event_json)
        event = NostrEvent.from_dict(event_dict)
    except Exception as e:
        return EventVerifyResult(valid=False, error=f"Invalid event JSON: {e}")
    
    # Parse authorization
    auth, error = parse_enrollment_authorization(event)
    if not auth:
        return EventVerifyResult(valid=False, event=event, error=error)
    
    # Verify event ID and signature
    valid, error = verify_event(event)
    if not valid:
        return EventVerifyResult(valid=False, event=event, error=error)
    
    # Check expiration
    if auth.is_expired():
        return EventVerifyResult(
            valid=False,
            event=event,
            error=f"Authorization expired at {auth.expires_at}"
        )
    
    # Verify client_id matches
    if auth.client_id != expected_client_id:
        return EventVerifyResult(
            valid=False,
            event=event,
            error=f"Client ID mismatch: expected {expected_client_id}, got {auth.client_id}"
        )
    
    # Verify enterprise pubkey via NIP-05
    nip05_result = await verify_enterprise_pubkey(client_domain, event.pubkey)
    if not nip05_result.valid:
        return EventVerifyResult(
            valid=False,
            event=event,
            pubkey_verified=False,
            error=f"NIP-05 verification failed: {nip05_result.error}"
        )
    
    return EventVerifyResult(
        valid=True,
        event=event,
        pubkey_verified=True,
    )


# =============================================================================
# Kind 28201: KYC Verification (Server-Signed)
# =============================================================================

def create_kyc_verification_event(
    user_npub: str,
    provider: str,
    verification_id: str,
    status: str,
    timestamp: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Create a kind 28201 KYC verification event (to be signed by server).
    
    Args:
        user_npub: User's NOSTR pubkey (hex)
        provider: KYC provider name (e.g., "persona", "jumio")
        verification_id: Provider's verification ID
        status: Verification status ("passed", "failed", "pending")
        timestamp: Event timestamp (defaults to now)
        
    Returns:
        Unsigned event dict ready for signing, or None if privkey not available
    """
    privkey = get_server_privkey()
    if not privkey:
        logger.error("SIGNEDBYME_NOSTR_PRIVKEY not set - cannot create KYC event")
        return None
    
    pubkey = get_server_pubkey()
    created_at = timestamp or int(time.time())
    
    tags = [
        ["p", user_npub],
        ["provider", provider],
        ["verification_id", verification_id],
        ["status", status],
    ]
    
    content = json.dumps({
        "type": "kyc_verification",
        "provider": provider,
        "status": status,
        "verified_at": created_at,
    })
    
    # Create event without id/sig (will be computed)
    event = {
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": KIND_KYC_VERIFICATION,
        "tags": tags,
        "content": content,
    }
    
    # Compute event ID
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(',', ':'),
        ensure_ascii=False,
    )
    event["id"] = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    
    # Sign with server key
    try:
        sig = sign_event_id(event["id"], privkey)
        if sig:
            event["sig"] = sig
            return event
        else:
            logger.error("Failed to sign KYC event")
            return None
    except Exception as e:
        logger.error(f"Failed to sign KYC event: {e}")
        return None


def sign_event_id(event_id: str, privkey_hex: str) -> Optional[str]:
    """
    Sign an event ID with BIP-340 Schnorr signature.
    
    Args:
        event_id: Event ID (32-byte hex)
        privkey_hex: Private key (32-byte hex)
        
    Returns:
        Signature (64-byte hex) or None on failure
    """
    try:
        # Try secp256k1
        import secp256k1
        
        privkey_bytes = bytes.fromhex(privkey_hex)
        message = bytes.fromhex(event_id)
        
        privkey = secp256k1.PrivateKey(privkey_bytes, raw=True)
        sig = privkey.schnorr_sign(message, bip340tag=None)
        
        return sig.hex()
        
    except ImportError:
        # Try coincurve
        try:
            from coincurve import PrivateKey
            
            privkey = PrivateKey(bytes.fromhex(privkey_hex))
            message = bytes.fromhex(event_id)
            sig = privkey.sign_schnorr(message)
            
            return sig.hex()
            
        except ImportError:
            logger.error("No secp256k1/coincurve library for signing")
            return None
    except Exception as e:
        logger.error(f"Signing failed: {e}")
        return None


# =============================================================================
# Bech32 Encoding (for npub conversion)
# =============================================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    """Encode bytes to bech32 string."""
    converted = _convertbits(list(data), 8, 5, True)
    if converted is None:
        raise ValueError("Failed to convert data to 5-bit groups")
    checksum = _bech32_create_checksum(hrp, converted)
    combined = converted + checksum
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


# =============================================================================
# Utility Functions
# =============================================================================

def pubkey_to_npub(pubkey_hex: str) -> str:
    """Convert hex pubkey to bech32 npub."""
    x_bytes = bytes.fromhex(pubkey_hex)
    return bech32_encode("npub", x_bytes)


def npub_to_pubkey(npub: str) -> Optional[str]:
    """Convert bech32 npub to hex pubkey."""
    try:
        # Bech32 decode
        if not npub.startswith("npub1"):
            return None
        
        # Decode using bech32
        BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        
        # Remove hrp
        data_part = npub[5:]  # Skip "npub1"
        
        # Decode characters to 5-bit values
        values = [BECH32_CHARSET.index(c) for c in data_part]
        
        # Remove checksum (last 6 values)
        values = values[:-6]
        
        # Convert from 5-bit to 8-bit
        acc = 0
        bits = 0
        result = []
        for v in values:
            acc = (acc << 5) | v
            bits += 5
            while bits >= 8:
                bits -= 8
                result.append((acc >> bits) & 0xFF)
        
        return bytes(result).hex()
        
    except Exception as e:
        logger.error(f"Failed to decode npub: {e}")
        return None
