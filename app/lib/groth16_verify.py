"""
Groth16 proof verification using the Rust verifier binary.

Calls: server/groth16-verifier/target/release/verify
"""
import subprocess
import json
import os
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

# Paths
VERIFIER_PATH = Path(__file__).resolve().parents[2] / "server" / "groth16-verifier" / "target" / "release" / "verify"
VK_PATH = Path(__file__).resolve().parents[2] / "circuits" / "build" / "verification_key_final.json"


@dataclass
class VerifyResult:
    """Result of Groth16 proof verification"""
    valid: bool
    merkle_root: Optional[str] = None
    npub_x_hex: Optional[str] = None
    npub_y_hex: Optional[str] = None
    npub_compressed: Optional[str] = None
    verify_time_ms: Optional[float] = None
    error: Optional[str] = None


def has_verifier() -> bool:
    """Check if the Groth16 verifier binary exists"""
    return VERIFIER_PATH.exists() and os.access(VERIFIER_PATH, os.X_OK)


def has_vk() -> bool:
    """Check if the verification key exists"""
    return VK_PATH.exists()


def verify_proof(proof_json: str, public_json: str) -> VerifyResult:
    """
    Verify a Groth16 proof using the Rust verifier.
    
    Args:
        proof_json: JSON string containing the snarkjs proof
        public_json: JSON string containing the 9 public outputs
        
    Returns:
        VerifyResult with verification status and extracted npub
    """
    if not has_verifier():
        return VerifyResult(valid=False, error=f"Verifier not found at {VERIFIER_PATH}")
    
    if not has_vk():
        return VerifyResult(valid=False, error=f"Verification key not found at {VK_PATH}")
    
    # Write proof and public to temp files (verifier expects file paths)
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as proof_file:
            proof_file.write(proof_json)
            proof_path = proof_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as public_file:
            public_file.write(public_json)
            public_path = public_file.name
        
        # Call verifier
        result = subprocess.run(
            [str(VERIFIER_PATH), str(VK_PATH), proof_path, public_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        # Parse output
        if result.returncode == 0:
            # Parse the output to extract npub info
            lines = result.stdout.strip().split('\n')
            
            merkle_root = None
            npub_x = None
            npub_y = None
            npub_compressed = None
            verify_time_ms = None
            
            for line in lines:
                if 'merkle_root:' in line:
                    merkle_root = line.split(':', 1)[1].strip()
                elif 'npub_x:' in line:
                    npub_x = line.split(':', 1)[1].strip()
                elif 'npub_y:' in line:
                    npub_y = line.split(':', 1)[1].strip()
                elif 'npub (compressed):' in line:
                    npub_compressed = line.split(':', 1)[1].strip()
                elif 'Verify:' in line:
                    # Parse verify time (e.g., "1.576354ms")
                    time_str = line.split(':', 1)[1].strip()
                    if 'ms' in time_str:
                        verify_time_ms = float(time_str.replace('ms', ''))
                    elif 'µs' in time_str or 'us' in time_str:
                        verify_time_ms = float(time_str.replace('µs', '').replace('us', '')) / 1000
            
            return VerifyResult(
                valid=True,
                merkle_root=merkle_root,
                npub_x_hex=npub_x,
                npub_y_hex=npub_y,
                npub_compressed=npub_compressed,
                verify_time_ms=verify_time_ms,
            )
        else:
            return VerifyResult(valid=False, error=result.stderr or result.stdout)
            
    except subprocess.TimeoutExpired:
        return VerifyResult(valid=False, error="Verification timed out")
    except Exception as e:
        return VerifyResult(valid=False, error=str(e))
    finally:
        # Clean up temp files
        try:
            os.unlink(proof_path)
            os.unlink(public_path)
        except:
            pass


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
    
    # Bech32 encode
    return bech32_encode("npub", x_bytes)


# Bech32 implementation (Nostr uses bech32, not bech32m)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
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
    # Convert 8-bit bytes to 5-bit groups
    converted = convertbits(list(data), 8, 5, True)
    if converted is None:
        raise ValueError("Failed to convert data to 5-bit groups")
    
    # Compute checksum
    checksum = bech32_create_checksum(hrp, converted)
    
    # Encode
    combined = converted + checksum
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


# Self-test
if __name__ == "__main__":
    # Test bech32 encoding with known value
    test_x = bytes.fromhex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
    npub = bech32_encode("npub", test_x)
    print(f"Test npub: {npub}")
    # Expected: npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6
