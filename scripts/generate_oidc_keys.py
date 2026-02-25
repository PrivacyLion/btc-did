#!/usr/bin/env python3
"""
Generate OIDC signing keys for SignedByMe.

Creates:
- keys/oidc_rs256.pem - RSA private key for signing JWTs
- keys/jwks.json - Public JWKS for verification

Run once during deployment setup.
"""

import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_keys():
    """Generate RSA key pair for OIDC JWT signing."""
    
    # Create keys directory
    keys_dir = Path(__file__).resolve().parents[1] / "keys"
    keys_dir.mkdir(exist_ok=True)
    
    # Generate RSA key (2048 bits for RS256)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save private key (PEM format)
    pem_path = keys_dir / "oidc_rs256.pem"
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_path.write_bytes(pem_data)
    print(f"✓ Private key saved: {pem_path}")
    
    # Extract public key components for JWKS
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # Convert to bytes (big-endian, minimal length)
    n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
    
    # Generate key ID from public key hash
    kid = hashlib.sha256(n_bytes).hexdigest()[:16]
    
    # Build JWKS
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": b64url(n_bytes),
                "e": b64url(e_bytes),
            }
        ]
    }
    
    # Save JWKS
    jwks_path = keys_dir / "jwks.json"
    jwks_path.write_text(json.dumps(jwks, indent=2))
    print(f"✓ JWKS saved: {jwks_path}")
    
    print(f"\nKey ID (kid): {kid}")
    print(f"Generated: {datetime.utcnow().isoformat()}Z")
    print("\n⚠️  Keep oidc_rs256.pem SECRET! Never commit to git.")


if __name__ == "__main__":
    generate_keys()
