# ID Token Reference

Complete guide to the SignedByMe ID token (JWT) structure and validation.

---

## Overview

The ID token is a signed JWT (JSON Web Token) containing:
- User's identity (DID)
- Authentication methods used
- Payment verification
- Optional membership claims

**Format:** `header.payload.signature` (base64url encoded, RS256 signed)

---

## Token Structure

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-1"
}
```

| Field | Description |
|-------|-------------|
| `alg` | Signing algorithm (always RS256) |
| `typ` | Token type (always JWT) |
| `kid` | Key ID for signature verification |

### Payload (Claims)

```json
{
  "iss": "https://api.signedbyme.com",
  "sub": "did:key:z6MkhaXgBZDvotDUGZjQ8WCNfD8GmYzGdL6aLNsqRCj3KSEy",
  "aud": "acme",
  "iat": 1704067200,
  "exp": 1704070800,
  "nonce": "abc123xyz",
  "sid": "sess_def456",
  "amr": ["did_sig", "stwo_proof", "ln_payment"],
  
  "https://signedby.me/claims/attestation_hash": "a1b2c3...",
  "https://signedby.me/claims/payment_verified": true,
  "https://signedby.me/claims/payment_hash": "d4e5f6...",
  "https://signedby.me/claims/amount_sats": 100,
  "https://signedby.me/claims/membership_verified": false
}
```

---

## Standard OIDC Claims

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string | Issuer URL (always `https://api.signedbyme.com`) |
| `sub` | string | Subject - the user's DID |
| `aud` | string | Audience - your client_id |
| `iat` | number | Issued at (Unix timestamp) |
| `exp` | number | Expiration (Unix timestamp) |
| `nonce` | string | Replay protection nonce |
| `sid` | string | Session ID |
| `amr` | array | Authentication Methods Reference |

---

## Authentication Methods (amr)

The `amr` claim lists all authentication methods used:

| Value | Meaning |
|-------|---------|
| `did_sig` | User signed with their DID private key |
| `stwo_proof` | STWO zero-knowledge proof verified |
| `ln_payment` | Lightning payment confirmed |
| `merkle` | Merkle membership proof verified |

**Example interpretations:**

```json
// Basic login (no membership)
"amr": ["did_sig", "stwo_proof", "ln_payment"]

// With membership verification
"amr": ["did_sig", "stwo_proof", "ln_payment", "merkle"]
```

---

## SignedByMe-Specific Claims

All custom claims are namespaced under `https://signedby.me/claims/`:

### Payment Claims

| Claim | Type | Description |
|-------|------|-------------|
| `payment_verified` | boolean | Payment was confirmed |
| `payment_hash` | string | Lightning payment hash (hex) |
| `amount_sats` | number | Amount paid in satoshis |

### Identity Claims

| Claim | Type | Description |
|-------|------|-------------|
| `attestation_hash` | string | Hash of the full attestation record |

### Membership Claims

| Claim | Type | Description |
|-------|------|-------------|
| `membership_verified` | boolean | Membership proof was verified |
| `membership_purpose` | string | Purpose ID of the verified tree |
| `membership_root_id` | string | Root ID that was verified against |

---

## Example Tokens

### Basic Login

```json
{
  "iss": "https://api.signedbyme.com",
  "sub": "did:key:z6MkhaXgBZDvotDUGZjQ8WCNfD8GmYzGdL6aLNsqRCj3KSEy",
  "aud": "acme",
  "iat": 1704067200,
  "exp": 1704070800,
  "nonce": "random123",
  "sid": "sess_abc123",
  "amr": ["did_sig", "stwo_proof", "ln_payment"],
  
  "https://signedby.me/claims/payment_verified": true,
  "https://signedby.me/claims/amount_sats": 100,
  "https://signedby.me/claims/membership_verified": false
}
```

### With Membership

```json
{
  "iss": "https://api.signedbyme.com",
  "sub": "did:key:z6MkhaXgBZDvotDUGZjQ8WCNfD8GmYzGdL6aLNsqRCj3KSEy",
  "aud": "acme",
  "iat": 1704067200,
  "exp": 1704070800,
  "nonce": "random456",
  "sid": "sess_def456",
  "amr": ["did_sig", "stwo_proof", "ln_payment", "merkle"],
  
  "https://signedby.me/claims/payment_verified": true,
  "https://signedby.me/claims/amount_sats": 100,
  "https://signedby.me/claims/membership_verified": true,
  "https://signedby.me/claims/membership_purpose": "employees",
  "https://signedby.me/claims/membership_root_id": "acme-employees-2024-02"
}
```

---

## Validating the Token

### 1. Fetch Public Keys

```bash
curl https://api.signedbyme.com/.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGc...",
      "e": "AQAB"
    }
  ]
}
```

### 2. Verify Signature

Match the `kid` from the token header to the key in JWKS, then verify RS256 signature.

### 3. Validate Claims

```python
def validate_id_token(token, expected_client_id, expected_nonce=None):
    # Decode (after signature verification)
    claims = decode_jwt(token)
    
    # Required checks
    assert claims["iss"] == "https://api.signedbyme.com"
    assert claims["aud"] == expected_client_id
    assert claims["exp"] > time.time()  # Not expired
    assert claims["iat"] <= time.time() + 60  # Not from future (60s skew)
    
    # Optional nonce check
    if expected_nonce:
        assert claims["nonce"] == expected_nonce
    
    return claims
```

---

## Code Examples

### JavaScript (Node.js)

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://api.signedbyme.com/.well-known/jwks.json'
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(err, key?.getPublicKey());
  });
}

function verifyToken(token, clientId) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      algorithms: ['RS256'],
      issuer: 'https://api.signedbyme.com',
      audience: clientId
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}

// Usage
const claims = await verifyToken(idToken, 'acme');
console.log('User DID:', claims.sub);
console.log('Payment verified:', claims['https://signedby.me/claims/payment_verified']);
```

### Python

```python
import jwt
import requests
from jwt import PyJWKClient

JWKS_URL = "https://api.signedbyme.com/.well-known/jwks.json"
ISSUER = "https://api.signedbyme.com"

jwks_client = PyJWKClient(JWKS_URL)

def verify_token(token: str, client_id: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=ISSUER
    )
    
    return claims

# Usage
claims = verify_token(id_token, "acme")
print(f"User DID: {claims['sub']}")
print(f"Payment: {claims['https://signedby.me/claims/amount_sats']} sats")

if claims.get("https://signedby.me/claims/membership_verified"):
    print(f"Member of: {claims['https://signedby.me/claims/membership_purpose']}")
```

### Go

```go
package main

import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/MicahParks/keyfunc/v2"
)

func verifyToken(tokenString, clientID string) (*jwt.Token, error) {
    jwksURL := "https://api.signedbyme.com/.well-known/jwks.json"
    jwks, _ := keyfunc.Get(jwksURL, keyfunc.Options{})
    
    token, err := jwt.Parse(tokenString, jwks.Keyfunc,
        jwt.WithIssuer("https://api.signedbyme.com"),
        jwt.WithAudience(clientID),
    )
    
    return token, err
}
```

---

## Extracting the DID

The `sub` claim contains the user's DID (Decentralized Identifier):

```
did:key:z6MkhaXgBZDvotDUGZjQ8WCNfD8GmYzGdL6aLNsqRCj3KSEy
```

**Format:** `did:key:{multibase-encoded-public-key}`

This is a self-sovereign identifier. The user controls the private key; no central authority can revoke it.

**Using the DID:**
- Use as unique user ID in your database
- Verify signatures from this user in the future
- Look up associated data in DID documents (if published)

---

## Security Notes

### Token Lifetime
- Tokens expire in 1 hour (`exp` claim)
- Do not cache tokens beyond expiration
- Re-authenticate for sensitive operations

### Key Rotation
- Keys may rotate periodically
- Always fetch JWKS dynamically (cache with TTL)
- Use the `kid` header to select the correct key

### Clock Skew
- Allow 60 seconds of clock skew when validating `iat` and `exp`
- This handles minor time differences between servers
