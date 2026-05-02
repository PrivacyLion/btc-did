# API Reference

Complete reference for all SignedByMe API endpoints.

**Base URL:** `https://api.signedbyme.com`

---

## Authentication

Most endpoints require authentication via API key header:

```
X-API-Key: your_api_key
```

Public endpoints (OIDC discovery, JWKS) do not require authentication.

---

## Session Management

### Create Session

Create a new login session for a user.

```
POST /v1/enterprise/session
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | Your registered client ID |
| `redirect_uri` | string | Yes | Callback URL (must be pre-registered) |
| `amount_sats` | integer | No | Payment amount (default: from client config) |
| `memo` | string | No | Description shown to user |
| `state` | string | No | Opaque value returned in callback |
| `nonce` | string | No | For replay protection |

**Example Request:**

```bash
curl -X POST https://api.signedbyme.com/v1/enterprise/session \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "client_id": "acme",
    "redirect_uri": "https://acme.com/callback",
    "amount_sats": 100,
    "memo": "Login to Acme Corp"
  }'
```

**Response:**

```json
{
  "session_id": "sess_abc123def456",
  "deep_link": "signedby.me://login?session=sess_abc123def456&employer=Acme&amount=100",
  "qr_data": "signedby.me://login?session=sess_abc123def456&employer=Acme&amount=100",
  "expires_at": 1704067200,
  "status": "pending"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| 400 | Invalid request body |
| 401 | Invalid or missing API key |
| 403 | redirect_uri not allowed for client |

---

### Get Session Status

Check the status of a login session.

```
GET /v1/enterprise/session/{session_id}/status
```

**Path Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | The session ID from create |

**Example Request:**

```bash
curl https://api.signedbyme.com/v1/enterprise/session/sess_abc123/status \
  -H "X-API-Key: your_api_key"
```

**Response (pending):**

```json
{
  "session_id": "sess_abc123",
  "status": "pending",
  "expires_at": 1704067200
}
```

**Response (complete):**

```json
{
  "session_id": "sess_abc123",
  "status": "complete",
  "auth_code": "code_xyz789...",
  "did": "did:key:z6MkhaXgBZD..."
}
```

**Status Values:**

| Status | Description |
|--------|-------------|
| `pending` | Waiting for user |
| `proof_submitted` | User submitted proof, awaiting payment |
| `payment_confirmed` | Payment received |
| `complete` | Ready to exchange for token |
| `expired` | Session timed out |
| `failed` | Verification failed |

---

### Confirm Payment (Option B)

For enterprises that pay users directly, confirm the payment.

```
POST /v1/confirm-payment
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | string | Yes | The session ID |
| `preimage` | string | Yes | Lightning payment preimage (hex) |

**Example Request:**

```bash
curl -X POST https://api.signedbyme.com/v1/confirm-payment \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "session_id": "sess_abc123",
    "preimage": "0123456789abcdef..."
  }'
```

**Response:**

```json
{
  "session_id": "sess_abc123",
  "status": "complete",
  "auth_code": "code_xyz789..."
}
```

---

## OIDC Endpoints

Standard OpenID Connect endpoints for token exchange and discovery.

### OIDC Discovery

```
GET /.well-known/openid-configuration
```

**Response:**

```json
{
  "issuer": "https://api.signedbyme.com",
  "authorization_endpoint": "https://api.signedbyme.com/oidc/authorize",
  "token_endpoint": "https://api.signedbyme.com/oidc/token",
  "userinfo_endpoint": "https://api.signedbyme.com/oidc/userinfo",
  "jwks_uri": "https://api.signedbyme.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce", "amr"]
}
```

---

### JWKS (Public Keys)

Fetch public keys for JWT validation.

```
GET /.well-known/jwks.json
```

**Response:**

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

---

### Token Exchange

Exchange an authorization code for an ID token.

```
POST /oidc/token
Content-Type: application/x-www-form-urlencoded
```

**Form Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `authorization_code` |
| `code` | string | Yes | The auth_code from session |
| `client_id` | string | Yes | Your client ID |
| `redirect_uri` | string | Yes | Must match session creation |
| `code_verifier` | string | PKCE | If using PKCE |

**Example Request:**

```bash
curl -X POST https://api.signedbyme.com/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=code_xyz789..." \
  -d "client_id=acme" \
  -d "redirect_uri=https://acme.com/callback"
```

**Response:**

```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Errors:**

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_grant` | Code expired or already used |
| 400 | `invalid_request` | Missing required parameter |
| 400 | `invalid_client` | client_id mismatch |

---

### User Info

Get information about the authenticated user.

```
GET /oidc/userinfo
Authorization: Bearer {id_token}
```

**Response:**

```json
{
  "sub": "did:key:z6MkhaXgBZD...",
  "amr": ["did_sig", "stwo_proof", "ln_payment"]
}
```

---

## Membership / Roots

Endpoints for managing Merkle roots and membership proofs.

### Get Current Root

Get the active Merkle root for a client.

```
GET /v1/roots/current?client_id={client_id}
```

**Query Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | The client ID |
| `purpose_id` | string | No | Filter by purpose |

**Response:**

```json
{
  "root_id": "acme-employees-2024-01",
  "root_hash": "abc123...",
  "purpose_id": "employees",
  "created_at": 1704067200,
  "leaf_count": 150
}
```

---

### Publish Root

Publish a new Merkle root.

```
POST /v1/roots/publish
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `root_id` | string | Yes | Unique identifier for this root |
| `root_hash` | string | Yes | The Merkle root hash (hex) |
| `purpose_id` | string | Yes | Purpose identifier (e.g., "employees") |
| `metadata` | object | No | Optional metadata |

**Example Request:**

```bash
curl -X POST https://api.signedbyme.com/v1/roots/publish \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "root_id": "acme-employees-2024-02",
    "root_hash": "def456...",
    "purpose_id": "employees"
  }'
```

**Response:**

```json
{
  "root_id": "acme-employees-2024-02",
  "status": "active",
  "published_at": 1704153600
}
```

---

### Enroll Member

Add a user to a membership tree (auto-enrollment).

```
POST /v1/membership/enroll
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | The client ID |
| `purpose_id` | string | Yes | Purpose identifier |
| `leaf_commitment` | string | Yes | User's leaf commitment (hex) |

**Example Request:**

```bash
curl -X POST https://api.signedbyme.com/v1/membership/enroll \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "client_id": "acme",
    "purpose_id": "employees",
    "leaf_commitment": "789abc..."
  }'
```

**Response:**

```json
{
  "enrolled": true,
  "leaf_index": 150,
  "pending_root_rebuild": true
}
```

---

### Get Membership Witness

Fetch a Merkle proof for a user.

```
GET /v1/membership/witness
```

**Query Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | The client ID |
| `purpose_id` | string | Yes | Purpose identifier |
| `leaf_commitment` | string | Yes | User's leaf commitment (hex) |

**Response:**

```json
{
  "root_id": "acme-employees-2024-02",
  "root_hash": "def456...",
  "leaf_index": 42,
  "siblings": ["aaa...", "bbb...", "ccc..."],
  "path_indices": [0, 1, 0, 1]
}
```

---

## Health Check

### API Health

```
GET /healthz
```

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable description"
}
```

**Common Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `invalid_client` | 401 | Unknown client_id |
| `unauthorized` | 401 | Missing or invalid API key |
| `forbidden` | 403 | Operation not allowed |
| `not_found` | 404 | Resource doesn't exist |
| `expired` | 410 | Session or code expired |
| `rate_limited` | 429 | Too many requests |
| `server_error` | 500 | Internal error |

---

## Rate Limits

- **Default:** 100 requests per minute per IP
- **Authenticated:** 1000 requests per minute per client

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067260
```

When rate limited, you'll receive:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 30
```
