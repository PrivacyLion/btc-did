# Quick Start

Get SignedByMe authentication working in 5 minutes.

---

## Prerequisites

- `client_id` from SignedByMe registration
- HTTPS endpoint for your callback URL
- Server that can make HTTP requests

---

## The Flow

```
Your Server                    SignedByMe API                 User's App
     │                              │                              │
     │ 1. Create session            │                              │
     │ ─────────────────────────▶   │                              │
     │                              │                              │
     │ 2. Session ID + deep link    │                              │
     │ ◀─────────────────────────   │                              │
     │                              │                              │
     │ 3. Display QR/link to user   │                              │
     │ ─────────────────────────────────────────────────────────▶  │
     │                              │                              │
     │                              │   4. User scans, proves,     │
     │                              │ ◀──── submits invoice        │
     │                              │                              │
     │ 5. Poll for completion       │                              │
     │ ─────────────────────────▶   │                              │
     │                              │                              │
     │ 6. Status: complete +        │                              │
     │    auth_code returned        │                              │
     │ ◀─────────────────────────   │                              │
     │                              │                              │
     │ 7. Exchange code for token   │                              │
     │ ─────────────────────────▶   │                              │
     │                              │                              │
     │ 8. ID Token (JWT)            │                              │
     │ ◀─────────────────────────   │                              │
     │                              │                              │
```

---

## Step 1: Create a Session

```bash
curl -X POST https://api.signedbyme.com/v1/enterprise/session \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your_client_id",
    "redirect_uri": "https://yourapp.com/callback",
    "amount_sats": 100,
    "memo": "Login to YourApp"
  }'
```

**Response:**

```json
{
  "session_id": "abc123...",
  "deep_link": "signedby.me://login?session=abc123&employer=YourApp&amount=100",
  "qr_data": "signedby.me://login?session=abc123&employer=YourApp&amount=100",
  "expires_at": 1704067200
}
```

---

## Step 2: Display to User

Show the QR code or deep link to your user:

```html
<!-- Option A: QR Code (use any QR library) -->
<div id="qr-code"></div>
<script>
  new QRCode(document.getElementById("qr-code"), {
    text: "signedby.me://login?session=abc123&employer=YourApp&amount=100",
    width: 256,
    height: 256
  });
</script>

<!-- Option B: Deep link button (mobile) -->
<a href="signedby.me://login?session=abc123&employer=YourApp&amount=100">
  Sign in with SignedByMe
</a>
```

---

## Step 3: Poll for Completion

```bash
curl https://api.signedbyme.com/v1/enterprise/session/abc123/status
```

**Response (pending):**

```json
{
  "session_id": "abc123",
  "status": "pending"
}
```

**Response (complete):**

```json
{
  "session_id": "abc123",
  "status": "complete",
  "auth_code": "xyz789..."
}
```

Poll every 2-3 seconds until `status` is `complete` or `expired`.

---

## Step 4: Exchange Code for Token

```bash
curl -X POST https://api.signedbyme.com/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=xyz789..." \
  -d "client_id=your_client_id" \
  -d "redirect_uri=https://yourapp.com/callback"
```

**Response:**

```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

## Step 5: Validate the Token

The `id_token` is a signed JWT. Validate it:

1. Fetch the public keys from `/.well-known/jwks.json`
2. Verify the signature (RS256)
3. Check `iss`, `aud`, `exp` claims

**Decoded token payload:**

```json
{
  "iss": "https://api.signedbyme.com",
  "aud": "your_client_id",
  "sub": "did:key:z6MkhaXgBZD...",
  "iat": 1704067200,
  "exp": 1704070800,
  "nonce": "random123",
  "amr": ["did_sig", "stwo_proof", "ln_payment"],
  "https://signedby.me/claims/payment_verified": true,
  "https://signedby.me/claims/amount_sats": 100
}
```

---

## Complete JavaScript Example

```javascript
const API_BASE = 'https://api.signedbyme.com';

async function startLogin(clientId, redirectUri) {
  // 1. Create session
  const res = await fetch(`${API_BASE}/v1/enterprise/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: clientId,
      redirect_uri: redirectUri,
      amount_sats: 100,
      memo: 'Login to MyApp'
    })
  });
  
  const session = await res.json();
  console.log('Display this QR:', session.qr_data);
  
  // 2. Poll for completion
  let status = 'pending';
  let authCode = null;
  
  while (status === 'pending') {
    await new Promise(r => setTimeout(r, 2000)); // Wait 2s
    
    const pollRes = await fetch(
      `${API_BASE}/v1/enterprise/session/${session.session_id}/status`
    );
    const pollData = await pollRes.json();
    status = pollData.status;
    
    if (status === 'complete') {
      authCode = pollData.auth_code;
    }
  }
  
  if (!authCode) {
    throw new Error('Login failed or expired');
  }
  
  // 3. Exchange code for token
  const tokenRes = await fetch(`${API_BASE}/oidc/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      client_id: clientId,
      redirect_uri: redirectUri
    })
  });
  
  const tokenData = await tokenRes.json();
  return tokenData.id_token;
}
```

---

## What's Next?

- **[Authentication Flow](./AUTHENTICATION.md)** - Understand the full sequence
- **[Membership Proofs](./MEMBERSHIP.md)** - Restrict access to specific groups
- **[API Reference](./API_REFERENCE.md)** - All endpoints and options
- **[ID Token Claims](./ID_TOKEN.md)** - Understand the JWT contents
