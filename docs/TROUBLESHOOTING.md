# Troubleshooting

Common issues and how to fix them.

---

## Session Issues

### "Invalid redirect_uri for client"

**Cause:** The `redirect_uri` you're using isn't registered for your client.

**Fix:**
1. Check your client configuration with SignedByMe
2. Ensure the redirect_uri matches EXACTLY (including trailing slashes)
3. Only HTTPS URIs are allowed

```bash
# Wrong
redirect_uri=http://acme.com/callback    # HTTP not allowed
redirect_uri=https://acme.com/callback/  # Trailing slash mismatch

# Right
redirect_uri=https://acme.com/callback
```

---

### "Session expired"

**Cause:** Sessions expire after 10 minutes by default.

**Fix:**
- Create a new session
- Start polling immediately after showing QR
- Consider increasing timeout in client config if needed

---

### "Session not found"

**Cause:** Invalid session_id or session was already completed/expired.

**Fix:**
- Verify the session_id is correct
- Sessions are single-use; don't reuse completed sessions
- Create a fresh session for each login attempt

---

## Token Issues

### "Invalid or expired code"

**Cause:** Auth codes are single-use and expire in 5 minutes.

**Fix:**
- Exchange the code immediately after receiving it
- Don't retry with the same code
- Create a new session if needed

---

### "PKCE verification failed"

**Cause:** The `code_verifier` doesn't match the `code_challenge`.

**Fix:**
```javascript
// 1. Generate verifier (before session creation)
const verifier = generateRandomString(64);

// 2. Create challenge
const challenge = base64url(sha256(verifier));

// 3. Include challenge in session creation
{ code_challenge: challenge, code_challenge_method: 'S256' }

// 4. Include SAME verifier in token exchange
{ code_verifier: verifier }
```

---

### "Invalid token signature"

**Cause:** Token wasn't signed by SignedByMe, or using wrong key.

**Fix:**
1. Fetch fresh JWKS from `/.well-known/jwks.json`
2. Use the `kid` from token header to select the right key
3. Ensure you're verifying RS256 (not HS256)

```python
# Wrong - using a static secret
jwt.decode(token, "some-secret", algorithms=["HS256"])

# Right - using JWKS
signing_key = jwks_client.get_signing_key_from_jwt(token)
jwt.decode(token, signing_key.key, algorithms=["RS256"])
```

---

### "Token expired"

**Cause:** The `exp` claim is in the past.

**Fix:**
- Tokens expire in 1 hour
- Request a new login for expired tokens
- Don't cache tokens beyond their expiration

---

### "Issuer mismatch"

**Cause:** Token `iss` claim doesn't match expected issuer.

**Fix:**
```python
# Expected issuer
ISSUER = "https://api.beta.privacy-lion.com"

# Verify against correct issuer
jwt.decode(token, key, issuer=ISSUER, ...)
```

---

## Membership Issues

### "Membership required but not provided"

**Cause:** Your client has `require_membership: true` but user isn't in any tree.

**Fix:**
1. Ensure user is enrolled: `POST /v1/membership/enroll`
2. Ensure root is published: `POST /v1/roots/publish`
3. User's app needs to fetch witness before login

---

### "Membership proof invalid"

**Cause:** Merkle proof doesn't verify against the current root.

**Possible causes:**
- User was removed from tree (new root published without them)
- User's witness is stale (fetched before root update)
- Wrong purpose_id

**Fix:**
1. User should fetch fresh witness: `GET /v1/membership/witness`
2. Check if user is still in current tree
3. Re-enroll if needed

---

### "Purpose not allowed for client"

**Cause:** User proved membership in a tree, but that purpose isn't in your `allowed_purposes`.

**Fix:**
```json
// Your client config
{
  "allowed_purposes": ["employees"]  // Only accepts "employees" tree
}

// User proved membership in "contractors" - rejected
```

Update your client config to allow the purpose, or enroll user in an allowed tree.

---

### "Root not found"

**Cause:** The root_id in the membership proof doesn't exist or isn't active.

**Fix:**
1. Publish your root: `POST /v1/roots/publish`
2. Ensure root_id is correct
3. Check root wasn't deleted

---

## Rate Limiting

### "429 Too Many Requests"

**Cause:** You've exceeded the rate limit.

**Limits:**
- 100 requests/minute per IP (unauthenticated)
- 1000 requests/minute per client (authenticated)

**Fix:**
- Implement exponential backoff
- Check `Retry-After` header
- Cache responses where possible
- Use webhooks instead of polling if available

```python
import time

def api_call_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url)
        
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 30))
            time.sleep(retry_after)
            continue
        
        return response
    
    raise Exception("Rate limited after retries")
```

---

## Connection Issues

### "Connection refused" / "Connection timed out"

**Cause:** Network issue or API is down.

**Fix:**
1. Check API status: `curl https://api.beta.privacy-lion.com/healthz`
2. Verify your network can reach the API
3. Check firewall rules

---

### SSL/TLS Errors

**Cause:** Certificate validation issue.

**Fix:**
- Ensure your system's CA certificates are up to date
- Don't disable certificate verification in production
- Check for corporate proxy interference

---

## Debugging Tips

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or for requests library specifically
import http.client
http.client.HTTPConnection.debuglevel = 1
```

### Inspect Token Contents

```python
import base64
import json

def decode_jwt_unsafe(token):
    """Decode JWT without verification (for debugging only)."""
    parts = token.split('.')
    payload = parts[1]
    # Add padding
    payload += '=' * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))

# Debug
print(json.dumps(decode_jwt_unsafe(id_token), indent=2))
```

### Check Session State

```bash
# Poll session to see current state
curl -s https://api.beta.privacy-lion.com/v1/enterprise/session/YOUR_SESSION_ID/status \
  -H "X-API-Key: your_key" | jq .
```

### Verify JWKS is Accessible

```bash
curl -s https://api.beta.privacy-lion.com/.well-known/jwks.json | jq .
```

---

## Error Reference

| Error Code | HTTP Status | Description | Solution |
|------------|-------------|-------------|----------|
| `invalid_request` | 400 | Malformed request | Check request body/params |
| `invalid_client` | 401 | Unknown client_id | Verify client registration |
| `unauthorized` | 401 | Missing/invalid API key | Check X-API-Key header |
| `forbidden` | 403 | Operation not allowed | Check permissions |
| `not_found` | 404 | Resource doesn't exist | Verify IDs |
| `expired` | 410 | Session/code expired | Create new session |
| `rate_limited` | 429 | Too many requests | Implement backoff |
| `server_error` | 500 | Internal error | Retry later, contact support |

---

## Getting Help

1. **Check this guide** for common issues
2. **API Reference** for endpoint details: [API_REFERENCE.md](./API_REFERENCE.md)
3. **GitHub Issues** for bugs: [Report an issue](https://github.com/PrivacyLion/SignedByMe/issues)
4. **Email support:** contact@signedbyme.com

When reporting issues, include:
- Your client_id (not secret!)
- Session ID (if applicable)
- Full error message
- Request/response (redact sensitive data)
- Timestamp of the issue
