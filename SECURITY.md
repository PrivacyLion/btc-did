# Security Audit Findings

*Audit Date: 2026-02-16*  
*Last Updated: 2026-02-19*

## Critical Issues

### 1. STWO Verifier (Server-Side)
**Status:** ✅ IMPLEMENTED  
**Location:** `app/lib/stwo_verify.py`  
**Resolution:** 
- Full verification code implemented (400+ lines)
- Verifies binding hash, expiry, domain binding, amount binding
- GitHub Actions workflow builds the Rust verifier binary (`stwo_verifier`)
- Deploy binary to `/opt/sbm-api/bin/stwo_verifier` for full STARK verification

**Fallback behavior:** If verifier binary not deployed, binding hash verification still catches tampering attacks. Full STARK verification requires deployed binary.

### 2. Signature Verification
**Status:** ✅ FIXED  
**Location:** `api/app/lib/crypto.py`  
**Resolution:** 
- Implemented real secp256k1 signature verification using `coincurve` library
- `verify_secp256k1_signature()` - verify raw message signatures
- `verify_binding_signature()` - verify login binding signatures
- Legacy stub now performs real verification when coincurve is installed

### 3. API_SECRET Default Fallback
**Status:** ✅ CONFIGURED (2026-02-19)  
**Location:** `/opt/sbm-api/.env`  
**Resolution:** Production `API_SECRET` set on VPS. Code still warns if missing.

## Medium Issues

### 4. Rate Limiting
**Status:** ✅ IMPLEMENTED  
**Location:** `app/main.py`  
**Resolution:** Added `slowapi` rate limiter — 100 requests/minute per IP by default

### 5. Session Token in URL (QR/Deep Link)
**Status:** ⚠️ ACCEPTABLE RISK  
**Location:** Login flow  
**Issue:** Session tokens appear in QR codes and deep links which could be logged.  
**Mitigation:** Tokens are short-lived (5 min default). Consider using reference tokens that are exchanged server-side.

## Low Issues

### 6. Verbose Logging
**Status:** ⏳ TODO  
**Location:** Various  
**Issue:** Some sensitive data may be logged (truncated proofs, partial tokens).  
**Fix:** Audit log statements before production.

## Security Features

### Implemented ✅

- **HTTPS for all API communication**
- **Android Keystore for key storage** - Private keys never leave secure hardware
- **AES-GCM encryption for sensitive local data** - Proofs encrypted at rest
- **Nonce-based replay attack prevention** - Each session has unique nonce
- **Domain binding in proofs** - Prevents cross-RP replay attacks
- **Binding hash verification** - Catches tampering without full STARK verification
- **Short-lived sessions** - 5 minute default TTL
- **Membership verification** - Privacy-preserving allowlist proofs (Poseidon + Merkle)
- **Real signature verification** - secp256k1 signatures cryptographically verified
- **STWO proof verification code** - Full verification pipeline implemented

### Membership (Mandatory by Default)

As of 2026-02-19, membership verification is **mandatory by default**. This means:

- All logins require the user to prove membership in an approved allowlist
- Enterprises must configure a `default_root_id` or provide `root_id` per session
- To opt-out (not recommended), set `require_membership: false` in client config

This prevents Sybil attacks and ensures only pre-approved identities can authenticate.

## Pre-Production Checklist

- [x] Implement real secp256k1 signature verification
- [x] Implement STWO proof verification code
- [x] Deploy `stwo_verifier` binary to VPS
- [x] Add rate limiting to API (slowapi)
- [x] Install `coincurve` on VPS
- [x] Set `API_SECRET` environment variable (2026-02-19)
- [x] Review and sanitize all log statements (2026-02-19)
- [x] Enable HSTS headers (2026-02-19, Caddy config)
- [x] Security review of OIDC implementation (2026-02-19)
- [ ] Penetration testing

## OIDC Security Review (2026-02-19)

**Reviewed:** `app/oidc_endpoints.py`

### Good Practices ✅
- PKCE S256 support for public clients
- One-time auth codes (deleted after use)
- 5-minute code expiry
- Redirect URI allowlist validation
- HTTPS-only redirects enforced
- Nonce validation with regex (1-128 chars, base64url-safe)
- Cache-Control: no-store on all token responses
- RS256 JWT signing with key rotation support (kid)
- Issuer/expiry validation with 60s clock skew tolerance

### Minor Issues (Low Risk)
1. **Unused access_token:** SignedByMe flow issues random access_token but /userinfo expects JWT. Not exploitable, just non-functional.
2. **Code DB cleanup:** Expired codes aren't proactively cleaned. Low disk impact.

### Recommendations
- Add periodic cleanup job for expired codes (cron)
- Consider removing access_token from SignedByMe response if unused

## Reporting Security Issues

If you discover a security vulnerability, please email contact@signedbyme.com. Do not open a public issue.
