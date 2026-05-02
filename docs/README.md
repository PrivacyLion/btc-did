# SignedByMe Integration Guide

**Users get PAID to log in. Enterprises get cryptographic identity.**

SignedByMe is a decentralized authentication system where users prove their identity with zero-knowledge proofs and receive Lightning payments for logging in.

---

## How It Works

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   1. ENTERPRISE              2. USER                3. RESULT        │
│   Creates session            Scans QR              Gets paid +       │
│   with payment offer         Proves identity       Enterprise gets   │
│                              via app               verified token    │
│                                                                      │
│   ┌─────────┐    QR/Link    ┌─────────┐   Proof   ┌─────────┐       │
│   │ Your    │ ───────────▶  │ User's  │ ────────▶ │ Signed  │       │
│   │ Server  │               │ App     │           │ ByMe    │       │
│   └─────────┘  ◀─────────── └─────────┘ ◀──────── └─────────┘       │
│                  ID Token      Sats via Lightning                    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**The user proves:**
- They control a DID (decentralized identifier)
- Their identity via STWO zero-knowledge proof
- Optionally: membership in a group you define

**You receive:**
- Signed OIDC-compatible ID token
- Cryptographic attestation of identity
- Proof of payment (Lightning preimage)

---

## Two Authentication Modes

### Basic Login
Any user with the SignedByMe app can authenticate.

```json
{
  "require_membership": false
}
```

Best for: Public apps, marketplaces, open communities

### Membership-Verified Login
Only users in your defined group can authenticate.

```json
{
  "require_membership": true,
  "allowed_purposes": ["employees"]
}
```

Best for: Employee SSO, premium tiers, age-gated content, KYC'd users

---

## Use Cases

| Scenario | Mode | Your Verification | Example |
|----------|------|-------------------|---------|
| Public app login | Basic | None needed | Social platform |
| Employee SSO | Membership | HR system | Corporate apps |
| Premium features | Membership | Payment processor | SaaS tiers |
| Age-gated content | Membership | ID verification service (Persona, Jumio) | Alcohol, gambling |
| KYC'd users | Membership | Compliance provider (Plaid, Onfido) | Finance apps |
| Anti-sybil | Membership | Your verification (ID service, vouching, etc.) | Voting, airdrops |

**How membership works:**
1. YOU verify users (however you want—ID check, payment, HR approval)
2. YOU enroll verified users in your Merkle tree via API
3. At login, SignedByMe proves membership cryptographically

SignedByMe stores and proves membership—verification is YOUR responsibility. This separation gives you full control over who gets in.

---

## Why SignedByMe?

### The Problem with Traditional Auth

| Issue | Traditional | SignedByMe |
|-------|-------------|------------|
| **Data honeypots** | You store passwords, emails, PII | Users keep their keys, you store nothing |
| **Account takeover** | Password resets, phishing, SIM swaps | Cryptographic keys can't be phished |
| **User exploitation** | Users pay with data or attention | Users get PAID to authenticate |
| **Identity silos** | Locked into Google/Apple/Facebook | Portable DID works everywhere |
| **Compliance burden** | GDPR, CCPA, data retention rules | No PII = no compliance headache |
| **Breach liability** | Login history, tracking data exposed | Nothing to steal—identity never stored |

### Privacy-Preserving Verification

```
Traditional Login:
  User → "I'm Alice, employee #EMP001" → Check database → ✓ Logged in
  
  PROBLEM: Every login creates a tracking record.
           Data breach = all login history exposed.

SignedByMe Login:
  User → "I'm someone in your approved list" (ZK proof) → ✓ Logged in
  
  WHAT YOU SEE:
    ✓ Someone from your Merkle root logged in
    ✓ They control a valid DID + Lightning wallet
    ✓ The proof is cryptographically sound
  
  WHAT YOU DON'T SEE:
    ✗ Which specific person
    ✗ Correlation between logins
    ✗ Tracking across sessions
```

### The Enterprise Value Prop

You've already KYC'd your employees. You know who they are. You have a database.

**The question is:** Do you need to know WHICH specific employee every time they log in?

In most cases, no. You just need to know:
- ✅ They're authorized (in your approved list)
- ✅ They control their identity (cryptographic proof)
- ✅ The session is legitimate (payment binding)

SignedByMe gives you all three—**without creating a tracking database.**

When there's a breach (and breaches happen), attackers get:
- ❌ No login history
- ❌ No identity correlation
- ❌ No PII

**Because that data never existed.** We verified membership, not identity.

### Why This Matters

| Benefit | Impact |
|---------|--------|
| **GDPR/CCPA Compliance** | No PII in authentication logs |
| **Zero-Knowledge Audit Trail** | Prove access happened without revealing who |
| **Breach Resistant** | Nothing to steal because identity isn't stored |
| **User Privacy** | People control their own identity data |
| **Regulatory Gold** | "We can prove compliance without logging identities" |

### One-Liner

> **"Your employees get paid to log in. You verify they're authorized. Neither of you creates tracking data."**

### Enterprise Integration Flow

```
┌───────────────┬─────────────────────────────────────────┬──────────────────────────────┐
│ Step          │ Enterprise Does                         │ SignedByMe Does              │
├───────────────┼─────────────────────────────────────────┼──────────────────────────────┤
│ 1. Setup      │ Export employee DIDs (HR portal or      │ Build Merkle tree,           │
│               │ self-service enrollment)                │ publish root                 │
├───────────────┼─────────────────────────────────────────┼──────────────────────────────┤
│ 2. Enrollment │ Employee links DID in app               │ Store leaf_commitment        │
│               │                                         │ (NOT identity)               │
├───────────────┼─────────────────────────────────────────┼──────────────────────────────┤
│ 3. Login      │ Show QR code with root_id               │ Verify membership ZK proof   │
├───────────────┼─────────────────────────────────────────┼──────────────────────────────┤
│ 4. Session    │ Receive "verified member" callback      │ Never know WHICH member      │
└───────────────┴─────────────────────────────────────────┴──────────────────────────────┘
```

---

## Quick Links

| Document | Description |
|----------|-------------|
| [Quick Start](./QUICK_START.md) | Get running in 5 minutes |
| [Authentication Flow](./AUTHENTICATION.md) | Detailed auth sequence with DID |
| [Membership Proofs](./MEMBERSHIP.md) | Restrict access to groups |
| [API Reference](./API_REFERENCE.md) | Complete endpoint docs |
| [ID Token Claims](./ID_TOKEN.md) | JWT structure and validation |
| [Code Examples](./EXAMPLES.md) | Copy-paste snippets |
| [Troubleshooting](./TROUBLESHOOTING.md) | Common issues and fixes |
| [STWO Integration](./STWO_INTEGRATION.md) | Zero-knowledge proof implementation |
| [Witness Spec](./WITNESS_SPEC.md) | Merkle witness format (technical) |

---

## Getting Started

### 1. Register as an Enterprise Client

Contact us to receive:
- `client_id` - Your unique identifier
- `client_secret` - For server-to-server calls (keep secret!)
- Configured `redirect_uris` - Your allowed callback URLs

### 2. Integrate the Flow

```bash
# Create a login session
curl -X POST https://api.signedbyme.com/v1/enterprise/session \
  -H "Content-Type: application/json" \
  -d '{"client_id": "your_client_id", "amount_sats": 100}'

# Response includes session_id and QR code data
```

### 3. Display QR to User

User scans with SignedByMe app → proves identity → gets paid → you get token.

**[Continue to Quick Start →](./QUICK_START.md)**

---

## API Base URL

```
https://api.signedbyme.com
```

## Support

- Documentation issues: Open a GitHub issue
- Security issues: contact@signedbyme.com
- Integration help: contact@signedbyme.com

---

## License

SignedByMe is dual-licensed under MIT and Apache 2.0. See [LICENSE](../LICENSE) for details.
