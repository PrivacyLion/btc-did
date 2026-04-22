# SignedByMe SDK for Rust

Self-signing digital signatures with zero-knowledge proofs.

## What is SignedByMe?

SignedByMe is a self-signing digital signature system. When a user authenticates, they generate a Groth16 zero-knowledge proof on their own device. That proof is signed with their DID (Decentralized Identifier) — a cryptographic key pair created on-device, stored in hardware-backed secure storage, and **never extractable**.

The DID key never leaves the phone. No certificate authority issued it. No enterprise controls it. The user created it. The user signs with it. The user owns it.

## Installation

```toml
[dependencies]
signedby-sdk = "0.1"
```

## Quick Start

### Verify a Proof (No Network Required)

```rust
use signedby_sdk::{Verifier, VerificationKey};

// Load the verification key (4KB, can be bundled)
let vk = VerificationKey::from_json(include_str!("verification_key.json"))?;
let verifier = Verifier::new(vk);

// Verify a proof from a SignedByMe login
let result = verifier.verify_proof(&proof_json, &public_inputs)?;
assert!(result.valid);
println!("User npub: {}", result.npub);  // Pseudonymous per-service ID
```

### Validate an OIDC Token

```rust
use signedby_sdk::oidc::{TokenValidator, ValidationConfig};

let config = ValidationConfig {
    issuer: "https://api.beta.privacy-lion.com".into(),
    audience: "your-client-id".into(),
    // Offline mode: bundle the JWKS
    jwks: Some(include_str!("jwks.json").into()),
};

let validator = TokenValidator::new(config)?;
let claims = validator.validate(id_token)?;

println!("Authenticated: {}", claims.sub);  // npub (bech32)
println!("Client: {}", claims.client_id);
```

## Decentralized by Design

- **Verification is local** — No network calls required to verify proofs
- **Keys stay on-device** — The SDK never touches private keys
- **ZK membership proofs** — Prove you're in a group without revealing who you are
- **Bitcoin-backed** — Every login is backed by a Lightning payment (optional)

## Features

- `default` — Includes OIDC discovery (requires network for initial key fetch)
- `--no-default-features` — Fully offline verification (bundle your own JWKS)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Your Server                          │
│  ┌─────────────────┐      ┌─────────────────────────────┐  │
│  │ signedby-sdk    │      │      Your Application       │  │
│  │                 │      │                             │  │
│  │ • Verify proofs │ ───▶ │ • Check membership          │  │
│  │ • Validate JWT  │      │ • Grant access              │  │
│  │ • Offline-first │      │ • Audit via NOSTR events    │  │
│  └─────────────────┘      └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ OIDC id_token (contains npub)
                              │
┌─────────────────────────────────────────────────────────────┐
│                     User's Device                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              SignedByMe Mobile App                   │   │
│  │                                                      │   │
│  │  DID (private) ──▶ Groth16 Proof ──▶ NOSTR Event    │   │
│  │       │                   │                          │   │
│  │       ▼                   ▼                          │   │
│  │  Secure Enclave    Proves membership                 │   │
│  │  (never leaves)    without revealing identity        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT
