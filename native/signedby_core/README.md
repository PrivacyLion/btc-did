# SignedByMe SDK

Human-controlled identity for autonomous agents.

## Installation

```toml
[dependencies]
signedby-sdk = "0.1"
```

## Quick Start

```rust
use signedby_sdk::{SignedByClient, LoginRequest};

// Load delegation from your human owner
let client = SignedByClient::from_delegation("./delegation.json")?;

println!("Your npub: {}", client.npub());
println!("Scopes: {:?}", client.scopes());

// Authenticate to an enterprise
let token = client.login(LoginRequest {
    client_id: "acme-corp",
    nonce: &generate_nonce(),
}).await?;

// Use the OIDC token
println!("ID Token: {}", token.id_token);
println!("Subject: {}", token.sub);
```

## Features

- **Groth16 Zero-Knowledge Proofs** - Prove group membership without revealing identity
- **NOSTR Integration** - Decentralized audit trail and relay communication
- **OIDC Tokens** - Standard RS256-signed JWTs for enterprise integration
- **Secure Storage** - OS keyring integration for key material
- **NWC Wallet** - NIP-47 Lightning wallet support

## Modules

- `signedby_sdk::sdk::identity` - Identity management (DID, leaf_secret)
- `signedby_sdk::sdk::delegation` - Delegation handling (kind 28250)
- `signedby_sdk::sdk::enrollment` - Enrollment flow (Genesis)
- `signedby_sdk::sdk::prover` - Groth16 proof generation
- `signedby_sdk::sdk::nostr_client` - NOSTR relay client
- `signedby_sdk::sdk::storage` - Encrypted storage
- `signedby_sdk::sdk::wallet` - NWC wallet integration

## Documentation

- [SDK Quick Start](https://signedbyme.com/docs/sdk-quickstart.html)
- [API Reference](https://signedbyme.com/docs/api-reference.html)
- [Understanding Delegation](https://signedbyme.com/docs/delegation.html)

## Requirements

- Rust 1.70+
- Supported platforms: Linux (x86_64, aarch64), macOS (x86_64, arm64), Windows (x86_64)

## License

SignedByMe Source-Available License v1.0 (SSAL-1.0)

See [LICENSE](https://github.com/PrivacyLion/SignedByMe/blob/main/LICENSE) for details.
