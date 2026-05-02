# SignedByMe Python SDK

Human-controlled identity for autonomous agents.

## Installation

```bash
pip install signedby
```

## Quick Start

### For Agents - Authenticate to Enterprises

```python
from signedby import SignedByClient

# Load delegation from your human owner
client = SignedByClient.from_delegation("./delegation.json")

print(f"Your npub: {client.npub}")
print(f"Authorized for: {client.scopes}")

# Authenticate to an enterprise
token = await client.login(
    client_id="acme-corp",
    nonce="random_nonce_here"
)

# Use the OIDC token
print(f"ID Token: {token.id_token}")
print(f"Subject: {token.sub}")
```

### For Agent Setup - Initialize Identity

```python
from signedby import SignedByAgent

# Initialize agent (creates DID if first run)
agent = SignedByAgent.init(storage_path="./agent_data")

print(f"Agent npub: {agent.npub}")

# Configure email mapping for enterprises
agent.set_email_mapping({
    "amazon.com": "you@gmail.com",
    "acme.com": "you@gmail.com"
})

# Connect to relay and watch for authorizations
agent.connect_relay("wss://relay.signedbyme.com")

async for event in agent.watch_for_authorizations():
    print(f"New authorization from: {event.enterprise}")
    print(f"Scopes: {event.scopes}")
```

## Error Handling

```python
from signedby import (
    SignedByClient,
    SignedByError,
    DelegationRevokedError,
    DelegationExpiredError,
    ScopeDeniedError,
)

try:
    token = await client.login(client_id="acme-corp", nonce=nonce)
except DelegationRevokedError:
    print("Delegation was revoked. Contact your human owner.")
except DelegationExpiredError:
    print("Delegation expired. Request renewal from your human owner.")
except ScopeDeniedError:
    print("Not authorized for this enterprise.")
except SignedByError as e:
    print(f"Authentication failed: {e}")
```

## Requirements

- Python 3.9+
- Supported platforms: Linux (x86_64, aarch64), macOS (x86_64, arm64), Windows (x86_64)

## Documentation

- [SDK Quick Start](https://signedbyme.com/docs/sdk-quickstart.html)
- [API Reference](https://signedbyme.com/docs/api-reference.html)
- [Understanding Delegation](https://signedbyme.com/docs/delegation.html)

## License

SignedByMe Source-Available License v1.0 (SSAL-1.0)

See [LICENSE](https://github.com/PrivacyLion/SignedByMe/blob/main/LICENSE) for details.
