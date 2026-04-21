# SignedByMe TypeScript SDK

Human-controlled identity for autonomous agents.

## Installation

```bash
npm install @signedby/sdk
```

## Quick Start

### For Agents - Authenticate to Enterprises

```typescript
import { SignedByClient } from '@signedby/sdk';

// Load delegation from your human owner
const client = await SignedByClient.fromDelegation('./delegation.json');

console.log(`Your npub: ${client.npub}`);
console.log(`Authorized for: ${JSON.stringify(client.scopes)}`);

// Authenticate to an enterprise
const token = await client.login({
  clientId: 'acme-corp',
  nonce: 'random_nonce_here'
});

// Use the OIDC token
console.log(`ID Token: ${token.idToken}`);
console.log(`Subject: ${token.sub}`);
```

### For Agent Setup - Initialize Identity

```typescript
import { SignedByAgent } from '@signedby/sdk';

// Initialize agent (creates DID if first run)
const agent = await SignedByAgent.init('./agent_data');

console.log(`Agent npub: ${agent.npub}`);

// Configure email mapping for enterprises
agent.setEmailMapping({
  'amazon.com': 'you@gmail.com',
  'acme.com': 'you@gmail.com'
});

// Connect to relay and watch for authorizations
await agent.connectRelay('wss://relay.privacy-lion.com');

for await (const event of agent.watchForAuthorizations()) {
  console.log(`New authorization from: ${event.enterprise}`);
  console.log(`Scopes: ${event.scopes}`);
}
```

## Error Handling

```typescript
import {
  SignedByClient,
  SignedByError,
  DelegationRevokedError,
  DelegationExpiredError,
  ScopeDeniedError,
} from '@signedby/sdk';

try {
  const token = await client.login({ clientId: 'acme-corp', nonce });
} catch (error) {
  if (error instanceof DelegationRevokedError) {
    console.log('Delegation was revoked. Contact your human owner.');
  } else if (error instanceof DelegationExpiredError) {
    console.log('Delegation expired. Request renewal from your human owner.');
  } else if (error instanceof ScopeDeniedError) {
    console.log('Not authorized for this enterprise.');
  } else if (error instanceof SignedByError) {
    console.log(`Authentication failed: ${error.message}`);
  }
}
```

## Requirements

- Node.js 18+
- Supported platforms: Linux (x86_64, arm64), macOS (x86_64, arm64), Windows (x86_64)

## Documentation

- [SDK Quick Start](https://signedbyme.com/docs/sdk-quickstart.html)
- [API Reference](https://signedbyme.com/docs/api-reference.html)
- [Understanding Delegation](https://signedbyme.com/docs/delegation.html)

## License

SignedByMe Source-Available License v1.0 (SSAL-1.0)

See [LICENSE](https://github.com/PrivacyLion/SignedByMe/blob/main/LICENSE) for details.
