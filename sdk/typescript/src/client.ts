/**
 * SignedByClient - Core client for agent authentication.
 */

import { readFileSync } from 'fs';
import type { LoginToken, LoginRequest, LoginOptions, Scopes, DelegationContent } from './types';
import { ScopeDeniedError, DelegationExpiredError } from './errors';

// Native binding (loaded via napi-rs)
// eslint-disable-next-line @typescript-eslint/no-var-requires
const native = require('./native');

const DEFAULT_RELAY_URL = 'wss://relay.privacy-lion.com';
const DEFAULT_API_URL = 'https://api.beta.privacy-lion.com';

/**
 * Client for authenticating to enterprises using SignedByMe.
 *
 * @example
 * ```typescript
 * const client = await SignedByClient.fromDelegation('./delegation.json');
 * const token = await client.login({
 *   clientId: 'acme-corp',
 *   nonce: 'random123'
 * });
 * console.log(`ID Token: ${token.idToken}`);
 * ```
 */
export class SignedByClient {
  private readonly nativeClient: unknown;
  private readonly delegation: DelegationContent;

  private constructor(nativeClient: unknown, delegation: DelegationContent) {
    this.nativeClient = nativeClient;
    this.delegation = delegation;
  }

  /**
   * Load a SignedByClient from a delegation file.
   *
   * @param path - Path to the delegation JSON file (kind 28250 event)
   * @returns SignedByClient instance ready for authentication
   * @throws {Error} If delegation file doesn't exist or is invalid
   */
  static async fromDelegation(path: string): Promise<SignedByClient> {
    const delegationJson = readFileSync(path, 'utf-8');
    const event = JSON.parse(delegationJson);
    const content: DelegationContent = JSON.parse(event.content);

    // Check expiration
    const expiresAt = new Date(content.expiresAt);
    if (expiresAt < new Date()) {
      throw new DelegationExpiredError();
    }

    const nativeClient = await native.SignedByClient.fromDelegationJson(delegationJson);
    return new SignedByClient(nativeClient, content);
  }

  /**
   * Get the agent's npub (public key in bech32 format).
   */
  get npub(): string {
    return native.getNpub(this.nativeClient);
  }

  /**
   * Get the delegation scopes (enterprise -> permissions mapping).
   */
  get scopes(): Scopes {
    return this.delegation.scopes;
  }

  /**
   * Authenticate to an enterprise and receive an OIDC token.
   *
   * @param request - Login request parameters
   * @param options - Optional configuration
   * @returns LoginToken containing the OIDC id_token
   * @throws {DelegationRevokedError} If delegation has been revoked
   * @throws {DelegationExpiredError} If delegation has expired
   * @throws {ScopeDeniedError} If client_id not in delegation scopes
   * @throws {MerkleRootExpiredError} If proof uses stale merkle root
   */
  async login(request: LoginRequest, options: LoginOptions = {}): Promise<LoginToken> {
    const { clientId, nonce } = request;
    const relayUrl = options.relayUrl ?? DEFAULT_RELAY_URL;
    const apiUrl = options.apiUrl ?? DEFAULT_API_URL;

    // Check scope authorization
    if (!this.scopes[clientId] && !Object.keys(this.scopes).some(k => clientId.includes(k))) {
      throw new ScopeDeniedError(`Not authorized for enterprise: ${clientId}`);
    }

    // Generate Groth16 proof
    const proofResult = await native.generateLoginProof(this.nativeClient, clientId, nonce);

    // Publish proof event to NOSTR (kind 28101)
    await native.publishProofEvent(this.nativeClient, relayUrl, proofResult);

    // Call API to verify and get token
    const tokenResponse = await native.verifyAndGetToken(
      this.nativeClient,
      apiUrl,
      proofResult,
      clientId,
      nonce
    );

    return {
      idToken: tokenResponse.id_token,
      tokenType: tokenResponse.token_type ?? 'Bearer',
      expiresIn: tokenResponse.expires_in ?? 3600,
      sub: tokenResponse.sub,
    };
  }
}
