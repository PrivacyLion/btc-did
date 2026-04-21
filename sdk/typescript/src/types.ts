/**
 * Type definitions for SignedByMe SDK.
 */

/**
 * OIDC token returned from successful authentication.
 */
export interface LoginToken {
  /** The OIDC id_token (JWT) */
  idToken: string;
  /** Token type, always "Bearer" */
  tokenType: string;
  /** Seconds until token expires */
  expiresIn: number;
  /** Subject - agent's npub in bech32 format */
  sub: string;
}

/**
 * Request parameters for login.
 */
export interface LoginRequest {
  /** Enterprise client ID */
  clientId: string;
  /** Random nonce for replay protection */
  nonce: string;
}

/**
 * Delegation scopes mapping enterprise to permissions.
 */
export type Scopes = Record<string, string[]>;

/**
 * An authorization request from an enterprise (kind 28200).
 */
export interface AuthorizationEvent {
  /** Enterprise name/domain */
  enterprise: string;
  /** Enterprise client ID */
  clientId: string;
  /** Offered permission scopes */
  scopes: string[];
  /** NOSTR event ID */
  eventId: string;
  /** Unix timestamp of event creation */
  createdAt: number;
}

/**
 * Delegation event content (kind 28250).
 */
export interface DelegationContent {
  agentNpub: string;
  scopes: Scopes;
  expiresAt: string;
  delegationId: string;
  subscriptionPreimage?: string;
}

/**
 * Login options for customizing authentication.
 */
export interface LoginOptions {
  /** NOSTR relay URL (default: wss://relay.privacy-lion.com) */
  relayUrl?: string;
  /** SignedByMe API URL (default: https://api.beta.privacy-lion.com) */
  apiUrl?: string;
}
