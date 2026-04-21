/**
 * SignedByAgent - Agent initialization and management.
 */

import { mkdirSync, existsSync } from 'fs';
import type { AuthorizationEvent, Scopes } from './types';
import { RelayConnectionError } from './errors';

// Native binding (loaded via napi-rs)
// eslint-disable-next-line @typescript-eslint/no-var-requires
const native = require('./native');

/**
 * Agent for managing identity and watching for authorization requests.
 *
 * @example
 * ```typescript
 * const agent = await SignedByAgent.init('./agent_data');
 * agent.setEmailMapping({
 *   'amazon.com': 'me@gmail.com',
 *   'acme.com': 'me@gmail.com'
 * });
 * await agent.connectRelay('wss://relay.privacy-lion.com');
 * agent.watchForAuthorizations();
 * ```
 */
export class SignedByAgent {
  private readonly nativeAgent: unknown;
  private relayConnected = false;
  private emailMapping: Record<string, string> = {};

  private constructor(nativeAgent: unknown) {
    this.nativeAgent = nativeAgent;
  }

  /**
   * Initialize a new agent or load existing identity.
   *
   * Creates DID keys and stores them securely if this is first run.
   * Loads existing identity if storage already exists.
   *
   * @param storagePath - Directory for agent data (keys, witness cache)
   * @returns SignedByAgent instance
   */
  static async init(storagePath: string): Promise<SignedByAgent> {
    if (!existsSync(storagePath)) {
      mkdirSync(storagePath, { recursive: true });
    }

    const nativeAgent = await native.SignedByAgent.init(storagePath);
    return new SignedByAgent(nativeAgent);
  }

  /**
   * Get the agent's npub (public key in bech32 format).
   */
  get npub(): string {
    return native.getAgentNpub(this.nativeAgent);
  }

  /**
   * Set email mapping for enterprises.
   *
   * This tells the agent which email to provide during Gate 1
   * enrollment for each enterprise domain.
   *
   * @param mapping - Dict of enterprise domain -> email address
   */
  setEmailMapping(mapping: Record<string, string>): void {
    this.emailMapping = mapping;
    native.setEmailMapping(this.nativeAgent, mapping);
  }

  /**
   * Connect to a NOSTR relay.
   *
   * @param relayUrl - WebSocket URL of the relay
   */
  async connectRelay(relayUrl: string): Promise<void> {
    try {
      await native.connectRelay(this.nativeAgent, relayUrl);
      this.relayConnected = true;
    } catch (error) {
      throw new RelayConnectionError(`Failed to connect to ${relayUrl}: ${error}`);
    }
  }

  /**
   * Watch for kind 28200 authorization events addressed to this agent.
   *
   * @yields AuthorizationEvent for each incoming authorization request
   */
  async *watchForAuthorizations(): AsyncGenerator<AuthorizationEvent> {
    if (!this.relayConnected) {
      throw new Error('Not connected to relay. Call connectRelay() first.');
    }

    const eventIterator = native.subscribeAuthorizations(this.nativeAgent);

    for await (const eventJson of eventIterator) {
      const event = JSON.parse(eventJson);
      yield {
        enterprise: event.enterprise ?? 'unknown',
        clientId: event.client_id,
        scopes: event.scopes ?? [],
        eventId: event.id,
        createdAt: event.created_at,
      };
    }
  }

  /**
   * Get recent agent activity (kinds 28101, 28102, 28103).
   *
   * @param limit - Maximum number of events to return
   * @returns List of activity events
   */
  getActivityLog(limit = 100): Array<Record<string, unknown>> {
    return native.getActivityLog(this.nativeAgent, limit);
  }
}
