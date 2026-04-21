/**
 * SignedByMe SDK - Human-controlled identity for autonomous agents.
 *
 * @packageDocumentation
 */

export { SignedByClient } from './client';
export { SignedByAgent } from './agent';
export {
  SignedByError,
  DelegationRevokedError,
  DelegationExpiredError,
  InvalidProofError,
  MerkleRootExpiredError,
  ScopeDeniedError,
  RelayConnectionError,
  ApiError,
} from './errors';
export type { LoginToken, LoginRequest, AuthorizationEvent, Scopes } from './types';
