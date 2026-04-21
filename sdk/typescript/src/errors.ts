/**
 * SignedByMe SDK Errors.
 */

/**
 * Base error class for all SignedByMe errors.
 */
export class SignedByError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignedByError';
  }
}

/**
 * Raised when the delegation has been revoked.
 *
 * The human owner published a kind 28251 revocation event.
 * Contact your human owner for a new delegation.
 */
export class DelegationRevokedError extends SignedByError {
  constructor(message = 'Delegation has been revoked') {
    super(message);
    this.name = 'DelegationRevokedError';
  }
}

/**
 * Raised when the delegation has expired.
 *
 * The expires_at timestamp in the delegation has passed.
 * Request a renewed delegation from your human owner.
 */
export class DelegationExpiredError extends SignedByError {
  constructor(message = 'Delegation has expired') {
    super(message);
    this.name = 'DelegationExpiredError';
  }
}

/**
 * Raised when Groth16 proof verification fails.
 *
 * This typically indicates corrupted proof data or
 * a mismatch between proof and public inputs.
 */
export class InvalidProofError extends SignedByError {
  constructor(message = 'Invalid Groth16 proof') {
    super(message);
    this.name = 'InvalidProofError';
  }
}

/**
 * Raised when the proof references a stale merkle root.
 *
 * The merkle root in the proof is not in the last 30 valid roots.
 * Refresh witness data and regenerate the proof.
 */
export class MerkleRootExpiredError extends SignedByError {
  constructor(message = 'Merkle root is expired') {
    super(message);
    this.name = 'MerkleRootExpiredError';
  }
}

/**
 * Raised when attempting to access an unauthorized enterprise.
 *
 * The client_id is not in the delegation scopes.
 * Request an updated delegation that includes this enterprise.
 */
export class ScopeDeniedError extends SignedByError {
  constructor(message = 'Enterprise not in delegation scopes') {
    super(message);
    this.name = 'ScopeDeniedError';
  }
}

/**
 * Raised when unable to connect to a NOSTR relay.
 */
export class RelayConnectionError extends SignedByError {
  constructor(message = 'Failed to connect to relay') {
    super(message);
    this.name = 'RelayConnectionError';
  }
}

/**
 * Raised when the SignedByMe API returns an error.
 */
export class ApiError extends SignedByError {
  public readonly errorCode?: string;
  public readonly statusCode?: number;

  constructor(message: string, errorCode?: string, statusCode?: number) {
    super(message);
    this.name = 'ApiError';
    this.errorCode = errorCode;
    this.statusCode = statusCode;
  }
}
