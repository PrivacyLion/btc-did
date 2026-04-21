"""
SignedByMe SDK Errors.
"""


class SignedByError(Exception):
    """Base exception for all SignedByMe errors."""
    pass


class DelegationRevokedError(SignedByError):
    """
    Raised when the delegation has been revoked.
    
    The human owner published a kind 28251 revocation event.
    Contact your human owner for a new delegation.
    """
    pass


class DelegationExpiredError(SignedByError):
    """
    Raised when the delegation has expired.
    
    The expires_at timestamp in the delegation has passed.
    Request a renewed delegation from your human owner.
    """
    pass


class InvalidProofError(SignedByError):
    """
    Raised when Groth16 proof verification fails.
    
    This typically indicates corrupted proof data or
    a mismatch between proof and public inputs.
    """
    pass


class MerkleRootExpiredError(SignedByError):
    """
    Raised when the proof references a stale merkle root.
    
    The merkle root in the proof is not in the last 30 valid roots.
    Refresh witness data and regenerate the proof.
    """
    pass


class ScopeDeniedError(SignedByError):
    """
    Raised when attempting to access an unauthorized enterprise.
    
    The client_id is not in the delegation scopes.
    Request an updated delegation that includes this enterprise.
    """
    pass


class RelayConnectionError(SignedByError):
    """
    Raised when unable to connect to a NOSTR relay.
    """
    pass


class ApiError(SignedByError):
    """
    Raised when the SignedByMe API returns an error.
    """
    def __init__(self, message: str, error_code: str = None, status_code: int = None):
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code
