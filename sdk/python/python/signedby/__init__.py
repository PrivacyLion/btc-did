"""
SignedByMe SDK - Human-controlled identity for autonomous agents.

This SDK allows agents to:
- Load delegated credentials from their human owner
- Generate Groth16 zero-knowledge proofs
- Authenticate to enterprises and receive OIDC tokens
- Manage NOSTR event publishing for audit trails
"""

from .client import SignedByClient
from .agent import SignedByAgent
from .errors import (
    SignedByError,
    DelegationRevokedError,
    DelegationExpiredError,
    InvalidProofError,
    MerkleRootExpiredError,
    ScopeDeniedError,
)

__version__ = "0.1.0"
__all__ = [
    "SignedByClient",
    "SignedByAgent",
    "SignedByError",
    "DelegationRevokedError",
    "DelegationExpiredError",
    "InvalidProofError",
    "MerkleRootExpiredError",
    "ScopeDeniedError",
]
