"""
SignedByClient - Core client for agent authentication.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

# Import the Rust core via PyO3
from signedby._core import (
    RustSignedByClient,
    generate_proof,
    verify_delegation,
)


@dataclass
class LoginToken:
    """OIDC token returned from successful authentication."""
    id_token: str
    token_type: str
    expires_in: int
    sub: str  # npub in bech32
    
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        import time
        # Token includes iat, expires_in tells us duration
        # For now, we track expiry client-side
        return False  # TODO: implement proper expiry tracking


@dataclass
class LoginRequest:
    """Request parameters for login."""
    client_id: str
    nonce: str


class SignedByClient:
    """
    Client for authenticating to enterprises using SignedByMe.
    
    Usage:
        client = SignedByClient.from_delegation("./delegation.json")
        token = await client.login(client_id="acme-corp", nonce="random123")
    """
    
    def __init__(self, rust_client: RustSignedByClient):
        self._rust = rust_client
    
    @classmethod
    def from_delegation(cls, path: str | Path) -> SignedByClient:
        """
        Load a SignedByClient from a delegation file.
        
        Args:
            path: Path to the delegation JSON file (kind 28250 event)
            
        Returns:
            SignedByClient instance ready for authentication
            
        Raises:
            FileNotFoundError: If delegation file doesn't exist
            SignedByError: If delegation is invalid or expired
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Delegation file not found: {path}")
        
        delegation_json = path.read_text()
        rust_client = RustSignedByClient.from_delegation_json(delegation_json)
        return cls(rust_client)
    
    @property
    def npub(self) -> str:
        """Get the agent's npub (public key in bech32 format)."""
        return self._rust.npub()
    
    @property
    def scopes(self) -> Dict[str, list[str]]:
        """Get the delegation scopes (enterprise -> permissions mapping)."""
        return self._rust.scopes()
    
    async def login(
        self,
        client_id: str,
        nonce: str,
        *,
        relay_url: str = "wss://relay.privacy-lion.com",
        api_url: str = "https://api.beta.privacy-lion.com",
    ) -> LoginToken:
        """
        Authenticate to an enterprise and receive an OIDC token.
        
        Args:
            client_id: The enterprise's client ID
            nonce: Random nonce for replay protection
            relay_url: NOSTR relay URL (optional)
            api_url: SignedByMe API URL (optional)
            
        Returns:
            LoginToken containing the OIDC id_token
            
        Raises:
            DelegationRevokedError: If delegation has been revoked
            DelegationExpiredError: If delegation has expired
            ScopeDeniedError: If client_id not in delegation scopes
            MerkleRootExpiredError: If proof uses stale merkle root
        """
        # Generate Groth16 proof
        proof_result = await self._rust.generate_login_proof(client_id, nonce)
        
        # Publish proof event to NOSTR (kind 28101)
        await self._rust.publish_proof_event(relay_url, proof_result)
        
        # Call API to verify and get token
        token_response = await self._rust.verify_and_get_token(
            api_url,
            proof_result,
            client_id,
            nonce,
        )
        
        return LoginToken(
            id_token=token_response["id_token"],
            token_type=token_response.get("token_type", "Bearer"),
            expires_in=token_response.get("expires_in", 3600),
            sub=token_response["sub"],
        )
