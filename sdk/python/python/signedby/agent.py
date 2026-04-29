"""
SignedByAgent - Agent initialization and management.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional, Dict, Any, AsyncIterator
from dataclasses import dataclass

# Import the Rust core via PyO3
from signedby._core import (
    RustSignedByAgent,
    init_agent_storage,
)

# SignedByMe relay infrastructure (Phase 29: Multi-relay)
SIGNEDBY_RELAYS = [
    "wss://relay.privacy-lion.com",      # US East (ATL) - primary
    "wss://relay-sfo.privacy-lion.com",  # US West (SFO)
    "wss://relay-ams.privacy-lion.com",  # Europe (AMS)
    "wss://relay-sgp.privacy-lion.com",  # Asia (SGP)
]


@dataclass
class AuthorizationEvent:
    """An authorization request from an enterprise (kind 28200)."""
    enterprise: str
    client_id: str
    scopes: list[str]
    event_id: str
    created_at: int


class SignedByAgent:
    """
    Agent for managing identity and watching for authorization requests.
    
    Usage:
        agent = SignedByAgent.init(storage_path="./agent_data")
        agent.set_email_mapping({"amazon.com": "me@gmail.com"})
        agent.connect_relays()  # Connects to all SignedByMe relays
        agent.watch_for_authorizations()
    """
    
    def __init__(self, rust_agent: RustSignedByAgent):
        self._rust = rust_agent
        self._relay_connected = False
        self._email_mapping: Dict[str, str] = {}
    
    @classmethod
    def init(cls, storage_path: str | Path) -> SignedByAgent:
        """
        Initialize a new agent or load existing identity.
        
        Creates DID keys and stores them securely if this is first run.
        Loads existing identity if storage already exists.
        
        Args:
            storage_path: Directory for agent data (keys, witness cache)
            
        Returns:
            SignedByAgent instance
        """
        storage_path = Path(storage_path)
        storage_path.mkdir(parents=True, exist_ok=True)
        
        rust_agent = RustSignedByAgent.init(str(storage_path))
        return cls(rust_agent)
    
    @property
    def npub(self) -> str:
        """Get the agent's npub (public key in bech32 format)."""
        return self._rust.npub()
    
    def set_email_mapping(self, mapping: Dict[str, str]) -> None:
        """
        Set email mapping for enterprises.
        
        This tells the agent which email to provide during Gate 1
        enrollment for each enterprise domain.
        
        Args:
            mapping: Dict of enterprise domain -> email address
                     e.g., {"amazon.com": "me@gmail.com"}
        """
        self._email_mapping = mapping
        self._rust.set_email_mapping(mapping)
    
    def connect_relay(self, relay_url: str) -> None:
        """
        Connect to a single NOSTR relay.
        
        Args:
            relay_url: WebSocket URL of the relay
                       e.g., "wss://relay.privacy-lion.com"
        """
        self._rust.connect_relay(relay_url)
        self._relay_connected = True
    
    def connect_relays(self, relay_urls: list[str] | None = None) -> None:
        """
        Connect to multiple NOSTR relays (Phase 29: multi-relay).
        
        Args:
            relay_urls: List of relay URLs (defaults to SIGNEDBY_RELAYS)
        """
        urls = relay_urls or SIGNEDBY_RELAYS
        for url in urls:
            try:
                self._rust.connect_relay(url)
            except Exception as e:
                # Log but continue - some relays may be down
                pass
        self._relay_connected = True
    
    async def watch_for_authorizations(self) -> AsyncIterator[AuthorizationEvent]:
        """
        Watch for kind 28200 authorization events addressed to this agent.
        
        Yields:
            AuthorizationEvent for each incoming authorization request
        """
        if not self._relay_connected:
            raise RuntimeError("Not connected to relay. Call connect_relay() first.")
        
        async for event_json in self._rust.subscribe_authorizations():
            event = json.loads(event_json)
            yield AuthorizationEvent(
                enterprise=event.get("enterprise", "unknown"),
                client_id=event["client_id"],
                scopes=event.get("scopes", []),
                event_id=event["id"],
                created_at=event["created_at"],
            )
    
    def get_activity_log(self, limit: int = 100) -> list[Dict[str, Any]]:
        """
        Get recent agent activity (kinds 28101, 28102, 28103).
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of activity events
        """
        return self._rust.get_activity_log(limit)
