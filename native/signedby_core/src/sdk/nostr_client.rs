// sdk/nostr_client.rs - Agent NOSTR Client (Phase 9A.3)
//
// Per Bible Section 9A.3:
// - Agent NOSTR identity derived from leaf_secret via get_agent_keys()
// - NIP-42 relay authentication with agent nsec
// - Event publishing (agent signs all events)
// - Event polling for enrollment/delegation/revocation
//
// Per Bible Section 15 Decision 941 (Apr 14, 2026):
// - Agent never holds human nsec
// - Human signs kind 28250 and kind 28251 with their own NOSTR client
// - Agent only publishes acknowledgment events (28102, 28103)

use anyhow::{Result, anyhow};
use nostr_sdk::prelude::*;
use nostr_sdk::client::EventSource;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::identity::AgentIdentity;
use super::storage::SecureStorage;

/// SignedByMe default relays (NIP-42 required for writes)
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.privacy-lion.com",      // US East (NYC)
    "wss://relay-sfo.privacy-lion.com",  // US West (SFO)
    "wss://relay-ams.privacy-lion.com",  // Europe (AMS)
    "wss://relay-sgp.privacy-lion.com",  // Asia (SGP)
];

/// Legacy single relay constant for backwards compatibility
pub const RELAY_URL: &str = "wss://relay.privacy-lion.com";

/// Event kinds for Phase 26 flow
pub const KIND_ENROLLMENT_AUTH: u16 = 28200;    // Enterprise → agent authorization
pub const KIND_PROOF_EVENT: u16 = 28101;        // Agent publishes ZK proof
pub const KIND_DELEGATION_ACK: u16 = 28102;     // Agent acks delegation (28250)
pub const KIND_REVOCATION_ACK: u16 = 28103;     // Agent acks revocation (28251)
pub const KIND_HUMAN_DELEGATION: u16 = 28250;   // Human → agent delegation
pub const KIND_HUMAN_REVOCATION: u16 = 28251;   // Human revokes agent

/// Proof event data for publishing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEventData {
    /// Groth16 proof bytes (hex-encoded)
    pub proof_hex: String,
    /// Merkle root (public output)
    pub merkle_root: String,
    /// npub_x coordinate (public output)
    pub npub_x: String,
    /// npub_y coordinate (public output)
    pub npub_y: String,
    /// Session ID from login QR
    pub session_id: String,
    /// Enterprise client_id
    pub client_id: String,
}

/// Agent NOSTR client for SignedByMe SDK
/// 
/// Connects to the audit relays with NIP-42 authentication.
/// All events are signed by the agent's nsec (derived from leaf_secret).
pub struct NostrClient {
    client: Client,
    keys: Keys,
    agent_npub: String,
    /// Active relay URLs (defaults + any custom relays added)
    relays: Vec<String>,
}

impl NostrClient {
    /// Create a new NOSTR client from AgentIdentity
    /// 
    /// Derives agent keys from leaf_secret (never stored separately).
    /// Connects to all SignedByMe default relays with NIP-42 auth.
    pub async fn new<S: SecureStorage>(identity: &AgentIdentity<S>) -> Result<Self> {
        // Derive agent keys fresh from leaf_secret
        let keys = identity.get_agent_keys()?;
        let agent_npub = keys.public_key().to_bech32()?;
        
        // Create nostr-sdk client with agent keys
        let client = Client::new(keys.clone());
        
        // Initialize with default relays
        let relays: Vec<String> = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect();
        
        let mut nostr_client = Self {
            client,
            keys,
            agent_npub,
            relays,
        };
        
        // Connect and authenticate to all default relays
        nostr_client.connect_and_auth().await?;
        
        Ok(nostr_client)
    }
    
    /// Connect to all relays and perform NIP-42 authentication
    async fn connect_and_auth(&mut self) -> Result<()> {
        // Add all relays
        for relay_url in &self.relays {
            if let Err(e) = self.client.add_relay(relay_url.as_str()).await {
                eprintln!("[nostr] Warning: Failed to add relay {}: {}", relay_url, e);
            }
        }
        
        // Connect with timeout
        let timeout = Duration::from_secs(10);
        match tokio::time::timeout(timeout, self.client.connect()).await {
            Ok(_) => {}
            Err(_) => {
                return Err(anyhow!("Connection to relays timed out after 10 seconds"));
            }
        }
        
        // NIP-42 authentication happens automatically via nostr-sdk when the relay
        // sends an AUTH challenge. The client will sign the challenge with our keys.
        // Wait a moment for auth to complete
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        Ok(())
    }
    
    /// Add custom relays (e.g., from enterprise kind 28200 "relays" tag)
    /// 
    /// Call this when an enterprise specifies custom relays in their authorization event.
    /// The agent will publish responses to these relays in addition to defaults.
    pub async fn add_custom_relays(&mut self, relay_urls: &[String]) -> Result<()> {
        for relay_url in relay_urls {
            // Skip if already added
            if self.relays.contains(relay_url) {
                continue;
            }
            
            // Add to our list
            self.relays.push(relay_url.clone());
            
            // Add to nostr-sdk client
            if let Err(e) = self.client.add_relay(relay_url.as_str()).await {
                eprintln!("[nostr] Warning: Failed to add custom relay {}: {}", relay_url, e);
            }
        }
        
        // Reconnect to include new relays
        self.client.connect().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        Ok(())
    }
    
    /// Get the list of active relay URLs
    pub fn active_relays(&self) -> &[String] {
        &self.relays
    }
    
    /// Get the agent's npub (bech32)
    pub fn agent_npub(&self) -> &str {
        &self.agent_npub
    }
    
    /// Get the agent's public key
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }
    
    /// Get a clone of the inner nostr-sdk Client
    /// 
    /// Returns a clone so the caller can use it without holding the NostrClient lock.
    /// Useful for advanced queries like delegation validation.
    pub fn inner_client(&self) -> Client {
        self.client.clone()
    }
    
    /// Publish proof event (kind 28101)
    /// 
    /// Published after successful ZK proof generation.
    /// Tags: session_id, client_id, merkle_root
    pub async fn publish_proof_event(&self, data: ProofEventData) -> Result<EventId> {
        let tags = vec![
            Tag::custom(TagKind::Custom("session_id".into()), vec![data.session_id.clone()]),
            Tag::custom(TagKind::Custom("client_id".into()), vec![data.client_id.clone()]),
            Tag::custom(TagKind::Custom("merkle_root".into()), vec![data.merkle_root.clone()]),
        ];
        
        let content = serde_json::json!({
            "proof": data.proof_hex,
            "merkle_root": data.merkle_root,
            "npub_x": data.npub_x,
            "npub_y": data.npub_y,
            "session_id": data.session_id,
            "client_id": data.client_id,
            "timestamp": current_timestamp(),
        }).to_string();
        
        let event_builder = EventBuilder::new(Kind::Custom(KIND_PROOF_EVENT), content, tags);
        
        let output = self.client.send_event_builder(event_builder).await
            .map_err(|e| anyhow!("Failed to publish proof event: {}", e))?;
        
        Ok(output.val)
    }
    
    /// Publish delegation acknowledgment (kind 28102)
    /// 
    /// Agent confirms receipt of kind 28250 from human.
    /// References the delegation event by ID.
    pub async fn publish_delegation_ack(&self, delegation_event_id: EventId) -> Result<EventId> {
        let tags = vec![
            Tag::event(delegation_event_id),
            Tag::custom(TagKind::Custom("ack_type".into()), vec!["delegation".to_string()]),
        ];
        
        let content = serde_json::json!({
            "type": "delegation_ack",
            "delegation_event_id": delegation_event_id.to_hex(),
            "agent_npub": self.agent_npub,
            "timestamp": current_timestamp(),
        }).to_string();
        
        let event_builder = EventBuilder::new(Kind::Custom(KIND_DELEGATION_ACK), content, tags);
        
        let output = self.client.send_event_builder(event_builder).await
            .map_err(|e| anyhow!("Failed to publish delegation ack: {}", e))?;
        
        Ok(output.val)
    }
    
    /// Publish revocation acknowledgment (kind 28103)
    /// 
    /// Agent confirms receipt of kind 28251 from human.
    /// References the revocation event by ID.
    pub async fn publish_revocation_ack(&self, revocation_event_id: EventId) -> Result<EventId> {
        let tags = vec![
            Tag::event(revocation_event_id),
            Tag::custom(TagKind::Custom("ack_type".into()), vec!["revocation".to_string()]),
        ];
        
        let content = serde_json::json!({
            "type": "revocation_ack",
            "revocation_event_id": revocation_event_id.to_hex(),
            "agent_npub": self.agent_npub,
            "timestamp": current_timestamp(),
        }).to_string();
        
        let event_builder = EventBuilder::new(Kind::Custom(KIND_REVOCATION_ACK), content, tags);
        
        let output = self.client.send_event_builder(event_builder).await
            .map_err(|e| anyhow!("Failed to publish revocation ack: {}", e))?;
        
        Ok(output.val)
    }
    
    /// Poll for enrollment authorization events (kind 28200)
    /// 
    /// These are signed by the enterprise and tagged with the agent's npub.
    /// Returns events where this agent is authorized.
    pub async fn poll_enrollment_events(&self, agent_npub: &str) -> Result<Vec<Event>> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_ENROLLMENT_AUTH))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::P), vec![agent_npub.to_string()])
            .limit(100);
        
        let events = self.client.get_events_of(vec![filter], EventSource::relays(Some(Duration::from_secs(5)))).await
            .map_err(|e| anyhow!("Failed to fetch enrollment events: {}", e))?;
        
        Ok(events)
    }
    
    /// Poll for human delegation events (kind 28250)
    /// 
    /// Human → agent authorization events.
    /// Filtered by human's npub (the author).
    pub async fn poll_delegation_events(&self, human_npub: &str) -> Result<Vec<Event>> {
        let human_pubkey = PublicKey::from_bech32(human_npub)
            .or_else(|_| PublicKey::from_hex(human_npub))
            .map_err(|e| anyhow!("Invalid human npub: {}", e))?;
        
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_HUMAN_DELEGATION))
            .author(human_pubkey)
            .limit(100);
        
        let events = self.client.get_events_of(vec![filter], EventSource::relays(Some(Duration::from_secs(5)))).await
            .map_err(|e| anyhow!("Failed to fetch delegation events: {}", e))?;
        
        Ok(events)
    }
    
    /// Poll for revocation events (kind 28251)
    /// 
    /// Human revokes agent authorization.
    /// Filtered by human's npub (the author).
    pub async fn poll_revocation_events(&self, human_npub: &str) -> Result<Vec<Event>> {
        let human_pubkey = PublicKey::from_bech32(human_npub)
            .or_else(|_| PublicKey::from_hex(human_npub))
            .map_err(|e| anyhow!("Invalid human npub: {}", e))?;
        
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_HUMAN_REVOCATION))
            .author(human_pubkey)
            .limit(100);
        
        let events = self.client.get_events_of(vec![filter], EventSource::relays(Some(Duration::from_secs(5)))).await
            .map_err(|e| anyhow!("Failed to fetch revocation events: {}", e))?;
        
        Ok(events)
    }
    
    /// Disconnect from relay
    pub async fn disconnect(&self) -> Result<()> {
        self.client.disconnect().await?;
        Ok(())
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::storage::EncryptedFileStorage;
    use tempfile::tempdir;
    
    /// Test that we can create agent keys from identity
    /// (Does not require network - just tests key derivation)
    #[test]
    fn test_agent_keys_derivation() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        let identity = AgentIdentity::new(storage);
        
        // Skip if keyring not available (CI environment)
        match identity.initialize() {
            Ok(state) => {
                let keys = identity.get_agent_keys().unwrap();
                assert_eq!(keys.public_key().to_bech32().unwrap(), state.agent_npub);
            }
            Err(_) => {
                eprintln!("Skipping test: keyring not available");
            }
        }
    }
    
    /// Integration test: Connect to relay with NIP-42 auth
    /// Run with: cargo test test_nip42_connection -- --ignored --nocapture
    #[tokio::test]
    #[ignore] // Requires network and working keyring
    async fn test_nip42_connection() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        let identity = AgentIdentity::new(storage);
        
        // Initialize identity
        let state = identity.initialize().expect("Failed to initialize identity");
        println!("Agent npub: {}", state.agent_npub);
        
        // Create NOSTR client
        let client = NostrClient::new(&identity).await
            .expect("Failed to create NOSTR client");
        
        println!("Connected and authenticated to {}", RELAY_URL);
        assert_eq!(client.agent_npub(), state.agent_npub);
        
        // Disconnect
        client.disconnect().await.expect("Failed to disconnect");
        println!("Disconnected successfully");
    }
}
