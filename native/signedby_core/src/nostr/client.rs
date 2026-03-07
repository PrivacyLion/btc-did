// nostr/client.rs - NOSTR relay client for SignedByMe
//
// Connects to relays on QR scan, publishes audit trail events.
// NOSTR is invisible to user - no UI elements, no settings.

use anyhow::{Result, anyhow};
use nostr_sdk::prelude::*;
use std::time::Duration;

use super::{DEFAULT_RELAYS, KIND_PROOF_EVENT, KIND_PAYMENT_RECEIPT, KIND_LOGIN_COMPLETE};
use super::events::{ProofEvent, PaymentReceiptEvent, LoginCompleteEvent};

/// NOSTR client for SignedByMe audit trail
pub struct NostrClient {
    client: Client,
    keys: Keys,
    connected: bool,
}

impl NostrClient {
    /// Create a new NOSTR client with the given keys
    pub fn new(keys: Keys) -> Self {
        let client = Client::new(keys.clone());
        Self {
            client,
            keys,
            connected: false,
        }
    }
    
    /// Connect to default relays (including SignedByMe audit relay)
    /// 
    /// Called on QR scan. If connection fails to ALL relays within 3 seconds,
    /// show warning but do NOT block login - proof is also sent via REST.
    pub async fn connect(&mut self) -> Result<()> {
        self.connect_to_relays(DEFAULT_RELAYS).await
    }
    
    /// Connect to specific relays
    pub async fn connect_to_relays(&mut self, relay_urls: &[&str]) -> Result<()> {
        for url in relay_urls {
            if let Err(e) = self.client.add_relay(*url).await {
                eprintln!("Warning: Failed to add relay {}: {}", url, e);
            }
        }
        
        // Connect with 3-second timeout
        let timeout = Duration::from_secs(3);
        match tokio::time::timeout(timeout, self.client.connect()).await {
            Ok(_) => {
                self.connected = true;
                Ok(())
            }
            Err(_) => {
                // Timeout - but don't fail completely
                // Check if we connected to any relay
                let stats = self.client.relays().await;
                if stats.is_empty() {
                    Err(anyhow!("Failed to connect to any relay within 3 seconds"))
                } else {
                    self.connected = true;
                    Ok(())
                }
            }
        }
    }
    
    /// Disconnect from all relays
    pub async fn disconnect(&mut self) -> Result<()> {
        self.client.disconnect().await?;
        self.connected = false;
        Ok(())
    }
    
    /// Check if connected to at least one relay
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    
    /// Get the public key (npub) of this client
    pub fn npub(&self) -> PublicKey {
        self.keys.public_key()
    }
    
    /// Get the npub as bech32 string
    pub fn npub_bech32(&self) -> String {
        self.keys.public_key().to_bech32().unwrap_or_default()
    }
    
    /// Publish proof_event (kind 28101) to all connected relays
    /// 
    /// Contains: proof bytes, merkle_root, npub, both BOLT11 invoices
    /// Tags: nonce, client_id
    pub async fn publish_proof_event(&self, event: &ProofEvent) -> Result<EventId> {
        let tags = vec![
            Tag::custom(TagKind::Custom("nonce".into()), vec![event.nonce.clone()]),
            Tag::custom(TagKind::Custom("client_id".into()), vec![event.client_id.clone()]),
            Tag::custom(TagKind::Custom("merkle_root".into()), vec![event.merkle_root.clone()]),
            Tag::custom(TagKind::Custom("npub".into()), vec![event.npub.clone()]),
            Tag::custom(TagKind::Custom("user_invoice".into()), vec![event.user_invoice.clone()]),
            Tag::custom(TagKind::Custom("operator_invoice".into()), vec![event.operator_invoice.clone()]),
        ];
        
        let content = serde_json::json!({
            "proof": event.proof_hex,
            "merkle_root": event.merkle_root,
            "npub": event.npub,
            "user_invoice": event.user_invoice,
            "operator_invoice": event.operator_invoice,
            "timestamp": event.timestamp,
        }).to_string();
        
        let event_builder = EventBuilder::new(Kind::Custom(KIND_PROOF_EVENT), content, tags);
        
        let output = self.client.send_event_builder(event_builder).await
            .map_err(|e| anyhow!("Failed to publish proof_event: {}", e))?;
        
        Ok(output.val)
    }
    
    /// Publish payment_receipt (kind 28102) after receiving payment via NWC
    pub async fn publish_payment_receipt(&self, event: &PaymentReceiptEvent) -> Result<EventId> {
        let tags = vec![
            Tag::custom(TagKind::Custom("nonce".into()), vec![event.nonce.clone()]),
            Tag::custom(TagKind::Custom("payment_hash".into()), vec![event.payment_hash.clone()]),
        ];
        
        let content = serde_json::json!({
            "preimage": event.preimage_hex,
            "payment_hash": event.payment_hash,
            "amount_sats": event.amount_sats,
            "timestamp": event.timestamp,
        }).to_string();
        
        let event_builder = EventBuilder::new(Kind::Custom(KIND_PAYMENT_RECEIPT), content, tags);
        
        let output = self.client.send_event_builder(event_builder).await
            .map_err(|e| anyhow!("Failed to publish payment_receipt: {}", e))?;
        
        Ok(output.val)
    }
    
    /// Publish login_complete (kind 28103) after successful authentication
    pub async fn publish_login_complete(&self, event: &LoginCompleteEvent) -> Result<EventId> {
        let tags = vec![
            Tag::custom(TagKind::Custom("nonce".into()), vec![event.nonce.clone()]),
            Tag::custom(TagKind::Custom("client_id".into()), vec![event.client_id.clone()]),
        ];
        
        let content = serde_json::json!({
            "status": "complete",
            "npub": event.npub,
            "timestamp": event.timestamp,
        }).to_string();
        
        let event_builder = EventBuilder::new(Kind::Custom(KIND_LOGIN_COMPLETE), content, tags);
        
        let output = self.client.send_event_builder(event_builder).await
            .map_err(|e| anyhow!("Failed to publish login_complete: {}", e))?;
        
        Ok(output.val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_client() {
        let keys = Keys::generate();
        let client = NostrClient::new(keys.clone());
        assert_eq!(client.npub(), keys.public_key());
    }
}
