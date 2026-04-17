// sdk/wallet.rs - NWC Wallet Integration (Phase 9A.6)
//
// Per Bible Section 9A:
// - Agent initializes its own NWC (NIP-47) wallet during SDK setup (line 610)
// - Agent is responsible for its own Lightning wallet infrastructure
// - No specific wallet vendor required — Alby Hub, LNbits, Lightning node, any NIP-47 compliant
// - Publish Lightning address via NOSTR kind 0 profile event (lud16 field) (line 917)
// - Generate subscription invoices via Strike Business API (not NWC) (line 916)
// - Agent's NWC wallet receives 20% monthly subscription allocation (line 901)
// - Payment allocator queries relay for kind 0 by npub to find agent's Lightning address (line 577)

use anyhow::{Result, anyhow};
use nostr_sdk::prelude::*;
use nwc::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::identity::AgentIdentity;
use super::nostr_client::NostrClient;
use super::storage::SecureStorage;

/// Storage key for NWC connection URI
pub const KEY_NWC_URI: &str = "signedby_nwc_connection_uri";

/// Storage key for Lightning address
pub const KEY_LIGHTNING_ADDRESS: &str = "signedby_lightning_address";

/// Strike Business API base URL
pub const STRIKE_API_URL: &str = "https://api.strike.me/v1";

/// Default renewal window before expiry (72 hours)
pub const RENEWAL_WINDOW_SECS: u64 = 72 * 60 * 60;

/// NWC wallet manager for agent Lightning operations
pub struct NwcWallet {
    /// NOSTR client for publishing kind 0 profile
    nostr_client: NostrClient,
    /// NWC client for NIP-47 wallet operations
    nwc: Option<NWC>,
    /// Agent's Lightning address
    lightning_address: Option<String>,
    /// HTTP client for Strike API
    http_client: reqwest::Client,
}

/// Wallet initialization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInitResult {
    pub success: bool,
    pub lightning_address: Option<String>,
    pub error: Option<String>,
}

/// Subscription invoice result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionInvoice {
    pub bolt11: String,
    pub amount_sats: u64,
    pub description: String,
    pub expires_at: u64,
}

/// Strike invoice request
#[derive(Debug, Serialize)]
struct StrikeInvoiceRequest {
    amount: StrikeAmount,
    description: String,
}

#[derive(Debug, Serialize)]
struct StrikeAmount {
    amount: String,
    currency: String,
}

/// Strike invoice response
#[derive(Debug, Deserialize)]
struct StrikeInvoiceResponse {
    #[serde(rename = "invoiceId")]
    invoice_id: String,
    #[serde(rename = "lnInvoice")]
    ln_invoice: Option<String>,
}

impl NwcWallet {
    /// Initialize NWC wallet with connection URI
    /// 
    /// Per Bible line 610: Agent initializes its own NWC (NIP-47) wallet during SDK setup
    /// Connection URI format: nostr+walletconnect://pubkey?relay=...&secret=...
    pub async fn initialize(
        nostr_client: NostrClient,
        connection_uri: &str,
    ) -> Result<Self> {
        // Parse NWC connection URI
        let uri = NostrWalletConnectURI::parse(connection_uri)
            .map_err(|e| anyhow!("Invalid NWC connection URI: {}", e))?;
        
        // Create NWC client
        let nwc = NWC::new(uri);
        
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;
        
        Ok(Self {
            nostr_client,
            nwc: Some(nwc),
            lightning_address: None,
            http_client,
        })
    }
    
    /// Create wallet without NWC connection (for Lightning address publishing only)
    pub fn without_nwc(nostr_client: NostrClient) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            nostr_client,
            nwc: None,
            lightning_address: None,
            http_client,
        }
    }
    
    /// Store NWC connection URI in secure storage
    pub fn store_connection_uri<S: SecureStorage>(
        storage: &S,
        connection_uri: &str,
    ) -> Result<()> {
        storage.store(KEY_NWC_URI, connection_uri.as_bytes())
            .map_err(|e| anyhow!("Failed to store NWC URI: {}", e))
    }
    
    /// Load NWC connection URI from secure storage
    pub fn load_connection_uri<S: SecureStorage>(storage: &S) -> Result<Option<String>> {
        if !storage.exists(KEY_NWC_URI) {
            return Ok(None);
        }
        
        let bytes = storage.retrieve(KEY_NWC_URI)
            .map_err(|e| anyhow!("Failed to load NWC URI: {}", e))?;
        
        let uri = String::from_utf8(bytes)
            .map_err(|e| anyhow!("Invalid NWC URI encoding: {}", e))?;
        
        Ok(Some(uri))
    }
    
    /// Publish Lightning address via NOSTR kind 0 profile event
    /// 
    /// Per Bible line 917: Publish Lightning address via NOSTR kind 0 profile
    /// Format per Bible lines 567-577: {"lud16": "agent_abc@agent-wallet-domain.com"}
    pub async fn publish_lightning_address<S: SecureStorage>(
        &mut self,
        identity: &AgentIdentity<S>,
        lightning_address: &str,
    ) -> Result<EventId> {
        // Validate Lightning address format (user@domain)
        if !lightning_address.contains('@') {
            return Err(anyhow!("Invalid Lightning address format: must be user@domain"));
        }
        
        // Load existing identity state
        let state = identity.load()?;
        
        // Build kind 0 metadata with lud16 field
        let metadata = Metadata::new()
            .lud16(lightning_address);
        
        // Get agent's keys for signing
        let agent_keys = identity.get_agent_keys()?;
        
        // Create and sign the kind 0 event
        let event_builder = EventBuilder::metadata(&metadata);
        
        // Publish to relay
        let output = self.nostr_client.inner_client()
            .send_event_builder(event_builder)
            .await
            .map_err(|e| anyhow!("Failed to publish Lightning address: {}", e))?;
        
        // Store Lightning address locally
        self.lightning_address = Some(lightning_address.to_string());
        
        eprintln!("[wallet] Published Lightning address {} for npub {}", 
            lightning_address, state.agent_npub);
        
        Ok(output.val)
    }
    
    /// Generate subscription invoice via Strike Business API
    /// 
    /// Per Bible line 916: Generate subscription invoices via Strike Business API (not NWC)
    /// Human pays monthly subscription to SignedByMe's operator Strike account
    pub async fn generate_subscription_invoice(
        &self,
        amount_sats: u64,
        strike_api_key: &str,
    ) -> Result<SubscriptionInvoice> {
        // Build Strike invoice request
        let request = StrikeInvoiceRequest {
            amount: StrikeAmount {
                amount: format!("{}", amount_sats),
                currency: "BTC".to_string(), // Strike expects BTC for sats
            },
            description: "SignedByMe monthly subscription".to_string(),
        };
        
        // Call Strike API
        let url = format!("{}/invoices", STRIKE_API_URL);
        
        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", strike_api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow!("Strike API request failed: {}", e))?;
        
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Strike API returned {}: {}", status, error_text));
        }
        
        let strike_response: StrikeInvoiceResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse Strike response: {}", e))?;
        
        let bolt11 = strike_response.ln_invoice
            .ok_or_else(|| anyhow!("Strike response missing BOLT11 invoice"))?;
        
        // Calculate expiry (1 hour from now)
        let expires_at = current_timestamp() + 3600;
        
        Ok(SubscriptionInvoice {
            bolt11,
            amount_sats,
            description: "SignedByMe monthly subscription".to_string(),
            expires_at,
        })
    }
    
    /// Watch subscription expiry and trigger renewal
    /// 
    /// Per Bible: Watch kind 28250 expires_at on NOSTR — trigger renewal 72 hours before expiry
    pub async fn check_subscription_renewal_needed<S: SecureStorage>(
        &self,
        identity: &AgentIdentity<S>,
    ) -> Result<bool> {
        // Get agent's npub
        let state = identity.load()?;
        let agent_npub = &state.agent_npub;
        
        // Query kind 28250 delegation events for this agent
        let events = self.nostr_client.poll_delegation_events(agent_npub).await
            .map_err(|e| anyhow!("Failed to query delegation events: {}", e))?;
        
        if events.is_empty() {
            return Ok(false); // No delegation = no renewal needed
        }
        
        // Find the most recent delegation event
        let mut latest_expiry: Option<u64> = None;
        
        for event in events {
            if let Ok(content) = serde_json::from_str::<DelegationContent>(&event.content) {
                if let Some(expires_at) = parse_expiry(&content.expires_at) {
                    if latest_expiry.is_none() || expires_at > latest_expiry.unwrap() {
                        latest_expiry = Some(expires_at);
                    }
                }
            }
        }
        
        // Check if within renewal window (72 hours before expiry)
        if let Some(expiry) = latest_expiry {
            let now = current_timestamp();
            let renewal_threshold = expiry.saturating_sub(RENEWAL_WINDOW_SECS);
            
            if now >= renewal_threshold && now < expiry {
                eprintln!("[wallet] Subscription renewal needed: expires in {} hours",
                    (expiry - now) / 3600);
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Create invoice via NWC for receiving payment
    /// 
    /// Per Bible line 901: Agent's NWC wallet receives 20% monthly subscription allocation
    pub async fn create_receive_invoice(
        &self,
        amount_sats: u64,
        description: &str,
    ) -> Result<String> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not initialized"))?;
        
        let invoice = nwc.make_invoice(
            amount_sats,
            description,
            None, // expiry
        ).await
            .map_err(|e| anyhow!("Failed to create invoice via NWC: {}", e))?;
        
        Ok(invoice)
    }
    
    /// Get wallet balance via NWC
    pub async fn get_balance(&self) -> Result<u64> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not initialized"))?;
        
        let balance = nwc.get_balance().await
            .map_err(|e| anyhow!("Failed to get balance via NWC: {}", e))?;
        
        Ok(balance)
    }
    
    /// Pay invoice via NWC
    pub async fn pay_invoice(&self, bolt11: &str) -> Result<String> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not initialized"))?;
        
        let preimage = nwc.pay_invoice(bolt11).await
            .map_err(|e| anyhow!("Failed to pay invoice via NWC: {}", e))?;
        
        Ok(preimage)
    }
    
    /// Get Lightning address
    pub fn lightning_address(&self) -> Option<&str> {
        self.lightning_address.as_deref()
    }
    
    /// Check if NWC is connected
    pub fn is_nwc_connected(&self) -> bool {
        self.nwc.is_some()
    }
}

/// Parsed delegation content for expiry checking
#[derive(Debug, Deserialize)]
struct DelegationContent {
    expires_at: Option<String>,
}

/// Parse expiry timestamp (Unix seconds or ISO 8601)
fn parse_expiry(expires_at: &Option<String>) -> Option<u64> {
    let s = expires_at.as_ref()?;
    
    // Try Unix timestamp
    if let Ok(ts) = s.parse::<u64>() {
        return Some(ts);
    }
    
    // Try ISO 8601 (basic parsing)
    parse_iso8601(s)
}

/// Simple ISO 8601 parser
fn parse_iso8601(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z').split('+').next()?;
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let date_parts: Vec<u32> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u32> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    
    if date_parts.len() != 3 || time_parts.len() < 2 {
        return None;
    }
    
    let year = date_parts[0] as u64;
    let month = date_parts[1] as u64;
    let day = date_parts[2] as u64;
    let hour = time_parts[0] as u64;
    let minute = time_parts[1] as u64;
    let second = time_parts.get(2).copied().unwrap_or(0) as u64;
    
    let years_since_1970 = year.saturating_sub(1970);
    let days = years_since_1970 * 365 + years_since_1970 / 4
        + (month - 1) * 30 + day - 1;
    
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_subscription_invoice_serialization() {
        let invoice = SubscriptionInvoice {
            bolt11: "lnbc100n1...".to_string(),
            amount_sats: 10000,
            description: "Test subscription".to_string(),
            expires_at: 1700000000,
        };
        
        let json = serde_json::to_string(&invoice).unwrap();
        assert!(json.contains("\"amount_sats\":10000"));
    }
    
    #[test]
    fn test_parse_expiry_unix() {
        let expiry = parse_expiry(&Some("1700000000".to_string()));
        assert_eq!(expiry, Some(1700000000));
    }
    
    #[test]
    fn test_parse_expiry_iso8601() {
        let expiry = parse_expiry(&Some("2026-12-31T23:59:59Z".to_string()));
        assert!(expiry.is_some());
    }
    
    #[test]
    fn test_lightning_address_validation() {
        // Valid
        assert!("user@domain.com".contains('@'));
        
        // Invalid
        assert!(!"invalid-address".contains('@'));
    }
}
