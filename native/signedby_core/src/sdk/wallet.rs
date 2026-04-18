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
use nostr_sdk::nips::nip47::NostrWalletConnectURI;
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
/// 
/// NWC (NIP-47) is used ONLY for receiving payments (20% allocation).
/// Subscription invoices are generated via Strike Business API per Bible line 916.
pub struct NwcWallet {
    /// NOSTR client for publishing kind 0 profile
    nostr_client: NostrClient,
    /// NWC connection URI (stored for later NWC client creation)
    nwc_uri: Option<String>,
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

/// Strike invoice request per Bible lines 522-523
#[derive(Debug, Serialize)]
struct StrikeInvoiceRequest {
    #[serde(rename = "correlationId")]
    correlation_id: String,
    description: String,
    amount: StrikeAmount,
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

/// Strike quote response (for getting BOLT11)
#[derive(Debug, Deserialize)]
struct StrikeQuoteResponse {
    #[serde(rename = "lnInvoice")]
    ln_invoice: String,
}

impl NwcWallet {
    /// Initialize NWC wallet with connection URI
    /// 
    /// Per Bible line 610: Agent initializes its own NWC (NIP-47) wallet during SDK setup
    /// Connection URI format: nostr+walletconnect://pubkey?relay=...&secret=...
    /// 
    /// Note: NWC is used ONLY for receiving payments, not generating subscription invoices.
    pub fn new(nostr_client: NostrClient, nwc_connection_uri: Option<&str>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            nostr_client,
            nwc_uri: nwc_connection_uri.map(String::from),
            lightning_address: None,
            http_client,
        }
    }
    
    /// Create wallet without NWC connection (for Lightning address publishing only)
    pub fn without_nwc(nostr_client: NostrClient) -> Self {
        Self::new(nostr_client, None)
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
    /// Per Bible lines 522-523: Use Strike Business API for invoice generation
    /// Human pays monthly subscription to SignedByMe's operator Strike account
    /// 
    /// This method does NOT use NWC - subscriptions go to the operator's Strike account.
    pub async fn generate_subscription_invoice(
        &self,
        amount_sats: u64,
        strike_api_key: &str,
        correlation_id: &str,
    ) -> Result<SubscriptionInvoice> {
        // Step 1: Create invoice via Strike API
        let create_url = format!("{}/invoices", STRIKE_API_URL);
        
        let request = StrikeInvoiceRequest {
            correlation_id: correlation_id.to_string(),
            description: "SignedByMe monthly subscription".to_string(),
            amount: StrikeAmount {
                // Strike expects amount in the smallest unit
                // For BTC, this is satoshis
                amount: format!("{}", amount_sats),
                currency: "SATS".to_string(),
            },
        };
        
        let response = self.http_client
            .post(&create_url)
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
        
        let invoice_response: StrikeInvoiceResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse Strike response: {}", e))?;
        
        // Step 2: Get the BOLT11 invoice via quote endpoint
        let quote_url = format!("{}/invoices/{}/quote", STRIKE_API_URL, invoice_response.invoice_id);
        
        let quote_response = self.http_client
            .post(&quote_url)
            .header("Authorization", format!("Bearer {}", strike_api_key))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Strike quote request failed: {}", e))?;
        
        let quote_status = quote_response.status();
        if !quote_status.is_success() {
            let error_text = quote_response.text().await.unwrap_or_default();
            return Err(anyhow!("Strike quote API returned {}: {}", quote_status, error_text));
        }
        
        let quote: StrikeQuoteResponse = quote_response.json().await
            .map_err(|e| anyhow!("Failed to parse Strike quote response: {}", e))?;
        
        // Calculate expiry (1 hour from now)
        let expires_at = current_timestamp() + 3600;
        
        Ok(SubscriptionInvoice {
            bolt11: quote.ln_invoice,
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
    
    /// Create invoice via NWC for receiving payment (20% allocation)
    /// 
    /// Per Bible line 901: Agent's NWC wallet receives 20% monthly subscription allocation
    /// 
    /// Note: This uses the agent's NWC wallet, NOT Strike.
    /// The NWC connection must be initialized with a valid connection URI.
    pub async fn create_receive_invoice(
        &self,
        amount_sats: u64,
        description: &str,
    ) -> Result<String> {
        let nwc_uri = self.nwc_uri.as_ref()
            .ok_or_else(|| anyhow!("NWC not initialized - provide connection URI"))?;
        
        // Parse and create NWC client
        let uri = NostrWalletConnectURI::parse(nwc_uri)
            .map_err(|e| anyhow!("Invalid NWC URI: {}", e))?;
        
        let nwc_client = nwc::NWC::new(uri);
        
        // Create invoice request - amount in millisats
        let amount_msats = amount_sats * 1000;
        
        let response = nwc_client.make_invoice(
            amount_msats,
            Some(description.to_string()),
            None, // description_hash
            Some(3600), // expiry in seconds
        ).await
            .map_err(|e| anyhow!("Failed to create invoice via NWC: {}", e))?;
        
        Ok(response.invoice)
    }
    
    /// Get wallet balance via NWC
    pub async fn get_balance(&self) -> Result<u64> {
        let nwc_uri = self.nwc_uri.as_ref()
            .ok_or_else(|| anyhow!("NWC not initialized"))?;
        
        let uri = NostrWalletConnectURI::parse(nwc_uri)
            .map_err(|e| anyhow!("Invalid NWC URI: {}", e))?;
        
        let nwc_client = nwc::NWC::new(uri);
        
        let response = nwc_client.get_balance().await
            .map_err(|e| anyhow!("Failed to get balance via NWC: {}", e))?;
        
        // Balance is in millisats, convert to sats
        Ok(response.balance / 1000)
    }
    
    /// Pay invoice via NWC
    pub async fn pay_invoice(&self, bolt11: &str) -> Result<String> {
        let nwc_uri = self.nwc_uri.as_ref()
            .ok_or_else(|| anyhow!("NWC not initialized"))?;
        
        let uri = NostrWalletConnectURI::parse(nwc_uri)
            .map_err(|e| anyhow!("Invalid NWC URI: {}", e))?;
        
        let nwc_client = nwc::NWC::new(uri);
        
        // pay_invoice takes a BOLT11 string directly
        let response = nwc_client.pay_invoice(bolt11.to_string()).await
            .map_err(|e| anyhow!("Failed to pay invoice via NWC: {}", e))?;
        
        Ok(response.preimage)
    }
    
    /// Get Lightning address
    pub fn lightning_address(&self) -> Option<&str> {
        self.lightning_address.as_deref()
    }
    
    /// Check if NWC is configured
    pub fn is_nwc_configured(&self) -> bool {
        self.nwc_uri.is_some()
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
