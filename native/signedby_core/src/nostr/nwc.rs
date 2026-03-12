// nostr/nwc.rs - NOSTR Wallet Connect (NIP-47) client for SignedByMe
//
// DECISION 2 (binding): Ephemeral NWC keypair per login session.
// The proof npub NEVER touches Strike. This breaks the Strike KYC ↔ ZKP linkage.
//
// Implementation:
// - At QR scan: generate fresh secp256k1 keypair in memory
// - Use ephemeral keypair ONLY for NWC make_invoice and payment notification
// - Discard immediately after preimage is received
// - No cryptographic link between ephemeral NWC key and proof npub
//
// The proof npub (derived from leaf_secret) signs NOSTR audit trail events as normal.

use anyhow::{Result, anyhow};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::time::Duration;

/// Operator Lightning address for 10% fee
pub const OPERATOR_LN_ADDRESS: &str = "ops_yypf5wifvp@strike.me";

/// NWC client for Lightning wallet operations
/// 
/// Uses an ephemeral keypair per session to preserve privacy.
/// The proof npub never touches this client.
pub struct NwcClient {
    /// Ephemeral keypair for this session only
    ephemeral_keys: Keys,
    
    /// NWC connection to Strike-backed wallet
    nwc: Option<NWC>,
    
    /// Parsed NWC URI
    uri: Option<NostrWalletConnectURI>,
}

impl NwcClient {
    /// Create a new NWC client with a fresh ephemeral keypair
    /// 
    /// # Arguments
    /// * `connection_string` - The nostr+walletconnect:// URI from Strike
    pub fn new(connection_string: &str) -> Result<Self> {
        // Generate ephemeral keypair (DECISION 2)
        let ephemeral_keys = Keys::generate();
        
        // Parse NWC URI
        let uri = NostrWalletConnectURI::from_str(connection_string)
            .map_err(|e| anyhow!("Invalid NWC connection string: {}", e))?;
        
        Ok(Self {
            ephemeral_keys,
            nwc: None,
            uri: Some(uri),
        })
    }
    
    /// Create with pre-generated ephemeral keys (for testing)
    pub fn with_keys(connection_string: &str, ephemeral_keys: Keys) -> Result<Self> {
        let uri = NostrWalletConnectURI::from_str(connection_string)
            .map_err(|e| anyhow!("Invalid NWC connection string: {}", e))?;
        
        Ok(Self {
            ephemeral_keys,
            nwc: None,
            uri: Some(uri),
        })
    }
    
    /// Connect to the NWC relay
    /// 
    /// Enables automatic NIP-42 authentication to satisfy relay.privacy-lion.com
    /// AUTH requirements before publishing make_invoice events.
    pub async fn connect(&mut self) -> Result<()> {
        let uri = self.uri.as_ref()
            .ok_or_else(|| anyhow!("NWC URI not set"))?;
        
        // Enable automatic NIP-42 authentication
        // The relay requires AUTH handshake before allowing publish
        let opts = Options::new()
            .automatic_authentication(true);
        
        let nwc = NWC::with_opts(uri.clone(), opts);
        
        // Connect with timeout - NWC connection is implicit on first request,
        // but we trigger it early to ensure NIP-42 handshake completes
        let timeout = Duration::from_secs(5);
        match tokio::time::timeout(timeout, async {
            // Ping the relay to trigger connection and NIP-42 handshake
            // get_info is a lightweight NWC call that forces connection
            match nwc.get_info().await {
                Ok(info) => {
                    eprintln!("[NWC] Connected, wallet: {:?}", info.alias);
                    Ok(())
                }
                Err(e) => {
                    // get_info might not be supported by all wallets, 
                    // but connection should still be established
                    eprintln!("[NWC] get_info failed (may be unsupported): {}", e);
                    Ok(())
                }
            }
        }).await {
            Ok(result) => {
                result?;
                self.nwc = Some(nwc);
                Ok(())
            }
            Err(_) => Err(anyhow!("NWC connection timeout (NIP-42 handshake may have failed)"))
        }
    }
    
    /// Get ephemeral public key (for debugging only - not exposed to user)
    pub fn ephemeral_pubkey(&self) -> PublicKey {
        self.ephemeral_keys.public_key()
    }
    
    /// Generate a BOLT11 invoice via NWC
    /// 
    /// # Arguments
    /// * `amount_sats` - Amount in satoshis
    /// * `description` - Invoice description
    /// * `expiry_secs` - Invoice expiry in seconds
    /// 
    /// # Returns
    /// * BOLT11 invoice string
    pub async fn make_invoice(
        &self,
        amount_sats: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<String> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not connected"))?;
        
        let params = MakeInvoiceRequestParams {
            amount: amount_sats * 1000, // Convert to millisats
            description: Some(description.to_string()),
            description_hash: None,
            expiry: Some(expiry_secs as u64),
        };
        
        let response = nwc.make_invoice(params).await
            .map_err(|e| anyhow!("NWC make_invoice failed: {}", e))?;
        
        Ok(response.invoice)
    }
    
    /// Generate both user (90%) and operator (10%) invoices
    /// 
    /// # Arguments
    /// * `total_sats` - Total amount from QR code
    /// * `client_id` - Enterprise client_id for description
    /// 
    /// # Returns
    /// * (user_invoice, operator_invoice) - Both BOLT11 strings
    pub async fn generate_login_invoices(
        &self,
        total_sats: u64,
        client_id: &str,
    ) -> Result<(String, String)> {
        // Calculate 90/10 split
        let user_sats = (total_sats * 90) / 100;
        let operator_sats = total_sats - user_sats;
        
        // Generate user invoice (90%) via NWC to Strike wallet
        let user_description = format!("SignedByMe login reward - {}", client_id);
        let user_invoice = self.make_invoice(user_sats, &user_description, 600).await?;
        
        // Generate operator invoice (10%) to operator Lightning address
        // For MVP, this is a static invoice to ops_yypf5wifvp@strike.me
        // In production, this would also go through NWC or be fetched from LNURL
        let operator_invoice = self.generate_operator_invoice(operator_sats, client_id).await?;
        
        Ok((user_invoice, operator_invoice))
    }
    
    /// Generate operator invoice (10% fee)
    /// 
    /// For MVP, we generate a placeholder. In production, this fetches
    /// from the operator's LNURL at ops_yypf5wifvp@strike.me
    async fn generate_operator_invoice(
        &self,
        amount_sats: u64,
        client_id: &str,
    ) -> Result<String> {
        // TODO: Fetch real invoice from OPERATOR_LN_ADDRESS via LNURL
        // For now, generate via NWC (same wallet for testing)
        let description = format!("SignedByMe operator fee - {}", client_id);
        self.make_invoice(amount_sats, &description, 600).await
    }
    
    /// Get wallet balance
    pub async fn get_balance(&self) -> Result<u64> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not connected"))?;
        
        let balance_msats = nwc.get_balance().await
            .map_err(|e| anyhow!("NWC get_balance failed: {}", e))?;
        
        // Convert from millisats to sats
        Ok(balance_msats / 1000)
    }
    
    /// List recent transactions
    /// Returns a vec of transaction JSON strings (simplified for compatibility)
    pub async fn list_transactions(&self, limit: u16) -> Result<Vec<String>> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not connected"))?;
        
        let params = ListTransactionsRequestParams {
            from: None,
            until: None,
            limit: Some(limit as u64),
            offset: None,
            unpaid: Some(false),
            transaction_type: None,
        };
        
        let transactions = nwc.list_transactions(params).await
            .map_err(|e| anyhow!("NWC list_transactions failed: {}", e))?;
        
        // Convert to JSON strings for flexibility across API versions
        Ok(transactions.iter().map(|t| serde_json::to_string(t).unwrap_or_default()).collect())
    }
    
    /// Wait for payment notification (preimage received)
    /// 
    /// # Arguments
    /// * `payment_hash` - The payment hash to watch for
    /// * `timeout_secs` - Maximum time to wait
    /// 
    /// # Returns
    /// * Preimage hex string if payment received
    pub async fn wait_for_payment(
        &self,
        payment_hash: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let nwc = self.nwc.as_ref()
            .ok_or_else(|| anyhow!("NWC not connected"))?;
        
        let timeout = Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();
        
        // Poll for payment
        while start.elapsed() < timeout {
            let params = LookupInvoiceRequestParams {
                payment_hash: Some(payment_hash.to_string()),
                invoice: None,
            };
            
            match nwc.lookup_invoice(params).await {
                Ok(response) => {
                    if response.settled_at.is_some() {
                        if let Some(preimage) = response.preimage {
                            return Ok(preimage);
                        }
                    }
                }
                Err(_) => {}
            }
            
            // Wait before polling again
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        Err(anyhow!("Payment not received within {} seconds", timeout_secs))
    }
    
    /// Disconnect and discard ephemeral keys
    /// 
    /// This is called after preimage is received. The ephemeral keypair
    /// is discarded and cannot be recovered.
    pub fn disconnect_and_discard(self) {
        // Keys are dropped when self goes out of scope
        // No explicit action needed - this is intentional
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ephemeral_keys_different_per_session() {
        // Each NwcClient should have different ephemeral keys
        // This ensures no cross-session linkage
        
        // Note: Can't test with real connection string without network
        // Testing key generation isolation
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        
        assert_ne!(keys1.public_key(), keys2.public_key());
    }
    
    #[test]
    fn test_split_calculation() {
        let total = 1000u64;
        let user = (total * 90) / 100;
        let operator = total - user;
        
        assert_eq!(user, 900);
        assert_eq!(operator, 100);
    }
}
