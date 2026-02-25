// lightning.rs
// Lightning Network payment generation and verification

use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};

/// A Lightning payment hash (32 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentHash {
    pub hash_hex: String,
}

impl PaymentHash {
    /// Create from a preimage
    pub fn from_preimage(preimage: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        Self {
            hash_hex: hex::encode(hasher.finalize()),
        }
    }
    
    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(anyhow!("Payment hash must be 32 bytes (64 hex chars)"));
        }
        hex::decode(hex)?; // Validate hex
        Ok(Self { hash_hex: hex.to_lowercase() })
    }
    
    /// Verify that a preimage matches this hash
    pub fn verify_preimage(&self, preimage: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        let computed = hex::encode(hasher.finalize());
        computed.eq_ignore_ascii_case(&self.hash_hex)
    }
}

/// A Lightning preimage (32 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preimage {
    pub preimage_hex: String,
    pub hash: PaymentHash,
}

impl Preimage {
    /// Generate a new random preimage
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        let preimage_hex = hex::encode(bytes);
        let hash = PaymentHash::from_preimage(&bytes);
        Self { preimage_hex, hash }
    }
    
    /// Create from existing hex
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(anyhow!("Preimage must be 32 bytes (64 hex chars)"));
        }
        let bytes = hex::decode(hex)?;
        let hash = PaymentHash::from_preimage(&bytes);
        Ok(Self { 
            preimage_hex: hex.to_lowercase(),
            hash,
        })
    }
    
    /// Get the payment hash
    pub fn payment_hash(&self) -> &PaymentHash {
        &self.hash
    }
    
    /// Verify this preimage against a payment hash
    pub fn verify(&self, payment_hash: &PaymentHash) -> bool {
        self.hash.hash_hex.eq_ignore_ascii_case(&payment_hash.hash_hex)
    }
}

/// Lightning invoice metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceMetadata {
    pub description: String,
    pub amount_msat: Option<u64>,
    pub expiry_secs: u32,
    pub created_at: u64,
    pub expires_at: u64,
}

/// A simplified Lightning invoice (for mobile use)
/// Note: Real BOLT11 invoice generation requires more infrastructure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningInvoice {
    pub payment_hash: PaymentHash,
    pub metadata: InvoiceMetadata,
    /// The invoice string (BOLT11 format or simplified)
    pub invoice_string: String,
    /// Lightning address (if applicable)
    pub ln_address: Option<String>,
    /// Whether this is a real BOLT11 or simplified format
    pub format: String,
}

impl LightningInvoice {
    /// Create a simplified invoice (not full BOLT11)
    /// For actual BOLT11, you'd need a Lightning node or LNURL endpoint
    pub fn create_simple(
        preimage: &Preimage,
        amount_sats: Option<u64>,
        description: &str,
        expiry_secs: u32,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let amount_msat = amount_sats.map(|s| s * 1000);
        
        let metadata = InvoiceMetadata {
            description: description.to_string(),
            amount_msat,
            expiry_secs,
            created_at: now,
            expires_at: now + expiry_secs as u64,
        };
        
        // Create a simplified invoice string
        // Format: lnsb<amount>_<payment_hash>_<expiry>
        let amount_str = amount_sats.map(|s| format!("{}", s)).unwrap_or_default();
        let invoice_string = format!(
            "lnsb{}_{}_{}",
            amount_str,
            &preimage.hash.hash_hex[..16],
            expiry_secs
        );
        
        Self {
            payment_hash: preimage.hash.clone(),
            metadata,
            invoice_string,
            ln_address: None,
            format: "simplified-v1".to_string(),
        }
    }
    
    /// Check if invoice is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.metadata.expires_at
    }
    
    /// Get amount in sats (if specified)
    pub fn amount_sats(&self) -> Option<u64> {
        self.metadata.amount_msat.map(|m| m / 1000)
    }
}

/// Payment Request Package for DLC-tagged payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequestPackage {
    pub schema: String,
    pub prp_type: String,
    pub payment_hash: String,
    pub amount_sats: u64,
    pub description: String,
    pub expiry_secs: u32,
    pub created_at: u64,
    pub expires_at: u64,
    /// DID of the payee
    pub payee_did: String,
    /// Lightning address of the payee
    pub payee_ln_address: String,
    /// DLC contract ID (if applicable)
    pub dlc_contract_id: Option<String>,
    /// Payout split
    pub split: Option<PayoutSplit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutSplit {
    pub user_pct: u8,
    pub operator_pct: u8,
}

impl PaymentRequestPackage {
    /// Create a new PRP
    pub fn new(
        preimage: &Preimage,
        amount_sats: u64,
        description: &str,
        payee_did: &str,
        payee_ln_address: &str,
        expiry_secs: u32,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            schema: "signedby.me/prp/v1".to_string(),
            prp_type: "payment_request".to_string(),
            payment_hash: preimage.hash.hash_hex.clone(),
            amount_sats,
            description: description.to_string(),
            expiry_secs,
            created_at: now,
            expires_at: now + expiry_secs as u64,
            payee_did: payee_did.to_string(),
            payee_ln_address: payee_ln_address.to_string(),
            dlc_contract_id: None,
            split: Some(PayoutSplit {
                user_pct: 90,
                operator_pct: 10,
            }),
        }
    }
    
    /// Add DLC contract reference
    pub fn with_dlc_contract(mut self, contract_id: &str) -> Self {
        self.dlc_contract_id = Some(contract_id.to_string());
        self
    }
    
    /// Set custom payout split
    pub fn with_split(mut self, user_pct: u8, operator_pct: u8) -> Self {
        self.split = Some(PayoutSplit { user_pct, operator_pct });
        self
    }
    
    /// Check if PRP is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
    
    /// Convert to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("JSON serialization failed: {}", e))
    }
}

/// Payment verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentVerification {
    pub verified: bool,
    pub payment_hash: String,
    pub preimage_hex: Option<String>,
    pub verified_at: u64,
    pub error: Option<String>,
}

/// Verify a payment by checking preimage against payment hash
pub fn verify_payment(payment_hash: &str, preimage_hex: &str) -> PaymentVerification {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Decode preimage
    let preimage_bytes = match hex::decode(preimage_hex) {
        Ok(b) => b,
        Err(e) => return PaymentVerification {
            verified: false,
            payment_hash: payment_hash.to_string(),
            preimage_hex: None,
            verified_at: now,
            error: Some(format!("Invalid preimage hex: {}", e)),
        },
    };
    
    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(&preimage_bytes);
    let computed_hash = hex::encode(hasher.finalize());
    
    let verified = computed_hash.eq_ignore_ascii_case(payment_hash);
    
    PaymentVerification {
        verified,
        payment_hash: payment_hash.to_string(),
        preimage_hex: if verified { Some(preimage_hex.to_string()) } else { None },
        verified_at: now,
        error: if !verified { Some("Preimage does not match payment hash".to_string()) } else { None },
    }
}

/// Parse a Lightning address into username and domain
pub fn parse_ln_address(address: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = address.split('@').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid Lightning address format"));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Generate an LNURL-pay compatible callback URL
pub fn generate_lnurl_callback(ln_address: &str) -> Result<String> {
    let (username, domain) = parse_ln_address(ln_address)?;
    Ok(format!("https://{}/.well-known/lnurlp/{}", domain, username))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_preimage_generation() {
        let preimage = Preimage::generate();
        assert_eq!(preimage.preimage_hex.len(), 64);
        assert_eq!(preimage.hash.hash_hex.len(), 64);
    }
    
    #[test]
    fn test_preimage_verification() {
        let preimage = Preimage::generate();
        assert!(preimage.verify(&preimage.hash));
        
        // Wrong preimage should fail
        let other = Preimage::generate();
        assert!(!other.verify(&preimage.hash));
    }
    
    #[test]
    fn test_payment_verification() {
        let preimage = Preimage::generate();
        let result = verify_payment(&preimage.hash.hash_hex, &preimage.preimage_hex);
        assert!(result.verified);
        
        // Wrong preimage
        let other = Preimage::generate();
        let result = verify_payment(&preimage.hash.hash_hex, &other.preimage_hex);
        assert!(!result.verified);
    }
    
    #[test]
    fn test_ln_address_parsing() {
        let (user, domain) = parse_ln_address("scott@getalby.com").unwrap();
        assert_eq!(user, "scott");
        assert_eq!(domain, "getalby.com");
    }
    
    #[test]
    fn test_prp_creation() {
        let preimage = Preimage::generate();
        let prp = PaymentRequestPackage::new(
            &preimage,
            1000,
            "Test payment",
            "did:btcr:abc123",
            "scott@getalby.com",
            3600,
        );
        assert_eq!(prp.amount_sats, 1000);
        assert!(!prp.is_expired());
    }
}
