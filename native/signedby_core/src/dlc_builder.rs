// dlc_builder.rs
// Constructs DLC contracts with 90/10 payout splits
//
// Phase 11 Architecture (Bible Section 7.4):
// - DLC builds and executes entirely on mobile device
// - Server has ZERO knowledge of DLCs
// - Settlement triggered by Breez SDK preimage receipt
// - SHA256(preimage) == payment_hash is the settlement proof
//
// Contract lifecycle:
// 1. Build: After invoice generation (nonce, payment_hash, timeout)
// 2. Pending: Waiting for payment
// 3. Settle: Breez SDK delivers preimage → verify → settled
// 4. Timeout: 10 minutes with no payment → refunded

use anyhow::{Result, anyhow};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, XOnlyPublicKey, Message};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::key_manager::ManagedKey;
use crate::dlc_oracle::{verify_preimage, PreimageSettlement};

/// Default timeout for DLC contracts (10 minutes)
const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Payout split configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutSplit {
    pub user_pct: u8,
    pub operator_pct: u8,
}

impl Default for PayoutSplit {
    fn default() -> Self {
        Self {
            user_pct: 90,
            operator_pct: 10,
        }
    }
}

impl PayoutSplit {
    pub fn new(user_pct: u8, operator_pct: u8) -> Result<Self> {
        if user_pct + operator_pct != 100 {
            return Err(anyhow!("Payout split must sum to 100"));
        }
        Ok(Self { user_pct, operator_pct })
    }
    
    /// Calculate actual amounts from total sats
    pub fn calculate(&self, total_sats: u64) -> (u64, u64) {
        let user_amount = (total_sats * self.user_pct as u64) / 100;
        let operator_amount = total_sats - user_amount;
        (user_amount, operator_amount)
    }
}

/// Oracle information for DLC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleInfo {
    pub name: String,
    pub pubkey_hex: String,
    pub x_only_pubkey: Option<String>,
}

/// Possible outcomes for a DLC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DlcOutcome {
    /// Payment verified, execute 90/10 split
    Paid,
    /// Payment failed or timeout, refund
    Refund,
    /// Custom outcome string
    Custom(String),
}

impl DlcOutcome {
    pub fn as_str(&self) -> &str {
        match self {
            DlcOutcome::Paid => "paid=true",
            DlcOutcome::Refund => "refund=true",
            DlcOutcome::Custom(s) => s,
        }
    }
    
    /// Create tagged hash for signing (BIP340 style)
    pub fn tagged_hash(&self) -> [u8; 32] {
        let tag = "DLC/outcome/v1";
        let mut hasher = Sha256::new();
        hasher.update(tag.as_bytes());
        let tag_hash = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(&tag_hash);
        hasher.update(&tag_hash);
        hasher.update(self.as_str().as_bytes());
        
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// DLC contract status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractStatus {
    /// Waiting for payment
    Pending,
    /// Payment received, DLC settled
    Settled,
    /// Timeout expired, no payment received
    Refunded,
    /// Settlement failed (invalid preimage)
    Failed,
}

impl ContractStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ContractStatus::Pending => "pending",
            ContractStatus::Settled => "settled",
            ContractStatus::Refunded => "refunded",
            ContractStatus::Failed => "failed",
        }
    }
}

/// A DLC contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcContract {
    pub contract_id: String,
    pub created_at: u64,
    pub user_did: String,
    pub user_pubkey_hex: String,
    pub oracle: OracleInfo,
    pub outcomes: Vec<String>,
    pub payout_split: PayoutSplit,
    pub amount_sats: u64,
    pub status: String,
    /// Adaptor signature point for "paid" outcome (hex)
    pub adaptor_point_hex: Option<String>,
    /// Contract script hash (for verification)
    pub script_hash_hex: Option<String>,
    
    // Phase 11 additions for Breez preimage settlement
    /// Login nonce (from QR code)
    pub nonce: Option<String>,
    /// Payment hash for the user's 90% invoice (32 bytes, hex)
    pub payment_hash_hex: Option<String>,
    /// Contract timeout (Unix timestamp)
    pub timeout_at: Option<u64>,
    /// Preimage received from Breez SDK (32 bytes, hex) - set on settlement
    pub preimage_hex: Option<String>,
    /// Settlement timestamp
    pub settled_at: Option<u64>,
}

impl DlcContract {
    /// Create a new DLC contract (legacy - for backward compatibility)
    pub fn new(
        user_key: &ManagedKey,
        oracle: OracleInfo,
        amount_sats: u64,
        payout_split: PayoutSplit,
    ) -> Result<Self> {
        Self::new_with_payment(user_key, oracle, amount_sats, payout_split, None, None)
    }
    
    /// Create a new DLC contract with payment hash for Breez settlement
    /// 
    /// Phase 11: This is the production constructor.
    /// 
    /// @param nonce Login identifier from QR code
    /// @param payment_hash_hex Payment hash for the user's 90% invoice (from Breez SDK)
    pub fn new_with_payment(
        user_key: &ManagedKey,
        oracle: OracleInfo,
        amount_sats: u64,
        payout_split: PayoutSplit,
        nonce: Option<String>,
        payment_hash_hex: Option<String>,
    ) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate contract ID from components
        let mut hasher = Sha256::new();
        hasher.update(user_key.pubkey_hex().as_bytes());
        hasher.update(oracle.pubkey_hex.as_bytes());
        hasher.update(&now.to_le_bytes());
        hasher.update(&amount_sats.to_le_bytes());
        if let Some(ref n) = nonce {
            hasher.update(n.as_bytes());
        }
        let contract_id = hex::encode(&hasher.finalize()[..16]);
        
        // Generate adaptor point (simplified - in real DLC this is more complex)
        let adaptor_point = generate_adaptor_point(user_key, &oracle, &DlcOutcome::Paid)?;
        
        // Generate script hash for the contract
        let script_hash = generate_contract_script_hash(
            &user_key.x_only_pubkey_hex(),
            &oracle.pubkey_hex,
            &payout_split,
        )?;
        
        // Set timeout to 10 minutes from now
        let timeout_at = now + DEFAULT_TIMEOUT_SECS;
        
        Ok(Self {
            contract_id,
            created_at: now,
            user_did: user_key.to_did(),
            user_pubkey_hex: user_key.pubkey_hex(),
            oracle,
            outcomes: vec!["paid=true".to_string(), "refund=true".to_string()],
            payout_split,
            amount_sats,
            status: ContractStatus::Pending.as_str().to_string(),
            adaptor_point_hex: Some(adaptor_point),
            script_hash_hex: Some(script_hash),
            // Phase 11 fields
            nonce,
            payment_hash_hex,
            timeout_at: Some(timeout_at),
            preimage_hex: None,
            settled_at: None,
        })
    }
    
    /// Settle the DLC with a preimage from Breez SDK
    /// 
    /// This is the core settlement function for Phase 11:
    /// - Receives preimage from Breez SDK payment notification
    /// - Verifies SHA256(preimage) == payment_hash
    /// - If valid, marks contract as settled
    /// 
    /// @param preimage_hex The preimage from Breez SDK (32 bytes, hex)
    /// @return Ok(()) if settled successfully, Err if invalid
    pub fn settle(&mut self, preimage_hex: &str) -> Result<()> {
        // Check status
        if self.status != ContractStatus::Pending.as_str() {
            return Err(anyhow!("Contract is not pending, current status: {}", self.status));
        }
        
        // Need payment hash to verify
        let payment_hash = self.payment_hash_hex.as_ref()
            .ok_or_else(|| anyhow!("No payment_hash set on contract"))?;
        
        // Verify preimage: SHA256(preimage) == payment_hash
        if !verify_preimage(preimage_hex, payment_hash) {
            self.status = ContractStatus::Failed.as_str().to_string();
            return Err(anyhow!("Invalid preimage: SHA256(preimage) != payment_hash"));
        }
        
        // Settlement successful
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.preimage_hex = Some(preimage_hex.to_string());
        self.settled_at = Some(now);
        self.status = ContractStatus::Settled.as_str().to_string();
        
        Ok(())
    }
    
    /// Check if the contract has timed out (10 minutes with no payment)
    pub fn is_timed_out(&self) -> bool {
        if self.status != ContractStatus::Pending.as_str() {
            return false;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.timeout_at.map(|t| now > t).unwrap_or(false)
    }
    
    /// Handle timeout - mark contract as refunded
    pub fn handle_timeout(&mut self) -> Result<()> {
        if !self.is_timed_out() {
            return Err(anyhow!("Contract has not timed out"));
        }
        
        self.status = ContractStatus::Refunded.as_str().to_string();
        Ok(())
    }
    
    /// Get seconds until timeout (0 if already timed out)
    pub fn seconds_until_timeout(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.timeout_at
            .map(|t| if t > now { t - now } else { 0 })
            .unwrap_or(0)
    }
    
    /// Check if contract is settled
    pub fn is_settled(&self) -> bool {
        self.status == ContractStatus::Settled.as_str()
    }
    
    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("JSON serialization failed: {}", e))
    }
}

/// Generate an adaptor point for a DLC outcome
/// In a real implementation, this creates a point that can only be completed
/// with the oracle's signature on the outcome
fn generate_adaptor_point(
    user_key: &ManagedKey,
    oracle: &OracleInfo,
    outcome: &DlcOutcome,
) -> Result<String> {
    let secp = Secp256k1::new();
    
    // Parse oracle pubkey
    let oracle_pubkey_bytes = hex::decode(&oracle.pubkey_hex)
        .map_err(|e| anyhow!("Invalid oracle pubkey hex: {}", e))?;
    
    let oracle_pubkey = PublicKey::from_slice(&oracle_pubkey_bytes)
        .map_err(|e| anyhow!("Invalid oracle pubkey: {}", e))?;
    
    // Create adaptor point: H(user_pubkey || oracle_pubkey || outcome) * G
    // This is a simplified version - real DLCs use more sophisticated adaptor signatures
    let mut hasher = Sha256::new();
    hasher.update(&user_key.public_key.serialize());
    hasher.update(&oracle_pubkey.serialize());
    hasher.update(outcome.as_str().as_bytes());
    let adaptor_secret = hasher.finalize();
    
    // Use the hash as a "secret" to derive a point
    let adaptor_key = SecretKey::from_slice(&adaptor_secret)
        .map_err(|e| anyhow!("Invalid adaptor secret: {}", e))?;
    let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_key);
    
    Ok(hex::encode(adaptor_point.serialize()))
}

/// Generate a script hash for the DLC contract
fn generate_contract_script_hash(
    user_x_only_pubkey: &str,
    oracle_pubkey: &str,
    payout_split: &PayoutSplit,
) -> Result<String> {
    // Simplified Taproot script structure:
    // The real implementation would create actual Bitcoin Script
    let mut hasher = Sha256::new();
    hasher.update(b"taproot_dlc_v1");
    hasher.update(user_x_only_pubkey.as_bytes());
    hasher.update(oracle_pubkey.as_bytes());
    hasher.update(&[payout_split.user_pct, payout_split.operator_pct]);
    
    Ok(hex::encode(hasher.finalize()))
}

/// Oracle attestation for a DLC outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleAttestation {
    pub outcome: String,
    pub signature_hex: String,
    pub pubkey_hex: String,
    pub timestamp: u64,
}

/// Sign an outcome as an oracle (Schnorr signature)
pub fn oracle_sign_outcome(
    oracle_key: &ManagedKey,
    outcome: &DlcOutcome,
) -> Result<OracleAttestation> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Sign the outcome's tagged hash
    let outcome_hash = outcome.tagged_hash();
    let sig = oracle_key.sign_schnorr(&outcome_hash)?;
    
    Ok(OracleAttestation {
        outcome: outcome.as_str().to_string(),
        signature_hex: sig,
        pubkey_hex: oracle_key.x_only_pubkey_hex(),
        timestamp: now,
    })
}

/// Verify an oracle attestation
pub fn verify_oracle_attestation(
    attestation: &OracleAttestation,
    oracle_x_only_pubkey: &XOnlyPublicKey,
) -> Result<bool> {
    let secp = Secp256k1::new();
    
    // Reconstruct the outcome
    let outcome = if attestation.outcome == "paid=true" {
        DlcOutcome::Paid
    } else if attestation.outcome == "refund=true" {
        DlcOutcome::Refund
    } else {
        DlcOutcome::Custom(attestation.outcome.clone())
    };
    
    let outcome_hash = outcome.tagged_hash();
    let msg = Message::from_digest_slice(&outcome_hash)
        .map_err(|e| anyhow!("Invalid message: {}", e))?;
    
    let sig_bytes = hex::decode(&attestation.signature_hex)
        .map_err(|e| anyhow!("Invalid signature hex: {}", e))?;
    let sig = SchnorrSignature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("Invalid signature: {}", e))?;
    
    Ok(secp.verify_schnorr(&sig, &msg, oracle_x_only_pubkey).is_ok())
}

/// Complete a DLC with an oracle attestation
/// Returns the completed contract state
pub fn complete_dlc_with_attestation(
    contract: &mut DlcContract,
    attestation: &OracleAttestation,
) -> Result<()> {
    // Verify the attestation matches expected outcomes
    if !contract.outcomes.contains(&attestation.outcome) {
        return Err(anyhow!("Attestation outcome not in contract outcomes"));
    }
    
    // Update contract status
    contract.status = format!("completed:{}", attestation.outcome);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlc_oracle::compute_payment_hash;
    
    #[test]
    fn test_payout_split() {
        let split = PayoutSplit::default();
        let (user, operator) = split.calculate(1000);
        assert_eq!(user, 900);
        assert_eq!(operator, 100);
    }
    
    #[test]
    fn test_outcome_tagged_hash() {
        let outcome = DlcOutcome::Paid;
        let hash1 = outcome.tagged_hash();
        let hash2 = outcome.tagged_hash();
        assert_eq!(hash1, hash2); // Deterministic
        
        let other_outcome = DlcOutcome::Refund;
        let hash3 = other_outcome.tagged_hash();
        assert_ne!(hash1, hash3); // Different outcomes = different hashes
    }
    
    // ========== Phase 11: Preimage Settlement Tests ==========
    
    #[test]
    fn test_contract_settle_valid_preimage() {
        // Create a known preimage and compute its hash
        let preimage = "aa".repeat(32);
        let payment_hash = compute_payment_hash(&preimage).unwrap();
        
        // Create contract with payment hash
        let mut contract = DlcContract {
            contract_id: "test_123".to_string(),
            created_at: 0,
            user_did: "did:btcr:test".to_string(),
            user_pubkey_hex: "".to_string(),
            oracle: OracleInfo {
                name: "test".to_string(),
                pubkey_hex: "".to_string(),
                x_only_pubkey: None,
            },
            outcomes: vec!["paid=true".to_string()],
            payout_split: PayoutSplit::default(),
            amount_sats: 100,
            status: "pending".to_string(),
            adaptor_point_hex: None,
            script_hash_hex: None,
            nonce: Some("nonce_123".to_string()),
            payment_hash_hex: Some(payment_hash),
            timeout_at: Some(u64::MAX), // Won't timeout
            preimage_hex: None,
            settled_at: None,
        };
        
        // Settle with valid preimage
        let result = contract.settle(&preimage);
        assert!(result.is_ok());
        assert!(contract.is_settled());
        assert_eq!(contract.preimage_hex, Some(preimage));
        assert!(contract.settled_at.is_some());
    }
    
    #[test]
    fn test_contract_settle_invalid_preimage() {
        let preimage = "bb".repeat(32);
        let payment_hash = compute_payment_hash(&preimage).unwrap();
        
        let mut contract = DlcContract {
            contract_id: "test_456".to_string(),
            created_at: 0,
            user_did: "did:btcr:test".to_string(),
            user_pubkey_hex: "".to_string(),
            oracle: OracleInfo {
                name: "test".to_string(),
                pubkey_hex: "".to_string(),
                x_only_pubkey: None,
            },
            outcomes: vec!["paid=true".to_string()],
            payout_split: PayoutSplit::default(),
            amount_sats: 100,
            status: "pending".to_string(),
            adaptor_point_hex: None,
            script_hash_hex: None,
            nonce: None,
            payment_hash_hex: Some(payment_hash),
            timeout_at: Some(u64::MAX),
            preimage_hex: None,
            settled_at: None,
        };
        
        // Try to settle with wrong preimage
        let wrong_preimage = "cc".repeat(32);
        let result = contract.settle(&wrong_preimage);
        
        assert!(result.is_err());
        assert_eq!(contract.status, "failed");
        assert!(!contract.is_settled());
    }
    
    #[test]
    fn test_contract_timeout() {
        let mut contract = DlcContract {
            contract_id: "test_timeout".to_string(),
            created_at: 0,
            user_did: "did:btcr:test".to_string(),
            user_pubkey_hex: "".to_string(),
            oracle: OracleInfo {
                name: "test".to_string(),
                pubkey_hex: "".to_string(),
                x_only_pubkey: None,
            },
            outcomes: vec!["paid=true".to_string()],
            payout_split: PayoutSplit::default(),
            amount_sats: 100,
            status: "pending".to_string(),
            adaptor_point_hex: None,
            script_hash_hex: None,
            nonce: None,
            payment_hash_hex: None,
            timeout_at: Some(0), // Already expired
            preimage_hex: None,
            settled_at: None,
        };
        
        assert!(contract.is_timed_out());
        
        let result = contract.handle_timeout();
        assert!(result.is_ok());
        assert_eq!(contract.status, "refunded");
    }
    
    #[test]
    fn test_contract_not_timed_out() {
        let contract = DlcContract {
            contract_id: "test_no_timeout".to_string(),
            created_at: 0,
            user_did: "did:btcr:test".to_string(),
            user_pubkey_hex: "".to_string(),
            oracle: OracleInfo {
                name: "test".to_string(),
                pubkey_hex: "".to_string(),
                x_only_pubkey: None,
            },
            outcomes: vec!["paid=true".to_string()],
            payout_split: PayoutSplit::default(),
            amount_sats: 100,
            status: "pending".to_string(),
            adaptor_point_hex: None,
            script_hash_hex: None,
            nonce: None,
            payment_hash_hex: None,
            timeout_at: Some(u64::MAX), // Far future
            preimage_hex: None,
            settled_at: None,
        };
        
        assert!(!contract.is_timed_out());
        assert!(contract.seconds_until_timeout() > 0);
    }
    
    #[test]
    fn test_cannot_settle_twice() {
        let preimage = "dd".repeat(32);
        let payment_hash = compute_payment_hash(&preimage).unwrap();
        
        let mut contract = DlcContract {
            contract_id: "test_double_settle".to_string(),
            created_at: 0,
            user_did: "did:btcr:test".to_string(),
            user_pubkey_hex: "".to_string(),
            oracle: OracleInfo {
                name: "test".to_string(),
                pubkey_hex: "".to_string(),
                x_only_pubkey: None,
            },
            outcomes: vec!["paid=true".to_string()],
            payout_split: PayoutSplit::default(),
            amount_sats: 100,
            status: "pending".to_string(),
            adaptor_point_hex: None,
            script_hash_hex: None,
            nonce: None,
            payment_hash_hex: Some(payment_hash),
            timeout_at: Some(u64::MAX),
            preimage_hex: None,
            settled_at: None,
        };
        
        // First settle should succeed
        assert!(contract.settle(&preimage).is_ok());
        
        // Second settle should fail
        assert!(contract.settle(&preimage).is_err());
    }
}
