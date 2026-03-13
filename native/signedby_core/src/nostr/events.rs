// nostr/events.rs - NOSTR event structures for SignedByMe audit trail
//
// Event kinds:
// - 28101: proof_event (proof published after generation)
// - 28102: payment_receipt (after receiving payment)
// - 28103: login_complete (after successful authentication)

use serde::{Deserialize, Serialize};

/// Proof event (kind 28101) - Published after Groth16 proof generation
/// 
/// Contains the proof, public outputs, and both BOLT11 invoices.
/// Enterprise watches NOSTR for this event (tagged with nonce).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEvent {
    /// Unique nonce from QR code (enterprise generates)
    pub nonce: String,
    
    /// Enterprise client_id
    pub client_id: String,
    
    /// Groth16 proof bytes (hex-encoded)
    pub proof_hex: String,
    
    /// Merkle root (public output #1)
    pub merkle_root: String,
    
    /// npub (public output #2, derived from nsec inside circuit)
    pub npub: String,
    
    /// BOLT11 invoice for user's 90% share
    pub user_invoice: String,
    
    /// BOLT11 invoice for operator's 10% share (to ops_yypf5wifvp@strike.me)
    pub operator_invoice: String,
    
    /// Unix timestamp (seconds)
    pub timestamp: u64,
}

impl ProofEvent {
    pub fn new(
        nonce: String,
        client_id: String,
        proof_hex: String,
        merkle_root: String,
        npub: String,
        user_invoice: String,
        operator_invoice: String,
    ) -> Self {
        Self {
            nonce,
            client_id,
            proof_hex,
            merkle_root,
            npub,
            user_invoice,
            operator_invoice,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Payment receipt event (kind 28102) - Published after receiving 90% payment
/// 
/// Proves the user received their share. Part of the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceiptEvent {
    /// Unique nonce from the login session
    pub nonce: String,
    
    /// Payment hash from the user invoice
    pub payment_hash: String,
    
    /// Preimage proving payment (hex-encoded)
    pub preimage_hex: String,
    
    /// Amount received in satoshis
    pub amount_sats: u64,
    
    /// Unix timestamp (seconds)
    pub timestamp: u64,
}

impl PaymentReceiptEvent {
    pub fn new(
        nonce: String,
        payment_hash: String,
        preimage_hex: String,
        amount_sats: u64,
    ) -> Self {
        Self {
            nonce,
            payment_hash,
            preimage_hex,
            amount_sats,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Login complete event (kind 28103) - Published after successful authentication
/// 
/// Marks the end of a successful login flow. Completes the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCompleteEvent {
    /// Unique nonce from the login session
    pub nonce: String,
    
    /// Enterprise client_id
    pub client_id: String,
    
    /// User's npub (same as in proof_event)
    pub npub: String,
    
    /// Unix timestamp (seconds)
    pub timestamp: u64,
}

impl LoginCompleteEvent {
    pub fn new(nonce: String, client_id: String, npub: String) -> Self {
        Self {
            nonce,
            client_id,
            npub,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_event_creation() {
        let event = ProofEvent::new(
            "abc123".to_string(),
            "acme".to_string(),
            "deadbeef".to_string(),
            "0x1234".to_string(),
            "npub1xyz".to_string(),
            "lnbc100n1...".to_string(),
            "lnbc10n1...".to_string(),
        );
        
        assert_eq!(event.nonce, "abc123");
        assert!(event.timestamp > 0);
    }
    
    #[test]
    fn test_payment_receipt_creation() {
        let event = PaymentReceiptEvent::new(
            "abc123".to_string(),
            "payment_hash_hex".to_string(),
            "preimage_hex".to_string(),
            1000,
        );
        
        assert_eq!(event.amount_sats, 1000);
    }
}
