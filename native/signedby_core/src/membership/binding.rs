//! V4 Binding Hash
//!
//! This module computes the canonical binding hash that:
//! - STWO proof must commit to
//! - Membership proof must commit to
//! - Prevents all replay attacks
//!
//! CRITICAL: This implementation MUST match the Python version exactly.
//! Any mismatch will cause verification failures.

use sha2::{Sha256, Digest};

/// Schema version for v4 binding
pub const SCHEMA_VERSION_V4: u8 = 4;

/// Domain separator (23 bytes, will be padded to 24 in hash)
pub const DOMAIN_SEPARATOR_V4: &[u8] = b"signedby.me:identity:v4";

/// Hash a string field with prefix for domain separation.
/// Matches Python: hashlib.sha256(f"{prefix}:{value}".encode()).digest()
pub fn hash_field(prefix: &str, value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", prefix, value).as_bytes());
    hasher.finalize().into()
}

/// Compute v4 binding hash (circuit-friendly, all fixed-size fields).
///
/// This is THE canonical binding that:
/// - STWO proof must commit to
/// - Membership proof must commit to
/// - Prevents all replay attacks
///
/// Layout (283 bytes fixed input):
/// ```text
///     schema_version: u8           = 4                              // 1 byte
///     domain_sep: [u8; 24]         = "signedby.me:identity:v4"      // 24 bytes
///     did_pubkey: [u8; 33]         = compressed secp256k1 pubkey    // 33 bytes
///     wallet_hash: [u8; 32]        = H("wallet:" || wallet_addr)    // 32 bytes
///     client_id_hash: [u8; 32]     = H("client_id:" || client_id)   // 32 bytes
///     session_id_hash: [u8; 32]    = H("session_id:" || session_id) // 32 bytes
///     payment_hash: [u8; 32]       = from invoice                   // 32 bytes
///     amount_sats: u64 LE          = payment amount                 // 8 bytes
///     expires_at: u64 LE           = session expiry                 // 8 bytes
///     nonce: [u8; 16]              = session nonce                  // 16 bytes
///     ea_domain_hash: [u8; 32]     = H("ea_domain:" || domain)      // 32 bytes
///     purpose_id: u8               = 0/1/2/3 enum                   // 1 byte
///     root_id_hash: [u8; 32]       = H("root_id:" || root_id)       // 32 bytes
///                                    or zeros if no membership
/// ```
pub fn compute_binding_hash_v4(
    did_pubkey: &[u8],           // 33 bytes compressed (will be padded)
    wallet_address: &str,
    client_id: &str,
    session_id: &str,
    payment_hash: &[u8],         // 32 bytes (will be padded)
    amount_sats: u64,
    expires_at: u64,
    nonce: &[u8],                // 16 bytes (will be padded)
    ea_domain: &str,
    purpose_id: u8,
    root_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Schema version (1 byte)
    hasher.update(&[SCHEMA_VERSION_V4]);
    
    // Domain separator (24 bytes, padded)
    let mut domain_sep = [0u8; 24];
    let sep_len = DOMAIN_SEPARATOR_V4.len().min(24);
    domain_sep[..sep_len].copy_from_slice(&DOMAIN_SEPARATOR_V4[..sep_len]);
    hasher.update(&domain_sep);
    
    // DID pubkey (33 bytes, padded)
    let mut did_padded = [0u8; 33];
    let did_len = did_pubkey.len().min(33);
    did_padded[..did_len].copy_from_slice(&did_pubkey[..did_len]);
    hasher.update(&did_padded);
    
    // Wallet address hash (32 bytes)
    hasher.update(&hash_field("wallet", wallet_address));
    
    // Client ID hash (32 bytes)
    hasher.update(&hash_field("client_id", client_id));
    
    // Session ID hash (32 bytes)
    hasher.update(&hash_field("session_id", session_id));
    
    // Payment hash (32 bytes, padded)
    let mut payment_padded = [0u8; 32];
    let payment_len = payment_hash.len().min(32);
    payment_padded[..payment_len].copy_from_slice(&payment_hash[..payment_len]);
    hasher.update(&payment_padded);
    
    // Amount sats (8 bytes LE)
    hasher.update(&amount_sats.to_le_bytes());
    
    // Expires at (8 bytes LE)
    hasher.update(&expires_at.to_le_bytes());
    
    // Nonce (16 bytes, padded)
    let mut nonce_padded = [0u8; 16];
    let nonce_len = nonce.len().min(16);
    nonce_padded[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
    hasher.update(&nonce_padded);
    
    // EA domain hash (32 bytes)
    hasher.update(&hash_field("ea_domain", ea_domain));
    
    // Purpose ID (1 byte)
    hasher.update(&[purpose_id]);
    
    // Root ID hash (32 bytes, zeros if no membership)
    if root_id.is_empty() {
        hasher.update(&[0u8; 32]);
    } else {
        hasher.update(&hash_field("root_id", root_id));
    }
    
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_field() {
        let result = hash_field("client_id", "acme_corp");
        assert_eq!(result.len(), 32);
        // The hash should be deterministic
        let result2 = hash_field("client_id", "acme_corp");
        assert_eq!(result, result2);
    }

    #[test]
    fn test_binding_hash_basic() {
        let did_pubkey = [0x02u8; 33]; // Dummy compressed pubkey
        let payment_hash = [0xaau8; 32];
        let nonce = [0xbbu8; 16];
        
        let hash = compute_binding_hash_v4(
            &did_pubkey,
            "did:btcr:test",
            "acme_corp",
            "session123",
            &payment_hash,
            500,
            1700000000,
            &nonce,
            "acme.com",
            1, // allowlist
            "allowlist-2026-Q1",
        );
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_binding_hash_no_membership() {
        let did_pubkey = [0x02u8; 33];
        let payment_hash = [0xaau8; 32];
        let nonce = [0xbbu8; 16];
        
        let hash = compute_binding_hash_v4(
            &did_pubkey,
            "did:btcr:test",
            "acme_corp",
            "session123",
            &payment_hash,
            500,
            1700000000,
            &nonce,
            "acme.com",
            0, // no membership
            "", // empty root_id
        );
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let did_pubkey = [0x02u8; 33];
        let payment_hash = [0xaau8; 32];
        let nonce = [0xbbu8; 16];
        
        let hash1 = compute_binding_hash_v4(
            &did_pubkey,
            "did:btcr:test",
            "acme_corp",
            "session123",
            &payment_hash,
            500,
            1700000000,
            &nonce,
            "acme.com",
            1,
            "root1",
        );
        
        let hash2 = compute_binding_hash_v4(
            &did_pubkey,
            "did:btcr:test",
            "acme_corp",
            "session456", // Different session
            &payment_hash,
            500,
            1700000000,
            &nonce,
            "acme.com",
            1,
            "root1",
        );
        
        assert_ne!(hash1, hash2, "Different sessions should produce different hashes");
    }
}
