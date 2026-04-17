// sdk/identity.rs - Agent Identity Management (Phase 9A.1)
//
// Per Bible Section 9A.1:
// - DID generation in TEE/encrypted storage
// - leaf_secret derivation
// - leaf_commitment computation
//
// Per Bible Section 15 Decision 941 (Apr 14, 2026):
// - Agent never holds human nsec
// - Human signs kind 28250 and kind 28251 with their own NOSTR client
//
// The identity chain (from Bible Section 2.1):
//   DID private key → leaf_secret → leaf_commitment
//                  → nsec (inside circuit) → npub
//
// This module does NOT modify the circuit or derivation logic.
// It wraps existing functionality for SDK storage context.

use anyhow::{Result, anyhow};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use nostr_sdk::prelude::*;
use serde::{Serialize, Deserialize};

use crate::key_manager::ManagedKey;
use crate::membership::bn254_leaf_commitment;
use crate::nostr::derive_nsec_from_leaf_secret;
use super::storage::{
    SecureStorage,
    KEY_DID_PRIVATE, KEY_LEAF_SECRET,
};

/// Agent identity state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentityState {
    /// DID string (did:btcr:pubkey_hex)
    pub did: String,
    /// Public key hex (compressed, 33 bytes)
    pub pubkey_hex: String,
    /// Agent's npub (bech32)
    pub agent_npub: String,
    /// Agent's npub hex (32 bytes)
    pub agent_npub_hex: String,
    /// Leaf commitment (hex, 32 bytes) - the ONLY thing server sees at enrollment
    pub leaf_commitment: String,
}

/// Agent identity manager
pub struct AgentIdentity<S: SecureStorage> {
    storage: S,
}

impl<S: SecureStorage> AgentIdentity<S> {
    /// Create new agent identity manager with storage backend
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
    
    /// Check if agent identity is initialized
    pub fn is_initialized(&self) -> bool {
        self.storage.exists(KEY_DID_PRIVATE) && self.storage.exists(KEY_LEAF_SECRET)
    }
    
    /// Initialize agent identity (one-time setup)
    /// Generates DID and derives leaf_secret
    pub fn initialize(&self) -> Result<AgentIdentityState> {
        if self.is_initialized() {
            return Err(anyhow!("Agent identity already initialized"));
        }
        
        // Generate DID keypair
        let did_key = ManagedKey::generate()?;
        
        // Store DID private key
        self.storage.store(KEY_DID_PRIVATE, &did_key.secret_key.secret_bytes())
            .map_err(|e| anyhow!("Failed to store DID private key: {}", e))?;
        
        // Derive leaf_secret from DID (5 BN254 field elements)
        let leaf_secret = derive_leaf_secret_from_did(&did_key)?;
        
        // Store leaf_secret
        let leaf_secret_bytes = serialize_leaf_secret(&leaf_secret);
        self.storage.store(KEY_LEAF_SECRET, &leaf_secret_bytes)
            .map_err(|e| anyhow!("Failed to store leaf_secret: {}", e))?;
        
        // Compute leaf_commitment
        let leaf_commitment = bn254_leaf_commitment(&leaf_secret);
        let leaf_commitment_hex = fr_to_hex(&leaf_commitment);
        
        // Derive agent's NOSTR keypair
        let agent_keys = derive_nsec_from_leaf_secret(&leaf_secret)?;
        let agent_npub = Keys::new(agent_keys.clone()).public_key();
        
        Ok(AgentIdentityState {
            did: did_key.to_did(),
            pubkey_hex: did_key.pubkey_hex(),
            agent_npub: agent_npub.to_bech32()?,
            agent_npub_hex: agent_npub.to_hex(),
            leaf_commitment: leaf_commitment_hex,
        })
    }
    
    /// Load existing agent identity
    pub fn load(&self) -> Result<AgentIdentityState> {
        if !self.is_initialized() {
            return Err(anyhow!("Agent identity not initialized"));
        }
        
        // Load DID private key
        let did_bytes = self.storage.retrieve(KEY_DID_PRIVATE)
            .map_err(|e| anyhow!("Failed to load DID: {}", e))?;
        let did_key = ManagedKey::from_bytes(&did_bytes)?;
        
        // Load leaf_secret
        let leaf_secret_bytes = self.storage.retrieve(KEY_LEAF_SECRET)
            .map_err(|e| anyhow!("Failed to load leaf_secret: {}", e))?;
        let leaf_secret = deserialize_leaf_secret(&leaf_secret_bytes)?;
        
        // Compute leaf_commitment
        let leaf_commitment = bn254_leaf_commitment(&leaf_secret);
        let leaf_commitment_hex = fr_to_hex(&leaf_commitment);
        
        // Derive agent's NOSTR keypair
        let agent_keys = derive_nsec_from_leaf_secret(&leaf_secret)?;
        let agent_npub = Keys::new(agent_keys).public_key();
        
        Ok(AgentIdentityState {
            did: did_key.to_did(),
            pubkey_hex: did_key.pubkey_hex(),
            agent_npub: agent_npub.to_bech32()?,
            agent_npub_hex: agent_npub.to_hex(),
            leaf_commitment: leaf_commitment_hex,
        })
    }
    
    /// Get agent's NOSTR keys (derived from leaf_secret)
    pub fn get_agent_keys(&self) -> Result<Keys> {
        let leaf_secret_bytes = self.storage.retrieve(KEY_LEAF_SECRET)
            .map_err(|e| anyhow!("Failed to load leaf_secret: {}", e))?;
        let leaf_secret = deserialize_leaf_secret(&leaf_secret_bytes)?;
        let nsec = derive_nsec_from_leaf_secret(&leaf_secret)?;
        Ok(Keys::new(nsec))
    }
    
    /// Get leaf_secret (for proof generation)
    pub fn get_leaf_secret(&self) -> Result<[Fr; 5]> {
        let leaf_secret_bytes = self.storage.retrieve(KEY_LEAF_SECRET)
            .map_err(|e| anyhow!("Failed to load leaf_secret: {}", e))?;
        deserialize_leaf_secret(&leaf_secret_bytes)
    }
}

/// Derive leaf_secret from DID key
/// Uses deterministic derivation so the same DID always produces the same leaf_secret
fn derive_leaf_secret_from_did(did_key: &ManagedKey) -> Result<[Fr; 5]> {
    use sha2::{Sha256, Digest};
    
    let mut leaf_secret = [Fr::from(0u64); 5];
    
    // Derive each field element from DID + index
    for i in 0..5 {
        let mut hasher = Sha256::new();
        hasher.update(b"signedby_leaf_secret_v1:");
        hasher.update(&did_key.secret_key.secret_bytes());
        hasher.update(&[i as u8]);
        let hash = hasher.finalize();
        
        // Convert to BN254 field element (mod p)
        leaf_secret[i] = Fr::from_be_bytes_mod_order(&hash);
    }
    
    Ok(leaf_secret)
}

/// Serialize leaf_secret to bytes
fn serialize_leaf_secret(leaf_secret: &[Fr; 5]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 * 32);
    for elem in leaf_secret {
        let bigint = elem.into_bigint();
        for limb in bigint.0.iter() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

/// Deserialize leaf_secret from bytes
fn deserialize_leaf_secret(bytes: &[u8]) -> Result<[Fr; 5]> {
    if bytes.len() != 5 * 32 {
        return Err(anyhow!("Invalid leaf_secret length: expected {}, got {}", 5 * 32, bytes.len()));
    }
    
    let mut leaf_secret = [Fr::from(0u64); 5];
    for i in 0..5 {
        let offset = i * 32;
        let elem_bytes: [u8; 32] = bytes[offset..offset + 32].try_into()?;
        leaf_secret[i] = Fr::from_le_bytes_mod_order(&elem_bytes);
    }
    
    Ok(leaf_secret)
}

/// Convert Fr to hex string
fn fr_to_hex(fr: &Fr) -> String {
    let bigint = fr.into_bigint();
    let mut bytes = Vec::new();
    for limb in bigint.0.iter().rev() {
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    // Remove leading zeros but keep at least 32 bytes
    while bytes.len() > 32 && bytes[0] == 0 {
        bytes.remove(0);
    }
    // Pad to 32 bytes if needed
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::storage::EncryptedFileStorage;
    use tempfile::tempdir;
    
    #[test]
    fn test_initialize_identity() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        let identity = AgentIdentity::new(storage);
        
        assert!(!identity.is_initialized());
        
        let state = identity.initialize().unwrap();
        
        assert!(identity.is_initialized());
        assert!(state.did.starts_with("did:btcr:"));
    }
    
    #[test]
    fn test_load_identity() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        let identity = AgentIdentity::new(storage);
        
        let state1 = identity.initialize().unwrap();
        let state2 = identity.load().unwrap();
        
        // Same identity produces same values
        assert_eq!(state1.did, state2.did);
        assert_eq!(state1.agent_npub, state2.agent_npub);
        assert_eq!(state1.leaf_commitment, state2.leaf_commitment);
    }
}
