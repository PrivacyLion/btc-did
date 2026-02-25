// key_manager.rs
// Manages DID keys and Taproot keys for BTC-native operations

use anyhow::{Result, anyhow};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair, XOnlyPublicKey};
use bitcoin::secp256k1::rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// Key types supported by the KeyManager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    /// Standard secp256k1 ECDSA key (for DID signatures)
    Ecdsa,
    /// Schnorr/Taproot key (for DLC and Bitcoin native ops)
    Schnorr,
}

/// A keypair with both ECDSA and Schnorr capabilities
#[derive(Debug, Clone)]
pub struct ManagedKey {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub x_only_pubkey: XOnlyPublicKey,
    pub keypair: Keypair,
}

impl ManagedKey {
    /// Generate a new random keypair
    pub fn generate() -> Result<Self> {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        
        Ok(Self {
            secret_key,
            public_key,
            x_only_pubkey,
            keypair,
        })
    }
    
    /// Create from existing secret key bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(bytes)
            .map_err(|e| anyhow!("Invalid secret key: {}", e))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        
        Ok(Self {
            secret_key,
            public_key,
            x_only_pubkey,
            keypair,
        })
    }
    
    /// Get DID string (did:btcr:pubkey_hex)
    pub fn to_did(&self) -> String {
        format!("did:btcr:{}", hex::encode(self.public_key.serialize()))
    }
    
    /// Get compressed public key hex (33 bytes)
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.public_key.serialize())
    }
    
    /// Get x-only public key hex (32 bytes, for Schnorr/Taproot)
    pub fn x_only_pubkey_hex(&self) -> String {
        hex::encode(self.x_only_pubkey.serialize())
    }
    
    /// Sign a message with ECDSA (returns DER hex)
    pub fn sign_ecdsa(&self, message: &[u8]) -> Result<String> {
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&hash)
            .map_err(|e| anyhow!("Invalid message: {}", e))?;
        
        let sig = secp.sign_ecdsa(&msg, &self.secret_key);
        Ok(hex::encode(sig.serialize_der()))
    }
    
    /// Sign a message with Schnorr (returns signature hex, 64 bytes)
    pub fn sign_schnorr(&self, message: &[u8]) -> Result<String> {
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&hash)
            .map_err(|e| anyhow!("Invalid message: {}", e))?;
        
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        Ok(hex::encode(sig.serialize()))
    }
    
    /// Verify a Schnorr signature
    pub fn verify_schnorr(&self, message: &[u8], sig_hex: &str) -> Result<bool> {
        let secp = Secp256k1::new();
        
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| anyhow!("Invalid signature hex: {}", e))?;
        
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| anyhow!("Invalid signature: {}", e))?;
        
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&hash)
            .map_err(|e| anyhow!("Invalid message: {}", e))?;
        
        Ok(secp.verify_schnorr(&sig, &msg, &self.x_only_pubkey).is_ok())
    }
}

/// Derive a Taproot internal key from a DID key
pub fn derive_taproot_internal_key(did_key: &ManagedKey) -> XOnlyPublicKey {
    did_key.x_only_pubkey
}

/// JSON representation for export
#[derive(Serialize, Deserialize)]
pub struct KeyManagerExport {
    pub did: String,
    pub pubkey_hex: String,
    pub x_only_pubkey_hex: String,
    pub key_type: String,
}

impl From<&ManagedKey> for KeyManagerExport {
    fn from(key: &ManagedKey) -> Self {
        Self {
            did: key.to_did(),
            pubkey_hex: key.pubkey_hex(),
            x_only_pubkey_hex: key.x_only_pubkey_hex(),
            key_type: "secp256k1".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key = ManagedKey::generate().unwrap();
        assert_eq!(key.pubkey_hex().len(), 66); // 33 bytes compressed
        assert_eq!(key.x_only_pubkey_hex().len(), 64); // 32 bytes x-only
    }
    
    #[test]
    fn test_schnorr_sign_verify() {
        let key = ManagedKey::generate().unwrap();
        let message = b"test message";
        let sig = key.sign_schnorr(message).unwrap();
        assert!(key.verify_schnorr(message, &sig).unwrap());
    }
}
