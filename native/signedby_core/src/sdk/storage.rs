// sdk/storage.rs - TEE/Encrypted Storage Abstraction (Phase 9A.1)
//
// Per Bible:
// - DID private key in TEE/secure storage, never extracted
// - leaf_secret in secure storage
// - Human nsec stored in same TEE/encrypted storage
//
// This module provides a platform-agnostic interface.
// Actual TEE implementation depends on target:
// - Android: Android Keystore with StrongBox
// - iOS: Secure Enclave
// - Desktop/Server: Encrypted file storage with OS keyring

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::path::PathBuf;

/// Storage error types
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Key not found: {0}")]
    NotFound(String),
    
    #[error("Storage access denied")]
    AccessDenied,
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Storage keys for SDK secrets
pub const KEY_DID_PRIVATE: &str = "signedby_did_private_key";
pub const KEY_LEAF_SECRET: &str = "signedby_leaf_secret";
pub const KEY_HUMAN_NSEC: &str = "signedby_human_nsec";
pub const KEY_HUMAN_NSEC_CONSENT: &str = "signedby_human_nsec_consent";

/// Human nsec consent record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanNsecConsent {
    /// Timestamp when consent was granted (Unix epoch)
    pub granted_at: u64,
    /// Human-readable description shown at consent time
    pub consent_text: String,
    /// Hash of the human's npub for verification
    pub human_npub_hash: String,
}

/// Platform-agnostic secure storage trait
pub trait SecureStorage: Send + Sync {
    /// Store bytes under a key
    fn store(&self, key: &str, data: &[u8]) -> Result<(), StorageError>;
    
    /// Retrieve bytes by key
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    
    /// Check if key exists
    fn exists(&self, key: &str) -> bool;
    
    /// Delete a key
    fn delete(&self, key: &str) -> Result<(), StorageError>;
}

/// Encrypted file storage (for desktop/server environments)
/// Uses ChaCha20-Poly1305 with a key derived from OS keyring
pub struct EncryptedFileStorage {
    storage_dir: PathBuf,
    // In production, encryption key comes from OS keyring
    // For now, this is a placeholder implementation
}

impl EncryptedFileStorage {
    /// Create new encrypted file storage
    pub fn new(storage_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&storage_dir)?;
        Ok(Self { storage_dir })
    }
    
    fn key_path(&self, key: &str) -> PathBuf {
        // Sanitize key name for filesystem
        let safe_key = key.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");
        self.storage_dir.join(format!("{}.enc", safe_key))
    }
}

impl SecureStorage for EncryptedFileStorage {
    fn store(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, OsRng},
            ChaCha20Poly1305, Nonce,
        };
        use chacha20poly1305::aead::rand_core::RngCore;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Derive encryption key (placeholder - should use OS keyring)
        let enc_key = derive_storage_key(key);
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        
        // Encrypt
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        
        // Store nonce + ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        
        std::fs::write(self.key_path(key), output)?;
        Ok(())
    }
    
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };
        
        let path = self.key_path(key);
        if !path.exists() {
            return Err(StorageError::NotFound(key.to_string()));
        }
        
        let data = std::fs::read(&path)?;
        if data.len() < 12 {
            return Err(StorageError::DeserializationError("Data too short".to_string()));
        }
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        // Derive encryption key
        let enc_key = derive_storage_key(key);
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        
        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        
        Ok(plaintext)
    }
    
    fn exists(&self, key: &str) -> bool {
        self.key_path(key).exists()
    }
    
    fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.key_path(key);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Derive storage encryption key from key name
/// In production, this should use OS keyring (macOS Keychain, Windows DPAPI, Linux Secret Service)
fn derive_storage_key(key: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    // Placeholder: derive from key name + machine-specific entropy
    // Production should use proper key derivation from secure source
    let mut hasher = Sha256::new();
    hasher.update(b"signedby_sdk_storage_v1:");
    hasher.update(key.as_bytes());
    
    let result = hasher.finalize();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&result);
    key_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_encrypted_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        
        let key = "test_key";
        let data = b"secret data here";
        
        storage.store(key, data).unwrap();
        assert!(storage.exists(key));
        
        let retrieved = storage.retrieve(key).unwrap();
        assert_eq!(retrieved, data);
        
        storage.delete(key).unwrap();
        assert!(!storage.exists(key));
    }
    
    #[test]
    fn test_not_found() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        
        let result = storage.retrieve("nonexistent");
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }
}
