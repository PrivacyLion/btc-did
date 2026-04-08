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
// - Desktop/Server: Encrypted file storage with OS keyring (macOS Keychain, Windows DPAPI, Linux Secret Service)

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
    
    #[error("Keyring error: {0}")]
    KeyringError(String),
}

/// Storage keys for SDK secrets
pub const KEY_DID_PRIVATE: &str = "signedby_did_private_key";
pub const KEY_LEAF_SECRET: &str = "signedby_leaf_secret";
pub const KEY_HUMAN_NSEC: &str = "signedby_human_nsec";
pub const KEY_HUMAN_NSEC_CONSENT: &str = "signedby_human_nsec_consent";

/// Keyring service name for SignedByMe storage encryption keys
const KEYRING_SERVICE: &str = "com.signedby.sdk";

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
/// Uses ChaCha20-Poly1305 with a key from OS keyring (macOS Keychain, Windows DPAPI, Linux Secret Service)
pub struct EncryptedFileStorage {
    storage_dir: PathBuf,
}

impl EncryptedFileStorage {
    /// Create new encrypted file storage
    pub fn new(storage_dir: PathBuf) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&storage_dir)?;
        Ok(Self { storage_dir })
    }
    
    fn key_path(&self, key: &str) -> PathBuf {
        // Sanitize key name for filesystem
        let safe_key = key.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");
        self.storage_dir.join(format!("{}.enc", safe_key))
    }
    
    /// Get or create the master encryption key from OS keyring
    /// This key is stored in:
    /// - macOS: Keychain
    /// - Windows: Credential Manager (DPAPI)
    /// - Linux: Secret Service (GNOME Keyring, KWallet, etc.)
    fn get_or_create_master_key() -> Result<[u8; 32], StorageError> {
        use keyring::Entry;
        use chacha20poly1305::aead::rand_core::{OsRng, RngCore};
        
        let entry = Entry::new(KEYRING_SERVICE, "master_encryption_key")
            .map_err(|e| StorageError::KeyringError(format!("Failed to access keyring: {}", e)))?;
        
        // Try to get existing key
        match entry.get_password() {
            Ok(key_hex) => {
                // Decode hex to bytes
                let key_bytes = hex::decode(&key_hex)
                    .map_err(|e| StorageError::KeyringError(format!("Invalid key in keyring: {}", e)))?;
                
                if key_bytes.len() != 32 {
                    return Err(StorageError::KeyringError(
                        format!("Invalid key length in keyring: expected 32, got {}", key_bytes.len())
                    ));
                }
                
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                Ok(key)
            }
            Err(keyring::Error::NoEntry) => {
                // Generate new random key
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                
                // Store in keyring as hex
                let key_hex = hex::encode(&key);
                entry.set_password(&key_hex)
                    .map_err(|e| StorageError::KeyringError(format!("Failed to store key in keyring: {}", e)))?;
                
                Ok(key)
            }
            Err(e) => {
                Err(StorageError::KeyringError(format!("Keyring access error: {}", e)))
            }
        }
    }
    
    /// Derive per-key encryption key from master key using HKDF-like construction
    /// This ensures different storage keys use different encryption keys
    fn derive_key_specific_key(master_key: &[u8; 32], storage_key: &str) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        // HKDF-like key derivation: SHA256(master_key || "signedby_v1:" || storage_key)
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(b"signedby_v1:");
        hasher.update(storage_key.as_bytes());
        
        let result = hasher.finalize();
        let mut derived = [0u8; 32];
        derived.copy_from_slice(&result);
        derived
    }
}

impl SecureStorage for EncryptedFileStorage {
    fn store(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, OsRng},
            ChaCha20Poly1305, Nonce,
        };
        use chacha20poly1305::aead::rand_core::RngCore;
        
        // Get master key from OS keyring
        let master_key = Self::get_or_create_master_key()?;
        
        // Derive key-specific encryption key
        let enc_key = Self::derive_key_specific_key(&master_key, key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
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
        
        // Get master key from OS keyring
        let master_key = Self::get_or_create_master_key()?;
        
        // Derive key-specific encryption key
        let enc_key = Self::derive_key_specific_key(&master_key, key);
        
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
        
        // This test requires a working OS keyring
        // Skip if keyring is not available (e.g., headless CI)
        match storage.store(key, data) {
            Ok(()) => {
                assert!(storage.exists(key));
                
                let retrieved = storage.retrieve(key).unwrap();
                assert_eq!(retrieved, data);
                
                storage.delete(key).unwrap();
                assert!(!storage.exists(key));
            }
            Err(StorageError::KeyringError(_)) => {
                // Keyring not available - skip test
                eprintln!("Skipping test: OS keyring not available");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
    
    #[test]
    fn test_not_found() {
        let dir = tempdir().unwrap();
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf()).unwrap();
        
        let result = storage.retrieve("nonexistent");
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }
    
    #[test]
    fn test_key_derivation_deterministic() {
        let master = [0xABu8; 32];
        let key1 = EncryptedFileStorage::derive_key_specific_key(&master, "test_key");
        let key2 = EncryptedFileStorage::derive_key_specific_key(&master, "test_key");
        assert_eq!(key1, key2);
    }
    
    #[test]
    fn test_key_derivation_different_keys() {
        let master = [0xABu8; 32];
        let key1 = EncryptedFileStorage::derive_key_specific_key(&master, "key_a");
        let key2 = EncryptedFileStorage::derive_key_specific_key(&master, "key_b");
        assert_ne!(key1, key2);
    }
}
