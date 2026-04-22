//! SignedByMe SDK - Self-signing digital signatures with zero-knowledge proofs
//!
//! This SDK enables server-side verification of SignedByMe authentication tokens
//! and Groth16 zero-knowledge proofs. Verification is fully decentralized — no
//! network calls are required if you bundle the verification key.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use signedby_sdk::{Verifier, VerificationKey};
//!
//! // Load verification key (can be bundled for offline use)
//! let vk = VerificationKey::from_json(include_str!("verification_key.json"))?;
//! let verifier = Verifier::new(vk);
//!
//! // Verify a proof
//! let result = verifier.verify_proof(&proof, &public_inputs)?;
//! println!("Valid: {}, npub: {}", result.valid, result.npub);
//! ```
//!
//! # Architecture
//!
//! SignedByMe is built on three pillars:
//!
//! 1. **Self-signing identity (DID)** — Users create their own cryptographic
//!    identity on-device. No certificate authority, no central issuer.
//!
//! 2. **Zero-knowledge membership proofs** — Users prove they belong to a group
//!    without revealing which member they are. Built on Groth16/BN254.
//!
//! 3. **Bitcoin-backed economic proof** — Every authentication is optionally
//!    backed by a Lightning payment, making auth economically unforgeable.

pub mod verifier;
pub mod verification_key;
pub mod proof;
pub mod error;

#[cfg(feature = "oidc")]
pub mod oidc;

// Re-exports
pub use verifier::Verifier;
pub use verification_key::VerificationKey;
pub use proof::{Groth16Proof, PublicInputs, VerificationResult};
pub use error::SdkError;

/// Bech32-encoded npub prefix for NOSTR public keys
pub const NPUB_PREFIX: &str = "npub";

/// Convert a hex public key to bech32 npub format
pub fn hex_to_npub(hex_pubkey: &str) -> Result<String, SdkError> {
    use bech32::{Hrp, Bech32m};
    
    let bytes = hex::decode(hex_pubkey)
        .map_err(|e| SdkError::InvalidInput(format!("Invalid hex: {}", e)))?;
    
    if bytes.len() != 32 {
        return Err(SdkError::InvalidInput("Public key must be 32 bytes".into()));
    }
    
    let hrp = Hrp::parse(NPUB_PREFIX)
        .map_err(|e| SdkError::InvalidInput(format!("Invalid HRP: {}", e)))?;
    
    bech32::encode::<Bech32m>(hrp, &bytes)
        .map_err(|e| SdkError::InvalidInput(format!("Bech32 encode failed: {}", e)))
}

/// Convert a bech32 npub to hex format
pub fn npub_to_hex(npub: &str) -> Result<String, SdkError> {
    use bech32::Hrp;
    
    let (hrp, bytes) = bech32::decode(npub)
        .map_err(|e| SdkError::InvalidInput(format!("Invalid bech32: {}", e)))?;
    
    let expected_hrp = Hrp::parse(NPUB_PREFIX).unwrap();
    if hrp != expected_hrp {
        return Err(SdkError::InvalidInput(format!(
            "Expected npub prefix, got: {}", hrp
        )));
    }
    
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_npub_roundtrip() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let npub = hex_to_npub(hex_key).unwrap();
        assert!(npub.starts_with("npub"));
        let recovered = npub_to_hex(&npub).unwrap();
        assert_eq!(recovered, hex_key);
    }
}
