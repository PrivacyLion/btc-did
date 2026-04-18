// lib.rs - SignedByMe Core Library
// Implements KeyManager and Groth16 membership proofs
//
// NOTE: JNI functions removed per Bible Section 16 (Mar 30, 2026).
// DLC modules (dlc_builder, dlc_oracle) and mobile FFI (ffi_c) removed per Bible Section 13.15 & 16.
// The mobile Android bridge is superseded. This is an SDK, not an Android app.

use sha2::{Digest, Sha256};

// Module declarations
pub mod key_manager;
pub mod membership; // Groth16 membership proofs
pub mod groth16;    // Native Groth16 prover
pub mod nostr;      // NOSTR client (Phase 9)
pub mod sdk;        // Agent SDK Core (Phase 9A)
pub mod ffi;        // C-compatible FFI bindings (Phase 9A.7)

// Re-exports for library consumers
pub use key_manager::ManagedKey;
pub use groth16::Prover;

/// SHA-256 hash helper
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("hello");
        assert_eq!(result.len(), 64);
    }
}
