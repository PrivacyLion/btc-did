//! Merkle membership proofs for SignedByMe (Groth16)
//!
//! This module provides:
//! - V4 binding hash computation (SHA-256, must match Python exactly)
//! - Poseidon2 over BN254 reference implementation (for test vectors)
//! - JNI bindings for Android
//!
//! HASH FUNCTION STRATEGY:
//! - SHA-256: External interfaces (binding hash, API communication)
//! - Poseidon2-BN254: Inside Groth16 circuit (handled by circom)
//!
//! The actual ZK proof generation uses:
//! - circom circuit: circuits/membership.circom
//! - C++ witness generator: circuits/build/membership_cpp/
//! - rapidsnark prover: (mobile integration Phase 14)
//!
//! This Rust code provides reference implementations and JNI bindings.

pub mod binding;
pub mod poseidon2_bn254;
pub mod jni;

pub use binding::{compute_binding_hash_v4, hash_field, SCHEMA_VERSION_V4, DOMAIN_SEPARATOR_V4};

// Poseidon2 over BN254 - reference implementation for test vectors
pub use poseidon2_bn254::{
    poseidon2_hash as bn254_poseidon2_hash,
    poseidon2_hash_5 as bn254_leaf_commitment,
    poseidon2_hash_2 as bn254_merkle_hash,
    derive_nsec as bn254_derive_nsec,
    derive_npub_commitment as bn254_derive_npub,
    generate_test_vectors as bn254_generate_test_vectors,
    scalar_to_hex, hex_to_scalar,
};

/// Purpose ID enum (circuit-friendly)
pub const PURPOSE_NONE: u8 = 0;
pub const PURPOSE_ALLOWLIST: u8 = 1;
pub const PURPOSE_ISSUER_BATCH: u8 = 2;
pub const PURPOSE_REVOCATION: u8 = 3;

/// Get purpose ID from string
pub fn get_purpose_id(purpose: &str) -> u8 {
    match purpose {
        "" => PURPOSE_NONE,
        "allowlist" => PURPOSE_ALLOWLIST,
        "issuer_batch" => PURPOSE_ISSUER_BATCH,
        "revocation" => PURPOSE_REVOCATION,
        _ => PURPOSE_NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purpose_ids() {
        assert_eq!(get_purpose_id(""), PURPOSE_NONE);
        assert_eq!(get_purpose_id("allowlist"), PURPOSE_ALLOWLIST);
        assert_eq!(get_purpose_id("issuer_batch"), PURPOSE_ISSUER_BATCH);
        assert_eq!(get_purpose_id("revocation"), PURPOSE_REVOCATION);
        assert_eq!(get_purpose_id("unknown"), PURPOSE_NONE);
    }
}
