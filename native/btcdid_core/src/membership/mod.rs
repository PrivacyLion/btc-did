//! Merkle membership proofs for SignedByMe
//!
//! This module provides:
//! - V4 binding hash computation (SHA-256, must match Python exactly)
//! - Poseidon2-M31 for ZK-internal operations (leaf commitment, nullifier, Merkle tree)
//! - Merkle tree construction and path verification
//! - Membership proof generation and verification
//!
//! HASH FUNCTION STRATEGY:
//! - SHA-256: External interfaces (binding hash, API communication)
//! - Poseidon2-M31: ZK-internal operations (inside STWO circuit)
//!
//! This hybrid approach is standard (used by Starknet, zkSync, Polygon Miden).
//! Python calls Rust CLI for Poseidon hashing (single source of truth).
//!
//! Privacy guarantees:
//! - Unlinkability: Same user proving to different employers cannot be correlated
//! - Anonymity: Verifier learns "user is in set" but not which member
//! - No correlators: leaf_commitment never exposed

pub mod binding;
pub mod merkle_hash;     // SHA-256 based (for non-ZK tree operations)
pub mod poseidon2_m31;   // Poseidon2 over M31 - ZK-friendly (Plonky3 parameters)
pub mod poseidon2_bn254; // Poseidon2 over BN254 - for Groth16 circuits (Phase 4)
pub mod poseidon;        // Legacy - kept for backwards compat
pub mod merkle;
pub mod proof;
pub mod jni;

// Phase 3: STWO circuit for real ZK proofs
#[cfg(feature = "real-stwo")]
pub mod circuit;

pub use binding::{compute_binding_hash_v4, hash_field, SCHEMA_VERSION_V4, DOMAIN_SEPARATOR_V4};

// Merkle tree operations - byte array API (compatibility)
pub use merkle_hash::{hash_pair as merkle_hash_pair, hash_leaf, verify_proof as verify_merkle_proof, build_tree, get_path};

// Merkle tree operations - native M31 API (preferred for new code)
pub use merkle_hash::{hash_pair_m31, build_tree_m31, verify_proof_m31, get_path_m31, leaf_commitment_m31};
pub use poseidon2_m31::{
    M31, Poseidon2Hasher, LeafSecret, SessionId, Nullifier,
    poseidon2_hash_pair, compute_leaf_commitment, compute_nullifier,
    verify_merkle_proof as verify_poseidon_merkle_proof,
    build_merkle_tree as build_poseidon_merkle_tree,
    get_merkle_path as get_poseidon_merkle_path,
    m31_to_bytes, m31_from_bytes,
    domains, OUTPUT_POSITION, NULLIFIER_OUTPUT_POSITIONS, WIDTH,
    RATE, FULL_ROUNDS_FIRST, FULL_ROUNDS_LAST, PARTIAL_ROUNDS,
    DOMAIN_LEAF, DOMAIN_NULL, DOMAIN_MERK,
    get_external_constants, get_internal_constants, get_internal_diag,
};
pub use poseidon::{poseidon_hash_pair, poseidon_hash_bytes, PoseidonHasher, FieldElement};  // Legacy

// Poseidon2 over BN254 - for Groth16 circuits (Phase 4)
pub use poseidon2_bn254::{
    poseidon2_hash as bn254_poseidon2_hash,
    poseidon2_hash_5 as bn254_leaf_commitment,
    poseidon2_hash_2 as bn254_merkle_hash,
    derive_nsec as bn254_derive_nsec,
    derive_npub_commitment as bn254_derive_npub,
    generate_test_vectors as bn254_generate_test_vectors,
    scalar_to_hex, hex_to_scalar,
};
pub use merkle::{MerkleTree, MerklePath, PathSibling, verify_merkle_path};
pub use proof::{MembershipProof, MembershipPublicInputs, MembershipWitness, prove_membership, verify_membership};

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
