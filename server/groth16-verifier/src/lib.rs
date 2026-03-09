//! SignedByMe Groth16 Verifier and Poseidon2 Hash Library
//!
//! Provides:
//! - Groth16 proof verification for membership proofs
//! - Poseidon2 hashing for Merkle trees (BN254 compatible)

pub mod verifier;
pub mod types;
pub mod poseidon;

pub use verifier::Verifier;
pub use poseidon::{compute_leaf_commitment, merkle_hash_pair, zero_hash, compute_zero_hashes};
