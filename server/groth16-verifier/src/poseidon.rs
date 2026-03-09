//! Poseidon2 hash functions for BN254
//!
//! Provides Merkle tree hashing compatible with the circom membership circuit.
//! Uses light-poseidon crate for BN254 field operations.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher, PoseidonBytesHasher, parameters::bn254_x5};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoseidonError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Hash computation failed: {0}")]
    HashFailed(String),
}

/// Compute leaf commitment from leaf_secret
/// 
/// Input: 32-byte leaf_secret
/// Output: 32-byte commitment hash
/// 
/// This matches the circuit's leaf commitment computation:
/// commitment = Poseidon(leaf_secret_as_field_elements)
pub fn compute_leaf_commitment(leaf_secret: &[u8]) -> Result<[u8; 32], PoseidonError> {
    if leaf_secret.len() != 32 {
        return Err(PoseidonError::InvalidInput(
            format!("leaf_secret must be 32 bytes, got {}", leaf_secret.len())
        ));
    }
    
    // Convert to field element (single 32-byte input)
    let input = Fr::from_be_bytes_mod_order(leaf_secret);
    
    // Hash using Poseidon with 2 inputs (standard arity for leaf commitment)
    // We use [input, 0] to match circom's Poseidon(1) which pads with zero
    let mut hasher = Poseidon::<Fr>::new_circom(2)
        .map_err(|e| PoseidonError::HashFailed(format!("{:?}", e)))?;
    
    let hash = hasher.hash(&[input, Fr::from(0u64)])
        .map_err(|e| PoseidonError::HashFailed(format!("{:?}", e)))?;
    
    // Convert result to bytes (big-endian)
    let mut result = [0u8; 32];
    let bigint = hash.into_bigint();
    let bytes = bigint.to_bytes_be();
    result.copy_from_slice(&bytes);
    
    Ok(result)
}

/// Compute Merkle tree internal node hash
/// 
/// Input: Two 32-byte child hashes (left, right)
/// Output: 32-byte parent hash
/// 
/// This matches the circuit's MerkleTreeChecker:
/// parent = Poseidon(left, right)
pub fn merkle_hash_pair(left: &[u8], right: &[u8]) -> Result<[u8; 32], PoseidonError> {
    if left.len() != 32 || right.len() != 32 {
        return Err(PoseidonError::InvalidInput(
            format!("Both inputs must be 32 bytes, got {} and {}", left.len(), right.len())
        ));
    }
    
    // Convert to field elements
    let left_fe = Fr::from_be_bytes_mod_order(left);
    let right_fe = Fr::from_be_bytes_mod_order(right);
    
    // Hash using Poseidon with 2 inputs
    let mut hasher = Poseidon::<Fr>::new_circom(2)
        .map_err(|e| PoseidonError::HashFailed(format!("{:?}", e)))?;
    
    let hash = hasher.hash(&[left_fe, right_fe])
        .map_err(|e| PoseidonError::HashFailed(format!("{:?}", e)))?;
    
    // Convert result to bytes
    let mut result = [0u8; 32];
    let bigint = hash.into_bigint();
    let bytes = bigint.to_bytes_be();
    result.copy_from_slice(&bytes);
    
    Ok(result)
}

/// Compute zero value for empty Merkle tree leaves
/// 
/// Returns the Poseidon hash of zero (used as default/empty leaf)
pub fn zero_hash() -> Result<[u8; 32], PoseidonError> {
    let mut hasher = Poseidon::<Fr>::new_circom(2)
        .map_err(|e| PoseidonError::HashFailed(format!("{:?}", e)))?;
    
    let hash = hasher.hash(&[Fr::from(0u64), Fr::from(0u64)])
        .map_err(|e| PoseidonError::HashFailed(format!("{:?}", e)))?;
    
    let mut result = [0u8; 32];
    let bigint = hash.into_bigint();
    let bytes = bigint.to_bytes_be();
    result.copy_from_slice(&bytes);
    
    Ok(result)
}

/// Precompute zero hashes for all levels of a Merkle tree
/// 
/// zeros[0] = hash of empty leaf (zero_hash())
/// zeros[i] = hash(zeros[i-1], zeros[i-1])
pub fn compute_zero_hashes(depth: usize) -> Result<Vec<[u8; 32]>, PoseidonError> {
    let mut zeros = Vec::with_capacity(depth);
    
    // Level 0: empty leaf hash
    let z0 = zero_hash()?;
    zeros.push(z0);
    
    // Each subsequent level
    for i in 1..depth {
        let prev = &zeros[i - 1];
        let next = merkle_hash_pair(prev, prev)?;
        zeros.push(next);
    }
    
    Ok(zeros)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_hash() {
        let z = zero_hash().unwrap();
        assert_eq!(z.len(), 32);
        // Should be deterministic
        let z2 = zero_hash().unwrap();
        assert_eq!(z, z2);
    }
    
    #[test]
    fn test_merkle_hash_pair() {
        let left = [0u8; 32];
        let right = [0u8; 32];
        let hash = merkle_hash_pair(&left, &right).unwrap();
        assert_eq!(hash.len(), 32);
        
        // Same inputs should give same output
        let hash2 = merkle_hash_pair(&left, &right).unwrap();
        assert_eq!(hash, hash2);
        
        // Different inputs should give different output
        let mut right2 = [0u8; 32];
        right2[0] = 1;
        let hash3 = merkle_hash_pair(&left, &right2).unwrap();
        assert_ne!(hash, hash3);
    }
    
    #[test]
    fn test_leaf_commitment() {
        let secret = [0xabu8; 32];
        let commitment = compute_leaf_commitment(&secret).unwrap();
        assert_eq!(commitment.len(), 32);
        
        // Deterministic
        let commitment2 = compute_leaf_commitment(&secret).unwrap();
        assert_eq!(commitment, commitment2);
        
        // Different secret = different commitment
        let secret2 = [0xcdu8; 32];
        let commitment3 = compute_leaf_commitment(&secret2).unwrap();
        assert_ne!(commitment, commitment3);
    }
    
    #[test]
    fn test_zero_hashes() {
        let zeros = compute_zero_hashes(20).unwrap();
        assert_eq!(zeros.len(), 20);
        
        // Verify relationship: zeros[i] = hash(zeros[i-1], zeros[i-1])
        for i in 1..20 {
            let expected = merkle_hash_pair(&zeros[i-1], &zeros[i-1]).unwrap();
            assert_eq!(zeros[i], expected);
        }
    }
}
