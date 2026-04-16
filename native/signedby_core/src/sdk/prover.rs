// sdk/prover.rs - Groth16 Proof Generation (Phase 9A.2)
//
// Per Bible Section 15 (Apr 16, 2026):
// - WASM/ark-circom approach eliminated
// - Proof generation uses native C++ libraries via dlopen/dlsym FFI
// - libmembership_witness.so for witness calculation
// - librapidsnark.so for Groth16 proving
// - arkworks crates retained for field arithmetic only
//
// THE CIRCUIT AND ZKEY ARE FROZEN. This module wires native FFI into the SDK.

use anyhow::{Result, anyhow};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use std::path::Path;

use crate::groth16::witness::{WitnessCalculator, MembershipInputs};
use crate::groth16::rapidsnark_ffi::prove_with_library;

/// Proof generation result
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// Groth16 proof JSON string (from rapidsnark)
    pub proof_bytes: Vec<u8>,
    /// Merkle root (hex, 32 bytes)
    pub merkle_root: String,
    /// npub X coordinate (hex, 32 bytes - reconstructed from 4 limbs)
    pub npub_x: String,
    /// npub Y coordinate (hex, 32 bytes - reconstructed from 4 limbs)
    pub npub_y: String,
    /// Proof generation time in milliseconds
    pub proof_time_ms: u64,
}

/// Groth16 prover configuration
pub struct ProverConfig {
    /// Path to libmembership_witness.so
    pub witness_lib_path: String,
    /// Path to membership.dat (witness calculator data)
    pub dat_path: String,
    /// Path to librapidsnark.so
    pub rapidsnark_lib_path: String,
    /// Path to membership_final.zkey (proving key)
    pub zkey_path: String,
}

impl ProverConfig {
    /// Create prover config from a circuits directory path
    /// Expects: {dir}/libmembership_witness.so, {dir}/membership.dat,
    ///          {dir}/librapidsnark.so, {dir}/membership_final.zkey
    pub fn from_circuits_dir<P: AsRef<Path>>(dir: P) -> Self {
        let dir = dir.as_ref();
        Self {
            witness_lib_path: dir.join("libmembership_witness.so").to_string_lossy().to_string(),
            dat_path: dir.join("membership.dat").to_string_lossy().to_string(),
            rapidsnark_lib_path: dir.join("librapidsnark.so").to_string_lossy().to_string(),
            zkey_path: dir.join("membership_final.zkey").to_string_lossy().to_string(),
        }
    }
    
    /// Create prover config with explicit paths
    pub fn new(
        witness_lib_path: String,
        dat_path: String,
        rapidsnark_lib_path: String,
        zkey_path: String,
    ) -> Self {
        Self { witness_lib_path, dat_path, rapidsnark_lib_path, zkey_path }
    }
}

/// Merkle witness for proof generation
#[derive(Debug, Clone)]
pub struct MerkleWitness {
    /// Merkle siblings (20 elements, hex strings)
    pub siblings: Vec<String>,
    /// Path direction bits (20 elements, 0 or 1)
    pub path_bits: Vec<u8>,
}

/// Groth16 prover for membership proofs
pub struct MembershipProver {
    config: ProverConfig,
}

impl MembershipProver {
    /// Create a new prover with the given configuration
    pub fn new(config: ProverConfig) -> Self {
        Self { config }
    }
    
    /// Generate a Groth16 proof
    /// 
    /// # Arguments
    /// * `leaf_secret` - The 5 BN254 field elements from AgentIdentity
    /// * `witness` - The Merkle witness (siblings and path_bits)
    /// 
    /// # Returns
    /// ProofResult containing proof JSON and public outputs (merkle_root, npub)
    pub fn generate_proof(
        &self,
        leaf_secret: &[Fr; 5],
        witness: &MerkleWitness,
    ) -> Result<ProofResult> {
        let start = std::time::Instant::now();
        
        // Validate inputs
        if witness.siblings.len() != 20 {
            return Err(anyhow!("Expected 20 siblings, got {}", witness.siblings.len()));
        }
        if witness.path_bits.len() != 20 {
            return Err(anyhow!("Expected 20 path_bits, got {}", witness.path_bits.len()));
        }
        
        // Convert leaf_secret Fr elements to decimal strings
        let leaf_secret_strs: [String; 5] = [
            fr_to_decimal(&leaf_secret[0]),
            fr_to_decimal(&leaf_secret[1]),
            fr_to_decimal(&leaf_secret[2]),
            fr_to_decimal(&leaf_secret[3]),
            fr_to_decimal(&leaf_secret[4]),
        ];
        
        // Create MembershipInputs for witness calculator
        let inputs = MembershipInputs::from_field_elements(
            leaf_secret_strs,
            &witness.siblings,
            &witness.path_bits,
        ).map_err(|e| anyhow!("Failed to create inputs: {}", e))?;
        
        // Step 1: Calculate witness via FFI
        eprintln!("[prover] Step 1: Calculating witness...");
        let witness_calc = WitnessCalculator::new(&self.config.witness_lib_path, &self.config.dat_path);
        
        if !witness_calc.is_available() {
            return Err(anyhow!(
                "Witness calculator not available. Check paths:\n  lib: {}\n  dat: {}",
                self.config.witness_lib_path,
                self.config.dat_path
            ));
        }
        
        let witness_bytes = witness_calc.calculate_to_buffer(&inputs)
            .map_err(|e| anyhow!("Witness calculation failed: {}", e))?;
        
        eprintln!("[prover] Witness generated: {} bytes", witness_bytes.len());
        
        // Step 2: Generate proof via rapidsnark FFI
        eprintln!("[prover] Step 2: Generating Groth16 proof...");
        let (proof_json, public_json) = prove_with_library(
            &self.config.rapidsnark_lib_path,
            &self.config.zkey_path,
            &witness_bytes,
        ).map_err(|e| anyhow!("Proof generation failed: {}", e))?;
        
        eprintln!("[prover] Proof generated, parsing public signals...");
        
        // Step 3: Parse public signals JSON
        // Format: ["root", "npub_x[0]", "npub_x[1]", "npub_x[2]", "npub_x[3]", 
        //          "npub_y[0]", "npub_y[1]", "npub_y[2]", "npub_y[3]"]
        let public_signals: Vec<String> = serde_json::from_str(&public_json)
            .map_err(|e| anyhow!("Failed to parse public signals: {}", e))?;
        
        if public_signals.len() != 9 {
            return Err(anyhow!(
                "Expected 9 public signals (1 root + 4 npub_x + 4 npub_y), got {}",
                public_signals.len()
            ));
        }
        
        // Extract merkle_root (first signal, decimal string -> hex)
        let merkle_root = decimal_to_hex_32(&public_signals[0])?;
        
        // Reconstruct npub_x from 4 limbs (64 bits each, little-endian)
        let npub_x = limbs_to_hex_256(&public_signals[1..5])?;
        
        // Reconstruct npub_y from 4 limbs (64 bits each, little-endian)
        let npub_y = limbs_to_hex_256(&public_signals[5..9])?;
        
        let elapsed = start.elapsed();
        eprintln!("[prover] Total proof time: {:?}", elapsed);
        
        Ok(ProofResult {
            proof_bytes: proof_json.into_bytes(),
            merkle_root,
            npub_x,
            npub_y,
            proof_time_ms: elapsed.as_millis() as u64,
        })
    }
}

/// Convert Fr to decimal string for witness calculator input
fn fr_to_decimal(fr: &Fr) -> String {
    let bigint = fr.into_bigint();
    let bytes = bigint.to_bytes_be();
    let val = num_bigint::BigUint::from_bytes_be(&bytes);
    val.to_string()
}

/// Convert decimal string to 32-byte hex (for merkle_root)
fn decimal_to_hex_32(decimal: &str) -> Result<String> {
    let val = num_bigint::BigUint::parse_bytes(decimal.as_bytes(), 10)
        .ok_or_else(|| anyhow!("Invalid decimal: {}", decimal))?;
    let bytes = val.to_bytes_be();
    
    // Pad to 32 bytes
    let mut padded = vec![0u8; 32];
    let start = 32 - bytes.len().min(32);
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    
    Ok(hex::encode(padded))
}

/// Reconstruct a 256-bit value from 4x64-bit limbs (decimal strings)
/// Limbs are in little-endian order (limb[0] is least significant)
fn limbs_to_hex_256(limbs: &[String]) -> Result<String> {
    if limbs.len() != 4 {
        return Err(anyhow!("Expected 4 limbs, got {}", limbs.len()));
    }
    
    let mut result = [0u8; 32];
    
    for (i, limb_str) in limbs.iter().enumerate() {
        // Parse decimal string to u64
        let limb_val: u64 = limb_str.parse()
            .map_err(|e| anyhow!("Invalid limb '{}': {}", limb_str, e))?;
        
        // Convert to little-endian bytes
        let limb_bytes = limb_val.to_le_bytes();
        
        // Place in result (little-endian: limb 0 at bytes 0-7, etc.)
        result[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    
    // Result is little-endian, reverse for big-endian hex output
    result.reverse();
    Ok(hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decimal_to_hex_32() {
        // Test with a known value
        let hex = decimal_to_hex_32("255").unwrap();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex.ends_with("ff"));
    }
    
    #[test]
    fn test_limbs_to_hex_256() {
        // All zeros
        let limbs = vec!["0".to_string(), "0".to_string(), "0".to_string(), "0".to_string()];
        let hex = limbs_to_hex_256(&limbs).unwrap();
        assert_eq!(hex, "0".repeat(64));
    }
    
    #[test]
    fn test_prover_config_from_dir() {
        let config = ProverConfig::from_circuits_dir("/tmp/circuits");
        assert!(config.witness_lib_path.contains("libmembership_witness.so"));
        assert!(config.rapidsnark_lib_path.contains("librapidsnark.so"));
        assert!(config.zkey_path.contains("membership_final.zkey"));
    }
}
