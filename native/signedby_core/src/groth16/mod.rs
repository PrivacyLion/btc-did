//! Groth16 prover module for SignedByMe
//! 
//! Provides native proof generation for Android/iOS.
//! 
//! Flow:
//! 1. Load proving key (.zkey) and witness data (.dat)
//! 2. Generate witness from private inputs
//! 3. Generate Groth16 proof
//! 
//! The prover uses ark-groth16 for the actual proof computation.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use std::path::Path;
use thiserror::Error;

pub mod witness;
pub mod zkey;
pub mod rapidsnark_ffi;

// NOTE: JNI module removed per Bible Section 16 (Mar 30, 2026).
// Mobile Android bridge superseded. This is an SDK, not an Android app.

#[derive(Error, Debug)]
pub enum ProverError {
    #[error("Failed to load proving key: {0}")]
    ProvingKeyError(String),
    #[error("Failed to generate witness: {0}")]
    WitnessError(String),
    #[error("Failed to generate proof: {0}")]
    ProofError(String),
    #[error("Invalid inputs: {0}")]
    InputError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Prover state - holds loaded keys for proof generation
pub struct Prover {
    /// Proving key (parsed from .zkey)
    proving_key: Option<ProvingKey<Bn254>>,
    /// Path to zkey file (for lazy loading)
    pub zkey_path: Option<String>,
    /// Circuit data path
    pub dat_path: Option<String>,
}

impl Prover {
    /// Create new prover (keys loaded lazily)
    pub fn new() -> Self {
        Self {
            proving_key: None,
            zkey_path: None,
            dat_path: None,
        }
    }
    
    /// Set paths for lazy loading
    pub fn with_paths(mut self, zkey_path: &str, dat_path: &str) -> Self {
        self.zkey_path = Some(zkey_path.to_string());
        self.dat_path = Some(dat_path.to_string());
        self
    }
    
    /// Load proving key from .zkey file
    /// 
    /// Note: .zkey format is snarkjs-specific.
    /// This requires converting to ark format first.
    /// For initial implementation, we'll use a pre-converted key.
    pub fn load_proving_key(&mut self, zkey_path: &str) -> Result<(), ProverError> {
        // TODO: Parse snarkjs .zkey format
        // For now, we expect an ark-serialized proving key
        let ark_pk_path = format!("{}.ark", zkey_path);
        
        if Path::new(&ark_pk_path).exists() {
            let pk_bytes = std::fs::read(&ark_pk_path)?;
            let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&pk_bytes[..])
                .map_err(|e| ProverError::ProvingKeyError(format!("Deserialize failed: {:?}", e)))?;
            self.proving_key = Some(pk);
            Ok(())
        } else {
            Err(ProverError::ProvingKeyError(format!(
                "Proving key not found: {}. Run zkey converter first.", 
                ark_pk_path
            )))
        }
    }
    
    /// Generate proof from witness
    /// 
    /// NOTE: ark-groth16 requires a ConstraintSynthesizer, not raw witness.
    /// For circom circuits, we need rapidsnark or snarkjs for proof generation.
    /// 
    /// Current implementation shells out to prover binary.
    /// Production: integrate rapidsnark as a static library.
    pub fn prove(&self, witness: &[Fr]) -> Result<ProofResult, ProverError> {
        let _pk = self.proving_key.as_ref()
            .ok_or_else(|| ProverError::ProvingKeyError("Proving key not loaded".into()))?;
        
        // For circom circuits, ark-groth16 can't directly use a witness array.
        // We need to use rapidsnark or snarkjs for the actual proving.
        // 
        // TODO: Integrate rapidsnark as native library for production
        // For now, return an error indicating the prover needs setup
        
        if witness.len() < 9 {
            return Err(ProverError::InputError("Witness too short".into()));
        }
        
        // Placeholder: In production, this calls rapidsnark
        Err(ProverError::ProofError(
            "Native proving not yet implemented. Use rapidsnark binary or snarkjs.".into()
        ))
    }
    
    /// Generate proof using external prover binary
    /// 
    /// This shells out to rapidsnark or snarkjs-cli for proof generation.
    /// The binary must be available on the device.
    pub fn prove_with_binary(
        &self,
        witness_path: &str,
        zkey_path: &str,
        proof_out: &str,
        public_out: &str,
    ) -> Result<(String, String), ProverError> {
        use std::process::Command;
        
        // Try rapidsnark first
        let result = Command::new("rapidsnark")
            .args([zkey_path, witness_path, proof_out, public_out])
            .output();
        
        match result {
            Ok(output) if output.status.success() => {
                let proof_json = std::fs::read_to_string(proof_out)?;
                let public_json = std::fs::read_to_string(public_out)?;
                Ok((proof_json, public_json))
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(ProverError::ProofError(format!("rapidsnark failed: {}", stderr)))
            }
            Err(_) => {
                // rapidsnark not available
                Err(ProverError::ProofError(
                    "rapidsnark binary not found. Install or use snarkjs.".into()
                ))
            }
        }
    }
    
    /// Generate proof in snarkjs JSON format
    /// 
    /// Uses external prover binary (rapidsnark preferred).
    pub fn prove_json(&self, witness_path: &str) -> Result<(String, String), ProverError> {
        let zkey = self.zkey_path.as_ref()
            .ok_or_else(|| ProverError::ProvingKeyError("zkey path not set".into()))?;
        
        let proof_out = "/tmp/signedby_proof.json";
        let public_out = "/tmp/signedby_public.json";
        
        self.prove_with_binary(witness_path, zkey, proof_out, public_out)
    }
}

/// Proof generation result
pub struct ProofResult {
    pub proof: Proof<Bn254>,
    pub public_inputs: Vec<Fr>,
}

/// Convert ark proof to snarkjs JSON format
#[allow(dead_code)]
fn proof_to_snarkjs_json(proof: &Proof<Bn254>) -> Result<String, ProverError> {
    // Format matches snarkjs output
    let json = serde_json::json!({
        "pi_a": g1_to_strings(&proof.a),
        "pi_b": g2_to_strings(&proof.b),
        "pi_c": g1_to_strings(&proof.c),
        "protocol": "groth16",
        "curve": "bn128"
    });
    
    serde_json::to_string_pretty(&json)
        .map_err(|e| ProverError::ProofError(e.to_string()))
}

/// Convert G1 point to snarkjs string array
#[allow(dead_code)]
fn g1_to_strings(point: &G1Affine) -> Vec<String> {
    vec![
        point.x.to_string(),
        point.y.to_string(),
        "1".to_string(),
    ]
}

/// Convert G2 point to snarkjs string array
#[allow(dead_code)]
fn g2_to_strings(point: &G2Affine) -> Vec<Vec<String>> {
    vec![
        vec![point.x.c0.to_string(), point.x.c1.to_string()],
        vec![point.y.c0.to_string(), point.y.c1.to_string()],
        vec!["1".to_string(), "0".to_string()],
    ]
}

/// Convert public inputs to JSON array
#[allow(dead_code)]
fn public_inputs_to_json(inputs: &[Fr]) -> Result<String, ProverError> {
    let strings: Vec<String> = inputs.iter()
        .map(|f| format!("{}", f.into_bigint()))
        .collect();
    
    serde_json::to_string_pretty(&strings)
        .map_err(|e| ProverError::ProofError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prover_creation() {
        let prover = Prover::new()
            .with_paths("/path/to/zkey", "/path/to/dat");
        
        assert!(prover.zkey_path.is_some());
        assert!(prover.dat_path.is_some());
    }
}
