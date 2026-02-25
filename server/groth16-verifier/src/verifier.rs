//! Groth16 verifier implementation using ark-groth16

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_std::str::FromStr;
use thiserror::Error;

use crate::types::{NpubResult, SnarkjsProof, SnarkjsVK};

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("Failed to parse verification key: {0}")]
    VKParseError(String),
    #[error("Failed to parse proof: {0}")]
    ProofParseError(String),
    #[error("Failed to parse public inputs: {0}")]
    PublicInputsError(String),
    #[error("Verification error: {0}")]
    VerificationError(String),
    #[error("Invalid public input count: expected 9, got {0}")]
    InvalidPublicInputCount(usize),
}

pub struct Verifier {
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Verifier {
    /// Create verifier from snarkjs JSON verification key
    pub fn from_json(vk_json: &str) -> Result<Self, VerifierError> {
        let snarkjs_vk: SnarkjsVK = serde_json::from_str(vk_json)
            .map_err(|e| VerifierError::VKParseError(e.to_string()))?;
        
        // Parse alpha (G1)
        let alpha_g1 = parse_g1(&snarkjs_vk.vk_alpha_1)?;
        
        // Parse beta (G2)
        let beta_g2 = parse_g2(&snarkjs_vk.vk_beta_2)?;
        
        // Parse gamma (G2)
        let gamma_g2 = parse_g2(&snarkjs_vk.vk_gamma_2)?;
        
        // Parse delta (G2)
        let delta_g2 = parse_g2(&snarkjs_vk.vk_delta_2)?;
        
        // Parse IC (G1 points)
        let gamma_abc_g1: Vec<G1Affine> = snarkjs_vk.ic
            .iter()
            .map(|p| parse_g1(p))
            .collect::<Result<Vec<_>, _>>()?;
        
        let vk = VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };
        
        let pvk = Groth16::<Bn254>::process_vk(&vk)
            .map_err(|e| VerifierError::VKParseError(format!("Failed to process VK: {:?}", e)))?;
        
        Ok(Self { pvk })
    }
    
    /// Parse proof from snarkjs JSON format
    pub fn parse_proof(&self, proof_json: &str) -> Result<Proof<Bn254>, VerifierError> {
        let snarkjs_proof: SnarkjsProof = serde_json::from_str(proof_json)
            .map_err(|e| VerifierError::ProofParseError(e.to_string()))?;
        
        let a = parse_g1(&snarkjs_proof.pi_a)?;
        let b = parse_g2(&snarkjs_proof.pi_b)?;
        let c = parse_g1(&snarkjs_proof.pi_c)?;
        
        Ok(Proof { a, b, c })
    }
    
    /// Parse public inputs from snarkjs JSON format
    pub fn parse_public_inputs(&self, public_json: &str) -> Result<Vec<Fr>, VerifierError> {
        let inputs: Vec<String> = serde_json::from_str(public_json)
            .map_err(|e| VerifierError::PublicInputsError(e.to_string()))?;
        
        if inputs.len() != 9 {
            return Err(VerifierError::InvalidPublicInputCount(inputs.len()));
        }
        
        inputs.iter()
            .map(|s| Fr::from_str(s).map_err(|_| VerifierError::PublicInputsError(format!("Invalid field element: {}", s))))
            .collect()
    }
    
    /// Verify a proof against public inputs
    pub fn verify(&self, proof: &Proof<Bn254>, public_inputs: &[Fr]) -> Result<bool, VerifierError> {
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, public_inputs, proof)
            .map_err(|e| VerifierError::VerificationError(format!("{:?}", e)))
    }
    
    /// Extract npub from public inputs
    /// 
    /// Public inputs layout:
    /// [0] = merkle_root
    /// [1-4] = npub_x (4 × 64-bit limbs, little-endian)
    /// [5-8] = npub_y (4 × 64-bit limbs, little-endian)
    pub fn extract_npub(&self, public_inputs: &[Fr]) -> Result<NpubResult, VerifierError> {
        if public_inputs.len() != 9 {
            return Err(VerifierError::InvalidPublicInputCount(public_inputs.len()));
        }
        
        // Extract merkle root
        let merkle_root = format!("{}", public_inputs[0].into_bigint());
        
        // Extract npub_x from limbs [1-4]
        let npub_x_bytes = limbs_to_bytes(&public_inputs[1..5])?;
        
        // Extract npub_y from limbs [5-8]
        let npub_y_bytes = limbs_to_bytes(&public_inputs[5..9])?;
        
        // Create hex strings
        let npub_x_hex = hex::encode(&npub_x_bytes);
        let npub_y_hex = hex::encode(&npub_y_bytes);
        
        // Create compressed pubkey (02/03 prefix based on y parity)
        let y_is_even = npub_y_bytes[31] & 1 == 0;
        let prefix = if y_is_even { "02" } else { "03" };
        let npub_compressed = format!("{}{}", prefix, npub_x_hex);
        
        Ok(NpubResult {
            merkle_root,
            npub_x_hex,
            npub_y_hex,
            npub_compressed,
            npub_x_bytes,
            npub_y_bytes,
        })
    }
}

/// Parse G1 affine point from snarkjs format ["x", "y", "1"]
fn parse_g1(coords: &[String]) -> Result<G1Affine, VerifierError> {
    if coords.len() < 2 {
        return Err(VerifierError::VKParseError("G1 point needs at least 2 coordinates".into()));
    }
    
    let x = ark_bn254::Fq::from_str(&coords[0])
        .map_err(|_| VerifierError::VKParseError(format!("Invalid G1 x: {}", coords[0])))?;
    let y = ark_bn254::Fq::from_str(&coords[1])
        .map_err(|_| VerifierError::VKParseError(format!("Invalid G1 y: {}", coords[1])))?;
    
    let point = G1Affine::new(x, y);
    
    if !point.is_on_curve() {
        return Err(VerifierError::VKParseError("G1 point not on curve".into()));
    }
    
    Ok(point)
}

/// Parse G2 affine point from snarkjs format [["x0", "x1"], ["y0", "y1"], ["1", "0"]]
fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, VerifierError> {
    if coords.len() < 2 {
        return Err(VerifierError::VKParseError("G2 point needs at least 2 coordinate pairs".into()));
    }
    
    let x0 = ark_bn254::Fq::from_str(&coords[0][0])
        .map_err(|_| VerifierError::VKParseError("Invalid G2 x0".into()))?;
    let x1 = ark_bn254::Fq::from_str(&coords[0][1])
        .map_err(|_| VerifierError::VKParseError("Invalid G2 x1".into()))?;
    let y0 = ark_bn254::Fq::from_str(&coords[1][0])
        .map_err(|_| VerifierError::VKParseError("Invalid G2 y0".into()))?;
    let y1 = ark_bn254::Fq::from_str(&coords[1][1])
        .map_err(|_| VerifierError::VKParseError("Invalid G2 y1".into()))?;
    
    let x = ark_bn254::Fq2::new(x0, x1);
    let y = ark_bn254::Fq2::new(y0, y1);
    
    let point = G2Affine::new(x, y);
    
    if !point.is_on_curve() {
        return Err(VerifierError::VKParseError("G2 point not on curve".into()));
    }
    
    Ok(point)
}

/// Convert 4 × 64-bit field element limbs to 32 bytes (big-endian for secp256k1)
fn limbs_to_bytes(limbs: &[Fr]) -> Result<[u8; 32], VerifierError> {
    if limbs.len() != 4 {
        return Err(VerifierError::PublicInputsError("Expected 4 limbs".into()));
    }
    
    let mut result = [0u8; 32];
    
    for (i, limb) in limbs.iter().enumerate() {
        // Get limb as u64
        let bigint = limb.into_bigint();
        let limb_bytes = bigint.0[0].to_le_bytes(); // First 64 bits
        
        // Place in little-endian order within result
        result[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    
    // Reverse to big-endian for secp256k1 convention
    result.reverse();
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_limbs_to_bytes() {
        // Test with known values
        let limbs: Vec<Fr> = vec![
            Fr::from(0x1234567890abcdefu64),
            Fr::from(0xfedcba0987654321u64),
            Fr::from(0x1111111111111111u64),
            Fr::from(0x2222222222222222u64),
        ];
        
        let bytes = limbs_to_bytes(&limbs).unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
