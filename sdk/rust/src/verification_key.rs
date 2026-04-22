//! Groth16 verification key handling
//!
//! The verification key is a small (4KB) file that enables anyone to verify
//! SignedByMe proofs. It can be bundled with your application for fully
//! offline verification.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};

use crate::error::SdkError;

/// Groth16 verification key for BN254 curve
#[derive(Clone)]
pub struct VerificationKey {
    /// The ark-groth16 verifying key
    pub(crate) inner: VerifyingKey<Bn254>,
}

/// JSON representation of verification key (snarkjs format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKeyJson {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "vk_alphabeta_12")]
    pub vk_alphabeta_12: Option<Vec<Vec<Vec<String>>>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

impl VerificationKey {
    /// Load verification key from snarkjs JSON format
    pub fn from_json(json: &str) -> Result<Self, SdkError> {
        let vk_json: VerificationKeyJson = serde_json::from_str(json)?;
        Self::from_snarkjs(&vk_json)
    }
    
    /// Load from parsed snarkjs JSON
    pub fn from_snarkjs(vk_json: &VerificationKeyJson) -> Result<Self, SdkError> {
        // Parse alpha (G1)
        let alpha_g1 = parse_g1(&vk_json.vk_alpha_1)?;
        
        // Parse beta (G2)
        let beta_g2 = parse_g2(&vk_json.vk_beta_2)?;
        
        // Parse gamma (G2)
        let gamma_g2 = parse_g2(&vk_json.vk_gamma_2)?;
        
        // Parse delta (G2)
        let delta_g2 = parse_g2(&vk_json.vk_delta_2)?;
        
        // Parse IC (G1 array)
        let gamma_abc_g1: Vec<G1Affine> = vk_json.ic
            .iter()
            .map(|p| parse_g1(p))
            .collect::<Result<Vec<_>, _>>()?;
        
        let inner = VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };
        
        Ok(Self { inner })
    }
    
    /// Load from ark-serialized binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SdkError> {
        let inner = VerifyingKey::<Bn254>::deserialize_uncompressed(bytes)
            .map_err(|e| SdkError::InvalidVerificationKey(format!("Deserialize failed: {:?}", e)))?;
        Ok(Self { inner })
    }
    
    /// Number of public inputs expected
    pub fn num_public_inputs(&self) -> usize {
        self.inner.gamma_abc_g1.len() - 1
    }
}

/// Parse a G1 point from snarkjs string array [x, y, z]
fn parse_g1(coords: &[String]) -> Result<G1Affine, SdkError> {
    if coords.len() < 2 {
        return Err(SdkError::InvalidVerificationKey("G1 needs at least 2 coordinates".into()));
    }
    
    let x = parse_fq(&coords[0])?;
    let y = parse_fq(&coords[1])?;
    
    Ok(G1Affine::new(x, y))
}

/// Parse a G2 point from snarkjs nested string array [[x0, x1], [y0, y1], [z0, z1]]
fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, SdkError> {
    if coords.len() < 2 {
        return Err(SdkError::InvalidVerificationKey("G2 needs at least 2 coordinate pairs".into()));
    }
    
    let x = Fq2::new(parse_fq(&coords[0][0])?, parse_fq(&coords[0][1])?);
    let y = Fq2::new(parse_fq(&coords[1][0])?, parse_fq(&coords[1][1])?);
    
    Ok(G2Affine::new(x, y))
}

/// Parse a field element from decimal string
fn parse_fq(s: &str) -> Result<Fq, SdkError> {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use std::str::FromStr;
    
    let n = BigUint::from_str(s)
        .map_err(|e| SdkError::InvalidVerificationKey(format!("Invalid field element: {}", e)))?;
    
    let bytes = n.to_bytes_le();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);
    
    Ok(Fq::from_le_bytes_mod_order(&padded))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_fq() {
        let result = parse_fq("123456789");
        assert!(result.is_ok());
    }
}
