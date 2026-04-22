//! Groth16 proof types and parsing

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, Fq, Fq2};
use ark_groth16::Proof;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::error::SdkError;

/// A Groth16 proof in snarkjs JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16ProofJson {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

/// Parsed Groth16 proof ready for verification
#[derive(Clone)]
pub struct Groth16Proof {
    pub(crate) inner: Proof<Bn254>,
}

impl Groth16Proof {
    /// Parse proof from snarkjs JSON format
    pub fn from_json(json: &str) -> Result<Self, SdkError> {
        let proof_json: Groth16ProofJson = serde_json::from_str(json)?;
        Self::from_snarkjs(&proof_json)
    }
    
    /// Parse from snarkjs proof object
    pub fn from_snarkjs(proof: &Groth16ProofJson) -> Result<Self, SdkError> {
        let a = parse_g1(&proof.pi_a)?;
        let b = parse_g2(&proof.pi_b)?;
        let c = parse_g1(&proof.pi_c)?;
        
        Ok(Self {
            inner: Proof { a, b, c }
        })
    }
}

/// Public inputs to the proof
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub(crate) values: Vec<Fr>,
    /// The npub (NOSTR public key) extracted from public outputs
    pub npub_hex: String,
    /// Merkle root hash
    pub merkle_root: String,
    /// Session binding (if present)
    pub session_binding: Option<String>,
}

impl PublicInputs {
    /// Parse public inputs from snarkjs JSON format (array of decimal strings)
    pub fn from_json(json: &str) -> Result<Self, SdkError> {
        let strings: Vec<String> = serde_json::from_str(json)?;
        Self::from_strings(&strings)
    }
    
    /// Parse from string array
    pub fn from_strings(strings: &[String]) -> Result<Self, SdkError> {
        // SignedByMe circuit public outputs:
        // [0]: npub_x (secp256k1 x-coordinate, 256 bits)
        // [1]: npub_y_parity (0 or 1)
        // [2]: merkle_root
        // [3]: session_binding (optional)
        
        if strings.len() < 3 {
            return Err(SdkError::InvalidProof(
                "Public inputs must have at least 3 elements (npub_x, npub_y_parity, merkle_root)".into()
            ));
        }
        
        let values: Vec<Fr> = strings
            .iter()
            .map(|s| parse_fr(s))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Extract npub from first two public inputs
        // npub_x is the x-coordinate, npub_y_parity determines even/odd y
        let npub_x = &strings[0];
        let npub_y_parity = &strings[1];
        
        // Convert to compressed public key format (33 bytes: prefix + x)
        let x_bytes = parse_bigint_to_bytes(npub_x, 32)?;
        let parity: u8 = npub_y_parity.parse()
            .map_err(|_| SdkError::InvalidProof("Invalid y parity".into()))?;
        let prefix = if parity == 0 { 0x02 } else { 0x03 };
        
        let mut compressed = vec![prefix];
        compressed.extend_from_slice(&x_bytes);
        
        // For NOSTR, we use the x-only format (32 bytes, no prefix)
        let npub_hex = hex::encode(&x_bytes);
        
        let merkle_root = format_as_hex(&strings[2])?;
        
        let session_binding = if strings.len() > 3 {
            Some(format_as_hex(&strings[3])?)
        } else {
            None
        };
        
        Ok(Self {
            values,
            npub_hex,
            merkle_root,
            session_binding,
        })
    }
    
    /// Get the npub in bech32 format
    pub fn npub_bech32(&self) -> Result<String, SdkError> {
        crate::hex_to_npub(&self.npub_hex)
    }
}

/// Result of proof verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,
    /// The npub (NOSTR public key) in hex format
    pub npub_hex: String,
    /// The npub in bech32 format
    pub npub: String,
    /// Merkle root the user proved membership in
    pub merkle_root: String,
    /// Session binding (prevents proof replay)
    pub session_binding: Option<String>,
}

// Helper functions

fn parse_g1(coords: &[String]) -> Result<G1Affine, SdkError> {
    if coords.len() < 2 {
        return Err(SdkError::InvalidProof("G1 needs at least 2 coordinates".into()));
    }
    
    let x = parse_fq(&coords[0])?;
    let y = parse_fq(&coords[1])?;
    
    Ok(G1Affine::new(x, y))
}

fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, SdkError> {
    if coords.len() < 2 {
        return Err(SdkError::InvalidProof("G2 needs at least 2 coordinate pairs".into()));
    }
    
    let x = Fq2::new(parse_fq(&coords[0][0])?, parse_fq(&coords[0][1])?);
    let y = Fq2::new(parse_fq(&coords[1][0])?, parse_fq(&coords[1][1])?);
    
    Ok(G2Affine::new(x, y))
}

fn parse_fq(s: &str) -> Result<Fq, SdkError> {
    use num_bigint::BigUint;
    use std::str::FromStr;
    
    let n = BigUint::from_str(s)
        .map_err(|e| SdkError::InvalidProof(format!("Invalid field element: {}", e)))?;
    
    let bytes = n.to_bytes_le();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);
    
    Ok(Fq::from_le_bytes_mod_order(&padded))
}

fn parse_fr(s: &str) -> Result<Fr, SdkError> {
    use num_bigint::BigUint;
    use std::str::FromStr;
    
    let n = BigUint::from_str(s)
        .map_err(|e| SdkError::InvalidProof(format!("Invalid field element: {}", e)))?;
    
    let bytes = n.to_bytes_le();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);
    
    Ok(Fr::from_le_bytes_mod_order(&padded))
}

fn parse_bigint_to_bytes(s: &str, len: usize) -> Result<Vec<u8>, SdkError> {
    use num_bigint::BigUint;
    use std::str::FromStr;
    
    let n = BigUint::from_str(s)
        .map_err(|e| SdkError::InvalidProof(format!("Invalid number: {}", e)))?;
    
    let mut bytes = n.to_bytes_be();
    
    // Pad or truncate to desired length
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend(bytes);
        bytes = padded;
    } else if bytes.len() > len {
        bytes = bytes[bytes.len() - len..].to_vec();
    }
    
    Ok(bytes)
}

fn format_as_hex(decimal_str: &str) -> Result<String, SdkError> {
    let bytes = parse_bigint_to_bytes(decimal_str, 32)?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_fr() {
        let result = parse_fr("123456789");
        assert!(result.is_ok());
    }
}
