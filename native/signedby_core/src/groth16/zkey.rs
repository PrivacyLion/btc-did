//! .zkey file parser
//! 
//! The .zkey format is snarkjs-specific and contains:
//! - Proving key parameters (α, β, δ, L, H)
//! - Circuit-specific data
//! 
//! This module handles converting .zkey to ark-groth16 ProvingKey.
//! 
//! NOTE: Full .zkey parsing is complex. For initial release:
//! - Pre-convert .zkey to ark format using a build script
//! - Load the ark-serialized key directly
//! 
//! Future: implement full .zkey parser for runtime loading.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkeyError {
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Load proving key from ark-serialized format
/// 
/// This expects a key that was pre-converted from snarkjs .zkey
/// using the convert_zkey tool.
pub fn load_ark_proving_key(path: &str) -> Result<ProvingKey<Bn254>, ZkeyError> {
    if !Path::new(path).exists() {
        return Err(ZkeyError::FileNotFound(path.to_string()));
    }
    
    let bytes = std::fs::read(path)?;
    
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&bytes[..])
        .map_err(|e| ZkeyError::ParseError(format!("{:?}", e)))?;
    
    Ok(pk)
}

/// Check if ark-format proving key exists
pub fn has_ark_proving_key(zkey_path: &str) -> bool {
    let ark_path = format!("{}.ark", zkey_path);
    Path::new(&ark_path).exists()
}

/// Placeholder: Parse snarkjs .zkey format
/// 
/// This is complex - the .zkey format includes:
/// - Header with curve info
/// - Coefficients
/// - Point arrays (A, B1, B2, C, H, L)
/// 
/// For now, we require pre-conversion using the snarkjs-to-ark tool.
#[allow(unused)]
pub fn parse_snarkjs_zkey(_path: &str) -> Result<ProvingKey<Bn254>, ZkeyError> {
    Err(ZkeyError::InvalidFormat(
        "Direct .zkey parsing not implemented. Use pre-converted .zkey.ark file.".into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_has_ark_key() {
        assert!(!has_ark_proving_key("/nonexistent/path"));
    }
}
