//! Witness generation for Groth16 proofs
//!
//! Calls external witness calculator binary to generate witness from circuit inputs.
//! 
//! For ARM64 Android, need cross-compiled witness calculator binary.
//! See circuits/build/membership_cpp/Makefile for build instructions.
//!
//! Input layout (membership circuit):
//! - leaf_secret[8]: 8 × 32-bit values (256-bit secret)
//! - siblings[20]: 20 merkle siblings (depth 20)
//! - path_bits[20]: 20 path direction bits
//!
//! Output: .wtns file for rapidsnark

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WitnessError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Witness calculator not found: {0}")]
    CalculatorNotFound(String),
    #[error("Witness calculation failed: {0}")]
    CalculationFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Inputs for membership proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipInputs {
    /// Leaf secret (256 bits as 8 × 32-bit values)
    pub leaf_secret: [u64; 8],
    /// Merkle siblings (depth 20)
    pub siblings: Vec<String>,
    /// Path direction bits
    pub path_bits: Vec<u8>,
}

impl MembershipInputs {
    /// Create from raw bytes
    pub fn from_bytes(
        secret: &[u8; 32],
        siblings: &[String],
        path_bits: &[u8],
    ) -> Result<Self, WitnessError> {
        if siblings.len() != 20 {
            return Err(WitnessError::InvalidInput(
                format!("Expected 20 siblings, got {}", siblings.len())
            ));
        }
        if path_bits.len() != 20 {
            return Err(WitnessError::InvalidInput(
                format!("Expected 20 path bits, got {}", path_bits.len())
            ));
        }
        
        // Split 32-byte secret into 8 × 32-bit chunks (little-endian)
        let mut leaf_secret = [0u64; 8];
        for i in 0..8 {
            let chunk = &secret[i * 4..(i + 1) * 4];
            leaf_secret[i] = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
        }
        
        Ok(Self {
            leaf_secret,
            siblings: siblings.to_vec(),
            path_bits: path_bits.to_vec(),
        })
    }
    
    /// Convert to JSON for witness calculator
    pub fn to_json(&self) -> Result<String, WitnessError> {
        let mut map = HashMap::<String, serde_json::Value>::new();
        
        // leaf_secret as array of decimal strings
        let secret_strs: Vec<String> = self.leaf_secret.iter()
            .map(|v| v.to_string())
            .collect();
        map.insert("leaf_secret".into(), serde_json::json!(secret_strs));
        
        // siblings as array of decimal strings (from hex)
        let sibling_strs: Vec<String> = self.siblings.iter()
            .map(|hex| {
                let clean = hex.strip_prefix("0x").unwrap_or(hex);
                if let Ok(bytes) = hex::decode(clean) {
                    // Parse as big-endian integer, convert to decimal
                    let val = num_bigint::BigUint::from_bytes_be(&bytes);
                    val.to_string()
                } else {
                    "0".to_string()
                }
            })
            .collect();
        map.insert("siblings".into(), serde_json::json!(sibling_strs));
        
        // path_bits as array of strings
        let path_strs: Vec<String> = self.path_bits.iter()
            .map(|v| v.to_string())
            .collect();
        map.insert("path_bits".into(), serde_json::json!(path_strs));
        
        serde_json::to_string(&map)
            .map_err(|e| WitnessError::ParseError(e.to_string()))
    }
}

/// Witness calculator using external binary
pub struct WitnessCalculator {
    /// Path to witness calculator (binary or .wasm)
    calculator_path: String,
    /// Path to .dat file
    dat_path: String,
}

impl WitnessCalculator {
    /// Create calculator with paths
    pub fn new(calculator_path: &str, dat_path: &str) -> Self {
        Self {
            calculator_path: calculator_path.to_string(),
            dat_path: dat_path.to_string(),
        }
    }
    
    /// Check if calculator exists and is executable
    pub fn is_available(&self) -> bool {
        let path = Path::new(&self.calculator_path);
        if !path.exists() {
            eprintln!("[witness] Calculator not found: {}", self.calculator_path);
            return false;
        }
        
        // Check if it's executable (skip on Windows)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = path.metadata() {
                let mode = meta.permissions().mode();
                if mode & 0o111 == 0 {
                    eprintln!("[witness] Calculator not executable: {}", self.calculator_path);
                    return false;
                }
            }
        }
        
        let dat = Path::new(&self.dat_path);
        if !dat.exists() {
            eprintln!("[witness] Dat file not found: {}", self.dat_path);
            return false;
        }
        
        true
    }
    
    /// Generate witness by calling external calculator
    pub fn calculate(&self, inputs: &MembershipInputs) -> Result<Vec<Fr>, WitnessError> {
        // Just call calculate_to_file and parse result
        let output_path = get_witness_output_path();
        self.calculate_to_file(inputs, &output_path)?;
        
        let witness_bytes = std::fs::read(&output_path)?;
        parse_witness_file(&witness_bytes)
    }
    
    /// Generate witness to file
    pub fn calculate_to_file(&self, inputs: &MembershipInputs, output_path: &str) -> Result<(), WitnessError> {
        if !self.is_available() {
            return Err(WitnessError::CalculatorNotFound(format!(
                "Witness calculator not available.\n\
                Expected binary: {}\n\
                Expected dat: {}\n\
                \n\
                For ARM64 Android, cross-compile with Android NDK:\n\
                  cd circuits/build/membership_cpp\n\
                  $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang++ \\\n\
                    -O2 -o membership_arm64 membership.cpp calcwit.cpp fr.cpp \\\n\
                    -I. -static-libstdc++ -lgmp\n\
                Then copy membership_arm64 to assets/groth16/membership",
                self.calculator_path, self.dat_path
            )));
        }
        
        // Write input JSON
        let input_json = inputs.to_json()?;
        let input_path = get_witness_input_path();
        std::fs::write(&input_path, &input_json)?;
        
        eprintln!("[witness] Running: {} {} {}", self.calculator_path, input_path, output_path);
        let start = std::time::Instant::now();
        
        // Run calculator
        let output = Command::new(&self.calculator_path)
            .arg(&input_path)
            .arg(output_path)
            .output()?;
        
        let elapsed = start.elapsed();
        eprintln!("[witness] Calculator completed in {:?}", elapsed);
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(WitnessError::CalculationFailed(format!(
                "Exit code: {:?}\nStderr: {}\nStdout: {}",
                output.status.code(), stderr, stdout
            )));
        }
        
        // Verify output exists
        if !Path::new(output_path).exists() {
            return Err(WitnessError::CalculationFailed(
                "Calculator succeeded but output file not created".into()
            ));
        }
        
        Ok(())
    }
}

/// Get witness input path (temp file)
fn get_witness_input_path() -> String {
    #[cfg(target_os = "android")]
    { "/data/local/tmp/signedby_witness_input.json".to_string() }
    #[cfg(not(target_os = "android"))]
    { "/tmp/signedby_witness_input.json".to_string() }
}

/// Get witness output path (temp file)
fn get_witness_output_path() -> String {
    #[cfg(target_os = "android")]
    { "/data/local/tmp/signedby_witness.wtns".to_string() }
    #[cfg(not(target_os = "android"))]
    { "/tmp/signedby_witness.wtns".to_string() }
}

/// Parse .wtns witness file format
pub fn parse_witness_file(bytes: &[u8]) -> Result<Vec<Fr>, WitnessError> {
    if bytes.len() < 12 {
        return Err(WitnessError::ParseError("Witness file too short".into()));
    }
    
    // Check magic
    if &bytes[0..4] != b"wtns" {
        return Err(WitnessError::ParseError("Invalid witness magic".into()));
    }
    
    let mut offset = 12;
    
    // Skip section 1 header
    if bytes.len() < offset + 12 {
        return Err(WitnessError::ParseError("Missing section header".into()));
    }
    
    let section1_size = u64::from_le_bytes(bytes[offset + 4..offset + 12].try_into().unwrap());
    offset += 12 + section1_size as usize;
    
    // Now at section 2 (witness values)
    if bytes.len() < offset + 12 {
        return Err(WitnessError::ParseError("Missing witness section".into()));
    }
    
    let section2_size = u64::from_le_bytes(bytes[offset + 4..offset + 12].try_into().unwrap());
    offset += 12;
    
    // Each witness value is 32 bytes
    let num_values = section2_size as usize / 32;
    let mut witness = Vec::with_capacity(num_values);
    
    for _ in 0..num_values {
        if bytes.len() < offset + 32 {
            break;
        }
        
        let value_bytes: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
        let fr = Fr::from_le_bytes_mod_order(&value_bytes);
        witness.push(fr);
        offset += 32;
    }
    
    eprintln!("[witness] Parsed {} witness elements", witness.len());
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_membership_inputs() {
        let secret = [0u8; 32];
        let siblings: Vec<String> = (0..20).map(|_| "0x00".to_string()).collect();
        let path_bits: Vec<u8> = vec![0; 20];
        
        let inputs = MembershipInputs::from_bytes(&secret, &siblings, &path_bits).unwrap();
        assert_eq!(inputs.leaf_secret.len(), 8);
        
        let json = inputs.to_json().unwrap();
        assert!(json.contains("leaf_secret"));
    }
}
