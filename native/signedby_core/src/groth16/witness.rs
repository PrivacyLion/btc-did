//! Witness generation for Groth16 proofs
//!
//! On Android: Uses dlopen to load libmembership.so and call witnesscalc_membership()
//! On desktop: Falls back to subprocess execution for testing
//!
//! Input layout (membership circuit):
//! - leaf_secret[8]: 8 × 32-bit values (256-bit secret)
//! - siblings[20]: 20 merkle siblings (depth 20)
//! - path_bits[20]: 20 path direction bits
//!
//! Output: .wtns witness bytes for rapidsnark

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
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
    #[error("FFI error: {0}")]
    FfiError(String),
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

// ============================================================================
// FFI types for witnesscalc library
// ============================================================================

/// Function signature for witnesscalc_membership
/// Returns: 0 on success, negative on error
type WitnesscalcFn = unsafe extern "C" fn(
    dat_path: *const std::os::raw::c_char,
    json_input: *const std::os::raw::c_char,
    json_len: std::os::raw::c_ulong,
    wtns_buffer: *mut u8,
    wtns_size: *mut std::os::raw::c_ulong,
    error_msg: *mut std::os::raw::c_char,
    error_msg_size: std::os::raw::c_ulong,
) -> std::os::raw::c_int;

/// Function signature for witnesscalc_membership_size
type WitnesscalcSizeFn = unsafe extern "C" fn() -> std::os::raw::c_ulong;

// ============================================================================
// Witness Calculator
// ============================================================================

/// Witness calculator - uses FFI on Android, subprocess on desktop
pub struct WitnessCalculator {
    /// Path to witness calculator library (.so) or binary
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
    
    /// Check if calculator is available
    pub fn is_available(&self) -> bool {
        let path = Path::new(&self.calculator_path);
        if !path.exists() {
            eprintln!("[witness] Calculator not found: {}", self.calculator_path);
            return false;
        }
        
        let dat = Path::new(&self.dat_path);
        if !dat.exists() {
            eprintln!("[witness] Dat file not found: {}", self.dat_path);
            return false;
        }
        
        true
    }
    
    /// Calculate witness and return bytes
    pub fn calculate_to_buffer(&self, inputs: &MembershipInputs) -> Result<Vec<u8>, WitnessError> {
        let input_json = inputs.to_json()?;
        
        #[cfg(target_os = "android")]
        {
            self.calculate_via_ffi(&input_json)
        }
        
        #[cfg(not(target_os = "android"))]
        {
            self.calculate_via_subprocess(&input_json)
        }
    }
    
    /// Calculate witness via FFI (Android)
    #[cfg(target_os = "android")]
    fn calculate_via_ffi(&self, input_json: &str) -> Result<Vec<u8>, WitnessError> {
        use std::ffi::CString;
        
        eprintln!("[witness] Loading library: {}", self.calculator_path);
        let start = std::time::Instant::now();
        
        // dlopen the library
        let lib_path = CString::new(self.calculator_path.as_str())
            .map_err(|e| WitnessError::FfiError(format!("Invalid path: {}", e)))?;
        
        let handle = unsafe {
            libc::dlopen(lib_path.as_ptr(), libc::RTLD_NOW)
        };
        
        if handle.is_null() {
            let error = unsafe {
                let err = libc::dlerror();
                if err.is_null() {
                    "Unknown dlopen error".to_string()
                } else {
                    std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned()
                }
            };
            return Err(WitnessError::FfiError(format!("dlopen failed: {}", error)));
        }
        
        eprintln!("[witness] Library loaded in {:?}", start.elapsed());
        
        // Get function pointers
        let size_fn_name = CString::new("witnesscalc_membership_size").unwrap();
        let calc_fn_name = CString::new("witnesscalc_membership").unwrap();
        
        let size_fn: WitnesscalcSizeFn = unsafe {
            let ptr = libc::dlsym(handle, size_fn_name.as_ptr());
            if ptr.is_null() {
                libc::dlclose(handle);
                return Err(WitnessError::FfiError("witnesscalc_membership_size not found".into()));
            }
            std::mem::transmute(ptr)
        };
        
        let calc_fn: WitnesscalcFn = unsafe {
            let ptr = libc::dlsym(handle, calc_fn_name.as_ptr());
            if ptr.is_null() {
                libc::dlclose(handle);
                return Err(WitnessError::FfiError("witnesscalc_membership not found".into()));
            }
            std::mem::transmute(ptr)
        };
        
        // Get required buffer size
        let required_size = unsafe { size_fn() } as usize;
        eprintln!("[witness] Required buffer size: {} bytes", required_size);
        
        // Allocate buffers
        let mut witness_buf = vec![0u8; required_size];
        let mut witness_size = required_size as std::os::raw::c_ulong;
        let mut error_buf: Vec<std::os::raw::c_char> = vec![0; 1024];
        
        let dat_path_c = CString::new(self.dat_path.as_str())
            .map_err(|e| WitnessError::FfiError(format!("Invalid dat path: {}", e)))?;
        let json_c = CString::new(input_json)
            .map_err(|e| WitnessError::FfiError(format!("Invalid JSON: {}", e)))?;
        
        eprintln!("[witness] Calling witnesscalc_membership...");
        let calc_start = std::time::Instant::now();
        
        let result = unsafe {
            calc_fn(
                dat_path_c.as_ptr(),
                json_c.as_ptr(),
                input_json.len() as std::os::raw::c_ulong,
                witness_buf.as_mut_ptr(),
                &mut witness_size,
                error_buf.as_mut_ptr(),
                error_buf.len() as std::os::raw::c_ulong,
            )
        };
        
        let calc_elapsed = calc_start.elapsed();
        eprintln!("[witness] witnesscalc_membership completed in {:?}, result={}", calc_elapsed, result);
        
        // Close library
        unsafe { libc::dlclose(handle); }
        
        if result != 0 {
            let error_msg = unsafe {
                std::ffi::CStr::from_ptr(error_buf.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            return Err(WitnessError::CalculationFailed(format!(
                "witnesscalc returned {}: {}", result, error_msg
            )));
        }
        
        // Truncate to actual size
        witness_buf.truncate(witness_size as usize);
        eprintln!("[witness] Generated {} bytes of witness data", witness_buf.len());
        
        Ok(witness_buf)
    }
    
    /// Calculate witness via subprocess (desktop/testing)
    #[cfg(not(target_os = "android"))]
    fn calculate_via_subprocess(&self, input_json: &str) -> Result<Vec<u8>, WitnessError> {
        use std::process::Command;
        
        if !self.is_available() {
            return Err(WitnessError::CalculatorNotFound(
                format!("Calculator not found: {}", self.calculator_path)
            ));
        }
        
        // Write input JSON to temp file
        let input_path = "/tmp/signedby_witness_input.json";
        let output_path = "/tmp/signedby_witness.wtns";
        std::fs::write(input_path, input_json)?;
        
        eprintln!("[witness] Running: {} {} {}", self.calculator_path, input_path, output_path);
        let start = std::time::Instant::now();
        
        let output = Command::new(&self.calculator_path)
            .arg(input_path)
            .arg(output_path)
            .output()?;
        
        let elapsed = start.elapsed();
        eprintln!("[witness] Calculator completed in {:?}", elapsed);
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WitnessError::CalculationFailed(format!(
                "Exit code: {:?}, stderr: {}", output.status.code(), stderr
            )));
        }
        
        let witness_bytes = std::fs::read(output_path)?;
        eprintln!("[witness] Read {} bytes from {}", witness_bytes.len(), output_path);
        
        Ok(witness_bytes)
    }
    
    /// Generate witness to file (for compatibility)
    pub fn calculate_to_file(&self, inputs: &MembershipInputs, output_path: &str) -> Result<(), WitnessError> {
        let witness_bytes = self.calculate_to_buffer(inputs)?;
        std::fs::write(output_path, &witness_bytes)?;
        Ok(())
    }
    
    /// Generate witness and parse to Fr elements
    pub fn calculate(&self, inputs: &MembershipInputs) -> Result<Vec<Fr>, WitnessError> {
        let witness_bytes = self.calculate_to_buffer(inputs)?;
        parse_witness_file(&witness_bytes)
    }
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
