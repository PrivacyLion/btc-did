//! FFI bindings for rapidsnark library
//!
//! Links against librapidsnark.so for native proof generation on Android.
//! Falls back to binary invocation on desktop.

use std::ffi::{c_char, c_void, CStr, CString};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RapidsnarkError {
    #[error("Prover error: {0}")]
    ProverError(String),
    #[error("Short buffer error - proof needs {proof_size}, public needs {public_size}")]
    ShortBuffer { proof_size: u64, public_size: u64 },
    #[error("Invalid witness length")]
    InvalidWitnessLength,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Library not loaded")]
    LibraryNotLoaded,
}

// Error codes from prover.hpp
const PROVER_OK: i32 = 0x0;
const PROVER_ERROR: i32 = 0x1;
const PROVER_ERROR_SHORT_BUFFER: i32 = 0x2;
const PROVER_INVALID_WITNESS_LENGTH: i32 = 0x3;

// FFI declarations for librapidsnark.so
#[cfg(target_os = "android")]
extern "C" {
    fn groth16_prover_zkey_file(
        zkey_file_path: *const c_char,
        wtns_buffer: *const c_void,
        wtns_size: u64,
        proof_buffer: *mut c_char,
        proof_size: *mut u64,
        public_buffer: *mut c_char,
        public_size: *mut u64,
        error_msg: *mut c_char,
        error_msg_maxsize: u64,
    ) -> i32;

    fn groth16_proof_size(proof_size: *mut u64);

    fn groth16_public_size_for_zkey_file(
        zkey_fname: *const c_char,
        public_size: *mut u64,
        error_msg: *mut c_char,
        error_msg_maxsize: u64,
    ) -> i32;
}

/// Generate Groth16 proof using librapidsnark
///
/// # Arguments
/// * `zkey_path` - Path to .zkey file
/// * `witness_bytes` - .wtns file contents (not path)
///
/// # Returns
/// Tuple of (proof_json, public_inputs_json)
#[cfg(target_os = "android")]
pub fn prove_with_library(
    zkey_path: &str,
    witness_bytes: &[u8],
) -> Result<(String, String), RapidsnarkError> {
    // Get required buffer sizes
    let mut proof_size: u64 = 0;
    unsafe {
        groth16_proof_size(&mut proof_size);
    }
    
    let mut public_size: u64 = 0;
    let mut error_buf = vec![0u8; 2048];
    let zkey_cstr = CString::new(zkey_path).map_err(|e| 
        RapidsnarkError::ProverError(format!("Invalid zkey path: {}", e)))?;
    
    let ret = unsafe {
        groth16_public_size_for_zkey_file(
            zkey_cstr.as_ptr(),
            &mut public_size,
            error_buf.as_mut_ptr() as *mut c_char,
            error_buf.len() as u64,
        )
    };
    
    if ret != PROVER_OK {
        let error_msg = extract_error(&error_buf);
        return Err(RapidsnarkError::ProverError(
            format!("Failed to get public size: {}", error_msg)
        ));
    }
    
    // Add some buffer margin
    proof_size = proof_size.max(4096);
    public_size = public_size.max(4096);
    
    // Allocate output buffers
    let mut proof_buf = vec![0u8; proof_size as usize];
    let mut public_buf = vec![0u8; public_size as usize];
    
    // Generate proof
    let ret = unsafe {
        groth16_prover_zkey_file(
            zkey_cstr.as_ptr(),
            witness_bytes.as_ptr() as *const c_void,
            witness_bytes.len() as u64,
            proof_buf.as_mut_ptr() as *mut c_char,
            &mut proof_size,
            public_buf.as_mut_ptr() as *mut c_char,
            &mut public_size,
            error_buf.as_mut_ptr() as *mut c_char,
            error_buf.len() as u64,
        )
    };
    
    match ret {
        PROVER_OK => {
            // Extract strings up to proof_size/public_size bytes
            let proof_json = String::from_utf8_lossy(&proof_buf[..proof_size as usize])
                .trim_end_matches('\0')
                .to_string();
            let public_json = String::from_utf8_lossy(&public_buf[..public_size as usize])
                .trim_end_matches('\0')
                .to_string();
            Ok((proof_json, public_json))
        }
        PROVER_ERROR_SHORT_BUFFER => {
            Err(RapidsnarkError::ShortBuffer { proof_size, public_size })
        }
        PROVER_INVALID_WITNESS_LENGTH => {
            Err(RapidsnarkError::InvalidWitnessLength)
        }
        _ => {
            let error_msg = extract_error(&error_buf);
            Err(RapidsnarkError::ProverError(error_msg))
        }
    }
}

/// Desktop fallback - use binary
#[cfg(not(target_os = "android"))]
pub fn prove_with_library(
    zkey_path: &str,
    witness_bytes: &[u8],
) -> Result<(String, String), RapidsnarkError> {
    use std::process::Command;
    
    // Write witness to temp file
    let witness_path = "/tmp/signedby_witness.wtns";
    let proof_path = "/tmp/signedby_proof.json";
    let public_path = "/tmp/signedby_public.json";
    
    std::fs::write(witness_path, witness_bytes)?;
    
    // Try rapidsnark binary
    let output = Command::new("rapidsnark")
        .args([zkey_path, witness_path, proof_path, public_path])
        .output();
    
    match output {
        Ok(out) if out.status.success() => {
            let proof_json = std::fs::read_to_string(proof_path)?;
            let public_json = std::fs::read_to_string(public_path)?;
            Ok((proof_json, public_json))
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(RapidsnarkError::ProverError(format!("rapidsnark failed: {}", stderr)))
        }
        Err(e) => {
            Err(RapidsnarkError::ProverError(format!("rapidsnark not found: {}", e)))
        }
    }
}

/// Extract error message from C buffer
fn extract_error(buf: &[u8]) -> String {
    match CStr::from_bytes_until_nul(buf) {
        Ok(s) => s.to_string_lossy().to_string(),
        Err(_) => String::from_utf8_lossy(buf).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_types() {
        let e = RapidsnarkError::InvalidWitnessLength;
        assert!(e.to_string().contains("Invalid witness"));
    }
}
