//! FFI bindings for rapidsnark library
//!
//! Uses dlopen/dlsym to load librapidsnark.so at runtime on all platforms.
//! Library path is passed as parameter — no static initialization required.

use std::ffi::{c_char, c_void, CStr, CString};
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
    #[error("Library not loaded: {0}")]
    LibraryNotLoaded(String),
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
}

// Error codes from prover.hpp
const PROVER_OK: i32 = 0x0;
const _PROVER_ERROR: i32 = 0x1;
const PROVER_ERROR_SHORT_BUFFER: i32 = 0x2;
const PROVER_INVALID_WITNESS_LENGTH: i32 = 0x3;

// Function pointer types matching prover.h
type FnGroth16ProofSize = unsafe extern "C" fn(*mut u64);
type FnGroth16PublicSizeForZkeyFile = unsafe extern "C" fn(
    *const c_char, *mut u64, *mut c_char, u64
) -> i32;
type FnGroth16ProverZkeyFile = unsafe extern "C" fn(
    *const c_char,      // zkey_file_path
    *const c_void, u64, // wtns_buffer, wtns_size
    *mut c_char, *mut u64, // proof_buffer, proof_size
    *mut c_char, *mut u64, // public_buffer, public_size
    *mut c_char, u64,   // error_msg, error_msg_maxsize
) -> i32;

/// Get dlerror message
fn get_dlerror() -> String {
    unsafe {
        let err = libc::dlerror();
        if err.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(err).to_string_lossy().to_string()
        }
    }
}

/// Generate Groth16 proof using librapidsnark via dlopen/dlsym
///
/// # Arguments
/// * `rapidsnark_lib_path` - Path to librapidsnark.so
/// * `zkey_path` - Path to the .zkey file
/// * `witness_bytes` - Witness data (.wtns format)
///
/// # Returns
/// Tuple of (proof_json, public_signals_json)
pub fn prove_with_library(
    rapidsnark_lib_path: &str,
    zkey_path: &str,
    witness_bytes: &[u8],
) -> Result<(String, String), RapidsnarkError> {
    eprintln!("[rapidsnark] Loading library: {}", rapidsnark_lib_path);
    let start = std::time::Instant::now();
    
    // dlopen the library
    let lib_path = CString::new(rapidsnark_lib_path)
        .map_err(|e| RapidsnarkError::LibraryNotLoaded(format!("Invalid path: {}", e)))?;
    
    let handle = unsafe {
        libc::dlopen(lib_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL)
    };
    
    if handle.is_null() {
        return Err(RapidsnarkError::LibraryNotLoaded(
            format!("dlopen failed: {}", get_dlerror())
        ));
    }
    
    eprintln!("[rapidsnark] Library loaded in {:?}", start.elapsed());
    
    // Resolve function pointers via dlsym
    let fn_proof_size: FnGroth16ProofSize = unsafe {
        let sym = CString::new("groth16_proof_size").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if ptr.is_null() {
            libc::dlclose(handle);
            return Err(RapidsnarkError::SymbolNotFound(
                format!("groth16_proof_size: {}", get_dlerror())
            ));
        }
        std::mem::transmute(ptr)
    };
    
    let fn_public_size: FnGroth16PublicSizeForZkeyFile = unsafe {
        let sym = CString::new("groth16_public_size_for_zkey_file").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if ptr.is_null() {
            libc::dlclose(handle);
            return Err(RapidsnarkError::SymbolNotFound(
                format!("groth16_public_size_for_zkey_file: {}", get_dlerror())
            ));
        }
        std::mem::transmute(ptr)
    };
    
    let fn_prover: FnGroth16ProverZkeyFile = unsafe {
        let sym = CString::new("groth16_prover_zkey_file").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if ptr.is_null() {
            libc::dlclose(handle);
            return Err(RapidsnarkError::SymbolNotFound(
                format!("groth16_prover_zkey_file: {}", get_dlerror())
            ));
        }
        std::mem::transmute(ptr)
    };
    
    // Get required buffer sizes
    let mut proof_size: u64 = 0;
    unsafe { fn_proof_size(&mut proof_size) };
    
    let mut public_size: u64 = 0;
    let mut error_buf = vec![0u8; 2048];
    let zkey_cstr = CString::new(zkey_path).map_err(|e| {
        unsafe { libc::dlclose(handle) };
        RapidsnarkError::ProverError(format!("Invalid zkey path: {}", e))
    })?;
    
    let ret = unsafe {
        fn_public_size(
            zkey_cstr.as_ptr(),
            &mut public_size,
            error_buf.as_mut_ptr() as *mut c_char,
            error_buf.len() as u64,
        )
    };
    
    if ret != PROVER_OK {
        let error_msg = extract_error(&error_buf);
        unsafe { libc::dlclose(handle) };
        return Err(RapidsnarkError::ProverError(
            format!("Failed to get public size: {}", error_msg)
        ));
    }
    
    // Add buffer margin
    proof_size = proof_size.max(4096);
    public_size = public_size.max(4096);
    
    eprintln!("[rapidsnark] Buffer sizes: proof={}, public={}", proof_size, public_size);
    
    // Allocate output buffers
    let mut proof_buf = vec![0u8; proof_size as usize];
    let mut public_buf = vec![0u8; public_size as usize];
    
    // Generate proof
    eprintln!("[rapidsnark] Generating proof...");
    let prove_start = std::time::Instant::now();
    
    let ret = unsafe {
        fn_prover(
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
    
    let prove_elapsed = prove_start.elapsed();
    eprintln!("[rapidsnark] Proof generation completed in {:?}, result={}", prove_elapsed, ret);
    
    // Close library
    unsafe { libc::dlclose(handle) };
    
    match ret {
        PROVER_OK => {
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

/// Extract error message from C buffer
fn extract_error(buf: &[u8]) -> String {
    // Find null terminator
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).to_string()
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
