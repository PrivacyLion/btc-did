//! FFI bindings for rapidsnark library
//!
//! Uses dlopen/dlsym on Android to load librapidsnark.so at runtime.
//! This avoids RTLD_LOCAL visibility issues where symbols from one .so
//! aren't visible to another when loaded via System.loadLibrary().
//!
//! Falls back to binary invocation on desktop.

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

/// Lazily loaded rapidsnark function pointers
#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use std::sync::{Once, Mutex};
    
    static INIT: Once = Once::new();
    static mut LIB_HANDLE: *mut c_void = std::ptr::null_mut();
    static mut FN_PROOF_SIZE: Option<FnGroth16ProofSize> = None;
    static mut FN_PUBLIC_SIZE: Option<FnGroth16PublicSizeForZkeyFile> = None;
    static mut FN_PROVER: Option<FnGroth16ProverZkeyFile> = None;
    static mut INIT_ERROR: Option<String> = None;
    
    // Path to librapidsnark.so, set from Kotlin
    static RAPIDSNARK_PATH: Mutex<Option<String>> = Mutex::new(None);
    
    // dlopen/dlsym declarations
    extern "C" {
        fn dlopen(filename: *const c_char, flags: i32) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlerror() -> *const c_char;
    }
    
    const RTLD_NOW: i32 = 2;
    const RTLD_GLOBAL: i32 = 0x100;  // Make symbols available globally
    
    fn get_dlerror() -> String {
        unsafe {
            let err = dlerror();
            if err.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().to_string()
            }
        }
    }
    
    /// Set the path to librapidsnark.so (called from JNI)
    pub fn set_rapidsnark_path(path: String) {
        if let Ok(mut guard) = RAPIDSNARK_PATH.lock() {
            *guard = Some(path);
        }
    }
    
    /// Get the configured path
    fn get_rapidsnark_path() -> Option<String> {
        RAPIDSNARK_PATH.lock().ok().and_then(|g| g.clone())
    }
    
    pub fn ensure_loaded() -> Result<(), RapidsnarkError> {
        unsafe {
            INIT.call_once(|| {
                // Get path from Kotlin
                let lib_path = match get_rapidsnark_path() {
                    Some(p) => p,
                    None => {
                        INIT_ERROR = Some("rapidsnark path not set - call NativeBridge.initNativeLibPath() first".into());
                        return;
                    }
                };
                
                // Load librapidsnark.so with RTLD_GLOBAL so symbols are visible
                let lib_cstr = match CString::new(lib_path.clone()) {
                    Ok(s) => s,
                    Err(e) => {
                        INIT_ERROR = Some(format!("Invalid library path: {}", e));
                        return;
                    }
                };
                
                LIB_HANDLE = dlopen(lib_cstr.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
                
                if LIB_HANDLE.is_null() {
                    INIT_ERROR = Some(format!("dlopen failed for {}: {}", lib_path, get_dlerror()));
                    return;
                }
                
                // Load function pointers
                let sym_proof_size = CString::new("groth16_proof_size").unwrap();
                let ptr = dlsym(LIB_HANDLE, sym_proof_size.as_ptr());
                if ptr.is_null() {
                    INIT_ERROR = Some(format!("symbol not found: groth16_proof_size - {}", get_dlerror()));
                    return;
                }
                FN_PROOF_SIZE = Some(std::mem::transmute(ptr));
                
                let sym_public_size = CString::new("groth16_public_size_for_zkey_file").unwrap();
                let ptr = dlsym(LIB_HANDLE, sym_public_size.as_ptr());
                if ptr.is_null() {
                    INIT_ERROR = Some(format!("symbol not found: groth16_public_size_for_zkey_file - {}", get_dlerror()));
                    return;
                }
                FN_PUBLIC_SIZE = Some(std::mem::transmute(ptr));
                
                let sym_prover = CString::new("groth16_prover_zkey_file").unwrap();
                let ptr = dlsym(LIB_HANDLE, sym_prover.as_ptr());
                if ptr.is_null() {
                    INIT_ERROR = Some(format!("symbol not found: groth16_prover_zkey_file - {}", get_dlerror()));
                    return;
                }
                FN_PROVER = Some(std::mem::transmute(ptr));
            });
            
            if let Some(ref e) = INIT_ERROR {
                return Err(RapidsnarkError::LibraryNotLoaded(e.clone()));
            }
            
            if LIB_HANDLE.is_null() {
                return Err(RapidsnarkError::LibraryNotLoaded("library not initialized".into()));
            }
            
            Ok(())
        }
    }
    
    pub fn groth16_proof_size(size: &mut u64) -> Result<(), RapidsnarkError> {
        ensure_loaded()?;
        unsafe {
            if let Some(f) = FN_PROOF_SIZE {
                f(size);
                Ok(())
            } else {
                Err(RapidsnarkError::SymbolNotFound("groth16_proof_size".into()))
            }
        }
    }
    
    pub fn groth16_public_size_for_zkey_file(
        zkey_path: &CStr,
        public_size: &mut u64,
        error_buf: &mut [u8],
    ) -> Result<i32, RapidsnarkError> {
        ensure_loaded()?;
        unsafe {
            if let Some(f) = FN_PUBLIC_SIZE {
                Ok(f(
                    zkey_path.as_ptr(),
                    public_size,
                    error_buf.as_mut_ptr() as *mut c_char,
                    error_buf.len() as u64,
                ))
            } else {
                Err(RapidsnarkError::SymbolNotFound("groth16_public_size_for_zkey_file".into()))
            }
        }
    }
    
    pub fn groth16_prover_zkey_file(
        zkey_path: &CStr,
        witness_bytes: &[u8],
        proof_buf: &mut [u8],
        proof_size: &mut u64,
        public_buf: &mut [u8],
        public_size: &mut u64,
        error_buf: &mut [u8],
    ) -> Result<i32, RapidsnarkError> {
        ensure_loaded()?;
        unsafe {
            if let Some(f) = FN_PROVER {
                Ok(f(
                    zkey_path.as_ptr(),
                    witness_bytes.as_ptr() as *const c_void,
                    witness_bytes.len() as u64,
                    proof_buf.as_mut_ptr() as *mut c_char,
                    proof_size,
                    public_buf.as_mut_ptr() as *mut c_char,
                    public_size,
                    error_buf.as_mut_ptr() as *mut c_char,
                    error_buf.len() as u64,
                ))
            } else {
                Err(RapidsnarkError::SymbolNotFound("groth16_prover_zkey_file".into()))
            }
        }
    }
}

/// Generate Groth16 proof using librapidsnark (Android via dlopen)
#[cfg(target_os = "android")]
pub fn prove_with_library(
    zkey_path: &str,
    witness_bytes: &[u8],
) -> Result<(String, String), RapidsnarkError> {
    use android::*;
    
    // Get required buffer sizes
    let mut proof_size: u64 = 0;
    groth16_proof_size(&mut proof_size)?;
    
    let mut public_size: u64 = 0;
    let mut error_buf = vec![0u8; 2048];
    let zkey_cstr = CString::new(zkey_path).map_err(|e| 
        RapidsnarkError::ProverError(format!("Invalid zkey path: {}", e)))?;
    
    let ret = groth16_public_size_for_zkey_file(&zkey_cstr, &mut public_size, &mut error_buf)?;
    
    if ret != PROVER_OK {
        let error_msg = extract_error(&error_buf);
        return Err(RapidsnarkError::ProverError(
            format!("Failed to get public size: {}", error_msg)
        ));
    }
    
    // Add buffer margin
    proof_size = proof_size.max(4096);
    public_size = public_size.max(4096);
    
    // Allocate output buffers
    let mut proof_buf = vec![0u8; proof_size as usize];
    let mut public_buf = vec![0u8; public_size as usize];
    
    // Generate proof
    let ret = groth16_prover_zkey_file(
        &zkey_cstr,
        witness_bytes,
        &mut proof_buf,
        &mut proof_size,
        &mut public_buf,
        &mut public_size,
        &mut error_buf,
    )?;
    
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
