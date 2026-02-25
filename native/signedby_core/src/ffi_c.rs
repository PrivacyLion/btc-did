//! C-ABI FFI exports for iOS
//!
//! This module provides C-compatible function exports that can be called
//! from Swift via the bridging header.
//!
//! Naming convention: sbm_* (SignedByMe)
//!
//! Memory rules:
//! - String returns: Caller must call sbm_free_string()
//! - Byte array returns: Caller must call sbm_free_bytes()
//! - Input strings: Caller owns, function borrows

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use sha2::{Digest, Sha256};

// ============================================================================
// Memory Management
// ============================================================================

/// Free a string allocated by Rust
#[no_mangle]
pub extern "C" fn sbm_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// Free a byte array allocated by Rust
#[no_mangle]
pub extern "C" fn sbm_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_from_ptr(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(String::from) }
}

fn string_to_ptr(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn bytes_to_ptr(data: Vec<u8>) -> *mut u8 {
    let mut boxed = data.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

// ============================================================================
// Basic Functions
// ============================================================================

/// Hello from Rust - sanity check
#[no_mangle]
pub extern "C" fn sbm_hello_from_rust() -> *mut c_char {
    string_to_ptr("Hello from Rust core v3 (Groth16) 👋".to_string())
}

/// SHA-256 hash of input string
#[no_mangle]
pub extern "C" fn sbm_sha256_hex(input: *const c_char) -> *mut c_char {
    let s = match str_from_ptr(input) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hex = hex::encode(hasher.finalize());
    string_to_ptr(hex)
}

// ============================================================================
// Key Management
// ============================================================================

/// Generate a random 32-byte private key
#[no_mangle]
pub extern "C" fn sbm_generate_private_key() -> *mut u8 {
    use rand_core::OsRng;
    use k256::SecretKey;
    
    let sk = SecretKey::random(&mut OsRng);
    let bytes = sk.to_bytes().to_vec();
    bytes_to_ptr(bytes)
}

/// Derive compressed public key hex from private key
#[no_mangle]
pub extern "C" fn sbm_derive_public_key_hex(
    priv_ptr: *const u8,
    priv_len: usize,
) -> *mut c_char {
    if priv_ptr.is_null() || priv_len != 32 {
        return ptr::null_mut();
    }
    
    let priv_bytes = unsafe { std::slice::from_raw_parts(priv_ptr, priv_len) };
    
    use k256::SecretKey;
    let sk = match SecretKey::from_slice(priv_bytes) {
        Ok(sk) => sk,
        Err(_) => return ptr::null_mut(),
    };
    
    let pk = sk.public_key();
    let compressed = pk.to_sec1_bytes();
    string_to_ptr(hex::encode(&compressed))
}

/// Get x-only public key (32 bytes) for Taproot/Schnorr
#[no_mangle]
pub extern "C" fn sbm_get_x_only_pubkey(
    priv_ptr: *const u8,
    priv_len: usize,
) -> *mut c_char {
    if priv_ptr.is_null() || priv_len != 32 {
        return ptr::null_mut();
    }
    
    let priv_bytes = unsafe { std::slice::from_raw_parts(priv_ptr, priv_len) };
    
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    
    let sk = match SecretKey::from_slice(priv_bytes) {
        Ok(sk) => sk,
        Err(_) => return ptr::null_mut(),
    };
    
    let pk = sk.public_key();
    let point = pk.to_encoded_point(false);
    // X coordinate is bytes 1..33 of uncompressed point
    let x_bytes = &point.as_bytes()[1..33];
    string_to_ptr(hex::encode(x_bytes))
}

/// Sign message with ECDSA (DER format)
#[no_mangle]
pub extern "C" fn sbm_sign_message_der_hex(
    priv_ptr: *const u8,
    priv_len: usize,
    message: *const c_char,
) -> *mut c_char {
    if priv_ptr.is_null() || priv_len != 32 {
        return ptr::null_mut();
    }
    
    let priv_bytes = unsafe { std::slice::from_raw_parts(priv_ptr, priv_len) };
    let msg = match str_from_ptr(message) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    
    use k256::ecdsa::{SigningKey, signature::Signer};
    use sha2::{Sha256, Digest};
    
    let sk = match SigningKey::from_slice(priv_bytes) {
        Ok(sk) => sk,
        Err(_) => return ptr::null_mut(),
    };
    
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let digest = hasher.finalize();
    
    let sig: k256::ecdsa::Signature = sk.sign(&digest);
    string_to_ptr(hex::encode(sig.to_der()))
}

/// Sign message with Schnorr (64 bytes)
#[no_mangle]
pub extern "C" fn sbm_sign_schnorr(
    priv_ptr: *const u8,
    priv_len: usize,
    message: *const c_char,
) -> *mut c_char {
    if priv_ptr.is_null() || priv_len != 32 {
        return ptr::null_mut();
    }
    
    let priv_bytes = unsafe { std::slice::from_raw_parts(priv_ptr, priv_len) };
    let msg = match str_from_ptr(message) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    
    // Use secp256k1 for BIP340 Schnorr
    use secp256k1::{Secp256k1, SecretKey, Message};
    
    let secp = Secp256k1::new();
    let sk = match SecretKey::from_slice(priv_bytes) {
        Ok(sk) => sk,
        Err(_) => return ptr::null_mut(),
    };
    
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    
    let msg = match Message::from_digest(digest) {
        m => m,
    };
    
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let sig = secp.sign_schnorr(&msg, &keypair);
    string_to_ptr(hex::encode(sig.serialize()))
}

// ============================================================================
// Groth16 Proof Generation
// ============================================================================

/// Check if prover is ready
#[no_mangle]
pub extern "C" fn sbm_is_prover_ready() -> bool {
    // TODO: Check global prover state
    false
}

/// Initialize prover with paths
#[no_mangle]
pub extern "C" fn sbm_init_prover(
    zkey_path: *const c_char,
    dat_path: *const c_char,
    calc_path: *const c_char,
) -> bool {
    let _zkey = match str_from_ptr(zkey_path) {
        Some(s) => s,
        None => return false,
    };
    let _dat = match str_from_ptr(dat_path) {
        Some(s) => s,
        None => return false,
    };
    let _calc = match str_from_ptr(calc_path) {
        Some(s) => s,
        None => return false,
    };
    
    // TODO: Initialize prover (same as JNI)
    true
}

/// Generate Groth16 proof
#[no_mangle]
pub extern "C" fn sbm_generate_proof(
    input_json: *const c_char,
) -> *mut c_char {
    let _input = match str_from_ptr(input_json) {
        Some(s) => s,
        None => {
            return string_to_ptr(r#"{"success":false,"error":"Invalid input"}"#.to_string());
        }
    };
    
    // TODO: Call prover (same as JNI)
    string_to_ptr(r#"{"success":false,"error":"Prover not implemented for iOS yet"}"#.to_string())
}

// ============================================================================
// Membership Proofs
// ============================================================================

/// Compute leaf commitment from secret
#[no_mangle]
pub extern "C" fn sbm_compute_leaf_commitment(
    secret_ptr: *const u8,
    secret_len: usize,
) -> *mut u8 {
    if secret_ptr.is_null() || secret_len != 32 {
        return ptr::null_mut();
    }
    
    let secret = unsafe { std::slice::from_raw_parts(secret_ptr, secret_len) };
    
    // Use Poseidon2 via membership module
    let secret_arr: [u8; 32] = match secret.try_into() {
        Ok(arr) => arr,
        Err(_) => return ptr::null_mut(),
    };
    
    // Compute leaf commitment using SHA256 for now
    // TODO: Use actual Poseidon2 when poseidon_hash binary is available
    let mut hasher = Sha256::new();
    hasher.update(b"sbm:leaf:");
    hasher.update(&secret_arr);
    let commitment: [u8; 32] = hasher.finalize().into();
    
    bytes_to_ptr(commitment.to_vec())
}

/// Check if real STWO support is available (legacy - always false now)
#[no_mangle]
pub extern "C" fn sbm_has_real_stwo() -> bool {
    false  // STWO removed, using Groth16
}

// ============================================================================
// Lightning / Payment
// ============================================================================

/// Generate preimage and payment hash
#[no_mangle]
pub extern "C" fn sbm_generate_preimage() -> *mut c_char {
    use rand_core::{OsRng, RngCore};
    
    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let payment_hash = hasher.finalize();
    
    let json = serde_json::json!({
        "preimage_hex": hex::encode(&preimage),
        "payment_hash": hex::encode(&payment_hash),
    });
    
    string_to_ptr(json.to_string())
}

/// Verify payment preimage
#[no_mangle]
pub extern "C" fn sbm_verify_payment(
    payment_hash: *const c_char,
    preimage_hex: *const c_char,
) -> *mut c_char {
    let hash_str = match str_from_ptr(payment_hash) {
        Some(s) => s,
        None => return string_to_ptr(r#"{"valid":false,"error":"Invalid payment_hash"}"#.to_string()),
    };
    let preimage_str = match str_from_ptr(preimage_hex) {
        Some(s) => s,
        None => return string_to_ptr(r#"{"valid":false,"error":"Invalid preimage"}"#.to_string()),
    };
    
    let preimage = match hex::decode(&preimage_str) {
        Ok(b) => b,
        Err(_) => return string_to_ptr(r#"{"valid":false,"error":"Invalid preimage hex"}"#.to_string()),
    };
    
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let computed = hex::encode(hasher.finalize());
    
    let valid = computed.to_lowercase() == hash_str.to_lowercase();
    
    let json = serde_json::json!({
        "valid": valid,
    });
    
    string_to_ptr(json.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hello() {
        let ptr = sbm_hello_from_rust();
        assert!(!ptr.is_null());
        sbm_free_string(ptr);
    }
}
