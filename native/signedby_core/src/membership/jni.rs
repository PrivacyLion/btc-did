//! JNI Bindings for Membership Proofs (Groth16)
//!
//! Provides Android native methods for:
//! - computeBindingHashV4: Compute the V4 binding hash
//! - computeLeafCommitment: Compute leaf from secret (SHA-256)
//! - computeNullifier: Compute nullifier from leaf secret + session
//!
//! Note: Groth16 proof generation will use rapidsnark (Phase 14).
//! These functions provide helper utilities.

use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use sha2::{Sha256, Digest};

/// Domain separator for leaf commitment
const LEAF_COMMITMENT_DOMAIN: &[u8] = b"leaf_commit:";

/// Compute V4 binding hash (called from Kotlin)
///
/// This allows the app to compute the binding hash client-side
/// to include in proof generation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_computeBindingHashV4<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    did_pubkey: JByteArray<'local>,
    wallet_address: jni::objects::JString<'local>,
    client_id: jni::objects::JString<'local>,
    session_id: jni::objects::JString<'local>,
    payment_hash: JByteArray<'local>,
    amount_sats: jni::sys::jlong,
    expires_at: jni::sys::jlong,
    nonce: JByteArray<'local>,
    ea_domain: jni::objects::JString<'local>,
    purpose_id: jni::sys::jint,
    root_id: jni::objects::JString<'local>,
) -> jbyteArray {
    use super::binding::compute_binding_hash_v4;
    
    let result = (|| -> Result<[u8; 32], String> {
        // Parse all inputs
        let did_pubkey_vec = env.convert_byte_array(&did_pubkey)
            .map_err(|e| e.to_string())?;
        
        let wallet_str: String = env.get_string(&wallet_address)
            .map_err(|e| e.to_string())?
            .into();
        
        let client_str: String = env.get_string(&client_id)
            .map_err(|e| e.to_string())?
            .into();
        
        let session_str: String = env.get_string(&session_id)
            .map_err(|e| e.to_string())?
            .into();
        
        let payment_hash_vec = env.convert_byte_array(&payment_hash)
            .map_err(|e| e.to_string())?;
        
        let nonce_vec = env.convert_byte_array(&nonce)
            .map_err(|e| e.to_string())?;
        
        let ea_domain_str: String = env.get_string(&ea_domain)
            .map_err(|e| e.to_string())?
            .into();
        
        let root_id_str: String = env.get_string(&root_id)
            .map_err(|e| e.to_string())?
            .into();
        
        Ok(compute_binding_hash_v4(
            &did_pubkey_vec,
            &wallet_str,
            &client_str,
            &session_str,
            &payment_hash_vec,
            amount_sats as u64,
            expires_at as u64,
            &nonce_vec,
            &ea_domain_str,
            purpose_id as u8,
            &root_id_str,
        ))
    })();
    
    match result {
        Ok(hash) => {
            match env.byte_array_from_slice(&hash) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// Compute leaf commitment from leaf secret (called from Kotlin)
///
/// Uses SHA-256 with domain separator:
/// leaf_commitment = SHA256("leaf_commit:" || leaf_secret)
///
/// Signature: (leafSecret: ByteArray) -> ByteArray (32 bytes)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_computeLeafCommitment<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    leaf_secret: JByteArray<'local>,
) -> jbyteArray {
    let result = (|| -> Result<[u8; 32], String> {
        let leaf_secret_vec = env.convert_byte_array(&leaf_secret)
            .map_err(|e| e.to_string())?;
        if leaf_secret_vec.len() != 32 {
            return Err("leaf_secret must be 32 bytes".into());
        }
        
        let mut hasher = Sha256::new();
        hasher.update(LEAF_COMMITMENT_DOMAIN);
        hasher.update(&leaf_secret_vec);
        let commitment: [u8; 32] = hasher.finalize().into();
        
        Ok(commitment)
    })();
    
    match result {
        Ok(hash) => {
            match env.byte_array_from_slice(&hash) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// Compute nullifier from leaf secret and session ID (called from Kotlin)
///
/// nullifier = SHA256("nullifier:" || leaf_secret || session_id)
///
/// Signature: (leafSecret: ByteArray, sessionId: ByteArray) -> ByteArray (32 bytes)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_computeNullifier<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    leaf_secret: JByteArray<'local>,
    session_id: JByteArray<'local>,
) -> jbyteArray {
    const NULLIFIER_DOMAIN: &[u8] = b"nullifier:";
    
    let result = (|| -> Result<[u8; 32], String> {
        let leaf_secret_vec = env.convert_byte_array(&leaf_secret)
            .map_err(|e| e.to_string())?;
        if leaf_secret_vec.len() != 32 {
            return Err("leaf_secret must be 32 bytes".into());
        }
        
        let session_id_vec = env.convert_byte_array(&session_id)
            .map_err(|e| e.to_string())?;
        if session_id_vec.len() != 32 {
            return Err("session_id must be 32 bytes".into());
        }
        
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_DOMAIN);
        hasher.update(&leaf_secret_vec);
        hasher.update(&session_id_vec);
        let nullifier: [u8; 32] = hasher.finalize().into();
        
        Ok(nullifier)
    })();
    
    match result {
        Ok(hash) => {
            match env.byte_array_from_slice(&hash) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}
