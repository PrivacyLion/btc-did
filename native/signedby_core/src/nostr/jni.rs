// nostr/jni.rs - JNI bindings for NOSTR functions (Android)
//
// These functions are called from Kotlin via NativeBridge.kt

use anyhow::Result;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jstring, jlong, jboolean};
use jni::JNIEnv;
use ark_bn254::Fr;
use ark_ff::PrimeField;

use super::{derive_nsec_from_leaf_secret, derive_nostr_keypair};

/// Derive nsec from leaf_secret bytes
/// 
/// Input: leaf_secret as 5 * 32 bytes (5 BN254 field elements, big-endian)
/// Output: nsec as 32-byte secret key
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_deriveNsecFromLeafSecret(
    mut env: JNIEnv,
    _clazz: JClass,
    leaf_secret_bytes: JByteArray,
) -> jbyteArray {
    let bytes = match env.convert_byte_array(leaf_secret_bytes) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // leaf_secret is 5 * 32 = 160 bytes
    if bytes.len() != 160 {
        return std::ptr::null_mut();
    }
    
    // Parse 5 Fr elements from bytes
    let leaf_secret = match parse_leaf_secret(&bytes) {
        Ok(ls) => ls,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Derive nsec
    let nsec = match derive_nsec_from_leaf_secret(&leaf_secret) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Return 32-byte secret key
    match env.byte_array_from_slice(&nsec.secret_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive npub (bech32) from leaf_secret
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_deriveNpubFromLeafSecret(
    mut env: JNIEnv,
    _clazz: JClass,
    leaf_secret_bytes: JByteArray,
) -> jstring {
    let bytes = match env.convert_byte_array(leaf_secret_bytes) {
        Ok(b) => b,
        Err(_) => return env.new_string("error:invalid_bytes").unwrap().into_raw(),
    };
    
    if bytes.len() != 160 {
        return env.new_string("error:invalid_length").unwrap().into_raw();
    }
    
    let leaf_secret = match parse_leaf_secret(&bytes) {
        Ok(ls) => ls,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    let keys = match derive_nostr_keypair(&leaf_secret) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    match keys.public_key().to_bech32() {
        Ok(npub) => env.new_string(npub).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Sign a NOSTR event with nsec derived from leaf_secret
/// 
/// Input: leaf_secret (160 bytes) + event content (string)
/// Output: Schnorr signature (64 bytes hex)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_signNostrEvent(
    mut env: JNIEnv,
    _clazz: JClass,
    leaf_secret_bytes: JByteArray,
    event_content: JString,
) -> jstring {
    let bytes = match env.convert_byte_array(leaf_secret_bytes) {
        Ok(b) => b,
        Err(_) => return env.new_string("error:invalid_bytes").unwrap().into_raw(),
    };
    
    let content = match env.get_string(&event_content) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_content").unwrap().into_raw(),
    };
    
    if bytes.len() != 160 {
        return env.new_string("error:invalid_length").unwrap().into_raw();
    }
    
    let leaf_secret = match parse_leaf_secret(&bytes) {
        Ok(ls) => ls,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    let keys = match derive_nostr_keypair(&leaf_secret) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    // Sign the content hash
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(content.as_bytes());
    
    use nostr_sdk::secp256k1::{Secp256k1, Message};
    let secp = Secp256k1::new();
    let msg = match Message::from_digest_slice(&hash) {
        Ok(m) => m,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    let keypair = match nostr_sdk::secp256k1::Keypair::from_secret_key(&secp, &keys.secret_key().inner) {
        keypair => keypair,
    };
    
    let sig = secp.sign_schnorr(&msg, &keypair);
    
    env.new_string(hex::encode(sig.as_ref())).unwrap().into_raw()
}

/// Generate ephemeral keypair for NWC (DECISION 2)
/// 
/// Returns: JSON with { ephemeral_nsec_hex, ephemeral_npub }
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_generateEphemeralNwcKeypair(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    use nostr_sdk::Keys;
    
    let keys = Keys::generate();
    
    let json = serde_json::json!({
        "ephemeral_nsec_hex": hex::encode(keys.secret_key().secret_bytes()),
        "ephemeral_npub": keys.public_key().to_bech32().unwrap_or_default(),
    });
    
    env.new_string(json.to_string()).unwrap().into_raw()
}

/// Parse leaf_secret from 160 bytes (5 * 32-byte big-endian Fr elements)
fn parse_leaf_secret(bytes: &[u8]) -> Result<[Fr; 5]> {
    if bytes.len() != 160 {
        anyhow::bail!("Expected 160 bytes, got {}", bytes.len());
    }
    
    let mut result = [Fr::from(0u64); 5];
    
    for i in 0..5 {
        let start = i * 32;
        let end = start + 32;
        let element_bytes: [u8; 32] = bytes[start..end].try_into()?;
        
        // Parse as big-endian
        result[i] = Fr::from_be_bytes_mod_order(&element_bytes);
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    
    #[test]
    fn test_parse_leaf_secret() {
        let mut rng = thread_rng();
        let original: [Fr; 5] = [
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        ];
        
        // Serialize to bytes
        let mut bytes = vec![0u8; 160];
        for (i, elem) in original.iter().enumerate() {
            use ark_ff::BigInteger;
            let bigint = elem.into_bigint();
            let elem_bytes = bigint.to_bytes_be();
            bytes[i * 32..(i + 1) * 32].copy_from_slice(&elem_bytes);
        }
        
        // Parse back
        let parsed = parse_leaf_secret(&bytes).unwrap();
        
        for i in 0..5 {
            assert_eq!(original[i], parsed[i]);
        }
    }
}
