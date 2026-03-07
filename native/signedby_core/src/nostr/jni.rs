// nostr/jni.rs - JNI bindings for NOSTR functions (Android)
//
// These functions are called from Kotlin via NativeBridge.kt

use anyhow::Result;
use jni::objects::{JByteArray, JClass, JString, JObjectArray};
use jni::sys::{jbyteArray, jstring, jlong, jboolean, jobjectArray, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use nostr_sdk::ToBech32;
use std::sync::Mutex;
use once_cell::sync::Lazy;

use super::derive_nsec_from_leaf_secret;
use super::client::NostrClient;
use super::events::{ProofEvent, PaymentReceiptEvent, LoginCompleteEvent};

// Global Tokio runtime for async operations
static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
});

// Global NOSTR client (protected by mutex)
static NOSTR_CLIENT: Lazy<Mutex<Option<NostrClient>>> = Lazy::new(|| Mutex::new(None));

// Global NWC client (protected by mutex) - Step 9.5
static NWC_CLIENT: Lazy<Mutex<Option<super::nwc::NwcClient>>> = Lazy::new(|| Mutex::new(None));

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
    
    let nsec = match derive_nsec_from_leaf_secret(&leaf_secret) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    let keys = nostr_sdk::Keys::new(nsec);
    
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
    
    let nsec = match derive_nsec_from_leaf_secret(&leaf_secret) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    let keys = nostr_sdk::Keys::new(nsec);
    
    // Sign the content hash
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(content.as_bytes());
    
    use nostr_sdk::secp256k1::{Secp256k1, Message};
    let secp = Secp256k1::new();
    let msg = match Message::from_digest_slice(&hash) {
        Ok(m) => m,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };
    
    let keypair = keys.secret_key().keypair(&secp);
    
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

// ============================================================================
// NOSTR Client Operations (Step 9.4 - Real Publishing)
// ============================================================================

/// Initialize NOSTR client with keys derived from leaf_secret
/// 
/// Must be called before connect/publish. Creates the global client instance.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrInitClient(
    mut env: JNIEnv,
    _clazz: JClass,
    leaf_secret_bytes: JByteArray,
) -> jboolean {
    let bytes = match env.convert_byte_array(leaf_secret_bytes) {
        Ok(b) => b,
        Err(_) => return JNI_FALSE,
    };
    
    if bytes.len() != 160 {
        return JNI_FALSE;
    }
    
    let leaf_secret = match parse_leaf_secret(&bytes) {
        Ok(ls) => ls,
        Err(_) => return JNI_FALSE,
    };
    
    let nsec = match derive_nsec_from_leaf_secret(&leaf_secret) {
        Ok(k) => k,
        Err(_) => return JNI_FALSE,
    };
    
    let keys = nostr_sdk::Keys::new(nsec);
    let client = NostrClient::new(keys);
    
    if let Ok(mut guard) = NOSTR_CLIENT.lock() {
        *guard = Some(client);
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Connect to NOSTR relays
/// 
/// Connects to default relays (SignedByMe audit relay + public relays).
/// Blocks until connected or 3-second timeout.
/// 
/// Returns: true if connected to at least one relay
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrConnect(
    _env: JNIEnv,
    _clazz: JClass,
) -> jboolean {
    let mut guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return JNI_FALSE,
    };
    
    let client = match guard.as_mut() {
        Some(c) => c,
        None => return JNI_FALSE,
    };
    
    match RUNTIME.block_on(client.connect()) {
        Ok(_) => JNI_TRUE,
        Err(e) => {
            eprintln!("NOSTR connect failed: {}", e);
            JNI_FALSE
        }
    }
}

/// Check if connected to at least one relay
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrIsConnected(
    _env: JNIEnv,
    _clazz: JClass,
) -> jboolean {
    let guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return JNI_FALSE,
    };
    
    match guard.as_ref() {
        Some(c) if c.is_connected() => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// Disconnect from all relays and cleanup client
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrDisconnect(
    _env: JNIEnv,
    _clazz: JClass,
) {
    if let Ok(mut guard) = NOSTR_CLIENT.lock() {
        if let Some(ref mut client) = *guard {
            let _ = RUNTIME.block_on(client.disconnect());
        }
        *guard = None;  // Drop the client
    }
}

/// Get the npub of the current client
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrGetNpub(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    let guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };
    
    match guard.as_ref() {
        Some(c) => env.new_string(c.npub_bech32()).unwrap().into_raw(),
        None => env.new_string("").unwrap().into_raw(),
    }
}

/// Publish proof_event (kind 28101) to all connected relays
/// 
/// Returns: event ID (hex) on success, "error:..." on failure
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrPublishProofEvent(
    mut env: JNIEnv,
    _clazz: JClass,
    nonce: JString,
    client_id: JString,
    proof_hex: JString,
    merkle_root: JString,
    user_invoice: JString,
    operator_invoice: JString,
) -> jstring {
    // Extract strings
    let nonce = match env.get_string(&nonce) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_nonce").unwrap().into_raw(),
    };
    let client_id = match env.get_string(&client_id) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_client_id").unwrap().into_raw(),
    };
    let proof_hex = match env.get_string(&proof_hex) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_proof_hex").unwrap().into_raw(),
    };
    let merkle_root = match env.get_string(&merkle_root) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_merkle_root").unwrap().into_raw(),
    };
    let user_invoice = match env.get_string(&user_invoice) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_user_invoice").unwrap().into_raw(),
    };
    let operator_invoice = match env.get_string(&operator_invoice) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_operator_invoice").unwrap().into_raw(),
    };
    
    // Get client and npub
    let guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:client_lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:client_not_initialized").unwrap().into_raw(),
    };
    
    if !client.is_connected() {
        return env.new_string("error:not_connected").unwrap().into_raw();
    }
    
    let npub = client.npub_bech32();
    
    // Build event
    let event = ProofEvent::new(
        nonce,
        client_id,
        proof_hex,
        merkle_root,
        npub,
        user_invoice,
        operator_invoice,
    );
    
    // Publish (drop guard first to avoid holding lock during async)
    drop(guard);
    
    let guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:client_lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:client_not_initialized").unwrap().into_raw(),
    };
    
    match RUNTIME.block_on(client.publish_proof_event(&event)) {
        Ok(event_id) => env.new_string(event_id.to_hex()).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Publish payment_receipt (kind 28102) to all connected relays
/// 
/// Returns: event ID (hex) on success, "error:..." on failure
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrPublishPaymentReceipt(
    mut env: JNIEnv,
    _clazz: JClass,
    nonce: JString,
    payment_hash: JString,
    preimage_hex: JString,
    amount_sats: jlong,
) -> jstring {
    let nonce = match env.get_string(&nonce) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_nonce").unwrap().into_raw(),
    };
    let payment_hash = match env.get_string(&payment_hash) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_payment_hash").unwrap().into_raw(),
    };
    let preimage_hex = match env.get_string(&preimage_hex) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_preimage").unwrap().into_raw(),
    };
    
    let guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:client_lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:client_not_initialized").unwrap().into_raw(),
    };
    
    if !client.is_connected() {
        return env.new_string("error:not_connected").unwrap().into_raw();
    }
    
    let event = PaymentReceiptEvent::new(
        nonce,
        payment_hash,
        preimage_hex,
        amount_sats as u64,
    );
    
    match RUNTIME.block_on(client.publish_payment_receipt(&event)) {
        Ok(event_id) => env.new_string(event_id.to_hex()).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Publish login_complete (kind 28103) to all connected relays
/// 
/// Returns: event ID (hex) on success, "error:..." on failure
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrPublishLoginComplete(
    mut env: JNIEnv,
    _clazz: JClass,
    nonce: JString,
    client_id: JString,
) -> jstring {
    let nonce = match env.get_string(&nonce) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_nonce").unwrap().into_raw(),
    };
    let client_id = match env.get_string(&client_id) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_client_id").unwrap().into_raw(),
    };
    
    let guard = match NOSTR_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:client_lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:client_not_initialized").unwrap().into_raw(),
    };
    
    if !client.is_connected() {
        return env.new_string("error:not_connected").unwrap().into_raw();
    }
    
    let npub = client.npub_bech32();
    
    let event = LoginCompleteEvent::new(nonce, client_id, npub);
    
    match RUNTIME.block_on(client.publish_login_complete(&event)) {
        Ok(event_id) => env.new_string(event_id.to_hex()).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

// ============================================================================
// NWC Client Operations (Step 9.5 - Lightning Wallet via NOSTR)
// ============================================================================

/// Initialize NWC client with connection string
/// 
/// Creates ephemeral keypair for this session (DECISION 2).
/// Connection string format: nostr+walletconnect://pubkey?relay=wss://...&secret=...
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcInit(
    mut env: JNIEnv,
    _clazz: JClass,
    connection_string: JString,
) -> jboolean {
    let conn_str = match env.get_string(&connection_string) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return JNI_FALSE,
    };
    
    match super::nwc::NwcClient::new(&conn_str) {
        Ok(client) => {
            if let Ok(mut guard) = NWC_CLIENT.lock() {
                *guard = Some(client);
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
        Err(e) => {
            eprintln!("NWC init failed: {}", e);
            JNI_FALSE
        }
    }
}

/// Connect NWC client to relay
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcConnect(
    _env: JNIEnv,
    _clazz: JClass,
) -> jboolean {
    let mut guard = match NWC_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return JNI_FALSE,
    };
    
    let client = match guard.as_mut() {
        Some(c) => c,
        None => return JNI_FALSE,
    };
    
    match RUNTIME.block_on(client.connect()) {
        Ok(_) => JNI_TRUE,
        Err(e) => {
            eprintln!("NWC connect failed: {}", e);
            JNI_FALSE
        }
    }
}

/// Generate login invoices (90% user, 10% operator)
/// 
/// Returns: JSON with { user_invoice, operator_invoice } or error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcGenerateLoginInvoices(
    mut env: JNIEnv,
    _clazz: JClass,
    total_sats: jlong,
    client_id: JString,
) -> jstring {
    let client_id = match env.get_string(&client_id) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string(r#"{"error":"invalid_client_id"}"#).unwrap().into_raw(),
    };
    
    let guard = match NWC_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string(r#"{"error":"lock_failed"}"#).unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string(r#"{"error":"not_initialized"}"#).unwrap().into_raw(),
    };
    
    match RUNTIME.block_on(client.generate_login_invoices(total_sats as u64, &client_id)) {
        Ok((user_invoice, operator_invoice)) => {
            let json = serde_json::json!({
                "user_invoice": user_invoice,
                "operator_invoice": operator_invoice,
            });
            env.new_string(json.to_string()).unwrap().into_raw()
        }
        Err(e) => {
            let json = serde_json::json!({ "error": e.to_string() });
            env.new_string(json.to_string()).unwrap().into_raw()
        }
    }
}

/// Make a single invoice via NWC
/// 
/// Returns: BOLT11 invoice string or "error:..."
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcMakeInvoice(
    mut env: JNIEnv,
    _clazz: JClass,
    amount_sats: jlong,
    description: JString,
    expiry_secs: jlong,
) -> jstring {
    let description = match env.get_string(&description) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_description").unwrap().into_raw(),
    };
    
    let guard = match NWC_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:not_initialized").unwrap().into_raw(),
    };
    
    match RUNTIME.block_on(client.make_invoice(amount_sats as u64, &description, expiry_secs as u32)) {
        Ok(invoice) => env.new_string(invoice).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Get wallet balance in satoshis
/// 
/// Returns: balance as string, or "error:..."
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcGetBalance(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    let guard = match NWC_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:not_initialized").unwrap().into_raw(),
    };
    
    match RUNTIME.block_on(client.get_balance()) {
        Ok(balance) => env.new_string(balance.to_string()).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Wait for payment (poll for preimage)
/// 
/// Returns: preimage hex on success, "error:..." on failure/timeout
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcWaitForPayment(
    mut env: JNIEnv,
    _clazz: JClass,
    payment_hash: JString,
    timeout_secs: jlong,
) -> jstring {
    let payment_hash = match env.get_string(&payment_hash) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_payment_hash").unwrap().into_raw(),
    };
    
    let guard = match NWC_CLIENT.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("error:lock_failed").unwrap().into_raw(),
    };
    
    let client = match guard.as_ref() {
        Some(c) => c,
        None => return env.new_string("error:not_initialized").unwrap().into_raw(),
    };
    
    match RUNTIME.block_on(client.wait_for_payment(&payment_hash, timeout_secs as u64)) {
        Ok(preimage) => env.new_string(preimage).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Disconnect NWC and discard ephemeral keys
/// 
/// Must be called after payment received. Ephemeral keys are discarded
/// and cannot be recovered (DECISION 2).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nwcDisconnect(
    _env: JNIEnv,
    _clazz: JClass,
) {
    if let Ok(mut guard) = NWC_CLIENT.lock() {
        if let Some(client) = guard.take() {
            // Explicitly discard keys
            client.disconnect_and_discard();
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

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
