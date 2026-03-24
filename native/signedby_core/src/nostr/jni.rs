// nostr/jni.rs - JNI bindings for NOSTR functions (Android)
//
// These functions are called from Kotlin via NativeBridge.kt

use anyhow::Result;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jstring, jlong, jboolean, JNI_TRUE, JNI_FALSE};
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

/// Derive nsec from leaf_secret bytes
/// 
/// Input: leaf_secret as 5 * 32 bytes (5 BN254 field elements, big-endian)
/// Output: nsec as 32-byte secret key
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_deriveNsecFromLeafSecret(
    env: JNIEnv,
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
    env: JNIEnv,
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

// ============================================================================
// NOSTR Client Operations (Step 9.4 - Real Publishing)
// ============================================================================

/// Initialize NOSTR client with keys derived from leaf_secret
/// 
/// Must be called before connect/publish. Creates the global client instance.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrInitClient(
    env: JNIEnv,
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
    env: JNIEnv,
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
// NOSTR Event Polling (Phase 26.5 / 26.7)
// ============================================================================

/// Poll for a NOSTR event matching kind and tag.
/// Used for:
/// - KYC verification events (kind 28201) - App polls for kyc_verification tagged with nonce
/// - M2M login events (kind 28200) - App polls for enrollment_authorization tagged with npub
/// 
/// Returns: Event content JSON if found, empty string if not found, "error:..." on failure
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrPollForEvent(
    mut env: JNIEnv,
    _clazz: JClass,
    kind: jni::sys::jint,
    tag_name: JString,
    tag_value: JString,
) -> jstring {
    use nostr_sdk::prelude::*;
    use std::time::Duration;
    
    // Extract tag parameters
    let tag_name_str = match env.get_string(&tag_name) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_tag_name").unwrap().into_raw(),
    };
    let tag_value_str = match env.get_string(&tag_value) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_tag_value").unwrap().into_raw(),
    };
    
    // Clone the inner client while holding the lock, then release lock
    let inner_client = {
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
        
        // Clone the inner client so we can release the lock
        client.inner_client().clone()
    };
    // Guard is dropped here, lock released
    
    // Poll for event with timeout
    let result = RUNTIME.block_on(async {
        let kind_u16 = kind as u16;
        
        // Build base filter for the specified kind
        let mut filter = Filter::new()
            .kind(Kind::Custom(kind_u16))
            .limit(10); // Fetch a few to filter client-side
        
        // Add tag filter based on tag type
        match tag_name_str.as_str() {
            "p" => {
                // "p" tag expects a pubkey - could be hex or npub
                let pubkey = if tag_value_str.starts_with("npub") {
                    match PublicKey::from_bech32(&tag_value_str) {
                        Ok(pk) => pk,
                        Err(e) => return Err(anyhow::anyhow!("Invalid npub: {}", e)),
                    }
                } else {
                    match PublicKey::from_hex(&tag_value_str) {
                        Ok(pk) => pk,
                        Err(e) => return Err(anyhow::anyhow!("Invalid pubkey hex: {}", e)),
                    }
                };
                filter = filter.pubkey(pubkey);
            }
            "e" => {
                // "e" tag for event reference
                let event_id = match EventId::from_hex(&tag_value_str) {
                    Ok(id) => id,
                    Err(e) => return Err(anyhow::anyhow!("Invalid event id: {}", e)),
                };
                filter = filter.event(event_id);
            }
            // For other tags, we filter client-side after fetching by kind
            _ => {}
        }
        
        // Fetch events with timeout using get_events_of
        let timeout = Duration::from_secs(5);
        let events: Vec<Event> = match inner_client.get_events_of(vec![filter], EventSource::both(Some(timeout))).await {
            Ok(evts) => evts,
            Err(e) => return Err(anyhow::anyhow!("Fetch failed: {}", e)),
        };
        
        // Filter events by custom tag if needed (for tags like "nonce", "client_id")
        for event in events.iter() {
            // Check if event has the tag we're looking for
            let has_matching_tag = event.tags.iter().any(|tag| {
                // Get tag as string slice
                if let Some(tag_kind) = tag.kind().to_string().strip_prefix("#") {
                    // For standard single-letter tags
                    if tag_kind == tag_name_str {
                        if let Some(value) = tag.content() {
                            return value == tag_value_str;
                        }
                    }
                }
                // For custom tags, check the tag structure directly
                let tag_as_vec = tag.as_slice();
                if tag_as_vec.len() >= 2 {
                    tag_as_vec[0] == tag_name_str && tag_as_vec[1] == tag_value_str
                } else {
                    false
                }
            });
            
            if has_matching_tag {
                return Ok(Some(event.content.clone()));
            }
        }
        
        // For standard tags (p, e) that were filtered server-side, return first match
        if matches!(tag_name_str.as_str(), "p" | "e") {
            if let Some(event) = events.first() {
                return Ok(Some(event.content.clone()));
            }
        }
        
        Ok(None)
    });
    
    match result {
        Ok(Some(content)) => env.new_string(content).unwrap().into_raw(),
        Ok(None) => env.new_string("").unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Poll for a NOSTR event by author (kind + authors filter), then match tag client-side.
/// Used when relay doesn't support multi-character tag filters (e.g., strfry).
/// 
/// Returns: Full event JSON if found, empty string if not found, "error:..." on failure
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_signedby_app_NativeBridge_nostrPollForEventByAuthor(
    mut env: JNIEnv,
    _clazz: JClass,
    kind: jni::sys::jint,
    author_hex: JString,
    tag_name: JString,
    tag_value: JString,
) -> jstring {
    use nostr_sdk::prelude::*;
    use std::time::Duration;
    
    // Extract parameters
    let author_str = match env.get_string(&author_hex) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_author").unwrap().into_raw(),
    };
    let tag_name_str = match env.get_string(&tag_name) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_tag_name").unwrap().into_raw(),
    };
    let tag_value_str = match env.get_string(&tag_value) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_tag_value").unwrap().into_raw(),
    };
    
    // Parse author pubkey
    let author_pubkey = match PublicKey::from_hex(&author_str) {
        Ok(pk) => pk,
        Err(e) => return env.new_string(format!("error:invalid_author_hex:{}", e)).unwrap().into_raw(),
    };
    
    // Clone the inner client while holding the lock, then release lock
    let inner_client = {
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
        
        client.inner_client().clone()
    };
    
    // Poll for event with timeout
    let result = RUNTIME.block_on(async {
        let kind_u16 = kind as u16;
        
        // Build filter: kind + author only (no tag filter to relay)
        let filter = Filter::new()
            .kind(Kind::Custom(kind_u16))
            .author(author_pubkey)
            .limit(20);
        
        // Fetch events with timeout
        let timeout = Duration::from_secs(5);
        let events: Vec<Event> = match inner_client.get_events_of(vec![filter], EventSource::both(Some(timeout))).await {
            Ok(evts) => evts,
            Err(e) => return Err(anyhow::anyhow!("Fetch failed: {}", e)),
        };
        
        // Filter events by tag client-side
        for event in events.iter() {
            let has_matching_tag = event.tags.iter().any(|tag| {
                let tag_as_vec = tag.as_slice();
                if tag_as_vec.len() >= 2 {
                    tag_as_vec[0] == tag_name_str && tag_as_vec[1] == tag_value_str
                } else {
                    false
                }
            });
            
            if has_matching_tag {
                // Return full event as JSON
                let event_json = serde_json::json!({
                    "id": event.id.to_hex(),
                    "pubkey": event.pubkey.to_hex(),
                    "created_at": event.created_at.as_u64(),
                    "kind": event.kind.as_u16(),
                    "tags": event.tags.iter().map(|t| t.as_slice().to_vec()).collect::<Vec<_>>(),
                    "content": event.content,
                    "sig": event.sig.to_string()
                });
                return Ok(Some(event_json.to_string()));
            }
        }
        
        Ok(None)
    });
    
    match result {
        Ok(Some(json)) => env.new_string(json).unwrap().into_raw(),
        Ok(None) => env.new_string("").unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
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
    use ark_std::rand::thread_rng;
    
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
