// lib.rs - BTC DID Core Library
// Implements KeyManager, DLC Builder, Lightning payments, and Groth16 membership proofs

use anyhow::{Result, anyhow};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jstring, jlong, jboolean};
use jni::JNIEnv;

use sha2::{Digest, Sha256};

// Module declarations
pub mod key_manager;
pub mod dlc_builder;
pub mod lightning;
pub mod dlc_oracle;
pub mod membership; // Groth16 membership proofs

use key_manager::ManagedKey;
use dlc_builder::{DlcContract, DlcOutcome, OracleInfo, PayoutSplit, oracle_sign_outcome};
use lightning::{Preimage, PaymentRequestPackage, verify_payment};

// ============================================================================
// CORE JNI FUNCTIONS
// ============================================================================

/// Simple sanity check
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_helloFromRust(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    env.new_string("Hello from Rust core v3 (Groth16) 👋")
        .unwrap()
        .into_raw()
}

/// SHA-256 helper
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_sha256Hex(
    mut env: JNIEnv,
    _clazz: JClass,
    input: JString,
) -> jstring {
    let s = match env.get_string(&input) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error").unwrap().into_raw(),
    };
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hex = hex::encode(hasher.finalize());
    env.new_string(hex).unwrap().into_raw()
}

/// Generate 32-byte secp256k1 private key
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateSecp256k1PrivateKey(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jbyteArray {
    match ManagedKey::generate() {
        Ok(key) => {
            let bytes = key.secret_key.secret_bytes();
            env.byte_array_from_slice(&bytes).unwrap().into_raw()
        }
        Err(_) => {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).unwrap();
            env.byte_array_from_slice(&bytes).unwrap().into_raw()
        }
    }
}

/// Derive compressed public key hex from private key bytes
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_derivePublicKeyHex(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
) -> jstring {
    let bytes = match env.convert_byte_array(priv_bytes) {
        Ok(b) => b,
        Err(_) => return env.new_string("error").unwrap().into_raw(),
    };
    
    match ManagedKey::from_bytes(&bytes) {
        Ok(key) => env.new_string(key.pubkey_hex()).unwrap().into_raw(),
        Err(_) => env.new_string("error").unwrap().into_raw(),
    }
}

/// Sign message with secp256k1 key (DER sig hex)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signMessageDerHex(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
    msg_jstr: JString,
) -> jstring {
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => return env.new_string("error:no_priv_bytes").unwrap().into_raw(),
    };

    let msg_str = match env.get_string(&msg_jstr) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:no_msg").unwrap().into_raw(),
    };

    let key = match ManagedKey::from_bytes(&priv_vec) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };

    match key.sign_ecdsa(msg_str.as_bytes()) {
        Ok(sig) => env.new_string(sig).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

// ============================================================================
// DLC BUILDER JNI FUNCTIONS
// ============================================================================

/// Create a DLC contract
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_createDlcContract(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
    payouts_json: JString,
    oracle_json: JString,
) -> jstring {
    let _outcome = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let payouts = env.get_string(&payouts_json)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let oracle = env.get_string(&oracle_json)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let oracle_info = match serde_json::from_str::<OracleInfo>(&oracle) {
        Ok(o) => o,
        Err(_) => OracleInfo {
            name: "local_oracle".to_string(),
            pubkey_hex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            x_only_pubkey: None,
        },
    };

    let split = match serde_json::from_str::<PayoutSplit>(&payouts) {
        Ok(s) => s,
        Err(_) => PayoutSplit::default(),
    };

    let user_key = match ManagedKey::generate() {
        Ok(k) => k,
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };

    match DlcContract::new(&user_key, oracle_info, 0, split) {
        Ok(contract) => {
            let json = contract.to_json().unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Sign a DLC outcome with real Schnorr signature
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
) -> jstring {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let json = dlc_oracle::oracle_sign_outcome(&outcome_str);
    env.new_string(json).unwrap().into_raw()
}

/// Get oracle x-only public key (BIP340 format)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oraclePubkeyHex(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    env.new_string(dlc_oracle::oracle_pubkey_hex())
        .unwrap()
        .into_raw()
}

/// Oracle sign outcome (alias for signDlcOutcome)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleSignOutcome(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
) -> jstring {
    Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(env, _clazz, outcome)
}

/// Acknowledge oracle signing policy for a contract
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleAcknowledgePolicy(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
    contract_id: JString,
) -> jstring {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let contract_str = env.get_string(&contract_id)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let json = dlc_oracle::oracle_acknowledge_policy(&outcome_str, &contract_str);
    env.new_string(json).unwrap().into_raw()
}

/// Verify an oracle attestation signature
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleVerifyAttestation(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
    signature_hex: JString,
    pubkey_hex: JString,
) -> jboolean {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sig_str = env.get_string(&signature_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let pubkey_str = env.get_string(&pubkey_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let is_valid = dlc_oracle::oracle_verify_attestation(&outcome_str, &sig_str, &pubkey_str);
    if is_valid { 1 } else { 0 }
}

// ============================================================================
// LIGHTNING PAYMENT JNI FUNCTIONS
// ============================================================================

/// Generate a Lightning preimage and payment hash
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generatePreimage(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    let preimage = Preimage::generate();
    let json = serde_json::json!({
        "preimage_hex": preimage.preimage_hex,
        "payment_hash": preimage.hash.hash_hex,
    });
    env.new_string(json.to_string()).unwrap().into_raw()
}

/// Verify a payment (preimage against payment hash)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_verifyPayment(
    mut env: JNIEnv,
    _clazz: JClass,
    payment_hash: JString,
    preimage_hex: JString,
) -> jstring {
    let hash = env.get_string(&payment_hash)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let preimage = env.get_string(&preimage_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let result = verify_payment(&hash, &preimage);
    let json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap().into_raw()
}

/// Extract payment hash from a BOLT11 invoice
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_extractPaymentHashFromBolt11(
    mut env: JNIEnv,
    _clazz: JClass,
    bolt11: JString,
) -> jstring {
    use lightning_invoice::Bolt11Invoice;
    use std::str::FromStr;
    
    let invoice_str = match env.get_string(&bolt11) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_string").unwrap().into_raw(),
    };
    
    match Bolt11Invoice::from_str(&invoice_str) {
        Ok(invoice) => {
            let payment_hash = invoice.payment_hash();
            let hash_hex = hex::encode(&payment_hash[..]);
            env.new_string(hash_hex).unwrap().into_raw()
        }
        Err(e) => {
            let error_msg = format!("error:bolt11_parse_failed:{}", e);
            env.new_string(error_msg).unwrap().into_raw()
        }
    }
}

/// Create a Payment Request Package (PRP)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_createPrp(
    mut env: JNIEnv,
    _clazz: JClass,
    amount_sats: jlong,
    description: JString,
    payee_did: JString,
    payee_ln_address: JString,
    expiry_secs: jlong,
) -> jstring {
    let desc = env.get_string(&description)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let did = env.get_string(&payee_did)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ln_addr = env.get_string(&payee_ln_address)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let preimage = Preimage::generate();
    let prp = PaymentRequestPackage::new(
        &preimage,
        amount_sats as u64,
        &desc,
        &did,
        &ln_addr,
        expiry_secs as u32,
    );

    match prp.to_json() {
        Ok(json) => {
            let full_json = serde_json::json!({
                "prp": serde_json::from_str::<serde_json::Value>(&json).unwrap_or_default(),
                "preimage_hex": preimage.preimage_hex,
            });
            env.new_string(full_json.to_string()).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Sign a message with Schnorr (for Taproot/DLC)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signSchnorr(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
    msg_jstr: JString,
) -> jstring {
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => return env.new_string("error:no_priv_bytes").unwrap().into_raw(),
    };

    let msg_str = match env.get_string(&msg_jstr) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:no_msg").unwrap().into_raw(),
    };

    let key = match ManagedKey::from_bytes(&priv_vec) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };

    match key.sign_schnorr(msg_str.as_bytes()) {
        Ok(sig) => env.new_string(sig).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Get x-only public key (for Taproot)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_getXOnlyPubkey(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
) -> jstring {
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => return env.new_string("error:no_priv_bytes").unwrap().into_raw(),
    };

    let key = match ManagedKey::from_bytes(&priv_vec) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };

    env.new_string(key.x_only_pubkey_hex()).unwrap().into_raw()
}

// ============================================================================
// GROTH16 MEMBERSHIP JNI FUNCTIONS (Phase 14 - to be implemented)
// ============================================================================

// TODO: Add JNI functions for Groth16 proof generation when mobile is updated
// - generateMembershipProof(leaf_secret, siblings, path_bits) -> proof JSON
// - These will call rapidsnark or similar native prover
