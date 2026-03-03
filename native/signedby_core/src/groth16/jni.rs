//! JNI bindings for Groth16 proof generation
//! 
//! Provides native proof generation for Android.
//! 
//! Functions:
//! - initProver(zkeyPath, datPath): Initialize prover with paths
//! - generateWitness(inputJson): Generate witness from inputs
//! - generateProof(witnessPath): Generate proof from witness
//! - proveFromInputs(inputJson): Full flow: inputs → proof

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};

use crate::groth16::witness::{MembershipInputs, WitnessCalculator};
use crate::groth16::Prover;
use crate::groth16::rapidsnark_ffi;

use std::sync::Mutex;
use once_cell::sync::Lazy;

/// Global prover instance
static PROVER: Lazy<Mutex<Option<Prover>>> = Lazy::new(|| Mutex::new(None));

/// Global witness calculator
static WITNESS_CALC: Lazy<Mutex<Option<WitnessCalculator>>> = Lazy::new(|| Mutex::new(None));

/// Set the path to librapidsnark.so for dlopen
/// Must be called before using any Groth16 functions on Android
#[no_mangle]
pub extern "system" fn Java_com_signedby_app_NativeBridge_initRapidsnarkPath<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
) -> jboolean {
    let path_str: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    
    #[cfg(target_os = "android")]
    {
        rapidsnark_ffi::android::set_rapidsnark_path(path_str);
    }
    
    #[cfg(not(target_os = "android"))]
    {
        let _ = path_str; // unused on non-Android
    }
    
    JNI_TRUE
}

/// Initialize the prover with paths to .zkey, .dat, and .wasm files
/// 
/// The calculator_path can be either:
/// - Path to .wasm file directly
/// - Path to directory containing membership.wasm
/// - Path to C++ binary (for compatibility, will look for .wasm)
#[no_mangle]
pub extern "system" fn Java_com_signedby_app_NativeBridge_initProver<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    zkey_path: JString<'local>,
    dat_path: JString<'local>,
    calculator_path: JString<'local>,
) -> jboolean {
    let zkey: String = match env.get_string(&zkey_path) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    
    let dat: String = match env.get_string(&dat_path) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    
    let calc: String = match env.get_string(&calculator_path) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    
    eprintln!("[initProver] zkey: {}", zkey);
    eprintln!("[initProver] dat: {}", dat);
    eprintln!("[initProver] calc: {}", calc);
    
    // Initialize prover
    let mut prover = Prover::new().with_paths(&zkey, &dat);
    
    // Try to load proving key
    if let Err(e) = prover.load_proving_key(&zkey) {
        eprintln!("[initProver] Warning: Could not load proving key: {}", e);
        // Continue anyway - proving key can be loaded later
    } else {
        eprintln!("[initProver] Proving key loaded successfully");
    }
    
    // Store prover
    if let Ok(mut guard) = PROVER.lock() {
        *guard = Some(prover);
    }
    
    // Initialize witness calculator (will find .wasm file)
    let witness_calc = WitnessCalculator::new(&calc, &dat);
    let wasm_available = witness_calc.is_available();
    eprintln!("[initProver] WASM witness calculator available: {}", wasm_available);
    
    if let Ok(mut guard) = WITNESS_CALC.lock() {
        *guard = Some(witness_calc);
    }
    
    JNI_TRUE
}

/// Check if prover is initialized
#[no_mangle]
pub extern "system" fn Java_com_signedby_app_NativeBridge_isProverReady<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    if let Ok(guard) = PROVER.lock() {
        if guard.is_some() {
            return JNI_TRUE;
        }
    }
    JNI_FALSE
}

/// Generate proof from input JSON
/// 
/// Input JSON format:
/// {
///   "leaf_secret": ["hex..."],  // 32 bytes as hex
///   "siblings": ["0x...", ...], // 20 merkle siblings
///   "path_bits": [0, 1, ...]    // 20 path direction bits
/// }
/// 
/// Returns JSON with proof and public inputs, or error string
#[no_mangle]
pub extern "system" fn Java_com_signedby_app_NativeBridge_generateProof<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    input_json: JString<'local>,
) -> jstring {
    let input: String = match env.get_string(&input_json) {
        Ok(s) => s.into(),
        Err(_) => {
            return make_error_string(&mut env, "Failed to read input JSON");
        }
    };
    
    // Parse input
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&input);
    let parsed = match parsed {
        Ok(v) => v,
        Err(e) => {
            return make_error_string(&mut env, &format!("Invalid JSON: {}", e));
        }
    };
    
    // Extract fields
    let secret_hex = match parsed.get("leaf_secret").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return make_error_string(&mut env, "Missing leaf_secret"),
    };
    
    let siblings: Vec<String> = match parsed.get("siblings").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        None => return make_error_string(&mut env, "Missing siblings"),
    };
    
    let path_bits: Vec<u8> = match parsed.get("path_bits").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect(),
        None => return make_error_string(&mut env, "Missing path_bits"),
    };
    
    // Parse secret
    let secret_bytes = match hex::decode(secret_hex.trim_start_matches("0x")) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return make_error_string(&mut env, "Invalid leaf_secret (must be 32 bytes hex)"),
    };
    
    // Create inputs
    let inputs = match MembershipInputs::from_bytes(&secret_bytes, &siblings, &path_bits) {
        Ok(i) => i,
        Err(e) => return make_error_string(&mut env, &format!("Invalid inputs: {}", e)),
    };
    
    // Generate witness
    let witness_calc = match WITNESS_CALC.lock() {
        Ok(guard) => guard,
        Err(_) => return make_error_string(&mut env, "Witness calculator lock failed"),
    };
    
    let calc = match witness_calc.as_ref() {
        Some(c) => c,
        None => return make_error_string(&mut env, "Witness calculator not initialized"),
    };
    
    eprintln!("[generateProof] Starting witness calculation...");
    let witness_start = std::time::Instant::now();
    
    // Generate witness directly to buffer (uses FFI on Android, subprocess on desktop)
    let witness_bytes = match calc.calculate_to_buffer(&inputs) {
        Ok(b) => {
            eprintln!("[generateProof] Witness generated: {} bytes", b.len());
            b
        }
        Err(e) => {
            drop(witness_calc);
            return make_error_string(&mut env, &format!("Witness generation failed: {}", e));
        }
    };
    
    let witness_elapsed = witness_start.elapsed();
    eprintln!("[generateProof] Witness calculation completed in {:?}", witness_elapsed);
    
    drop(witness_calc);  // Release lock
    
    // Get zkey path from prover
    let prover = match PROVER.lock() {
        Ok(guard) => guard,
        Err(_) => return make_error_string(&mut env, "Prover lock failed"),
    };
    
    let zkey_path = match prover.as_ref().and_then(|p| p.zkey_path.as_ref()) {
        Some(p) => p.clone(),
        None => return make_error_string(&mut env, "Prover not initialized with zkey path"),
    };
    
    drop(prover);  // Release lock before proof generation
    
    // Generate proof using rapidsnark FFI
    eprintln!("[generateProof] Starting rapidsnark proof generation...");
    let proof_start = std::time::Instant::now();
    
    let (proof_json, public_json) = match rapidsnark_ffi::prove_with_library(&zkey_path, &witness_bytes) {
        Ok(result) => result,
        Err(e) => return make_error_string(&mut env, &format!("Proof generation failed: {}", e)),
    };
    
    let proof_elapsed = proof_start.elapsed();
    eprintln!("[generateProof] Rapidsnark proof generation completed in {:?}", proof_elapsed);
    eprintln!("[generateProof] Total time: witness {:?} + proof {:?}", witness_elapsed, proof_elapsed);
    
    // Build result JSON
    let result = serde_json::json!({
        "success": true,
        "proof": serde_json::from_str::<serde_json::Value>(&proof_json).unwrap_or_default(),
        "public_inputs": serde_json::from_str::<serde_json::Value>(&public_json).unwrap_or_default(),
    });
    
    let result_str = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
    
    env.new_string(&result_str)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Helper to create error JSON string
fn make_error_string(env: &mut JNIEnv, msg: &str) -> jstring {
    let error = serde_json::json!({
        "success": false,
        "error": msg
    });
    
    let error_str = serde_json::to_string(&error).unwrap_or_else(|_| 
        format!(r#"{{"success":false,"error":"{}"}}"#, msg)
    );
    
    env.new_string(&error_str)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_jni_module_compiles() {
        // Just ensure the module compiles
        assert!(true);
    }
}
