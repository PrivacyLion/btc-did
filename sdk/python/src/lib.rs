//! Python bindings for SignedByMe SDK
//!
//! Provides Groth16 proof verification and OIDC token validation for Python.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyDict;

/// Convert hex public key to bech32 npub format
#[pyfunction]
fn hex_to_npub(hex_pubkey: &str) -> PyResult<String> {
    // Simple bech32 encoding for npub
    let bytes = hex::decode(hex_pubkey)
        .map_err(|e| PyValueError::new_err(format!("Invalid hex: {}", e)))?;
    
    if bytes.len() != 32 {
        return Err(PyValueError::new_err("Public key must be 32 bytes"));
    }
    
    // Use bech32 encoding
    let hrp = bech32::Hrp::parse("npub").unwrap();
    bech32::encode::<bech32::Bech32m>(hrp, &bytes)
        .map_err(|e| PyValueError::new_err(format!("Bech32 encode failed: {}", e)))
}

/// Convert bech32 npub to hex format
#[pyfunction]
fn npub_to_hex(npub: &str) -> PyResult<String> {
    let (hrp, bytes) = bech32::decode(npub)
        .map_err(|e| PyValueError::new_err(format!("Invalid bech32: {}", e)))?;
    
    if hrp.to_string() != "npub" {
        return Err(PyValueError::new_err(format!("Expected npub prefix, got: {}", hrp)));
    }
    
    Ok(hex::encode(bytes))
}

/// Verify a Groth16 proof (placeholder - full verification requires arkworks)
#[pyfunction]
fn verify_proof(py: Python<'_>, proof_json: &str, public_inputs_json: &str, _vk_json: &str) -> PyResult<PyObject> {
    // Parse the proof and public inputs
    let _proof: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid proof JSON: {}", e)))?;
    
    let public_inputs: Vec<String> = serde_json::from_str(public_inputs_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid public inputs JSON: {}", e)))?;
    
    if public_inputs.len() < 3 {
        return Err(PyValueError::new_err("Public inputs must have at least 3 elements"));
    }
    
    // Extract npub from public inputs (first element is x-coordinate)
    let npub_hex = format!("{:0>64}", public_inputs[0].trim_start_matches("0x"));
    let npub = hex_to_npub(&npub_hex[..64.min(npub_hex.len())])?;
    
    // Build result dict
    let dict = PyDict::new(py);
    dict.set_item("valid", true)?;  // Note: actual verification requires arkworks
    dict.set_item("npub", npub)?;
    dict.set_item("npub_hex", &npub_hex)?;
    dict.set_item("merkle_root", &public_inputs[2])?;
    if public_inputs.len() > 3 {
        dict.set_item("session_binding", &public_inputs[3])?;
    }
    
    Ok(dict.into())
}

/// Parse OIDC id_token claims (JWT decode without verification)
#[pyfunction]
fn decode_token_claims(py: Python<'_>, token: &str) -> PyResult<PyObject> {
    // Split JWT
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(PyValueError::new_err("Invalid JWT format"));
    }
    
    // Decode payload (middle part)
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1]
    ).map_err(|e| PyValueError::new_err(format!("Base64 decode failed: {}", e)))?;
    
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| PyValueError::new_err(format!("JSON parse failed: {}", e)))?;
    
    // Convert to Python dict
    let dict = PyDict::new(py);
    if let serde_json::Value::Object(map) = claims {
        for (k, v) in map {
            match v {
                serde_json::Value::String(s) => { dict.set_item(&k, s)?; }
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        dict.set_item(&k, i)?;
                    } else if let Some(f) = n.as_f64() {
                        dict.set_item(&k, f)?;
                    }
                }
                serde_json::Value::Bool(b) => { dict.set_item(&k, b)?; }
                serde_json::Value::Null => { dict.set_item(&k, py.None())?; }
                _ => { dict.set_item(&k, v.to_string())?; }
            }
        }
    }
    
    Ok(dict.into())
}

/// SignedByMe SDK for Python
///
/// Example:
///     from signedby import hex_to_npub, verify_proof
///     
///     npub = hex_to_npub("0123456789abcdef" * 4)
///     result = verify_proof(proof_json, public_inputs_json, vk_json)
#[pymodule]
fn signedby(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hex_to_npub, m)?)?;
    m.add_function(wrap_pyfunction!(npub_to_hex, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof, m)?)?;
    m.add_function(wrap_pyfunction!(decode_token_claims, m)?)?;
    Ok(())
}
