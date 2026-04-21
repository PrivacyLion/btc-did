//! PyO3 bindings for SignedByMe SDK
//!
//! This module exposes the Rust SDK to Python via PyO3.

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError, PyFileNotFoundError};
use std::collections::HashMap;
use std::path::PathBuf;

// Re-export from core
use signedby_core::sdk::{
    identity::IdentityManager,
    delegation::DelegationManager,
    enrollment::EnrollmentManager,
    prover::Prover,
    nostr_client::NostrClient,
    storage::SecureStorage,
    wallet::WalletManager,
};

/// Python wrapper for SignedByClient
#[pyclass]
struct RustSignedByClient {
    identity: IdentityManager,
    delegation: DelegationManager,
    prover: Prover,
    nostr: NostrClient,
}

#[pymethods]
impl RustSignedByClient {
    /// Create client from delegation JSON
    #[staticmethod]
    fn from_delegation_json(json: &str) -> PyResult<Self> {
        let delegation = DelegationManager::from_json(json)
            .map_err(|e| PyValueError::new_err(format!("Invalid delegation: {}", e)))?;
        
        let identity = IdentityManager::from_delegation(&delegation)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load identity: {}", e)))?;
        
        let prover = Prover::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to init prover: {}", e)))?;
        
        let nostr = NostrClient::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to init NOSTR client: {}", e)))?;
        
        Ok(Self {
            identity,
            delegation,
            prover,
            nostr,
        })
    }
    
    /// Get agent's npub
    fn npub(&self) -> String {
        self.identity.npub()
    }
    
    /// Get delegation scopes
    fn scopes(&self) -> HashMap<String, Vec<String>> {
        self.delegation.scopes().clone()
    }
    
    /// Generate login proof
    fn generate_login_proof<'py>(&self, py: Python<'py>, client_id: &str, nonce: &str) -> PyResult<&'py PyAny> {
        let identity = self.identity.clone();
        let prover = self.prover.clone();
        let client_id = client_id.to_string();
        let nonce = nonce.to_string();
        
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let proof = prover.generate_proof(&identity, &client_id, &nonce)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Proof generation failed: {}", e)))?;
            
            Ok(Python::with_gil(|py| {
                proof.to_object(py)
            }))
        })
    }
    
    /// Publish proof event to NOSTR
    fn publish_proof_event<'py>(&self, py: Python<'py>, relay_url: &str, proof: PyObject) -> PyResult<&'py PyAny> {
        let nostr = self.nostr.clone();
        let identity = self.identity.clone();
        let relay_url = relay_url.to_string();
        
        pyo3_asyncio::tokio::future_into_py(py, async move {
            nostr.connect(&relay_url)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Relay connection failed: {}", e)))?;
            
            // TODO: Convert PyObject proof back to Rust type
            nostr.publish_proof_event(&identity, &proof)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Publish failed: {}", e)))?;
            
            Ok(())
        })
    }
    
    /// Verify proof and get OIDC token
    fn verify_and_get_token<'py>(
        &self,
        py: Python<'py>,
        api_url: &str,
        proof: PyObject,
        client_id: &str,
        nonce: &str,
    ) -> PyResult<&'py PyAny> {
        let api_url = api_url.to_string();
        let client_id = client_id.to_string();
        let nonce = nonce.to_string();
        
        pyo3_asyncio::tokio::future_into_py(py, async move {
            // Call SignedByMe API
            let client = reqwest::Client::new();
            let response = client
                .post(format!("{}/v1/login/verify", api_url))
                .json(&serde_json::json!({
                    "proof": proof,
                    "public_outputs": {
                        "merkle_root": "", // TODO: extract from proof
                        "npub": "",
                    },
                    "client_id": client_id,
                    "nonce": nonce,
                }))
                .send()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("API call failed: {}", e)))?;
            
            let token: serde_json::Value = response
                .json()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Invalid response: {}", e)))?;
            
            Ok(Python::with_gil(|py| {
                token.to_object(py)
            }))
        })
    }
}

/// Python wrapper for SignedByAgent
#[pyclass]
struct RustSignedByAgent {
    storage: SecureStorage,
    identity: IdentityManager,
    nostr: NostrClient,
    email_mapping: HashMap<String, String>,
}

#[pymethods]
impl RustSignedByAgent {
    /// Initialize agent with storage path
    #[staticmethod]
    fn init(storage_path: &str) -> PyResult<Self> {
        let path = PathBuf::from(storage_path);
        
        let storage = SecureStorage::new(&path)
            .map_err(|e| PyRuntimeError::new_err(format!("Storage init failed: {}", e)))?;
        
        let identity = match storage.load_identity() {
            Ok(id) => id,
            Err(_) => {
                // First run - create new identity
                let id = IdentityManager::generate()
                    .map_err(|e| PyRuntimeError::new_err(format!("Identity generation failed: {}", e)))?;
                storage.save_identity(&id)
                    .map_err(|e| PyRuntimeError::new_err(format!("Failed to save identity: {}", e)))?;
                id
            }
        };
        
        let nostr = NostrClient::new()
            .map_err(|e| PyRuntimeError::new_err(format!("NOSTR client init failed: {}", e)))?;
        
        Ok(Self {
            storage,
            identity,
            nostr,
            email_mapping: HashMap::new(),
        })
    }
    
    /// Get agent's npub
    fn npub(&self) -> String {
        self.identity.npub()
    }
    
    /// Set email mapping
    fn set_email_mapping(&mut self, mapping: HashMap<String, String>) {
        self.email_mapping = mapping;
    }
    
    /// Connect to relay
    fn connect_relay<'py>(&self, py: Python<'py>, relay_url: &str) -> PyResult<&'py PyAny> {
        let nostr = self.nostr.clone();
        let relay_url = relay_url.to_string();
        
        pyo3_asyncio::tokio::future_into_py(py, async move {
            nostr.connect(&relay_url)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Connection failed: {}", e)))?;
            Ok(())
        })
    }
    
    /// Subscribe to authorization events
    fn subscribe_authorizations<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let nostr = self.nostr.clone();
        let npub = self.identity.npub();
        
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let events = nostr.subscribe_kind_28200(&npub)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Subscribe failed: {}", e)))?;
            
            // Return as async iterator
            Ok(Python::with_gil(|py| {
                events.to_object(py)
            }))
        })
    }
    
    /// Get activity log
    fn get_activity_log(&self, limit: usize) -> PyResult<Vec<serde_json::Value>> {
        self.nostr.get_activity_log(&self.identity.npub(), limit)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to get log: {}", e)))
    }
}

/// Standalone function to generate proof
#[pyfunction]
fn generate_proof(identity_json: &str, client_id: &str, nonce: &str) -> PyResult<String> {
    // Placeholder - actual implementation calls Prover
    Ok("{}".to_string())
}

/// Standalone function to verify delegation
#[pyfunction]
fn verify_delegation(delegation_json: &str) -> PyResult<bool> {
    DelegationManager::from_json(delegation_json)
        .map(|_| true)
        .map_err(|e| PyValueError::new_err(format!("Invalid delegation: {}", e)))
}

/// Python module definition
#[pymodule]
fn _core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustSignedByClient>()?;
    m.add_class::<RustSignedByAgent>()?;
    m.add_function(wrap_pyfunction!(generate_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_delegation, m)?)?;
    Ok(())
}
