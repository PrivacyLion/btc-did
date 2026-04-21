//! napi-rs bindings for SignedByMe SDK
//!
//! This module exposes the Rust SDK to Node.js via napi-rs.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

// Re-export from core
use signedby_sdk::sdk::{
    identity::IdentityManager,
    delegation::DelegationManager,
    enrollment::EnrollmentManager,
    prover::Prover,
    nostr_client::NostrClient,
    storage::SecureStorage,
    wallet::WalletManager,
};

/// SignedByClient for Node.js
#[napi]
pub struct SignedByClient {
    identity: Arc<IdentityManager>,
    delegation: Arc<DelegationManager>,
    prover: Arc<Prover>,
    nostr: Arc<Mutex<NostrClient>>,
}

#[napi]
impl SignedByClient {
    /// Create client from delegation JSON
    #[napi(factory)]
    pub async fn from_delegation_json(json: String) -> Result<Self> {
        let delegation = DelegationManager::from_json(&json)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid delegation: {}", e)))?;
        
        let identity = IdentityManager::from_delegation(&delegation)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to load identity: {}", e)))?;
        
        let prover = Prover::new()
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to init prover: {}", e)))?;
        
        let nostr = NostrClient::new()
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to init NOSTR client: {}", e)))?;
        
        Ok(Self {
            identity: Arc::new(identity),
            delegation: Arc::new(delegation),
            prover: Arc::new(prover),
            nostr: Arc::new(Mutex::new(nostr)),
        })
    }
}

/// Get npub from client
#[napi]
pub fn get_npub(client: &SignedByClient) -> String {
    client.identity.npub()
}

/// Generate login proof
#[napi]
pub async fn generate_login_proof(
    client: &SignedByClient,
    client_id: String,
    nonce: String,
) -> Result<serde_json::Value> {
    let proof = client.prover.generate_proof(&client.identity, &client_id, &nonce)
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("Proof generation failed: {}", e)))?;
    
    Ok(proof)
}

/// Publish proof event to NOSTR
#[napi]
pub async fn publish_proof_event(
    client: &SignedByClient,
    relay_url: String,
    proof: serde_json::Value,
) -> Result<()> {
    let mut nostr = client.nostr.lock().await;
    
    nostr.connect(&relay_url)
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("Relay connection failed: {}", e)))?;
    
    nostr.publish_proof_event(&client.identity, &proof)
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("Publish failed: {}", e)))?;
    
    Ok(())
}

/// Verify proof and get OIDC token
#[napi]
pub async fn verify_and_get_token(
    client: &SignedByClient,
    api_url: String,
    proof: serde_json::Value,
    client_id: String,
    nonce: String,
) -> Result<serde_json::Value> {
    let http_client = reqwest::Client::new();
    
    let response = http_client
        .post(format!("{}/v1/login/verify", api_url))
        .json(&serde_json::json!({
            "proof": proof,
            "public_outputs": {
                "merkle_root": proof.get("merkle_root").unwrap_or(&serde_json::Value::Null),
                "npub": client.identity.npub(),
            },
            "client_id": client_id,
            "nonce": nonce,
        }))
        .send()
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("API call failed: {}", e)))?;
    
    let token: serde_json::Value = response
        .json()
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("Invalid response: {}", e)))?;
    
    Ok(token)
}

/// SignedByAgent for Node.js
#[napi]
pub struct SignedByAgent {
    storage: Arc<SecureStorage>,
    identity: Arc<IdentityManager>,
    nostr: Arc<Mutex<NostrClient>>,
    email_mapping: Arc<Mutex<HashMap<String, String>>>,
}

#[napi]
impl SignedByAgent {
    /// Initialize agent with storage path
    #[napi(factory)]
    pub async fn init(storage_path: String) -> Result<Self> {
        let path = PathBuf::from(&storage_path);
        
        // Create directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(&path)
                .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to create directory: {}", e)))?;
        }
        
        let storage = SecureStorage::new(&path)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Storage init failed: {}", e)))?;
        
        let identity = match storage.load_identity() {
            Ok(id) => id,
            Err(_) => {
                // First run - create new identity
                let id = IdentityManager::generate()
                    .map_err(|e| Error::new(Status::GenericFailure, format!("Identity generation failed: {}", e)))?;
                storage.save_identity(&id)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to save identity: {}", e)))?;
                id
            }
        };
        
        let nostr = NostrClient::new()
            .map_err(|e| Error::new(Status::GenericFailure, format!("NOSTR client init failed: {}", e)))?;
        
        Ok(Self {
            storage: Arc::new(storage),
            identity: Arc::new(identity),
            nostr: Arc::new(Mutex::new(nostr)),
            email_mapping: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

/// Get agent npub
#[napi]
pub fn get_agent_npub(agent: &SignedByAgent) -> String {
    agent.identity.npub()
}

/// Set email mapping
#[napi]
pub async fn set_email_mapping(agent: &SignedByAgent, mapping: HashMap<String, String>) {
    let mut email_mapping = agent.email_mapping.lock().await;
    *email_mapping = mapping;
}

/// Connect to relay
#[napi]
pub async fn connect_relay(agent: &SignedByAgent, relay_url: String) -> Result<()> {
    let mut nostr = agent.nostr.lock().await;
    nostr.connect(&relay_url)
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("Connection failed: {}", e)))?;
    Ok(())
}

/// Subscribe to authorization events (returns async iterator)
#[napi]
pub async fn subscribe_authorizations(agent: &SignedByAgent) -> Result<Vec<String>> {
    let nostr = agent.nostr.lock().await;
    let npub = agent.identity.npub();
    
    let events = nostr.subscribe_kind_28200(&npub)
        .await
        .map_err(|e| Error::new(Status::GenericFailure, format!("Subscribe failed: {}", e)))?;
    
    // Convert to JSON strings for JS
    let json_events: Vec<String> = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .collect();
    
    Ok(json_events)
}

/// Get activity log
#[napi]
pub fn get_activity_log(agent: &SignedByAgent, limit: u32) -> Result<Vec<serde_json::Value>> {
    let npub = agent.identity.npub();
    let nostr = futures::executor::block_on(agent.nostr.lock());
    
    nostr.get_activity_log(&npub, limit as usize)
        .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to get log: {}", e)))
}
