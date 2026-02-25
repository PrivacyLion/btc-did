//! Type definitions for the verifier

use serde::{Deserialize, Serialize};

/// Result of npub extraction from public inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpubResult {
    /// Merkle root (decimal string)
    pub merkle_root: String,
    /// X coordinate as hex (64 chars)
    pub npub_x_hex: String,
    /// Y coordinate as hex (64 chars)  
    pub npub_y_hex: String,
    /// Compressed public key (66 chars: 02/03 + x)
    pub npub_compressed: String,
    /// X coordinate as bytes
    #[serde(skip)]
    pub npub_x_bytes: [u8; 32],
    /// Y coordinate as bytes
    #[serde(skip)]
    pub npub_y_bytes: [u8; 32],
}

/// snarkjs verification key format
#[derive(Debug, Deserialize)]
pub struct SnarkjsVK {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "vk_alphabeta_12")]
    pub vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

/// snarkjs proof format
#[derive(Debug, Deserialize)]
pub struct SnarkjsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

/// Verification result for API response
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub merkle_root: Option<String>,
    pub npub: Option<String>,
    pub error: Option<String>,
}
