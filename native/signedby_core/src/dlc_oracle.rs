// dlc_oracle.rs
// Real oracle implementation with Schnorr signatures for DLC outcomes
// Uses BIP340-style tagged hashes for outcome signing

use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair, XOnlyPublicKey, Message};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

// Domain separator for oracle key derivation
const ORACLE_KEY_DOMAIN: &[u8] = b"signedby.me:oracle:v1";

// Domain separator for outcome signing (BIP340 tagged hash)
const OUTCOME_TAG: &str = "signedby.me/dlc/outcome/v1";

/// Oracle for signing DLC outcomes
#[derive(Debug, Clone)]
pub struct Oracle {
    pub name: String,
    keypair: Keypair,
    pubkey: PublicKey,
    x_only_pubkey: XOnlyPublicKey,
}

impl Oracle {
    /// Create an oracle with a specific secret key
    pub fn from_secret(name: &str, secret: &[u8; 32]) -> Result<Self, String> {
        let secp = Secp256k1::new();
        
        let secret_key = SecretKey::from_slice(secret)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let pubkey = PublicKey::from_secret_key(&secp, &secret_key);
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        
        Ok(Self {
            name: name.to_string(),
            keypair,
            pubkey,
            x_only_pubkey,
        })
    }
    
    /// Create the default local oracle with deterministic key
    /// In production, this key should be stored securely and rotated
    pub fn local() -> Self {
        // Derive oracle key deterministically from domain separator
        // This ensures consistent key across app restarts
        let mut hasher = Sha256::new();
        hasher.update(ORACLE_KEY_DOMAIN);
        hasher.update(b"signedby_local_oracle_v1");
        let seed: [u8; 32] = hasher.finalize().into();
        
        Self::from_secret("signedby_oracle", &seed)
            .expect("Oracle key derivation should never fail")
    }
    
    /// Get the oracle's compressed public key (33 bytes, hex)
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey.serialize())
    }
    
    /// Get the oracle's x-only public key (32 bytes, hex) for BIP340
    pub fn x_only_pubkey_hex(&self) -> String {
        hex::encode(self.x_only_pubkey.serialize())
    }
    
    /// Compute tagged hash for an outcome (BIP340 style)
    fn outcome_tagged_hash(outcome: &str) -> [u8; 32] {
        // BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)
        let mut tag_hasher = Sha256::new();
        tag_hasher.update(OUTCOME_TAG.as_bytes());
        let tag_hash = tag_hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(&tag_hash);
        hasher.update(&tag_hash);
        hasher.update(outcome.as_bytes());
        
        hasher.finalize().into()
    }
    
    /// Sign an outcome with Schnorr signature
    pub fn sign_outcome(&self, outcome: &str) -> OracleAttestation {
        let secp = Secp256k1::new();
        
        // Create tagged hash of the outcome
        let outcome_hash = Self::outcome_tagged_hash(outcome);
        
        // Create message for signing
        let msg = Message::from_digest_slice(&outcome_hash)
            .expect("32 bytes is valid for Message");
        
        // Sign with Schnorr (BIP340)
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        OracleAttestation {
            outcome: outcome.to_string(),
            signature_hex: hex::encode(sig.as_ref()),
            pubkey_hex: self.x_only_pubkey_hex(),
            timestamp: now,
        }
    }
    
    /// Verify an attestation (static method, can verify any oracle's signature)
    pub fn verify_attestation(attestation: &OracleAttestation) -> Result<bool, String> {
        let secp = Secp256k1::new();
        
        // Parse the x-only pubkey
        let pubkey_bytes = hex::decode(&attestation.pubkey_hex)
            .map_err(|e| format!("Invalid pubkey hex: {}", e))?;
        
        let x_only_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| format!("Invalid x-only pubkey: {}", e))?;
        
        // Reconstruct the tagged hash
        let outcome_hash = Self::outcome_tagged_hash(&attestation.outcome);
        let msg = Message::from_digest_slice(&outcome_hash)
            .map_err(|e| format!("Invalid message: {}", e))?;
        
        // Parse signature
        let sig_bytes = hex::decode(&attestation.signature_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        
        let sig = SchnorrSignature::from_slice(&sig_bytes)
            .map_err(|e| format!("Invalid Schnorr signature: {}", e))?;
        
        // Verify
        Ok(secp.verify_schnorr(&sig, &msg, &x_only_pubkey).is_ok())
    }
    
    /// Acknowledge a signing policy request (returns policy confirmation)
    /// This is step 7-8 in the spec: Oracle acknowledges it will sign for this outcome
    pub fn acknowledge_policy(&self, outcome: &str, contract_id: &str) -> PolicyAcknowledgment {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create a commitment that we will sign this outcome
        // This doesn't reveal the signature yet, just commits to the policy
        let mut hasher = Sha256::new();
        hasher.update(b"policy_ack:");
        hasher.update(contract_id.as_bytes());
        hasher.update(b":");
        hasher.update(outcome.as_bytes());
        hasher.update(b":");
        hasher.update(&now.to_le_bytes());
        let commitment = hasher.finalize();
        
        PolicyAcknowledgment {
            contract_id: contract_id.to_string(),
            outcome: outcome.to_string(),
            oracle_pubkey_hex: self.x_only_pubkey_hex(),
            commitment_hex: hex::encode(&commitment[..16]), // Truncated for brevity
            acknowledged_at: now,
        }
    }
}

/// Oracle attestation (signed outcome)
#[derive(Debug, Clone)]
pub struct OracleAttestation {
    pub outcome: String,
    pub signature_hex: String,
    pub pubkey_hex: String,
    pub timestamp: u64,
}

impl OracleAttestation {
    /// Convert to JSON string
    pub fn to_json(&self) -> String {
        format!(r#"{{
  "status": "ok",
  "kind": "oracle_attestation",
  "outcome": "{}",
  "signature_hex": "{}",
  "pubkey_hex": "{}",
  "timestamp": {}
}}"#, 
            escape_json_str(&self.outcome),
            self.signature_hex,
            self.pubkey_hex,
            self.timestamp
        )
    }
}

/// Policy acknowledgment (commitment to sign an outcome)
#[derive(Debug, Clone)]
pub struct PolicyAcknowledgment {
    pub contract_id: String,
    pub outcome: String,
    pub oracle_pubkey_hex: String,
    pub commitment_hex: String,
    pub acknowledged_at: u64,
}

impl PolicyAcknowledgment {
    pub fn to_json(&self) -> String {
        format!(r#"{{
  "status": "ok",
  "kind": "policy_acknowledgment",
  "contract_id": "{}",
  "outcome": "{}",
  "oracle_pubkey_hex": "{}",
  "commitment_hex": "{}",
  "acknowledged_at": {}
}}"#,
            escape_json_str(&self.contract_id),
            escape_json_str(&self.outcome),
            self.oracle_pubkey_hex,
            self.commitment_hex,
            self.acknowledged_at
        )
    }
}

// --- JSON helper ---
fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _    => out.push(ch),
        }
    }
    out
}

// --- JNI-facing functions ---

/// Get the local oracle's compressed public key (hex) - 33 bytes
/// Used by DLC builder which expects compressed format
pub fn oracle_pubkey_hex() -> String {
    Oracle::local().pubkey_hex()
}

/// Get the local oracle's x-only public key (hex) - 32 bytes
/// Used for BIP340 Schnorr signature verification
pub fn oracle_x_only_pubkey_hex() -> String {
    Oracle::local().x_only_pubkey_hex()
}

/// Sign an outcome and return JSON attestation
pub fn oracle_sign_outcome(outcome: &str) -> String {
    Oracle::local().sign_outcome(outcome).to_json()
}

/// Acknowledge a signing policy for a contract
pub fn oracle_acknowledge_policy(outcome: &str, contract_id: &str) -> String {
    Oracle::local().acknowledge_policy(outcome, contract_id).to_json()
}

/// Verify an attestation (for testing)
pub fn oracle_verify_attestation(
    outcome: &str,
    signature_hex: &str,
    pubkey_hex: &str,
) -> bool {
    let attestation = OracleAttestation {
        outcome: outcome.to_string(),
        signature_hex: signature_hex.to_string(),
        pubkey_hex: pubkey_hex.to_string(),
        timestamp: 0, // Not needed for verification
    };
    
    Oracle::verify_attestation(&attestation).unwrap_or(false)
}

/// Create DLC contract JSON (unchanged interface for compatibility)
pub fn create_dlc_contract_json(outcome: &str, payouts_json: &str, oracle_json: &str) -> String {
    let oracle = Oracle::local();
    
    // Generate contract ID
    let mut hasher = Sha256::new();
    hasher.update(outcome.as_bytes());
    hasher.update(payouts_json.as_bytes());
    hasher.update(oracle_json.as_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    hasher.update(&now.to_le_bytes());
    let contract_id = hex::encode(&hasher.finalize()[..16]);
    
    format!(r#"{{
  "status": "ok",
  "kind": "dlc_contract",
  "contract_id": "{}",
  "outcome": "{}",
  "payouts": {},
  "oracle": {{
    "name": "{}",
    "pubkey_hex": "{}"
  }}
}}"#, 
        contract_id,
        escape_json_str(outcome),
        payouts_json,
        oracle.name,
        oracle.x_only_pubkey_hex()
    )
}

/// Sign an outcome and return JSON (legacy interface)
pub fn sign_dlc_outcome_json(outcome: &str) -> String {
    oracle_sign_outcome(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_oracle_creation() {
        let oracle = Oracle::local();
        assert!(!oracle.pubkey_hex().is_empty());
        assert_eq!(oracle.x_only_pubkey_hex().len(), 64); // 32 bytes = 64 hex chars
    }
    
    #[test]
    fn test_sign_and_verify() {
        let oracle = Oracle::local();
        let attestation = oracle.sign_outcome("auth_verified");
        
        // Verify the signature
        let is_valid = Oracle::verify_attestation(&attestation).unwrap();
        assert!(is_valid, "Signature should be valid");
    }
    
    #[test]
    fn test_different_outcomes_different_sigs() {
        let oracle = Oracle::local();
        let att1 = oracle.sign_outcome("auth_verified");
        let att2 = oracle.sign_outcome("refund");
        
        assert_ne!(att1.signature_hex, att2.signature_hex);
    }
    
    #[test]
    fn test_deterministic_oracle_key() {
        // Oracle key should be consistent across calls
        let oracle1 = Oracle::local();
        let oracle2 = Oracle::local();
        
        assert_eq!(oracle1.x_only_pubkey_hex(), oracle2.x_only_pubkey_hex());
    }
    
    #[test]
    fn test_policy_acknowledgment() {
        let oracle = Oracle::local();
        let ack = oracle.acknowledge_policy("auth_verified", "contract_123");
        
        assert_eq!(ack.outcome, "auth_verified");
        assert_eq!(ack.contract_id, "contract_123");
        assert!(!ack.commitment_hex.is_empty());
    }
    
    #[test]
    fn test_invalid_signature_fails() {
        let attestation = OracleAttestation {
            outcome: "auth_verified".to_string(),
            signature_hex: "00".repeat(64), // Invalid signature
            pubkey_hex: Oracle::local().x_only_pubkey_hex(),
            timestamp: 0,
        };
        
        let result = Oracle::verify_attestation(&attestation);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Invalid signature should fail verification");
    }
}
