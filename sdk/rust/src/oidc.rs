//! OIDC token validation
//!
//! SignedByMe issues standard OIDC id_tokens. This module validates them.
//!
//! For fully offline validation, bundle the JWKS (JSON Web Key Set) with
//! your application. For dynamic key rotation, enable the `oidc` feature
//! to fetch keys from the discovery endpoint.

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::SdkError;

/// OIDC token claims from SignedByMe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedByClaims {
    /// Subject - the user's npub (bech32 NOSTR public key)
    pub sub: String,
    
    /// Issuer - SignedByMe API URL
    pub iss: String,
    
    /// Audience - your client_id
    pub aud: String,
    
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    
    /// Issued at (Unix timestamp)
    pub iat: u64,
    
    /// Nonce (if provided in auth request)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    
    /// Client ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    
    /// Authentication method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    
    /// Merkle root hash (group membership)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    
    /// Whether proof was verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_verified: Option<bool>,
}

/// Configuration for token validation
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Expected issuer (e.g., "https://api.beta.privacy-lion.com")
    pub issuer: String,
    
    /// Expected audience (your client_id)
    pub audience: String,
    
    /// JWKS JSON (for offline validation)
    /// If None, will fetch from issuer's discovery endpoint
    pub jwks: Option<String>,
    
    /// Clock skew tolerance in seconds (default: 60)
    pub leeway: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            issuer: "https://api.beta.privacy-lion.com".into(),
            audience: String::new(),
            jwks: None,
            leeway: 60,
        }
    }
}

/// OIDC token validator
pub struct TokenValidator {
    config: ValidationConfig,
    keys: HashMap<String, DecodingKey>,
}

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// Individual JWK
#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    n: Option<String>,  // RSA modulus
    e: Option<String>,  // RSA exponent
    x: Option<String>,  // EC x coordinate
    y: Option<String>,  // EC y coordinate
    crv: Option<String>, // EC curve
}

impl TokenValidator {
    /// Create a new token validator
    pub fn new(config: ValidationConfig) -> Result<Self, SdkError> {
        let keys = if let Some(ref jwks_json) = config.jwks {
            parse_jwks(jwks_json)?
        } else {
            HashMap::new()
        };
        
        Ok(Self { config, keys })
    }
    
    /// Fetch JWKS from issuer's discovery endpoint
    #[cfg(feature = "oidc")]
    pub async fn fetch_keys(&mut self) -> Result<(), SdkError> {
        let discovery_url = format!("{}/.well-known/openid-configuration", self.config.issuer);
        
        let client = reqwest::Client::new();
        let discovery: serde_json::Value = client
            .get(&discovery_url)
            .send()
            .await?
            .json()
            .await?;
        
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or_else(|| SdkError::OidcError("No jwks_uri in discovery".into()))?;
        
        let jwks_json: String = client
            .get(jwks_uri)
            .send()
            .await?
            .text()
            .await?;
        
        self.keys = parse_jwks(&jwks_json)?;
        Ok(())
    }
    
    /// Validate an id_token and return claims
    pub fn validate(&self, token: &str) -> Result<SignedByClaims, SdkError> {
        // Decode header to get key ID
        let header = decode_header(token)?;
        
        let kid = header.kid
            .ok_or_else(|| SdkError::JwtError("Token missing kid header".into()))?;
        
        let key = self.keys.get(&kid)
            .ok_or_else(|| SdkError::JwtError(format!("Unknown key ID: {}", kid)))?;
        
        // Set up validation
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.leeway = self.config.leeway;
        
        // Decode and validate
        let token_data = decode::<SignedByClaims>(token, key, &validation)?;
        
        Ok(token_data.claims)
    }
    
    /// Validate token without checking expiration (for testing/debugging)
    pub fn validate_ignore_exp(&self, token: &str) -> Result<SignedByClaims, SdkError> {
        let header = decode_header(token)?;
        
        let kid = header.kid
            .ok_or_else(|| SdkError::JwtError("Token missing kid header".into()))?;
        
        let key = self.keys.get(&kid)
            .ok_or_else(|| SdkError::JwtError(format!("Unknown key ID: {}", kid)))?;
        
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = false;
        
        let token_data = decode::<SignedByClaims>(token, key, &validation)?;
        
        Ok(token_data.claims)
    }
}

/// Parse JWKS JSON into decoding keys
fn parse_jwks(jwks_json: &str) -> Result<HashMap<String, DecodingKey>, SdkError> {
    let jwks: Jwks = serde_json::from_str(jwks_json)?;
    let mut keys = HashMap::new();
    
    for jwk in jwks.keys {
        let key = match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.ok_or_else(|| SdkError::InvalidInput("RSA key missing n".into()))?;
                let e = jwk.e.ok_or_else(|| SdkError::InvalidInput("RSA key missing e".into()))?;
                DecodingKey::from_rsa_components(&n, &e)?
            }
            "EC" => {
                let x = jwk.x.ok_or_else(|| SdkError::InvalidInput("EC key missing x".into()))?;
                let y = jwk.y.ok_or_else(|| SdkError::InvalidInput("EC key missing y".into()))?;
                DecodingKey::from_ec_components(&x, &y)?
            }
            _ => continue, // Skip unsupported key types
        };
        
        keys.insert(jwk.kid, key);
    }
    
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.leeway, 60);
    }
}
