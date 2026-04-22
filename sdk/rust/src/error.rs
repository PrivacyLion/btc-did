//! Error types for SignedByMe SDK

use thiserror::Error;

/// SDK error type
#[derive(Error, Debug)]
pub enum SdkError {
    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),
    
    /// Invalid proof format
    #[error("Invalid proof format: {0}")]
    InvalidProof(String),
    
    /// Invalid verification key
    #[error("Invalid verification key: {0}")]
    InvalidVerificationKey(String),
    
    /// JWT validation error
    #[error("JWT validation failed: {0}")]
    JwtError(String),
    
    /// OIDC discovery error
    #[cfg(feature = "oidc")]
    #[error("OIDC discovery failed: {0}")]
    OidcError(String),
    
    /// Network error
    #[cfg(feature = "oidc")]
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<serde_json::Error> for SdkError {
    fn from(e: serde_json::Error) -> Self {
        SdkError::SerializationError(e.to_string())
    }
}

impl From<hex::FromHexError> for SdkError {
    fn from(e: hex::FromHexError) -> Self {
        SdkError::InvalidInput(format!("Invalid hex: {}", e))
    }
}

impl From<jsonwebtoken::errors::Error> for SdkError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        SdkError::JwtError(e.to_string())
    }
}

#[cfg(feature = "oidc")]
impl From<reqwest::Error> for SdkError {
    fn from(e: reqwest::Error) -> Self {
        SdkError::NetworkError(e.to_string())
    }
}
