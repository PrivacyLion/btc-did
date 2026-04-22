//! Groth16 proof verifier
//!
//! Verification is fully local — no network calls required.
//! The verification key (4KB) can be bundled with your application.

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;

use crate::error::SdkError;
use crate::verification_key::VerificationKey;
use crate::proof::{Groth16Proof, PublicInputs, VerificationResult};

/// Groth16 proof verifier
///
/// Create once with a verification key, then verify multiple proofs.
///
/// # Example
///
/// ```rust,ignore
/// use signedby_sdk::{Verifier, VerificationKey};
///
/// let vk = VerificationKey::from_json(vk_json)?;
/// let verifier = Verifier::new(vk);
///
/// let result = verifier.verify(&proof, &public_inputs)?;
/// assert!(result.valid);
/// ```
pub struct Verifier {
    verification_key: VerificationKey,
}

impl Verifier {
    /// Create a new verifier with the given verification key
    pub fn new(vk: VerificationKey) -> Self {
        Self { verification_key: vk }
    }
    
    /// Verify a Groth16 proof
    ///
    /// Returns a `VerificationResult` with:
    /// - `valid`: whether the proof is cryptographically valid
    /// - `npub`: the user's pseudonymous identifier (NOSTR public key)
    /// - `merkle_root`: the group membership tree they proved membership in
    /// - `session_binding`: prevents proof replay across sessions
    pub fn verify(
        &self,
        proof: &Groth16Proof,
        public_inputs: &PublicInputs,
    ) -> Result<VerificationResult, SdkError> {
        // Verify the Groth16 proof
        let valid = Groth16::<Bn254>::verify(
            &self.verification_key.inner,
            &public_inputs.values,
            &proof.inner,
        ).map_err(|e| SdkError::VerificationFailed(format!("Verification error: {:?}", e)))?;
        
        let npub = public_inputs.npub_bech32()?;
        
        Ok(VerificationResult {
            valid,
            npub_hex: public_inputs.npub_hex.clone(),
            npub,
            merkle_root: public_inputs.merkle_root.clone(),
            session_binding: public_inputs.session_binding.clone(),
        })
    }
    
    /// Verify proof from JSON strings (convenience method)
    pub fn verify_json(
        &self,
        proof_json: &str,
        public_inputs_json: &str,
    ) -> Result<VerificationResult, SdkError> {
        let proof = Groth16Proof::from_json(proof_json)?;
        let public_inputs = PublicInputs::from_json(public_inputs_json)?;
        self.verify(&proof, &public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: Full integration tests require actual proof data
    // See examples/ for end-to-end verification demos
    
    #[test]
    fn test_verifier_creation() {
        // This test would need a real verification key
        // Just testing the API compiles correctly
    }
}
