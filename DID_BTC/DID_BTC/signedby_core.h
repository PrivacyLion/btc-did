// signedby_core.h - C FFI header for SignedByMe
// Used by iOS Swift bridge via bridging header
//
// Memory rules:
// - String returns: Caller must call sbm_free_string()
// - Byte array returns: Caller must call sbm_free_bytes(ptr, len)
// - Input pointers: Caller owns, function borrows

#ifndef SIGNEDBY_CORE_H
#define SIGNEDBY_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Memory Management
// ============================================================================

/// Free a string allocated by Rust
void sbm_free_string(char* ptr);

/// Free a byte array allocated by Rust
void sbm_free_bytes(uint8_t* ptr, size_t len);

// ============================================================================
// Basic Functions
// ============================================================================

/// Hello from Rust - sanity check
/// Returns: String (caller must free)
char* sbm_hello_from_rust(void);

/// SHA-256 hash of input string
/// Returns: Hex string (caller must free)
char* sbm_sha256_hex(const char* input);

// ============================================================================
// Key Management (secp256k1)
// ============================================================================

/// Generate a random 32-byte private key
/// Returns: 32-byte array (caller must free with sbm_free_bytes(ptr, 32))
uint8_t* sbm_generate_private_key(void);

/// Derive compressed public key hex (33 bytes) from private key
/// Returns: Hex string (caller must free)
char* sbm_derive_public_key_hex(const uint8_t* priv_ptr, size_t priv_len);

/// Get x-only public key hex (32 bytes) for Taproot/Schnorr
/// Returns: Hex string (caller must free)
char* sbm_get_x_only_pubkey(const uint8_t* priv_ptr, size_t priv_len);

/// Sign message with ECDSA (returns DER hex signature)
/// Returns: Hex string (caller must free)
char* sbm_sign_message_der_hex(
    const uint8_t* priv_ptr,
    size_t priv_len,
    const char* message
);

/// Sign message with Schnorr (returns 64-byte signature hex)
/// Returns: Hex string (caller must free)
char* sbm_sign_schnorr(
    const uint8_t* priv_ptr,
    size_t priv_len,
    const char* message
);

// ============================================================================
// Groth16 Proof Generation
// ============================================================================

/// Check if prover is ready
bool sbm_is_prover_ready(void);

/// Initialize prover with paths
/// @param zkey_path Path to .zkey file (proving key)
/// @param dat_path Path to .dat file (circuit data)
/// @param calc_path Path to witness calculator binary
/// @return true if initialization succeeded
bool sbm_init_prover(
    const char* zkey_path,
    const char* dat_path,
    const char* calc_path
);

/// Generate Groth16 membership proof
/// 
/// Input JSON format:
/// {
///   "leaf_secret": "hex...",
///   "siblings": ["0x...", ...],
///   "path_bits": [0, 1, ...]
/// }
/// 
/// Returns JSON (caller must free):
/// On success: {"success": true, "proof": {...}, "public_inputs": [...]}
/// On error: {"success": false, "error": "message"}
char* sbm_generate_proof(const char* input_json);

// ============================================================================
// Membership Proofs
// ============================================================================

/// Compute leaf commitment from 32-byte secret
/// Returns: 32-byte commitment (caller must free with sbm_free_bytes(ptr, 32))
uint8_t* sbm_compute_leaf_commitment(
    const uint8_t* secret_ptr,
    size_t secret_len
);

/// Check if real STWO support is available (legacy - always false)
bool sbm_has_real_stwo(void);

// ============================================================================
// Lightning / Payment
// ============================================================================

/// Generate preimage and payment hash
/// Returns JSON (caller must free):
/// {"preimage_hex": "...", "payment_hash": "..."}
char* sbm_generate_preimage(void);

/// Verify payment preimage against payment hash
/// Returns JSON (caller must free):
/// {"valid": true/false}
char* sbm_verify_payment(
    const char* payment_hash,
    const char* preimage_hex
);

// ============================================================================
// Legacy STWO Functions (stubs for compatibility)
// ============================================================================

/// Generate identity proof (legacy - use Groth16 flow instead)
char* sbm_generate_identity_proof(
    const char* did_pubkey,
    const char* wallet_address,
    const char* wallet_signature,
    int64_t expiry_days
);

/// Verify identity proof (legacy)
char* sbm_verify_identity_proof(const char* proof_json);

/// Generate real identity proof v3 (legacy)
char* sbm_generate_real_identity_proof_v3(
    const char* did_pubkey_hex,
    const char* wallet_address,
    const char* payment_hash_hex,
    int64_t amount_sats,
    int64_t expires_at,
    const char* ea_domain,
    const char* nonce_hex
);

/// Generate real identity proof v4 (legacy)
char* sbm_generate_real_identity_proof_v4(
    const char* did_pubkey_hex,
    const char* wallet_address,
    const char* client_id,
    const char* session_id,
    const char* payment_hash_hex,
    int64_t amount_sats,
    int64_t expires_at,
    const char* ea_domain,
    const char* nonce_hex,
    int64_t purpose_id,
    const char* root_id
);

/// Verify real identity proof (legacy)
char* sbm_verify_real_identity_proof(const char* proof_json);

#ifdef __cplusplus
}
#endif

#endif // SIGNEDBY_CORE_H
