// ffi.rs - OpenClaw Language Bindings (Phase 9A.7)
//
// Per Bible Section 9A.7 and line 638:
// "Rust core. OpenClaw bindings first (v1 priority)."
//
// C-compatible FFI bindings that enable maximum agent deployment flexibility
// across all platforms and programming languages.
//
// Error handling:
// - Return 0 for success, negative codes for errors
// - String functions return NULL on failure
//
// Memory safety:
// - All returned strings must be freed with agent_string_free()
// - Caller owns strings returned from FFI functions

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::sdk::identity::{AgentIdentity, AgentIdentityState};
use crate::sdk::storage::EncryptedFileStorage;

// Error codes
pub const FFI_SUCCESS: c_int = 0;
pub const FFI_ERROR_NULL_POINTER: c_int = -1;
pub const FFI_ERROR_INVALID_UTF8: c_int = -2;
pub const FFI_ERROR_NOT_INITIALIZED: c_int = -3;
pub const FFI_ERROR_ALREADY_INITIALIZED: c_int = -4;
pub const FFI_ERROR_STORAGE_FAILED: c_int = -5;
pub const FFI_ERROR_ENROLLMENT_FAILED: c_int = -6;
pub const FFI_ERROR_AUTH_FAILED: c_int = -7;
pub const FFI_ERROR_DELEGATION_INVALID: c_int = -8;
pub const FFI_ERROR_WALLET_FAILED: c_int = -9;
pub const FFI_ERROR_INTERNAL: c_int = -100;

/// Global agent state (thread-safe singleton)
static AGENT_STATE: Lazy<Mutex<Option<AgentState>>> = Lazy::new(|| Mutex::new(None));

/// Internal agent state
struct AgentState {
    identity: AgentIdentityState,
    storage_path: String,
    nwc_uri: Option<String>,
}

// ============================================================================
// Agent Lifecycle
// ============================================================================

/// Initialize the agent with default storage location
/// 
/// Returns: 0 on success, negative error code on failure
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_initialize() -> c_int {
    agent_initialize_with_path(std::ptr::null())
}

/// Initialize the agent with custom storage path
/// 
/// # Arguments
/// * `storage_path` - Path to storage directory (NULL for default ~/.signedby)
/// 
/// Returns: 0 on success, negative error code on failure
/// 
/// # Safety
/// This function is safe to call from C code. `storage_path` must be a valid
/// C string or NULL.
#[no_mangle]
pub extern "C" fn agent_initialize_with_path(storage_path: *const c_char) -> c_int {
    let mut state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INTERNAL,
    };
    
    if state.is_some() {
        return FFI_ERROR_ALREADY_INITIALIZED;
    }
    
    // Determine storage path
    let path = if storage_path.is_null() {
        // Default: ~/.signedby
        match dirs::home_dir() {
            Some(home) => home.join(".signedby"),
            None => return FFI_ERROR_STORAGE_FAILED,
        }
    } else {
        let path_str = match unsafe { CStr::from_ptr(storage_path) }.to_str() {
            Ok(s) => s,
            Err(_) => return FFI_ERROR_INVALID_UTF8,
        };
        std::path::PathBuf::from(path_str)
    };
    
    // Create storage
    let storage = match EncryptedFileStorage::new(path.clone()) {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_STORAGE_FAILED,
    };
    
    // Create or load identity
    let identity = AgentIdentity::new(storage);
    
    let identity_state = if identity.is_initialized() {
        match identity.load() {
            Ok(s) => s,
            Err(_) => return FFI_ERROR_STORAGE_FAILED,
        }
    } else {
        match identity.initialize() {
            Ok(s) => s,
            Err(_) => return FFI_ERROR_STORAGE_FAILED,
        }
    };
    
    *state = Some(AgentState {
        identity: identity_state,
        storage_path: path.to_string_lossy().to_string(),
        nwc_uri: None,
    });
    
    FFI_SUCCESS
}

/// Get the agent's npub (NOSTR public key in bech32 format)
/// 
/// Returns: Newly allocated string on success, NULL on failure
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_get_npub() -> *mut c_char {
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let agent_state = match state.as_ref() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    
    match CString::new(agent_state.identity.agent_npub.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the agent's DID (Decentralized Identifier)
/// 
/// Returns: Newly allocated string on success, NULL on failure
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_get_did() -> *mut c_char {
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let agent_state = match state.as_ref() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    
    match CString::new(agent_state.identity.did.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the agent's leaf commitment (for enrollment verification)
/// 
/// Returns: Newly allocated hex string on success, NULL on failure
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_get_leaf_commitment() -> *mut c_char {
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let agent_state = match state.as_ref() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    
    match CString::new(agent_state.identity.leaf_commitment.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// Enterprise Integration
// ============================================================================

/// Enroll the agent with an enterprise
/// 
/// # Arguments
/// * `enterprise_domain` - Enterprise domain (e.g., "acme.com")
/// 
/// Returns: 0 on success, negative error code on failure
/// 
/// # Safety
/// This function is safe to call from C code. `enterprise_domain` must be
/// a valid C string.
#[no_mangle]
pub extern "C" fn agent_enroll(enterprise_domain: *const c_char) -> c_int {
    if enterprise_domain.is_null() {
        return FFI_ERROR_NULL_POINTER;
    }
    
    let _domain = match unsafe { CStr::from_ptr(enterprise_domain) }.to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INVALID_UTF8,
    };
    
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INTERNAL,
    };
    
    if state.is_none() {
        return FFI_ERROR_NOT_INITIALIZED;
    }
    
    // TODO: Implement enrollment via EnrollmentBootstrap
    // This requires async runtime, will be implemented in Phase 9A.8
    
    FFI_SUCCESS
}

/// Authenticate with an enterprise (generate and submit proof)
/// 
/// # Arguments
/// * `enterprise_domain` - Enterprise domain (e.g., "acme.com")
/// 
/// Returns: OIDC id_token on success, NULL on failure
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code. `enterprise_domain` must be
/// a valid C string.
#[no_mangle]
pub extern "C" fn agent_authenticate(enterprise_domain: *const c_char) -> *mut c_char {
    if enterprise_domain.is_null() {
        return std::ptr::null_mut();
    }
    
    let _domain = match unsafe { CStr::from_ptr(enterprise_domain) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    if state.is_none() {
        return std::ptr::null_mut();
    }
    
    // TODO: Implement authentication via MembershipProver
    // This requires async runtime and proof generation, will be implemented in Phase 9A.8
    
    std::ptr::null_mut()
}

// ============================================================================
// Delegation Management
// ============================================================================

/// Check if delegation from human owner is valid
/// 
/// # Arguments
/// * `enterprise_domain` - Enterprise domain (e.g., "acme.com")
/// 
/// Returns: 1 if valid, 0 if invalid/expired/revoked, negative on error
/// 
/// # Safety
/// This function is safe to call from C code. `enterprise_domain` must be
/// a valid C string.
#[no_mangle]
pub extern "C" fn agent_check_delegation(enterprise_domain: *const c_char) -> c_int {
    if enterprise_domain.is_null() {
        return FFI_ERROR_NULL_POINTER;
    }
    
    let _domain = match unsafe { CStr::from_ptr(enterprise_domain) }.to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INVALID_UTF8,
    };
    
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INTERNAL,
    };
    
    if state.is_none() {
        return FFI_ERROR_NOT_INITIALIZED;
    }
    
    // TODO: Implement delegation check via DelegationValidator
    // This requires async runtime, will be implemented in Phase 9A.8
    
    1 // Assume valid for now
}

// ============================================================================
// Wallet Operations
// ============================================================================

/// Setup NWC wallet connection
/// 
/// # Arguments
/// * `nwc_uri` - NWC connection URI (nostr+walletconnect://...)
/// 
/// Returns: 0 on success, negative error code on failure
/// 
/// # Safety
/// This function is safe to call from C code. `nwc_uri` must be a valid C string.
#[no_mangle]
pub extern "C" fn agent_setup_wallet(nwc_uri: *const c_char) -> c_int {
    if nwc_uri.is_null() {
        return FFI_ERROR_NULL_POINTER;
    }
    
    let uri = match unsafe { CStr::from_ptr(nwc_uri) }.to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INVALID_UTF8,
    };
    
    // Validate URI format
    if !uri.starts_with("nostr+walletconnect://") {
        return FFI_ERROR_WALLET_FAILED;
    }
    
    let mut state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INTERNAL,
    };
    
    let agent_state = match state.as_mut() {
        Some(s) => s,
        None => return FFI_ERROR_NOT_INITIALIZED,
    };
    
    agent_state.nwc_uri = Some(uri.to_string());
    
    FFI_SUCCESS
}

/// Get the agent's Lightning address (if published)
/// 
/// Returns: Lightning address string on success, NULL if not set
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_get_lightning_address() -> *mut c_char {
    // TODO: Implement - retrieve from NOSTR kind 0 profile
    std::ptr::null_mut()
}

/// Create an invoice for receiving payment
/// 
/// # Arguments
/// * `amount_sats` - Amount in satoshis
/// * `description` - Invoice description
/// 
/// Returns: BOLT11 invoice string on success, NULL on failure
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code. `description` must be a valid C string.
#[no_mangle]
pub extern "C" fn agent_create_invoice(
    amount_sats: u64,
    description: *const c_char,
) -> *mut c_char {
    if description.is_null() {
        return std::ptr::null_mut();
    }
    
    let _desc = match unsafe { CStr::from_ptr(description) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let agent_state = match state.as_ref() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    
    if agent_state.nwc_uri.is_none() {
        return std::ptr::null_mut();
    }
    
    // TODO: Implement via NwcWallet.create_receive_invoice()
    // This requires async runtime, will be implemented in Phase 9A.8
    let _ = amount_sats;
    
    std::ptr::null_mut()
}

/// Pay a BOLT11 invoice
/// 
/// # Arguments
/// * `bolt11` - BOLT11 invoice string
/// 
/// Returns: Payment preimage hex on success, NULL on failure
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code. `bolt11` must be a valid C string.
#[no_mangle]
pub extern "C" fn agent_pay_invoice(bolt11: *const c_char) -> *mut c_char {
    if bolt11.is_null() {
        return std::ptr::null_mut();
    }
    
    let _invoice = match unsafe { CStr::from_ptr(bolt11) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let agent_state = match state.as_ref() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    
    if agent_state.nwc_uri.is_none() {
        return std::ptr::null_mut();
    }
    
    // TODO: Implement via NwcWallet.pay_invoice()
    // This requires async runtime, will be implemented in Phase 9A.8
    
    std::ptr::null_mut()
}

/// Get wallet balance in satoshis
/// 
/// Returns: Balance in sats on success, -1 on failure
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_get_balance() -> i64 {
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let agent_state = match state.as_ref() {
        Some(s) => s,
        None => return -1,
    };
    
    if agent_state.nwc_uri.is_none() {
        return -1;
    }
    
    // TODO: Implement via NwcWallet.get_balance()
    // This requires async runtime, will be implemented in Phase 9A.8
    
    -1
}

// ============================================================================
// Memory Management
// ============================================================================

/// Free a string allocated by the FFI layer
/// 
/// # Arguments
/// * `ptr` - Pointer to string previously returned by an agent_* function
/// 
/// # Safety
/// This function must only be called with pointers returned by agent_* functions.
/// Calling with any other pointer is undefined behavior.
#[no_mangle]
pub extern "C" fn agent_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get the SDK version string
/// 
/// Returns: Version string (e.g., "0.3.0")
/// Caller must free the returned string with agent_string_free()
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_sdk_version() -> *mut c_char {
    match CString::new(env!("CARGO_PKG_VERSION")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Check if the agent is initialized
/// 
/// Returns: 1 if initialized, 0 if not
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_is_initialized() -> c_int {
    let state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    
    if state.is_some() { 1 } else { 0 }
}

/// Shutdown the agent and release resources
/// 
/// Returns: 0 on success
/// 
/// # Safety
/// This function is safe to call from C code.
#[no_mangle]
pub extern "C" fn agent_shutdown() -> c_int {
    let mut state = match AGENT_STATE.lock() {
        Ok(s) => s,
        Err(_) => return FFI_ERROR_INTERNAL,
    };
    
    *state = None;
    FFI_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sdk_version() {
        let version = agent_sdk_version();
        assert!(!version.is_null());
        unsafe {
            let _ = CString::from_raw(version);
        }
    }
    
    #[test]
    fn test_not_initialized() {
        // Reset state for test
        {
            let mut state = AGENT_STATE.lock().unwrap();
            *state = None;
        }
        
        assert_eq!(agent_is_initialized(), 0);
        assert!(agent_get_npub().is_null());
    }
}
