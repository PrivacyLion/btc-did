// NativeBridge.swift - Swift wrapper for Rust FFI
// SignedByMe iOS - Mirrors Android NativeBridge.kt

import Foundation

/// Swift wrapper for the signedby_core Rust library.
/// All cryptographic operations go through this bridge.
enum NativeBridge {
    
    // MARK: - Basic Functions
    
    /// Sanity check - returns hello from Rust
    static func helloFromRust() -> String {
        guard let ptr = sbm_hello_from_rust() else { return "error" }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Compute SHA-256 hash of input
    static func sha256Hex(_ input: String) -> String {
        guard let ptr = sbm_sha256_hex(input) else { return "error" }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    // MARK: - Key Management (secp256k1)
    
    /// Generate a random 32-byte secp256k1 private key
    static func generateSecp256k1PrivateKey() -> Data {
        guard let ptr = sbm_generate_private_key() else {
            // Fallback to SecRandomCopyBytes
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
            return Data(bytes)
        }
        let data = Data(bytes: ptr, count: 32)
        sbm_free_bytes(ptr, 32)
        return data
    }
    
    /// Derive compressed public key hex (33 bytes) from private key
    static func derivePublicKeyHex(_ privateKey: Data) -> String {
        return privateKey.withUnsafeBytes { privPtr -> String in
            guard let baseAddr = privPtr.baseAddress else { return "error" }
            guard let ptr = sbm_derive_public_key_hex(
                baseAddr.assumingMemoryBound(to: UInt8.self),
                privateKey.count
            ) else { return "error" }
            let result = String(cString: ptr)
            sbm_free_string(ptr)
            return result
        }
    }
    
    /// Get x-only public key hex (32 bytes) for Taproot/Schnorr
    static func getXOnlyPubkey(_ privateKey: Data) -> String {
        return privateKey.withUnsafeBytes { privPtr -> String in
            guard let baseAddr = privPtr.baseAddress else { return "error" }
            guard let ptr = sbm_get_x_only_pubkey(
                baseAddr.assumingMemoryBound(to: UInt8.self),
                privateKey.count
            ) else { return "error" }
            let result = String(cString: ptr)
            sbm_free_string(ptr)
            return result
        }
    }
    
    /// Sign message with ECDSA (returns DER hex signature)
    static func signMessageDerHex(_ privateKey: Data, message: String) -> String {
        return privateKey.withUnsafeBytes { privPtr -> String in
            guard let baseAddr = privPtr.baseAddress else { return "error" }
            guard let ptr = sbm_sign_message_der_hex(
                baseAddr.assumingMemoryBound(to: UInt8.self),
                privateKey.count,
                message
            ) else { return "error" }
            let result = String(cString: ptr)
            sbm_free_string(ptr)
            return result
        }
    }
    
    /// Sign message with Schnorr (returns 64-byte signature hex)
    static func signSchnorr(_ privateKey: Data, message: String) -> String {
        return privateKey.withUnsafeBytes { privPtr -> String in
            guard let baseAddr = privPtr.baseAddress else { return "error" }
            guard let ptr = sbm_sign_schnorr(
                baseAddr.assumingMemoryBound(to: UInt8.self),
                privateKey.count,
                message
            ) else { return "error" }
            let result = String(cString: ptr)
            sbm_free_string(ptr)
            return result
        }
    }
    
    // MARK: - STWO Prover
    
    /// Check if real STWO is compiled in
    static func hasRealStwo() -> Bool {
        return sbm_has_real_stwo()
    }
    
    /// Generate STWO proof for circuit
    static func generateStwoProof(circuit: String, inputHashHex: String, outputHashHex: String) -> String {
        guard let ptr = sbm_generate_stwo_proof(circuit, inputHashHex, outputHashHex) else {
            return #"{"status":"error","error":"FFI call failed"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Generate Identity Proof (Step 3 onboarding)
    static func generateIdentityProof(
        didPubkey: String,
        walletAddress: String,
        walletSignature: String,
        expiryDays: Int64
    ) -> String {
        guard let ptr = sbm_generate_identity_proof(
            didPubkey, walletAddress, walletSignature, expiryDays
        ) else {
            return #"{"status":"error","error":"FFI call failed"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Verify an Identity Proof
    static func verifyIdentityProof(_ proofJson: String) -> String {
        guard let ptr = sbm_verify_identity_proof(proofJson) else {
            return #"{"valid":false,"error":"FFI call failed"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Generate REAL STWO Identity Proof V3 (full security bindings)
    static func generateRealIdentityProofV3(
        didPubkeyHex: String,
        walletAddress: String,
        paymentHashHex: String,
        amountSats: Int64,
        expiresAt: Int64,
        eaDomain: String,
        nonceHex: String
    ) -> String {
        guard let ptr = sbm_generate_real_identity_proof_v3(
            didPubkeyHex, walletAddress, paymentHashHex,
            amountSats, expiresAt, eaDomain, nonceHex
        ) else {
            return #"{"status":"error","error":"FFI call failed"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Generate REAL STWO Identity Proof (v1 legacy)
    static func generateRealIdentityProof(
        didPubkeyHex: String,
        walletAddress: String,
        paymentHashHex: String,
        expiryDays: Int64
    ) -> String {
        guard let ptr = sbm_generate_real_identity_proof(
            didPubkeyHex, walletAddress, paymentHashHex, expiryDays
        ) else {
            return #"{"status":"error","error":"FFI call failed"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Verify REAL STWO proof
    static func verifyRealIdentityProof(_ proofJson: String) -> String {
        guard let ptr = sbm_verify_real_identity_proof(proofJson) else {
            return #"{"valid":false,"error":"FFI call failed"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    // MARK: - DLC (Discreet Log Contracts)
    
    /// Get oracle x-only public key
    static func oraclePubkeyHex() -> String {
        guard let ptr = sbm_oracle_pubkey_hex() else { return "error" }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Sign outcome as oracle
    static func oracleSignOutcome(_ outcome: String) -> String {
        guard let ptr = sbm_oracle_sign_outcome(outcome) else {
            return #"{"status":"error"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Acknowledge signing policy
    static func oracleAcknowledgePolicy(outcome: String, contractId: String) -> String {
        guard let ptr = sbm_oracle_acknowledge_policy(outcome, contractId) else {
            return #"{"status":"error"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Verify oracle attestation
    static func oracleVerifyAttestation(
        outcome: String,
        signatureHex: String,
        pubkeyHex: String
    ) -> Bool {
        return sbm_oracle_verify_attestation(outcome, signatureHex, pubkeyHex)
    }
    
    /// Create DLC contract
    static func createDlcContract(
        outcome: String,
        payoutsJson: String,
        oracleJson: String
    ) -> String {
        guard let ptr = sbm_create_dlc_contract(outcome, payoutsJson, oracleJson) else {
            return #"{"status":"error"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Sign DLC outcome
    static func signDlcOutcome(_ outcome: String) -> String {
        guard let ptr = sbm_sign_dlc_outcome(outcome) else {
            return #"{"status":"error"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    // MARK: - Lightning Payments
    
    /// Generate preimage and payment hash
    static func generatePreimage() -> String {
        guard let ptr = sbm_generate_preimage() else {
            return #"{"status":"error"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Verify payment
    static func verifyPayment(paymentHash: String, preimageHex: String) -> String {
        guard let ptr = sbm_verify_payment(paymentHash, preimageHex) else {
            return #"{"valid":false}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    /// Create Payment Request Package
    static func createPrp(
        amountSats: Int64,
        description: String,
        payeeDid: String,
        payeeLnAddress: String,
        expirySecs: Int64
    ) -> String {
        guard let ptr = sbm_create_prp(
            amountSats, description, payeeDid, payeeLnAddress, expirySecs
        ) else {
            return #"{"status":"error"}"#
        }
        let result = String(cString: ptr)
        sbm_free_string(ptr)
        return result
    }
    
    // MARK: - Membership Proofs (Merkle Tree)
    
    /// Generate membership proof
    static func proveMembership(
        leafSecret: Data,        // 32 bytes
        merklePath: [[UInt8]],   // 20 siblings, each 32 bytes
        pathIndices: [UInt8],    // 20 bytes
        root: Data,              // 32 bytes
        bindingHash: Data,       // 32 bytes
        purposeId: Int32
    ) -> Data? {
        // Flatten merkle path to 640 bytes
        var flatPath = [UInt8](repeating: 0, count: 640)
        for (i, sibling) in merklePath.prefix(20).enumerated() {
            for (j, byte) in sibling.prefix(32).enumerated() {
                flatPath[i * 32 + j] = byte
            }
        }
        
        // Ensure pathIndices is exactly 20 bytes
        var indices = [UInt8](repeating: 0, count: 20)
        for (i, idx) in pathIndices.prefix(20).enumerated() {
            indices[i] = idx
        }
        
        var outLen: Int = 0
        
        let result = leafSecret.withUnsafeBytes { leafPtr -> Data? in
            return root.withUnsafeBytes { rootPtr -> Data? in
                return bindingHash.withUnsafeBytes { hashPtr -> Data? in
                    guard let leafAddr = leafPtr.baseAddress,
                          let rootAddr = rootPtr.baseAddress,
                          let hashAddr = hashPtr.baseAddress else { return nil }
                    
                    guard let proofPtr = sbm_prove_membership(
                        leafAddr.assumingMemoryBound(to: UInt8.self),
                        flatPath,
                        indices,
                        rootAddr.assumingMemoryBound(to: UInt8.self),
                        hashAddr.assumingMemoryBound(to: UInt8.self),
                        purposeId,
                        &outLen
                    ) else { return nil }
                    
                    let data = Data(bytes: proofPtr, count: outLen)
                    sbm_free_bytes(proofPtr, outLen)
                    return data
                }
            }
        }
        
        return result
    }
    
    /// Verify membership proof locally
    static func verifyMembership(
        proof: Data,
        root: Data,
        bindingHash: Data,
        purposeId: Int32
    ) -> Bool {
        return proof.withUnsafeBytes { proofPtr -> Bool in
            return root.withUnsafeBytes { rootPtr -> Bool in
                return bindingHash.withUnsafeBytes { hashPtr -> Bool in
                    guard let proofAddr = proofPtr.baseAddress,
                          let rootAddr = rootPtr.baseAddress,
                          let hashAddr = hashPtr.baseAddress else { return false }
                    
                    return sbm_verify_membership(
                        proofAddr.assumingMemoryBound(to: UInt8.self),
                        proof.count,
                        rootAddr.assumingMemoryBound(to: UInt8.self),
                        hashAddr.assumingMemoryBound(to: UInt8.self),
                        purposeId
                    )
                }
            }
        }
    }
    
    /// Compute V4 binding hash
    static func computeBindingHashV4(
        didPubkey: Data,
        walletAddress: String,
        clientId: String,
        sessionId: String,
        paymentHash: Data,
        amountSats: Int64,
        expiresAt: Int64,
        nonce: Data,
        eaDomain: String,
        purposeId: Int32,
        rootId: String
    ) -> Data? {
        return didPubkey.withUnsafeBytes { didPtr -> Data? in
            return paymentHash.withUnsafeBytes { hashPtr -> Data? in
                return nonce.withUnsafeBytes { noncePtr -> Data? in
                    guard let didAddr = didPtr.baseAddress,
                          let hashAddr = hashPtr.baseAddress,
                          let nonceAddr = noncePtr.baseAddress else { return nil }
                    
                    guard let resultPtr = sbm_compute_binding_hash_v4(
                        didAddr.assumingMemoryBound(to: UInt8.self),
                        didPubkey.count,
                        walletAddress,
                        clientId,
                        sessionId,
                        hashAddr.assumingMemoryBound(to: UInt8.self),
                        amountSats,
                        expiresAt,
                        nonceAddr.assumingMemoryBound(to: UInt8.self),
                        eaDomain,
                        purposeId,
                        rootId
                    ) else { return nil }
                    
                    let data = Data(bytes: resultPtr, count: 32)
                    sbm_free_bytes(resultPtr, 32)
                    return data
                }
            }
        }
    }
    
    /// Compute leaf commitment from leaf secret
    static func computeLeafCommitment(_ leafSecret: Data) -> Data? {
        return leafSecret.withUnsafeBytes { ptr -> Data? in
            guard let addr = ptr.baseAddress else { return nil }
            guard let resultPtr = sbm_compute_leaf_commitment(
                addr.assumingMemoryBound(to: UInt8.self)
            ) else { return nil }
            
            let data = Data(bytes: resultPtr, count: 32)
            sbm_free_bytes(resultPtr, 32)
            return data
        }
    }
}

// MARK: - Data Extensions

extension Data {
    /// Convert data to hex string
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
    
    /// Initialize from hex string
    init?(hex: String) {
        let hex = hex.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }
        
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let endIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<endIndex], radix: 16) else { return nil }
            data.append(byte)
            index = endIndex
        }
        
        self = data
    }
}
