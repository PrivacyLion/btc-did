// File: app/src/main/java/com/signedby/app/NativeBridge.kt
package com.signedby.app

object NativeBridge {
    init {
        System.loadLibrary("signedby_core")
    }

    // ============================================================================
    // Basic Functions
    // ============================================================================
    
    @JvmStatic external fun helloFromRust(): String
    @JvmStatic external fun sha256Hex(input: String): String

    // ============================================================================
    // Key Management (secp256k1)
    // ============================================================================
    
    /** Generate a random 32-byte secp256k1 private key */
    @JvmStatic external fun generateSecp256k1PrivateKey(): ByteArray
    
    /** Derive compressed public key hex (33 bytes) from private key */
    @JvmStatic external fun derivePublicKeyHex(priv: ByteArray): String
    
    /** Get x-only public key hex (32 bytes) for Taproot/Schnorr */
    @JvmStatic external fun getXOnlyPubkey(priv: ByteArray): String
    
    /** Sign message with ECDSA (returns DER hex signature) */
    @JvmStatic external fun signMessageDerHex(priv: ByteArray, message: String): String
    
    /** Sign message with Schnorr (returns 64-byte signature hex) */
    @JvmStatic external fun signSchnorr(priv: ByteArray, message: String): String

    // ============================================================================
    // STWO Prover (Zero-Knowledge Proofs)
    // ============================================================================
    
    /**
     * Generate a STWO proof for the specified circuit type.
     * 
     * Circuit types:
     * - "hash_integrity" / "HashIntegrity" - Prove input/output hash equality
     * - "content_transform" / "ContentTransform" - Prove media transformation
     * - "login_proof" / "LoginProof" - Prove login without relay
     * - "signature_validation" / "SignatureValidation" - Prove signature validity
     * - "payment_trigger_hash" / "PaymentTriggerHash" - Prove payment trigger
     * 
     * @param circuit The circuit type
     * @param inputHashHex Input hash (64 hex chars)
     * @param outputHashHex Output hash (64 hex chars)
     * @return JSON string with proof data
     */
    @JvmStatic external fun generateStwoProof(
        circuit: String, 
        inputHashHex: String, 
        outputHashHex: String
    ): String
    
    /**
     * Generate an Identity Proof binding DID to wallet ownership.
     * This is the core STWO proof for SignedByMe - generated in Step 3.
     * 
     * Proves (in zero knowledge):
     * 1. User controls the DID (knows private key)
     * 2. User controls the wallet (signed challenge)
     * 3. Binding is fresh (timestamp + expiry)
     * 
     * @param didPubkey The DID public key (hex)
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param walletSignature Signature over a challenge proving wallet ownership
     * @param expiryDays How many days until the proof expires (default: 30)
     * @return JSON string with the identity proof
     */
    @JvmStatic external fun generateIdentityProof(
        didPubkey: String,
        walletAddress: String,
        walletSignature: String,
        expiryDays: Long
    ): String
    
    /**
     * Verify an Identity Proof is valid and not expired.
     * 
     * @param proofJson The proof JSON to verify
     * @return JSON with {valid: boolean, did_pubkey, wallet_address, expires_at, error?}
     */
    @JvmStatic external fun verifyIdentityProof(proofJson: String): String

    // ============================================================================
    // Real STWO (Circle STARK Proofs) - Cryptographically Sound
    // ============================================================================
    
    /**
     * Check if real STWO support is compiled in.
     * When true, generateRealIdentityProof produces actual STARK proofs.
     * When false, falls back to mock proofs (for testing only).
     */
    @JvmStatic external fun hasRealStwo(): Boolean
    
    /**
     * Generate a REAL STWO identity proof v4 with SHA-256 STARK circuit.
     * This creates a cryptographically sound zero-knowledge proof that:
     * 1. Proves knowledge of the binding hash preimage (via SHA-256 STARK)
     * 2. Binds the DID to the wallet address
     * 3. Binds to specific client/session (prevents cross-enterprise replay)
     * 4. Includes the payment hash for the login session
     * 5. Binds the exact amount (prevents payment substitution)
     * 6. Binds the enterprise domain (prevents cross-RP replay)
     * 7. Includes session nonce (prevents replay attacks)
     * 8. Has an expiry timestamp bound into the hash
     * 9. Binds membership root (if applicable)
     * 
     * @param didPubkeyHex The DID public key (hex encoded, 33 bytes compressed)
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param clientId The enterprise client ID (from session)
     * @param sessionId The session ID (from QR/deep link)
     * @param paymentHashHex The Lightning payment hash (32 bytes hex)
     * @param amountSats The payment amount in satoshis
     * @param expiresAt Unix timestamp when the proof expires
     * @param eaDomain Enterprise/RP domain (e.g., "acmecorp.com")
     * @param nonceHex Session nonce (16 bytes hex = 32 chars)
     * @param purposeId Membership purpose: 0=none, 1=allowlist, 2=issuer_batch, 3=revocation
     * @param rootId Membership root ID (empty if no membership required)
     * @return JSON string with the real STWO v4 proof (SHA-256 STARK circuit)
     */
    @JvmStatic external fun generateRealIdentityProofV4(
        didPubkeyHex: String,
        walletAddress: String,
        clientId: String,
        sessionId: String,
        paymentHashHex: String,
        amountSats: Long,
        expiresAt: Long,
        eaDomain: String,
        nonceHex: String,
        purposeId: Long,
        rootId: String
    ): String
    
    /**
     * Generate a REAL STWO identity proof v3 (legacy format).
     * For new code, prefer generateRealIdentityProofV4 which uses SHA-256 STARK circuit.
     * 
     * @param didPubkeyHex The DID public key (hex encoded)
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param paymentHashHex The Lightning payment hash (32 bytes hex)
     * @param amountSats The payment amount in satoshis
     * @param expiresAt Unix timestamp when the proof expires
     * @param eaDomain Enterprise/RP domain (e.g., "acmecorp.com")
     * @param nonceHex Session nonce (16 bytes hex = 32 chars)
     * @return JSON string with the real STWO v3 proof
     */
    @JvmStatic external fun generateRealIdentityProofV3(
        didPubkeyHex: String,
        walletAddress: String,
        paymentHashHex: String,
        amountSats: Long,
        expiresAt: Long,
        eaDomain: String,
        nonceHex: String
    ): String
    
    /**
     * Generate a REAL STWO identity proof (v1 legacy format).
     * Use generateRealIdentityProofV3 for new deployments.
     * 
     * @param didPubkeyHex The DID public key (hex encoded)
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param paymentHashHex The Lightning payment hash (32 bytes hex)
     * @param expiryDays How many days until the proof expires
     * @return JSON string with the real STWO proof
     */
    @JvmStatic external fun generateRealIdentityProof(
        didPubkeyHex: String,
        walletAddress: String,
        paymentHashHex: String,
        expiryDays: Long
    ): String
    
    /**
     * Verify a REAL STWO identity proof (v1, v2, or v3).
     * Automatically detects schema version and verifies appropriately.
     * 
     * @param proofJson The proof JSON to verify
     * @return JSON with {valid: boolean, real_stwo: true, error?}
     */
    @JvmStatic external fun verifyRealIdentityProof(proofJson: String): String

    // ============================================================================
    // DLC (Discreet Log Contracts) - Real Schnorr Oracle
    // ============================================================================
    
    /**
     * Get the oracle's x-only public key (BIP340 format, 32 bytes hex)
     * This is a deterministic key derived from the SignedByMe oracle domain.
     */
    @JvmStatic external fun oraclePubkeyHex(): String
    
    /**
     * Sign an outcome as the oracle using real Schnorr signature (BIP340)
     * This is steps 14-15 in the spec.
     * 
     * @param outcome The outcome string (e.g., "auth_verified", "paid=true", "refund")
     * @return JSON string with {status, outcome, signature_hex, pubkey_hex, timestamp}
     */
    @JvmStatic external fun oracleSignOutcome(outcome: String): String
    
    /**
     * Acknowledge a signing policy for a contract (steps 7-8)
     * The oracle commits to signing a specific outcome for a contract.
     * 
     * @param outcome The outcome to acknowledge (e.g., "auth_verified")
     * @param contractId The DLC contract ID
     * @return JSON string with policy acknowledgment {contract_id, outcome, commitment_hex, ...}
     */
    @JvmStatic external fun oracleAcknowledgePolicy(outcome: String, contractId: String): String
    
    /**
     * Verify an oracle attestation signature
     * Use this to verify that an oracle signature is valid.
     * 
     * @param outcome The outcome that was signed
     * @param signatureHex The Schnorr signature (64 bytes hex)
     * @param pubkeyHex The oracle's x-only public key (32 bytes hex)
     * @return true if signature is valid
     */
    @JvmStatic external fun oracleVerifyAttestation(
        outcome: String,
        signatureHex: String,
        pubkeyHex: String
    ): Boolean
    
    /**
     * Create a DLC contract
     * @param outcome Expected outcome
     * @param payoutsJson JSON string with payout split {"user_pct": 90, "operator_pct": 10}
     * @param oracleJson JSON string with oracle info {"name": "...", "pubkey_hex": "..."}
     * @return JSON string with contract details
     */
    @JvmStatic external fun createDlcContract(
        outcome: String, 
        payoutsJson: String, 
        oracleJson: String
    ): String
    
    /**
     * Sign a DLC outcome (alias for oracleSignOutcome)
     * @param outcome The outcome to sign
     * @return JSON string with signature
     */
    @JvmStatic external fun signDlcOutcome(outcome: String): String

    // ============================================================================
    // Lightning Payments
    // ============================================================================
    
    /**
     * Extract payment hash from a BOLT11 invoice using proper decoding.
     * 
     * SECURITY: This uses actual BOLT11 bech32 decoding, not string hashing.
     * The payment hash is the 'p' tagged field in the invoice data.
     * 
     * @param bolt11 The BOLT11 invoice string (starts with "ln")
     * @return The payment hash as 64-character hex string
     * @throws Exception if invoice cannot be parsed
     */
    @JvmStatic external fun extractPaymentHashFromBolt11(bolt11: String): String
    
    /**
     * Generate a new preimage and payment hash
     * @return JSON string with preimage_hex and payment_hash
     */
    @JvmStatic external fun generatePreimage(): String
    
    /**
     * Verify a payment by checking preimage against payment hash
     * @param paymentHash The expected payment hash (64 hex chars)
     * @param preimageHex The preimage to verify (64 hex chars)
     * @return JSON string with verification result
     */
    @JvmStatic external fun verifyPayment(paymentHash: String, preimageHex: String): String
    
    /**
     * Create a Payment Request Package (PRP) for DLC-tagged payments
     * @param amountSats Amount in satoshis
     * @param description Payment description
     * @param payeeDid DID of the payee
     * @param payeeLnAddress Lightning address of the payee
     * @param expirySecs Expiry time in seconds
     * @return JSON string with PRP data and preimage
     */
    @JvmStatic external fun createPrp(
        amountSats: Long,
        description: String,
        payeeDid: String,
        payeeLnAddress: String,
        expirySecs: Long
    ): String

    // ============================================================================
    // Membership Proofs (Merkle Tree)
    // ============================================================================

    /**
     * Generate a Merkle membership proof.
     * 
     * @param leafSecret 32-byte secret (user's private membership credential)
     * @param merklePath Array of 20 siblings (each 32 bytes, leaf→root order)
     * @param pathIndices 20 bytes: 0=sibling is left, 1=sibling is right
     * @param root 32-byte Merkle root (from server/witness)
     * @param bindingHash 32-byte V4 binding hash (computed via computeBindingHashV4)
     * @param sessionId 32-byte session ID (for nullifier computation)
     * @param purposeId 0=none, 1=allowlist, 2=issuer_batch, 3=revocation
     * @return Membership proof bytes (base64-encode for API submission)
     */
    @JvmStatic external fun proveMembership(
        leafSecret: ByteArray,
        merklePath: Array<ByteArray>,
        pathIndices: ByteArray,
        root: ByteArray,
        bindingHash: ByteArray,
        sessionId: ByteArray,
        purposeId: Int
    ): ByteArray

    /**
     * Verify a membership proof locally.
     * Note: Server is authoritative — this is for optional client-side validation.
     * 
     * @param proof Proof bytes from proveMembership
     * @param root 32-byte Merkle root
     * @param bindingHash 32-byte V4 binding hash
     * @param purposeId Purpose ID (must match proof)
     * @return true if valid
     */
    @JvmStatic external fun verifyMembership(
        proof: ByteArray,
        root: ByteArray,
        bindingHash: ByteArray,
        purposeId: Int
    ): Boolean

    /**
     * Compute V4 binding hash for membership proofs.
     * Must match server's computation exactly.
     * 
     * @param didPubkey DID public key bytes
     * @param walletAddress Wallet address string
     * @param clientId Enterprise client ID (from session)
     * @param sessionId Session ID (from QR/deep link)
     * @param paymentHash 32-byte Lightning payment hash (from invoice)
     * @param amountSats Payment amount in satoshis
     * @param expiresAt Unix timestamp when proof expires
     * @param nonce 16-byte session nonce (from session)
     * @param eaDomain Enterprise domain (from session)
     * @param purposeId Membership purpose ID
     * @param rootId Root ID (from session's required_root_id)
     * @return 32-byte binding hash
     */
    @JvmStatic external fun computeBindingHashV4(
        didPubkey: ByteArray,
        walletAddress: String,
        clientId: String,
        sessionId: String,
        paymentHash: ByteArray,
        amountSats: Long,
        expiresAt: Long,
        nonce: ByteArray,
        eaDomain: String,
        purposeId: Int,
        rootId: String
    ): ByteArray

    /**
     * Compute leaf commitment from leaf secret.
     * Uses: Poseidon(leaf_secret || "sbm:membership:v")
     * Must match sbm-tree and membership verifier exactly.
     * 
     * @param leafSecret 32-byte secret (NEVER log or transmit this)
     * @return 32-byte leaf commitment (safe to share with enterprise for tree building)
     */
    @JvmStatic external fun computeLeafCommitment(leafSecret: ByteArray): ByteArray
}
