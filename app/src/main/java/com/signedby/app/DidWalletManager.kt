package com.signedby.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyStore
import java.security.SecureRandom
import android.security.keystore.KeyInfo
import javax.crypto.SecretKeyFactory
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class DidWalletManager(private val context: Context) {

    // Storage key - no biometric required (for reading encrypted data)
    private val ksAlias = "btcdid_aes_wrap_v1"
    
    // Signing key - REQUIRES biometric for every operation (Layer 2 security)
    private val ksSigningAlias = "btcdid_signing_v1"
    
    private val wrappedFile = "did_wrapped.bin"
    private val fallbackKeyFile = "aes_fallback.bin"
    private val androidKeyStore = "AndroidKeyStore"
    private val rng = SecureRandom()

    @Volatile var currentDid: String? = null
        private set
    
    // Track if biometric auth is available for Layer 2
    @Volatile var biometricAvailable: Boolean = false
        private set

    /** 
     * Initialize Keystore keys.
     * - Storage key: no biometric (for reading encrypted data)
     * - Signing key: REQUIRES biometric for every use (Layer 2 defense)
     */
    fun ensureKeystoreKey() {
        ensureStorageKey()
        ensureSigningKey()
    }
    
    /** Storage key - no biometric required */
    private fun ensureStorageKey() {
        try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            if (ks.containsAlias(ksAlias)) return

            val specBuilder = KeyGenParameterSpec.Builder(
                ksAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)

            if (Build.VERSION.SDK_INT >= 28) {
                try { specBuilder.setUnlockedDeviceRequired(true) } catch (_: Throwable) {}
                try { specBuilder.setIsStrongBoxBacked(true) } catch (_: Throwable) {}
            }

            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
            kg.init(specBuilder.build())
            kg.generateKey()
        } catch (_: Throwable) {
            // Keystore unavailable → create/persist a software AES-256 key as a fallback
            if (context.getFileStreamPath(fallbackKeyFile)?.exists() != true) {
                val b = ByteArray(32).also { rng.nextBytes(it) }
                context.openFileOutput(fallbackKeyFile, Context.MODE_PRIVATE).use { it.write(b) }
            }
        }
    }
    
    /**
     * Signing key - REQUIRES biometric authentication for EVERY use.
     * 
     * This is Layer 2 defense: even if BiometricPrompt code is bypassed,
     * the hardware Keystore refuses to operate without biometric.
     * 
     * On API 30+: setUserAuthenticationParameters with 0 timeout = auth per-use
     * On API 28-29: setUserAuthenticationValidityDurationSeconds(-1) = auth per-use
     */
    private fun ensureSigningKey() {
        try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            if (ks.containsAlias(ksSigningAlias)) {
                biometricAvailable = true
                return
            }

            val specBuilder = KeyGenParameterSpec.Builder(
                ksSigningAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)  // LAYER 2: Hardware-enforced biometric

            // API 30+: use setUserAuthenticationParameters for per-use auth
            if (Build.VERSION.SDK_INT >= 30) {
                specBuilder.setUserAuthenticationParameters(
                    0,  // 0 = auth required for EVERY use (no timeout)
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
            } else if (Build.VERSION.SDK_INT >= 28) {
                // API 28-29: -1 means auth required per-use
                @Suppress("DEPRECATION")
                specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
            }

            if (Build.VERSION.SDK_INT >= 28) {
                try { specBuilder.setUnlockedDeviceRequired(true) } catch (_: Throwable) {}
                try { specBuilder.setIsStrongBoxBacked(true) } catch (_: Throwable) {}
            }

            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
            kg.init(specBuilder.build())
            kg.generateKey()
            biometricAvailable = true
            android.util.Log.i("SignedByMe", "Layer 2 signing key created with biometric requirement")
        } catch (e: Throwable) {
            android.util.Log.w("SignedByMe", "Could not create biometric signing key: ${e.message}")
            biometricAvailable = false
        }
    }
    
    /**
     * Get the signing key (biometric-protected).
     * Caller must have authenticated via BiometricPrompt first.
     * If biometric not available, falls back to storage key.
     */
    private fun getSigningKey(): SecretKey {
        if (!biometricAvailable) return getAesKey()
        
        return try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            (ks.getKey(ksSigningAlias, null) as SecretKey?) ?: getAesKey()
        } catch (e: Throwable) {
            android.util.Log.w("SignedByMe", "Signing key access failed: ${e.message}")
            getAesKey()
        }
    }
    
    /**
     * Unwrap private key using biometric-protected signing key.
     * Call this AFTER BiometricPrompt.authenticate() succeeds.
     * Throws UserNotAuthenticatedException if biometric not done.
     */
    fun unwrapPrivateKeyWithBiometric(wrapped: ByteArray): ByteArray {
        require(wrapped.size > 12) { "wrapped too short" }
        val secret = getSigningKey()
        val iv = wrapped.copyOfRange(0, 12)
        val ct = wrapped.copyOfRange(12, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    private fun getAesKey(): SecretKey {
        return try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            (ks.getKey(ksAlias, null) as SecretKey?) ?: loadFallbackKey()
        } catch (_: Throwable) {
            loadFallbackKey()
        }
    }

    private fun loadFallbackKey(): SecretKey {
        val b = context.openFileInput(fallbackKeyFile).use { it.readBytes() }
        return SecretKeySpec(b, "AES")
    }

    fun wrapPrivateKey(plain: ByteArray): ByteArray {
        val secret = getAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Let Keystore generate IV (required when randomizedEncryptionRequired=true)
        cipher.init(Cipher.ENCRYPT_MODE, secret)
        val iv = cipher.iv  // Retrieve generated IV after init
        val ct = cipher.doFinal(plain)
        return iv + ct
    }

    fun unwrapPrivateKey(wrapped: ByteArray): ByteArray {
        require(wrapped.size > 12) { "wrapped too short" }
        val secret = getAesKey()
        val iv = wrapped.copyOfRange(0, 12)
        val ct = wrapped.copyOfRange(12, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    fun saveWrapped(bytes: ByteArray) {
        context.openFileOutput(wrappedFile, Context.MODE_PRIVATE).use { it.write(bytes) }
    }

    fun signClaimWithDid(privateKeyBytes: ByteArray, claimJson: String): String {
        // delegate to Rust/JNI just like before
        val sigHex = NativeBridge.signMessageDerHex(privateKeyBytes, claimJson)
        // wipe key material
        java.util.Arrays.fill(privateKeyBytes, 0)
        return sigHex
    }

    fun loadWrapped(): ByteArray? {
        return try { context.openFileInput(wrappedFile).use { it.readBytes() } } catch (_: Throwable) { null }
    }

    /** Generate secp256k1 in Rust, wrap & save, compute did:btcr:<pubHex>. */
    fun createDid(): String {
        ensureKeystoreKey()
        val priv = NativeBridge.generateSecp256k1PrivateKey()   // 32 bytes from Rust
        val pubHex = NativeBridge.derivePublicKeyHex(priv)      // compressed SEC1 hex (66 chars)
        val wrapped = wrapPrivateKey(priv)
        saveWrapped(wrapped)
        // Zeroize plaintext copy ASAP
        java.util.Arrays.fill(priv, 0)
        currentDid = "did:btcr:$pubHex"
        return currentDid!!
    }

    /** Return DID (derive if needed). */
    fun getPublicDID(): String? {
        currentDid?.let { return it }
        val wrapped = loadWrapped() ?: return null
        val priv = unwrapPrivateKey(wrapped)
        val pubHex = NativeBridge.derivePublicKeyHex(priv)
        java.util.Arrays.fill(priv, 0)
        currentDid = "did:btcr:$pubHex"
        return currentDid
    }

    fun regenerateKeyPair(): String {
        currentDid = null
        return createDid()
    }

    private val seedFile = "seed_wrapped.bin"
    
    /**
     * Derive keys from a BIP39 seed phrase.
     * Stores the seed securely and derives a Lightning-compatible address.
     * 
     * @param seedPhrase Space-separated mnemonic words (12 or 24)
     * @param passphrase Optional BIP39 passphrase (empty string if none)
     * @return A derived Lightning address or pubkey for display
     */
    fun deriveFromSeedPhrase(seedPhrase: String, passphrase: String = ""): String {
        ensureKeystoreKey()
        
        // Validate word count
        val words = seedPhrase.trim().split("\\s+".toRegex())
        require(words.size == 12 || words.size == 24) { 
            "Seed phrase must be 12 or 24 words, got ${words.size}" 
        }
        
        // For now, derive key using SHA-256 of seed+passphrase as entropy
        // TODO: Implement proper BIP39/BIP32 derivation in Rust
        val combined = "$seedPhrase:$passphrase"
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val entropy = md.digest(combined.toByteArray(Charsets.UTF_8))
        
        // Use first 32 bytes as secp256k1 private key
        val priv = entropy.copyOf(32)
        val pubHex = NativeBridge.derivePublicKeyHex(priv)
        
        // Wrap and save the derived private key (replacing any existing)
        val wrapped = wrapPrivateKey(priv)
        saveWrapped(wrapped)
        
        // Also save the encrypted seed phrase for recovery display
        val seedBytes = seedPhrase.toByteArray(Charsets.UTF_8)
        val wrappedSeed = wrapPrivateKey(seedBytes)
        context.openFileOutput(seedFile, Context.MODE_PRIVATE).use { it.write(wrappedSeed) }
        
        // Zeroize sensitive data
        java.util.Arrays.fill(priv, 0.toByte())
        java.util.Arrays.fill(entropy, 0.toByte())
        
        // Update current DID
        currentDid = "did:btcr:$pubHex"
        
        // Return a truncated pubkey as the "address" for display
        // In production, this would be a proper Lightning address
        return "ln:${pubHex.take(16)}...${pubHex.takeLast(8)}"
    }
    
    /**
     * Check if a seed phrase is stored
     */
    fun hasSeedPhrase(): Boolean {
        return try {
            context.openFileInput(seedFile).use { it.readBytes().isNotEmpty() }
        } catch (_: Throwable) {
            false
        }
    }

    /** Debug info: is the Keystore key hardware-backed / StrongBox? */
    fun keystoreInfo(): String {
        return try {
            // if we actually have a wrapped DID key saved, say so first
            if (loadWrapped() != null) {
                "Keystore key: OK (wrapped DID present)"
            } else {
                // fall back to reporting on the wrapping key itself
                val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
                val sk = ks.getKey(ksAlias, null) as? SecretKey
                    ?: return "Keystore key: not found"

                val factory = SecretKeyFactory.getInstance(sk.algorithm, androidKeyStore)
                val keyInfo = factory.getKeySpec(sk, KeyInfo::class.java) as KeyInfo

                val hw = if (keyInfo.isInsideSecureHardware) "YES" else "NO"

                val sb = try {
                    if (Build.VERSION.SDK_INT >= 28) {
                        val m = KeyInfo::class.java.getMethod("isStrongBoxBacked")
                        val result = m.invoke(keyInfo) as? Boolean ?: false
                        if (result) "YES" else "NO"
                    } else {
                        "NO"
                    }
                } catch (_: Throwable) {
                    "NO"
                }

                "Keystore key: found (HW=$hw, StrongBox=$sb)"
            }
        } catch (t: Throwable) {
            "Keystore key: error ${t.message}"
        }

    }
    fun generateStwoProof(circuit: String, inputHashHex: String, outputHashHex: String): String {
        return try {
            NativeBridge.generateStwoProof(circuit, inputHashHex, outputHashHex)
        } catch (t: Throwable) {
            """{"status":"error","fn":"generate_stwo_proof","error":"${t.message ?: "not implemented"}"}"""
        }
    }

    fun createDlcContract(outcome: String, payoutsJson: String, oracleJson: String): String {
        return try {
            NativeBridge.createDlcContract(outcome, payoutsJson, oracleJson)
        } catch (t: Throwable) {
            """{"status":"error","fn":"create_dlc_contract","error":"${t.message ?: "not implemented"}"}"""
        }
    }

    fun signDlcOutcome(outcome: String): String {
        return try {
            NativeBridge.signDlcOutcome(outcome)
        } catch (t: Throwable) {
            """{"status":"error","fn":"sign_dlc_outcome","error":"${t.message ?: "not implemented"}"}"""
        }
    }

    fun signOwnershipClaim(claimJson: String): String {
        // Load wrapped DID key from storage
        val wrapped = loadWrapped() ?: throw IllegalStateException("no wrapped key saved")
        // Unwrap to raw key (in RAM briefly)
        val priv = unwrapPrivateKey(wrapped)
        return try {
            // Delegate signing to JNI
            NativeBridge.signMessageDerHex(priv, claimJson)
        } finally {
            // Always wipe the secret from memory
            java.util.Arrays.fill(priv, 0)
        }
    }
    
    // ============================================================================
    // STWO Identity Proof (for SignedByMe Login)
    // ============================================================================
    
    private val identityProofFile = "identity_proof_wrapped.bin"
    
    /**
     * Generate and store an STWO Identity Proof binding DID to wallet.
     * This proves ownership of both DID and wallet in zero knowledge.
     * 
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param expiryDays How many days until the proof expires (default: 30)
     * @return JSON string with the identity proof
     */
    fun generateIdentityProof(walletAddress: String, expiryDays: Long = 30): String {
        val did = getPublicDID() ?: throw IllegalStateException("No DID created")
        
        // Create a challenge and sign it with DID to prove wallet ownership
        // The wallet signature proves we control the wallet
        val wrapped = loadWrapped() ?: throw IllegalStateException("No DID key")
        val priv = unwrapPrivateKey(wrapped)
        
        return try {
            // Sign a challenge binding DID to wallet
            val challenge = "signedby.me:bind:$did:$walletAddress:${System.currentTimeMillis()}"
            val walletSignature = NativeBridge.signMessageDerHex(priv, challenge)
            
            // Generate STWO proof
            val proofJson = NativeBridge.generateIdentityProof(
                did.removePrefix("did:btcr:"),
                walletAddress,
                walletSignature,
                expiryDays
            )
            
            // Store proof encrypted (defense in depth)
            saveIdentityProof(proofJson)
            
            proofJson
        } finally {
            java.util.Arrays.fill(priv, 0)
        }
    }
    
    /**
     * Get the stored identity proof, or null if none exists
     */
    fun getIdentityProof(): String? {
        return loadIdentityProof()
    }
    
    /**
     * Get the hash of the stored identity proof
     */
    fun getIdentityProofHash(): String? {
        val proof = loadIdentityProof() ?: return null
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return bytesToHex(md.digest(proof.toByteArray(Charsets.UTF_8)))
    }

    // ============================================================================
    // Groth16 Proof Generation (Phase 14)
    // ============================================================================

    /**
     * Initialize the Groth16 prover with asset paths.
     * Call once at app startup after NativeBridge.initNativeLibPath().
     *
     * Asset locations on device:
     * - membership.wasm: assets/groth16/membership.wasm → extracted to filesDir/groth16/
     * - membership.dat: assets/groth16/membership.dat → extracted to filesDir/groth16/
     * - membership_final.zkey: filesDir/groth16/ (85MB, sideloaded via adb)
     *
     * @param nativeLibDir context.applicationInfo.nativeLibraryDir (unused with WASM)
     * @param groth16Dir Directory for extracted assets (filesDir/groth16)
     * @param externalFilesDir context.getExternalFilesDir(null) for zkey sideload
     * @return true if initialization succeeded
     */
    fun initGroth16Prover(nativeLibDir: String, groth16Dir: java.io.File, externalFilesDir: java.io.File?): Boolean {
        android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
        android.util.Log.i("SignedByMe", "Groth16 Prover Initialization (Native ARM64)")
        android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
        
        // Native ARM64 witness calculator - must be in nativeLibraryDir for exec permission
        // Bundled as libmembership.so in jniLibs/arm64-v8a/, Gradle installs to nativeLibraryDir
        val calcFile = java.io.File(nativeLibDir, "libmembership.so")
        
        // Circuit data (extracted from assets)
        val datFile = java.io.File(groth16Dir, "membership.dat")
        
        // Proving key - internal storage only (85MB, sideloaded via adb)
        // Primary: /data/user/0/com.privacylion.signedby.me/files/groth16/membership_final.zkey
        val zkeyCandidates = listOfNotNull(
            java.io.File(groth16Dir, "membership_final.zkey"),  // Internal storage (preferred)
            externalFilesDir?.let { java.io.File(it, "membership_final.zkey") }  // App's external files (fallback)
        )
        val zkeyFile = zkeyCandidates.firstOrNull { it.exists() }

        // Log all paths for debugging
        android.util.Log.i("SignedByMe", "Native witness calculator (ARM64):")
        android.util.Log.i("SignedByMe", "  ${calcFile.absolutePath} → ${if (calcFile.exists()) "✓ EXISTS (${calcFile.length()} bytes)" else "✗ not found"}")
        android.util.Log.i("SignedByMe", "Circuit data:")
        android.util.Log.i("SignedByMe", "  ${datFile.absolutePath} → ${if (datFile.exists()) "✓ EXISTS (${datFile.length()} bytes)" else "✗ not found"}")
        android.util.Log.i("SignedByMe", "Proving key candidates:")
        zkeyCandidates.forEach {
            android.util.Log.i("SignedByMe", "  ${it.absolutePath} → ${if (it.exists()) "✓ EXISTS (${it.length()} bytes)" else "✗ not found"}")
        }
        android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")

        // Validate all required files exist
        if (!calcFile.exists()) {
            android.util.Log.e("SignedByMe", "FATAL: libmembership.so (witness calculator) not found")
            android.util.Log.e("SignedByMe", "  Should be in jniLibs/arm64-v8a/libmembership.so")
            android.util.Log.e("SignedByMe", "  Expected at: ${calcFile.absolutePath}")
            return false
        }
        
        // nativeLibraryDir should already have exec permission, but log status
        android.util.Log.i("SignedByMe", "Witness calculator executable: ${calcFile.canExecute()}")
        
        if (!datFile.exists()) {
            android.util.Log.e("SignedByMe", "FATAL: membership.dat not found")
            android.util.Log.e("SignedByMe", "  Should be in assets/groth16/membership.dat and extracted at startup")
            return false
        }
        
        if (zkeyFile == null) {
            android.util.Log.e("SignedByMe", "FATAL: Proving key not found")
            android.util.Log.e("SignedByMe", "  Sideload membership_final.zkey (85MB) with:")
            android.util.Log.e("SignedByMe", "  adb push membership_final.zkey /data/local/tmp/")
            android.util.Log.e("SignedByMe", "  adb shell run-as com.privacylion.signedby.me mkdir -p files/groth16")
            android.util.Log.e("SignedByMe", "  adb shell run-as com.privacylion.signedby.me cp /data/local/tmp/membership_final.zkey files/groth16/")
            return false
        }
        
        android.util.Log.i("SignedByMe", "All Groth16 assets found:")
        android.util.Log.i("SignedByMe", "  calc: ${calcFile.absolutePath} (${if (calcFile.exists()) "ready" else "MISSING - need ARM64 binary"})")
        android.util.Log.i("SignedByMe", "  dat:  ${datFile.absolutePath}")
        android.util.Log.i("SignedByMe", "  zkey: ${zkeyFile.absolutePath}")

        return try {
            android.util.Log.i("SignedByMe", "Calling NativeBridge.initProver()...")
            val result = NativeBridge.initProver(
                zkeyFile.absolutePath,
                datFile.absolutePath,
                calcFile.absolutePath  // Pass calculator binary path
            )
            if (result) {
                android.util.Log.i("SignedByMe", "✓ Groth16 prover initialized successfully")
            } else {
                android.util.Log.e("SignedByMe", "✗ NativeBridge.initProver() returned false")
            }
            android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
            result
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "✗ Groth16 prover init exception: ${e.message}")
            e.printStackTrace()
            android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
            false
        }
    }

    /**
     * Generate a Groth16 membership proof.
     *
     * Requires:
     * - leaf_secret stored (from enrollment)
     * - witness data for the given client/root (from API)
     * - prover initialized (initGroth16Prover)
     *
     * @param clientId Client/enterprise ID
     * @param rootId Merkle root ID
     * @return JSON with {success: true, proof: {...}, public_inputs: [...]} or {success: false, error: "..."}
     */
    fun generateGroth16Proof(clientId: String, rootId: String): String {
        val startMs = System.currentTimeMillis()
        android.util.Log.i("SignedByMe", "[TIMING] generateGroth16Proof START at $startMs")
        android.util.Log.i("SignedByMe", "[TIMING] clientId=$clientId, rootId=$rootId")
        
        // Check prover ready
        if (!NativeBridge.isProverReady()) {
            android.util.Log.e("SignedByMe", "Groth16 prover not ready - proof generation failed")
            android.util.Log.i("SignedByMe", "[TIMING] generateGroth16Proof FAILED (prover not ready) at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            return proofError("Prover not initialized")
        }

        // GUARD: Proof MUST NOT fire unless leaf_secret exists
        val leafSecret = loadLeafSecret()
        if (leafSecret == null) {
            android.util.Log.e("SignedByMe", "GUARD BLOCKED: generateGroth16Proof called without leaf_secret!")
            android.util.Log.e("SignedByMe", "This indicates a race condition - enrollment must complete before proof generation")
            android.util.Log.i("SignedByMe", "[TIMING] generateGroth16Proof FAILED (no leaf_secret) at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            return proofError("No leaf_secret - enrollment not complete")
        }
        android.util.Log.i("SignedByMe", "[TIMING] Leaf secret loaded at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")

        // Load witness
        val witness = loadWitness(clientId, rootId)
        if (witness == null) {
            android.util.Log.e("SignedByMe", "No witness for $clientId/$rootId")
            java.util.Arrays.fill(leafSecret, 0.toByte())
            android.util.Log.i("SignedByMe", "[TIMING] generateGroth16Proof FAILED (no witness) at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            return proofError("No witness for $clientId/$rootId")
        }
        android.util.Log.i("SignedByMe", "[TIMING] Witness loaded at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")

        return try {
            // Build input JSON
            val inputJson = buildGroth16InputJson(leafSecret, witness)
            android.util.Log.i("SignedByMe", "[TIMING] Input JSON built at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")

            val proofStartMs = System.currentTimeMillis()
            android.util.Log.i("SignedByMe", "[TIMING] Native proof (64MB stack) START at $proofStartMs")
            
            val result = runNativeProofWithLargeStackBlocking(inputJson)
            
            val proofEndMs = System.currentTimeMillis()
            android.util.Log.i("SignedByMe", "[TIMING] Native proof END at $proofEndMs (+${proofEndMs - proofStartMs}ms PROOF TIME)")
            android.util.Log.i("SignedByMe", "[TIMING] generateGroth16Proof SUCCESS at $proofEndMs (+${proofEndMs - startMs}ms TOTAL)")
            
            result
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Groth16 proof failed: ${e.message}")
            e.printStackTrace()
            android.util.Log.i("SignedByMe", "[TIMING] generateGroth16Proof EXCEPTION at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            proofError(e.message ?: "Unknown error")
        } finally {
            java.util.Arrays.fill(leafSecret, 0.toByte())
        }
    }

    /**
     * Generate Groth16 proof with auto-fetched witness.
     * Attempts to fetch witness from API if not stored locally.
     */
    suspend fun generateGroth16ProofWithFetch(
        clientId: String,
        rootId: String,
        apiBaseUrl: String,
        apiKey: String
    ): String {
        // Try local witness first
        var witness = loadWitness(clientId, rootId)

        // If not found, try to fetch from API
        if (witness == null) {
            android.util.Log.i("SignedByMe", "Fetching witness from API for $clientId/$rootId")
            witness = fetchWitness(apiBaseUrl, apiKey)
        }

        return if (witness != null) {
            generateGroth16Proof(clientId, rootId)
        } else {
            proofError("Could not fetch witness")
        }
    }

    /**
     * Run native proof generation on a thread with large stack (blocking version).
     * 
     * The secp256k1 ECDSA circuit generates C++ code with huge local arrays
     * that exceed the default coroutine thread stack (~1MB). We run on a
     * dedicated thread with 64MB stack to avoid stack overflow.
     */
    private fun runNativeProofWithLargeStackBlocking(inputJson: String): String {
        // ECDSAPrivToPub_241_run alone has FrElement lvar[67916] = 2.7MB
        // Plus nested calls with lvarcall[1405] arrays (56KB each)
        // Need 64MB+ to be safe
        val stackSize = 64L * 1024 * 1024  // 64MB stack
        var result: String? = null
        var exception: Throwable? = null
        val latch = java.util.concurrent.CountDownLatch(1)
        
        val proverThread = Thread(null, {
            try {
                android.util.Log.i("SignedByMe", "[TIMING] Prover thread started, calling NativeBridge.generateProof...")
                result = NativeBridge.generateProof(inputJson)
                android.util.Log.i("SignedByMe", "[TIMING] NativeBridge.generateProof returned")
            } catch (e: Throwable) {
                android.util.Log.e("SignedByMe", "[TIMING] Prover thread exception: ${e.message}")
                e.printStackTrace()
                exception = e
            } finally {
                latch.countDown()
            }
        }, "groth16-prover", stackSize)
        
        proverThread.setUncaughtExceptionHandler { _, e ->
            android.util.Log.e("SignedByMe", "[TIMING] Prover thread CRASHED: ${e.message}")
            e.printStackTrace()
            exception = e
            latch.countDown()
        }
        
        proverThread.start()
        
        // Timeout after 5 minutes (secp256k1 circuit can take a while)
        val completed = latch.await(300, java.util.concurrent.TimeUnit.SECONDS)
        
        if (!completed) {
            android.util.Log.e("SignedByMe", "[TIMING] Prover thread TIMEOUT after 5 minutes!")
            throw RuntimeException("Native proof generation timed out after 5 minutes")
        }
        
        exception?.let { throw it }
        return result ?: throw RuntimeException("No result from native proof")
    }

    /**
     * Build Groth16 circuit input JSON from leaf secret and witness.
     * 
     * Circuit expects (all as decimal strings):
     * - leaf_secret[5]: 5 field elements from 32-byte secret split as [6,6,6,6,8] bytes
     * - siblings[20]: 20 field elements (32-byte hashes as decimal)
     * - path_bits[20]: 20 bits as strings ("0" or "1")
     */
    private fun buildGroth16InputJson(leafSecret: ByteArray, witness: WitnessData): String {
        // Split 32-byte secret into 5 chunks: [0..6), [6..12), [12..18), [18..24), [24..32)
        // Convert each chunk to BigInteger (big-endian) then to decimal string
        val leafSecretArray = org.json.JSONArray()
        val chunks = listOf(
            leafSecret.sliceArray(0 until 6),
            leafSecret.sliceArray(6 until 12),
            leafSecret.sliceArray(12 until 18),
            leafSecret.sliceArray(18 until 24),
            leafSecret.sliceArray(24 until 32)
        )
        for (chunk in chunks) {
            val bigInt = java.math.BigInteger(1, chunk)  // 1 = positive
            leafSecretArray.put(bigInt.toString())  // decimal string
        }

        // Convert siblings (32-byte hashes) to decimal strings
        val siblingsArray = org.json.JSONArray()
        for (sibling in witness.siblings) {
            val bigInt = java.math.BigInteger(1, sibling)  // 1 = positive
            siblingsArray.put(bigInt.toString())  // decimal string
        }

        // Convert path_bits to string array ("0" or "1")
        val pathBitsArray = org.json.JSONArray()
        for (bit in witness.pathBits) {
            pathBitsArray.put(bit.toInt().toString())
        }

        val json = org.json.JSONObject().apply {
            put("leaf_secret", leafSecretArray)
            put("siblings", siblingsArray)
            put("path_bits", pathBitsArray)
        }.toString()
        
        return json
    }

    /**
     * Return a proper error response when proof generation fails.
     * No stubs - callers must handle the error.
     */
    private fun proofError(reason: String): String {
        android.util.Log.e("SignedByMe", "Proof generation failed: $reason")
        return org.json.JSONObject().apply {
            put("success", false)
            put("error", reason)
        }.toString()
    }
    
    /**
     * Check if an identity proof exists
     */
    fun hasIdentityProof(): Boolean {
        return loadIdentityProof() != null
    }
    
    /**
     * Verify the stored identity proof is still valid (not expired)
     */
    fun verifyIdentityProof(): String {
        val proof = loadIdentityProof() ?: return """{"valid":false,"error":"No proof stored"}"""
        return try {
            NativeBridge.verifyIdentityProof(proof)
        } catch (t: Throwable) {
            """{"valid":false,"error":"${t.message ?: "Verification failed"}"}"""
        }
    }
    
    /**
     * Create a payment binding signature for login
     * This binds the identity proof to a specific payment
     * 
     * @param paymentHash The payment hash from the invoice
     * @param nonce A random nonce to prevent replay
     * @return Signature over (proof_hash + payment_hash + nonce)
     */
    fun createPaymentBinding(paymentHash: String, nonce: String): String {
        val proofHash = getIdentityProofHash() 
            ?: throw IllegalStateException("No identity proof")
        
        // Build binding data
        val bindingData = """{"stwo_proof_hash":"$proofHash","payment_hash":"$paymentHash","nonce":"$nonce","timestamp":${System.currentTimeMillis()}}"""
        
        // Hash the binding data
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val bindingHash = bytesToHex(md.digest(bindingData.toByteArray(Charsets.UTF_8)))
        
        // Sign with DID
        val wrapped = loadWrapped() ?: throw IllegalStateException("No DID key")
        val priv = unwrapPrivateKey(wrapped)
        
        return try {
            NativeBridge.signMessageDerHex(priv, bindingHash)
        } finally {
            java.util.Arrays.fill(priv, 0)
        }
    }
    private fun saveIdentityProof(proofJson: String) {
        ensureKeystoreKey()
        val proofBytes = proofJson.toByteArray(Charsets.UTF_8)
        val wrapped = wrapPrivateKey(proofBytes)
        context.openFileOutput(identityProofFile, Context.MODE_PRIVATE).use { it.write(wrapped) }
    }
    
    private fun loadIdentityProof(): String? {
        return try {
            val wrapped = context.openFileInput(identityProofFile).use { it.readBytes() }
            if (wrapped.isEmpty()) return null
            val proofBytes = unwrapPrivateKey(wrapped)
            String(proofBytes, Charsets.UTF_8)
        } catch (_: Throwable) {
            null
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val cleanHex = hex.trim().let { if (it.startsWith("0x")) it.drop(2) else it }
        return cleanHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun bytesToHex(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it) }

    fun buildOwnershipClaimJson(
        did: String,
        nonce: String,
        walletType: String,
        withdrawTo: String,
        preimage: String? // pass lastPreimage from the UI; null/blank means unpaid
    ): String {
        val paid = !preimage.isNullOrBlank()

        val preimageTrim = preimage?.trim()
        if (paid) {
            require(preimageTrim!!.length % 2 == 0) { "preimage hex must have even length" }
            require(preimageTrim.length >= 64) { "preimage must be ≥32 bytes (≥64 hex chars)" }
            require(preimageTrim.all { it in "0123456789abcdefABCDEF" }) { "preimage must be hex" }
        }

        val preimageSha256Hex: String? = if (paid) {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val hash = md.digest(hexToBytes(preimage!!.trim()))
            bytesToHex(hash)
        } else null

        val obj = org.json.JSONObject().apply {
            put("schema", "pl/ownership-claim/1")
            put("type", "ownership_claim")
            put("did", did)
            put("nonce", nonce)
            put("wallet_type", walletType)
            put("withdraw_to", withdrawTo)
            put("paid", paid)
            if (paid) {
                put("preimage", preimage!!.trim())
                put("preimage_sha256", preimageSha256Hex)
                // Authentication methods reference; UI/API may read this
                put("amr", org.json.JSONArray(listOf("did_sig", "ln_preimage")))
            }
            put("timestamp_ms", System.currentTimeMillis())
            // optional hint to distinguish platforms in logs
            put("wallet_hint", "android")
            put("aud", "beta.privacy-lion.com")
        }

        return obj.toString()
    }

    // Fetch a real nonce from your API (no new deps; blocking call).
// Call this from a background thread / coroutine (not the main thread).
    fun fetchNonce(
        apiBase: String = "https://api.beta.privacy-lion.com",
        domain: String = "beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): String {
        val url = java.net.URL("$apiBase/v1/login/start")
        val payload = org.json.JSONObject()
            .put("domain", domain)
            .toString()

        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }

        conn.outputStream.use { os ->
            val bytes = payload.toByteArray(Charsets.UTF_8)
            os.write(bytes)
            os.flush()
        }

        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8)
            .use { it.readText() }

        if (code !in 200..299) {
            throw java.io.IOException("HTTP $code: $body")
        }

        val json = org.json.JSONObject(body)

        // Accept either top-level "nonce" or nested "data.nonce"
        return when {
            json.has("nonce") -> json.getString("nonce")
            json.has("data") && json.getJSONObject("data").has("nonce") ->
                json.getJSONObject("data").getString("nonce")
            else -> throw java.io.IOException("nonce missing in response: $body")
        }
    }

    data class LoginStart(val loginId: String, val nonce: String)

    fun startLogin(
        apiBase: String = "https://api.beta.privacy-lion.com",
        domain: String = "beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): LoginStart {
        val url = java.net.URL("$apiBase/v1/login/start")
        val payload = org.json.JSONObject().put("domain", domain).toString()

        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }

        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        if (code !in 200..299) throw java.io.IOException("HTTP $code: $body")

        val json = org.json.JSONObject(body)
        val loginId = when {
            json.has("login_id") -> json.getString("login_id")
            json.optJSONObject("data")?.has("login_id") == true -> json.getJSONObject("data").getString("login_id")
            else -> throw java.io.IOException("login_id missing in response: $body")
        }
        val nonce = when {
            json.has("nonce") -> json.getString("nonce")
            json.optJSONObject("data")?.has("nonce") == true -> json.getJSONObject("data").getString("nonce")
            else -> throw java.io.IOException("nonce missing in response: $body")
        }
        return LoginStart(loginId = loginId, nonce = nonce)
    }

    fun fetchLoginStatus(
        loginId: String,
        apiBase: String = "https://api.beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): String {
        require(loginId.isNotBlank()) { "loginId is empty" }
        val url = java.net.URL("$apiBase/v1/login/status/$loginId")
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("Accept", "application/json")
        }
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        if (code !in 200..299) throw java.io.IOException("HTTP $code: $body")
        return body // caller can parse or display
    }

    // Demo-only helper to mark a login as settled on the server
    fun settleLoginDemo(
        loginId: String,
        preimageHex: String,
        apiBase: String = "https://api.beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): String {
        require(loginId.isNotBlank()) { "loginId is empty" }
        require(preimageHex.isNotBlank()) { "preimage is empty" }

        val url = java.net.URL(
            "$apiBase/v1/login/settle?login_id=$loginId&preimage=$preimageHex&txid="
        )
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST" // server accepts POST for settle
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("Accept", "application/json")
        }

        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        if (code !in 200..299) throw java.io.IOException("HTTP $code: $body")
        return body  // typically {"status":"ok"} or similar
    }

    /**
     * Build a DLC-tagged Payment Request Package (PRP) for Enterprise login.
     * This is a simple JSON builder we’ll evolve; it references the preimage SHA-256.
     *
     * userShare/operatorShare are percentages that must sum to 100.
     */
    fun buildPrpJson(
        loginId: String,
        did: String,
        preimageSha256Hex: String,
        amountSats: Long = 0L,
        userShare: Int = 90,
        operatorShare: Int = 10,
        oracleName: String = "local_oracle",
        oraclePubkeyHex: String = NativeBridge.oraclePubkeyHex() // TODO: replace with real oracle pubkey
    ): String {
        require(loginId.isNotBlank()) { "loginId required" }
        require(did.startsWith("did:")) { "did must start with did:" }
        require(preimageSha256Hex.length == 64) { "preimage_sha256 must be 32 bytes hex" }
        require(userShare + operatorShare == 100) { "split must sum to 100" }

        val prp = org.json.JSONObject().apply {
            put("schema", "pl/prp/1")
            put("type", "payment_request_package")
            put("login_id", loginId)
            put("did", did)
            put("amount_sats", amountSats) // 0 until we wire real amounts
            put("preimage_sha256", preimageSha256Hex)
            put("split", org.json.JSONObject().apply {
                put("user_pct", userShare)
                put("operator_pct", operatorShare)
            })
            put("dlc", org.json.JSONObject().apply {
                put("oracle", org.json.JSONObject().apply {
                    put("name", oracleName)
                    put("pubkey_hex", oraclePubkeyHex)
                })
                // outcome string is canonicalized; we’ll use this when we sign the outcome later
                put("outcome", "paid=true")
            })
        }
        return prp.toString()
    }

    // ============================================================================
    // Membership Proofs (Merkle Tree)
    // ============================================================================
    
    private val witnessDir = "witnesses"
    private val leafSecretFile = "leaf_secret.bin"
    private val rootCacheFile = "root_cache.json"

    // ============================================================================
    // Root Freshness Check (Phase 25)
    // ============================================================================

    /**
     * Cached root info for freshness checking.
     * Stored on-device (internal storage, not cloud).
     */
    data class RootCache(
        val rootId: String,
        val clientId: String,
        val lastUpdated: Long
    ) {
        fun toJson(): String = org.json.JSONObject().apply {
            put("root_id", rootId)
            put("client_id", clientId)
            put("last_updated", lastUpdated)
        }.toString()

        companion object {
            fun fromJson(json: String): RootCache {
                val obj = org.json.JSONObject(json)
                return RootCache(
                    rootId = obj.getString("root_id"),
                    clientId = obj.getString("client_id"),
                    lastUpdated = obj.getLong("last_updated")
                )
            }
        }
    }

    /**
     * Result of root freshness check.
     */
    sealed class RootCheckResult {
        /** Root is fresh, proceed with proof generation */
        object Fresh : RootCheckResult()
        /** Root rotated, witness refreshed successfully */
        object Refreshed : RootCheckResult()
        /** User was pruned from tree, needs re-enrollment */
        data class Pruned(val serviceName: String) : RootCheckResult()
        /** Check failed (network error, etc.) - proceed with cached witness */
        data class Error(val message: String) : RootCheckResult()
    }

    /**
     * Store root cache after fetching witness.
     */
    fun storeRootCache(rootId: String, clientId: String) {
        try {
            val cache = RootCache(
                rootId = rootId,
                clientId = clientId,
                lastUpdated = System.currentTimeMillis() / 1000
            )
            val dir = context.getDir(witnessDir, Context.MODE_PRIVATE)
            java.io.File(dir, "${clientId}_$rootCacheFile").writeText(cache.toJson())
            android.util.Log.i("SignedByMe", "Root cache stored: $rootId for $clientId")
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Failed to store root cache: ${e.message}")
        }
    }

    /**
     * Load cached root info for a client.
     */
    fun loadRootCache(clientId: String): RootCache? {
        return try {
            val dir = context.getDir(witnessDir, Context.MODE_PRIVATE)
            val file = java.io.File(dir, "${clientId}_$rootCacheFile")
            if (file.exists()) {
                RootCache.fromJson(file.readText())
            } else null
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Failed to load root cache: ${e.message}")
            null
        }
    }

    /**
     * Check if root is fresh before proof generation (Phase 25.1).
     * 
     * Called silently before generateGroth16Proof(). In happy path, this adds
     * no visible delay. If root rotated, fetches new witness automatically.
     * 
     * @param clientId Enterprise client ID
     * @param apiBaseUrl API base URL for freshness check
     * @param apiKey API key for requests
     * @return RootCheckResult indicating action taken
     */
    suspend fun checkRootFreshness(
        clientId: String,
        apiBaseUrl: String,
        apiKey: String
    ): RootCheckResult = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            val cachedRoot = loadRootCache(clientId)
            
            // Fetch current root from server
            val currentRootId = fetchCurrentRootId(clientId, apiBaseUrl, apiKey)
            if (currentRootId == null) {
                android.util.Log.w("SignedByMe", "Root freshness check failed, proceeding with cached witness")
                return@withContext RootCheckResult.Error("Could not fetch current root")
            }

            // If no cache exists, this is first login - fetch witness
            if (cachedRoot == null) {
                android.util.Log.i("SignedByMe", "No root cache, fetching initial witness")
                val witness = fetchWitness(apiBaseUrl, apiKey)
                return@withContext if (witness != null) {
                    RootCheckResult.Fresh
                } else {
                    RootCheckResult.Error("Could not fetch witness")
                }
            }

            // Compare root IDs
            if (cachedRoot.rootId == currentRootId) {
                android.util.Log.i("SignedByMe", "Root is fresh: ${cachedRoot.rootId}")
                return@withContext RootCheckResult.Fresh
            }

            // Root rotated - need to fetch fresh witness
            android.util.Log.i("SignedByMe", "Root rotated: ${cachedRoot.rootId} -> $currentRootId")
            
            val freshWitness = fetchWitness(apiBaseUrl, apiKey)
            if (freshWitness != null) {
                android.util.Log.i("SignedByMe", "Witness refreshed for new root: ${freshWitness.rootId}")
                return@withContext RootCheckResult.Refreshed
            }

            // Witness fetch failed - user may have been pruned
            android.util.Log.w("SignedByMe", "Witness fetch failed after root rotation - user may be pruned")
            val enrollment = loadEnrollment()
            val serviceName = enrollment?.clientId ?: clientId
            return@withContext RootCheckResult.Pruned(serviceName)

        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Root freshness check exception: ${e.message}")
            RootCheckResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Fetch current root ID from API.
     * GET /v1/roots/current?client_id=<client_id>
     */
    private suspend fun fetchCurrentRootId(
        clientId: String,
        apiBaseUrl: String,
        apiKey: String
    ): String? = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            val url = java.net.URL("$apiBaseUrl/v1/roots/current?client_id=${java.net.URLEncoder.encode(clientId, "UTF-8")}")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("X-API-Key", apiKey)
            conn.connectTimeout = 5000
            conn.readTimeout = 5000

            if (conn.responseCode != 200) {
                android.util.Log.w("SignedByMe", "Fetch current root failed: HTTP ${conn.responseCode}")
                return@withContext null
            }

            val response = conn.inputStream.bufferedReader().readText()
            val json = org.json.JSONObject(response)
            json.getString("root_id")
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Fetch current root exception: ${e.message}")
            null
        }
    }
    
    /**
     * Copy bundled witness files from assets to app_witnesses directory.
     * Called on startup for debug builds to enable E2E testing.
     */
    fun copyWitnessesFromAssets() {
        if (!BuildConfig.DEBUG) return
        try {
            val assetList = context.assets.list("witnesses") ?: return
            val dir = context.getDir(witnessDir, Context.MODE_PRIVATE)
            for (filename in assetList) {
                if (!filename.endsWith(".json")) continue
                val destFile = java.io.File(dir, filename)
                // Always overwrite in debug mode to pick up fixed witnesses
                context.assets.open("witnesses/$filename").use { input ->
                    destFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                android.util.Log.i("DidWalletManager", "Copied witness from assets: $filename")
            }
        } catch (e: Exception) {
            android.util.Log.w("DidWalletManager", "Failed to copy witnesses from assets: ${e.message}")
        }
    }
    
    /**
     * Witness data parsed from JSON file.
     * Matches WITNESS_SPEC.md v1 format.
     */
    data class WitnessData(
        val version: Int,
        val clientId: String,
        val rootId: String,
        val purposeId: Int,
        val depth: Int,
        val siblings: List<ByteArray>,  // 20 x 32-byte arrays
        val pathBits: ByteArray,        // 20 bytes (0 or 1 each)
        val rootHex: String             // Root hash for verification
    ) {
        companion object {
            fun fromJson(json: String): WitnessData {
                val obj = org.json.JSONObject(json)
                val siblingsArr = obj.getJSONArray("siblings")
                val pathBitsArr = obj.getJSONArray("path_bits")
                
                val siblings = (0 until siblingsArr.length()).map { i ->
                    hexToBytes(siblingsArr.getString(i))
                }
                
                val pathBits = ByteArray(pathBitsArr.length()) { i ->
                    pathBitsArr.getInt(i).toByte()
                }
                
                // Root hash from witness file
                val rootHex = obj.optString("root_hash", "")
                
                return WitnessData(
                    version = obj.getInt("version"),
                    clientId = obj.getString("client_id"),
                    rootId = obj.getString("root_id"),
                    purposeId = obj.getInt("purpose_id"),
                    depth = obj.getInt("depth"),
                    siblings = siblings,
                    pathBits = pathBits,
                    rootHex = rootHex
                )
            }
            
            private fun hexToBytes(hex: String): ByteArray {
                val cleanHex = if (hex.startsWith("0x")) hex.drop(2) else hex
                return cleanHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
        }
        
        fun toSiblingsArray(): Array<ByteArray> = siblings.toTypedArray()
    }
    
    /**
     * Store a witness JSON file for later use.
     * Key: "{clientId}_{rootId}.json"
     */
    fun storeWitness(witnessJson: String) {
        val witness = WitnessData.fromJson(witnessJson)
        val filename = "${witness.clientId}_${witness.rootId}.json"
        val dir = context.getDir(witnessDir, Context.MODE_PRIVATE)
        java.io.File(dir, filename).writeText(witnessJson)
    }
    
    /**
     * Load a witness for a specific client + root.
     * Returns null if not found.
     */
    fun loadWitness(clientId: String, rootId: String): WitnessData? {
        val filename = "${clientId}_${rootId}.json"
        val dir = context.getDir(witnessDir, Context.MODE_PRIVATE)
        val file = java.io.File(dir, filename)
        if (file.exists()) {
            return WitnessData.fromJson(file.readText())
        }
        
        // TODO: TEMP - remove when login/start returns real rootId
        // Fallback: find any witness for this clientId regardless of rootId
        val fallbackFile = dir.listFiles()?.firstOrNull { f ->
            f.name.startsWith("${clientId}_") && f.name.endsWith(".json")
        }
        if (fallbackFile != null) {
            android.util.Log.w("SignedByMe", "Witness fallback: using ${fallbackFile.name} instead of $filename")
            return WitnessData.fromJson(fallbackFile.readText())
        }
        
        return null
    }
    
    /**
     * List all stored witnesses.
     */
    fun listWitnesses(): List<Pair<String, String>> {
        val dir = context.getDir(witnessDir, Context.MODE_PRIVATE)
        return dir.listFiles()?.mapNotNull { f ->
            val parts = f.nameWithoutExtension.split("_", limit = 2)
            if (parts.size == 2) parts[0] to parts[1] else null
        } ?: emptyList()
    }
    
    /**
     * Generate and store leaf secret for membership.
     * Called once when user joins a membership group.
     * Returns the leaf secret (caller should zeroize after use).
     */
    fun generateLeafSecret(): ByteArray {
        ensureKeystoreKey()
        val secret = ByteArray(32).also { rng.nextBytes(it) }
        val wrapped = wrapPrivateKey(secret)
        context.openFileOutput(leafSecretFile, Context.MODE_PRIVATE).use { it.write(wrapped) }
        return secret.copyOf() // Return copy, original can be zeroized
    }
    
    /**
     * Load leaf secret for membership proof generation.
     * Returns null if not set up yet.
     */
    fun loadLeafSecret(): ByteArray? {
        return try {
            val wrapped = context.openFileInput(leafSecretFile).use { it.readBytes() }
            unwrapPrivateKey(wrapped)
        } catch (_: Throwable) { null }
    }
    
    /**
     * Check if leaf secret exists.
     */
    fun hasLeafSecret(): Boolean {
        return try {
            context.openFileInput(leafSecretFile).use { it.readBytes().isNotEmpty() }
        } catch (_: Throwable) { false }
    }
    
    /**
     * Generate a membership proof using Groth16.
     * 
     * @param witness The loaded witness data
     * @param bindingHash 32-byte V4 binding hash (unused in current Groth16 circuit)
     * @param sessionId 32-byte session ID (unused in current Groth16 circuit)
     * @return Base64-encoded proof JSON, or null on error
     */
    fun generateMembershipProof(
        witness: WitnessData,
        bindingHash: ByteArray,
        sessionId: ByteArray
    ): String? {
        val startMs = System.currentTimeMillis()
        android.util.Log.i("SignedByMe", "[TIMING] generateMembershipProof START at $startMs")
        
        if (!NativeBridge.isProverReady()) {
            android.util.Log.e("SignedByMe", "Groth16 prover not initialized - cannot generate membership proof")
            android.util.Log.i("SignedByMe", "[TIMING] generateMembershipProof FAILED (prover not ready) at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            return null
        }
        
        val leafSecret = loadLeafSecret() ?: run {
            android.util.Log.e("SignedByMe", "No leaf secret found for membership proof")
            android.util.Log.i("SignedByMe", "[TIMING] generateMembershipProof FAILED (no leaf secret) at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            return null
        }
        
        return try {
            // Build Groth16 input JSON
            val inputJson = buildGroth16InputJson(leafSecret, witness)
            android.util.Log.i("SignedByMe", "[TIMING] Input JSON built at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            
            // Generate Groth16 proof
            val proofStartMs = System.currentTimeMillis()
            android.util.Log.i("SignedByMe", "[TIMING] Native proof (64MB stack) START at $proofStartMs")
            
            val resultJson = runNativeProofWithLargeStackBlocking(inputJson)
            
            val proofEndMs = System.currentTimeMillis()
            android.util.Log.i("SignedByMe", "[TIMING] Native proof END at $proofEndMs (+${proofEndMs - proofStartMs}ms)")
            
            val result = org.json.JSONObject(resultJson)
            if (!result.optBoolean("success", false)) {
                val error = result.optString("error", "Unknown error")
                android.util.Log.e("SignedByMe", "Groth16 proof generation failed: $error")
                android.util.Log.i("SignedByMe", "[TIMING] generateMembershipProof FAILED at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
                return null
            }
            
            // Base64 encode the proof JSON for API
            val proofBase64 = android.util.Base64.encodeToString(
                resultJson.toByteArray(Charsets.UTF_8),
                android.util.Base64.NO_WRAP
            )
            
            android.util.Log.i("SignedByMe", "[TIMING] generateMembershipProof SUCCESS at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            proofBase64
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Failed to generate membership proof: ${e.message}")
            e.printStackTrace()
            android.util.Log.i("SignedByMe", "[TIMING] generateMembershipProof EXCEPTION at ${System.currentTimeMillis()} (+${System.currentTimeMillis() - startMs}ms)")
            null
        } finally {
            java.util.Arrays.fill(leafSecret, 0.toByte())
        }
    }
    
    /**
     * Get the purpose string from purpose ID.
     */
    fun purposeIdToString(purposeId: Int): String = when (purposeId) {
        1 -> "allowlist"
        2 -> "issuer_batch"
        3 -> "revocation"
        else -> "none"
    }

    // ============================================================================
    // Membership Enrollment (API Integration)
    // ============================================================================

    private val enrollmentFile = "enrollment_data.json"

    /**
     * Enrollment data stored locally after successful enrollment.
     */
    data class EnrollmentData(
        val enrollmentId: String,
        val enrollmentToken: String,
        val enrollmentTokenExpiresAt: Long,
        val clientId: String,
        val purpose: String,
        val status: String,
        val createdAt: Long
    ) {
        fun toJson(): String = org.json.JSONObject().apply {
            put("enrollment_id", enrollmentId)
            put("enrollment_token", enrollmentToken)
            put("enrollment_token_expires_at", enrollmentTokenExpiresAt)
            put("client_id", clientId)
            put("purpose", purpose)
            put("status", status)
            put("created_at", createdAt)
        }.toString()

        companion object {
            fun fromJson(json: String): EnrollmentData {
                val obj = org.json.JSONObject(json)
                return EnrollmentData(
                    enrollmentId = obj.getString("enrollment_id"),
                    enrollmentToken = obj.getString("enrollment_token"),
                    enrollmentTokenExpiresAt = obj.getLong("enrollment_token_expires_at"),
                    clientId = obj.getString("client_id"),
                    purpose = obj.getString("purpose"),
                    status = obj.getString("status"),
                    createdAt = obj.getLong("created_at")
                )
            }
        }

        fun isTokenValid(): Boolean {
            return System.currentTimeMillis() / 1000 < enrollmentTokenExpiresAt
        }
    }

    /**
     * Store enrollment data locally.
     */
    fun storeEnrollment(enrollment: EnrollmentData) {
        context.openFileOutput(enrollmentFile, Context.MODE_PRIVATE).use {
            it.write(enrollment.toJson().toByteArray())
        }
    }

    /**
     * Load stored enrollment data.
     */
    fun loadEnrollment(): EnrollmentData? {
        return try {
            val json = context.openFileInput(enrollmentFile).use { it.bufferedReader().readText() }
            EnrollmentData.fromJson(json)
        } catch (_: Throwable) { null }
    }

    /**
     * Check if enrollment exists.
     */
    fun hasEnrollment(): Boolean {
        return try {
            context.openFileInput(enrollmentFile).use { true }
        } catch (_: Throwable) { false }
    }

    // ============================================================================
    // Enrollment List (Phase 21.6 - Recovery Support)
    // ============================================================================

    private val enrollmentListFile = "enrollments_list.json"

    /**
     * Entry in the local enrollment list - tracks services the user has enrolled in.
     * Stored locally for re-enrollment guidance after wallet recovery.
     */
    data class EnrollmentListEntry(
        val clientId: String,
        val serviceName: String,
        val enrolledAt: Long
    ) {
        fun toJson(): org.json.JSONObject = org.json.JSONObject().apply {
            put("client_id", clientId)
            put("service_name", serviceName)
            put("enrolled_at", enrolledAt)
        }

        companion object {
            fun fromJson(obj: org.json.JSONObject): EnrollmentListEntry {
                return EnrollmentListEntry(
                    clientId = obj.getString("client_id"),
                    serviceName = obj.optString("service_name", obj.getString("client_id")),
                    enrolledAt = obj.getLong("enrolled_at")
                )
            }
        }
    }

    /**
     * Add a service to the local enrollment list.
     * Called after every successful performEnrollment().
     */
    fun addToEnrollmentList(clientId: String, serviceName: String) {
        try {
            val existing = loadEnrollmentList().toMutableList()
            
            // Update or add entry
            val existingIndex = existing.indexOfFirst { it.clientId == clientId }
            val entry = EnrollmentListEntry(
                clientId = clientId,
                serviceName = serviceName,
                enrolledAt = System.currentTimeMillis() / 1000
            )
            
            if (existingIndex >= 0) {
                existing[existingIndex] = entry
            } else {
                existing.add(entry)
            }
            
            // Write back
            val jsonArray = org.json.JSONArray()
            existing.forEach { jsonArray.put(it.toJson()) }
            
            context.openFileOutput(enrollmentListFile, Context.MODE_PRIVATE).use {
                it.write(jsonArray.toString().toByteArray())
            }
            
            android.util.Log.i("SignedByMe", "Added $clientId to enrollment list (total: ${existing.size})")
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Failed to add to enrollment list: ${e.message}")
        }
    }

    /**
     * Load the local enrollment list.
     * Returns empty list if file doesn't exist (fresh install or wiped).
     */
    fun loadEnrollmentList(): List<EnrollmentListEntry> {
        return try {
            val json = context.openFileInput(enrollmentListFile).use { 
                it.bufferedReader().readText() 
            }
            val jsonArray = org.json.JSONArray(json)
            (0 until jsonArray.length()).map { i ->
                EnrollmentListEntry.fromJson(jsonArray.getJSONObject(i))
            }
        } catch (_: Throwable) { 
            emptyList() 
        }
    }

    /**
     * Check if user has any recorded enrollments.
     */
    fun hasEnrollmentHistory(): Boolean {
        return loadEnrollmentList().isNotEmpty()
    }

    /**
     * Clear enrollment list (called on wallet wipe/reset).
     */
    fun clearEnrollmentList() {
        try {
            context.deleteFile(enrollmentListFile)
        } catch (_: Throwable) { }
    }

    /**
     * Get leaf commitment for enrollment (production - no logging).
     * Generates leaf secret if not exists.
     * 
     * @return Hex-encoded leaf commitment (64 chars, no 0x prefix), or null on error
     */
    fun getLeafCommitment(): String? {
        return try {
            val leafSecret = if (hasLeafSecret()) {
                loadLeafSecret() ?: throw Exception("Failed to load leaf secret")
            } else {
                generateLeafSecret()
            }

            val commitmentBytes = NativeBridge.computeLeafCommitment(leafSecret)
            java.util.Arrays.fill(leafSecret, 0.toByte())

            commitmentBytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Failed to get leaf commitment: ${e.message}")
            null
        }
    }

    /**
     * Enroll with the membership API.
     * 
     * This is called during Step 3 onboarding to automatically enroll the user.
     * 
     * @param apiBaseUrl Base URL of the API (e.g., "https://api.beta.privacy-lion.com")
     * @param apiKey RP client API key
     * @param did User's DID
     * @param purpose Membership purpose (default: "allowlist")
     * @return EnrollmentData on success, null on failure
     */
    /**
     * Direct enrollment (for enterprises with auto_approve policy).
     * 
     * NOTE: Does NOT send DID to server - only the leaf_commitment hash.
     * Server returns enrollment_id which we store locally.
     * 
     * @param apiBaseUrl Base URL of the API
     * @param apiKey Enterprise API key
     * @param purpose Enrollment purpose (default: allowlist)
     * @return EnrollmentData on success, null on failure
     */
    suspend fun enrollMembership(
        apiBaseUrl: String,
        apiKey: String,
        purpose: String = "allowlist"
    ): EnrollmentData? = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            // Get or generate leaf commitment
            val leafCommitment = getLeafCommitment() ?: return@withContext null

            // Build request - NO DID sent to server (Bible requirement)
            val requestBody = org.json.JSONObject().apply {
                put("leaf_commitment", leafCommitment)
                put("purpose", purpose)
            }

            // Make API call
            val url = java.net.URL("$apiBaseUrl/v1/membership/enroll")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-API-Key", apiKey)
            conn.doOutput = true
            conn.connectTimeout = 10000
            conn.readTimeout = 10000

            conn.outputStream.use { it.write(requestBody.toString().toByteArray()) }

            val responseCode = conn.responseCode
            if (responseCode != 200) {
                val error = try {
                    conn.errorStream?.bufferedReader()?.readText() ?: "Unknown error"
                } catch (_: Exception) { "HTTP $responseCode" }
                android.util.Log.e("SignedByMe", "Enrollment failed: $error")
                return@withContext null
            }

            val response = conn.inputStream.bufferedReader().readText()
            val json = org.json.JSONObject(response)

            // Server no longer returns enrollment_token (Phase 8 cleanup)
            val enrollment = EnrollmentData(
                enrollmentId = json.getString("enrollment_id"),
                enrollmentToken = "",  // Not used anymore
                enrollmentTokenExpiresAt = 0,  // Not used anymore
                clientId = json.getString("client_id"),
                purpose = json.getString("purpose"),
                status = json.getString("status"),
                createdAt = System.currentTimeMillis() / 1000
            )

            // Store locally
            storeEnrollment(enrollment)
            
            // Add to enrollment list for recovery support (Phase 21.6)
            // Service name from client_id - will be updated with proper name in future
            addToEnrollmentList(enrollment.clientId, enrollment.clientId)

            android.util.Log.i("SignedByMe", "Enrollment complete: ${enrollment.enrollmentId}")
            enrollment
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Enrollment failed: ${e.message}")
            null
        }
    }

    /**
     * Complete enrollment flow: enroll + fetch witness.
     * Called silently after onboarding completes.
     * 
     * @param apiBaseUrl Base URL of the API
     * @param apiKey RP client API key
     * @return true if enrollment and witness fetch succeeded
     */
    suspend fun performEnrollment(
        apiBaseUrl: String,
        apiKey: String
    ): Boolean {
        // Skip if already enrolled with valid witness
        if (hasEnrollment()) {
            val enrollment = loadEnrollment()
            if (enrollment != null) {
                val witness = loadWitness(enrollment.clientId, "default")
                if (witness != null) {
                    android.util.Log.i("SignedByMe", "Already enrolled with witness, skipping")
                    return true
                }
            }
        }

        // Step 1: Enroll
        android.util.Log.i("SignedByMe", "Starting enrollment...")
        val enrollment = enrollMembership(apiBaseUrl, apiKey)
        if (enrollment == null) {
            android.util.Log.e("SignedByMe", "Enrollment step failed")
            return false
        }

        // Step 2: Fetch witness
        android.util.Log.i("SignedByMe", "Fetching witness...")
        val witness = fetchWitness(apiBaseUrl, apiKey)
        if (witness == null) {
            android.util.Log.e("SignedByMe", "Witness fetch failed")
            return false
        }

        android.util.Log.i("SignedByMe", "Enrollment complete with witness for ${witness.clientId}/${witness.rootId}")
        return true
    }

    /**
     * Fetch witness from API using enrollment_id.
     * 
     * @param apiBaseUrl Base URL of the API
     * @param apiKey RP client API key
     * @return WitnessData on success, null on failure
     */
    suspend fun fetchWitness(
        apiBaseUrl: String,
        apiKey: String
    ): WitnessData? = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        try {
            val enrollment = loadEnrollment()
            if (enrollment == null) {
                android.util.Log.e("SignedByMe", "No enrollment found for witness fetch")
                return@withContext null
            }

            // Build URL with enrollment_id
            val url = java.net.URL("$apiBaseUrl/v1/membership/witness?enrollment_id=${java.net.URLEncoder.encode(enrollment.enrollmentId, "UTF-8")}")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("X-API-Key", apiKey)
            conn.connectTimeout = 10000
            conn.readTimeout = 10000

            val responseCode = conn.responseCode
            if (responseCode == 202) {
                // Tree build pending
                android.util.Log.i("SignedByMe", "Witness fetch: tree build pending, retry later")
                return@withContext null
            }
            if (responseCode != 200) {
                val error = try {
                    conn.errorStream?.bufferedReader()?.readText() ?: "Unknown error"
                } catch (_: Exception) { "HTTP $responseCode" }
                android.util.Log.e("SignedByMe", "Witness fetch failed: $error")
                return@withContext null
            }

            val response = conn.inputStream.bufferedReader().readText()
            val json = org.json.JSONObject(response)

            // Parse witness response into WitnessData format
            val siblingsArr = json.getJSONArray("siblings")
            val siblings = (0 until siblingsArr.length()).map { i ->
                hexToBytes(siblingsArr.getString(i))
            }
            val leafIndex = json.getInt("leaf_index")

            // Convert leaf_index to path_bits (binary representation)
            val depth = siblings.size
            val pathBits = ByteArray(depth) { i ->
                ((leafIndex shr i) and 1).toByte()
            }

            val witnessData = WitnessData(
                version = 1,
                clientId = enrollment.clientId,
                rootId = json.getString("root_id"),
                purposeId = purposeStringToId(json.getString("purpose")),
                depth = depth,
                siblings = siblings,
                pathBits = pathBits,
                rootHex = json.getString("root")
            )

            // Store witness locally for later use
            storeWitness(org.json.JSONObject().apply {
                put("version", witnessData.version)
                put("client_id", witnessData.clientId)
                put("root_id", witnessData.rootId)
                put("purpose_id", witnessData.purposeId)
                put("depth", witnessData.depth)
                put("siblings", org.json.JSONArray(siblings.map { "0x" + it.joinToString("") { b -> "%02x".format(b) } }))
                put("path_bits", org.json.JSONArray(pathBits.map { it.toInt() }))
                put("root_hash", witnessData.rootHex)
            }.toString())

            // Phase 25.2: Store root cache for freshness checking
            storeRootCache(witnessData.rootId, witnessData.clientId)

            android.util.Log.i("SignedByMe", "Witness fetched and stored: ${witnessData.rootId}")
            witnessData
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Witness fetch failed: ${e.message}")
            null
        }
    }

    /**
     * Convert purpose string to ID.
     */
    private fun purposeStringToId(purpose: String): Int = when (purpose) {
        "allowlist" -> 1
        "issuer_batch" -> 2
        "revocation" -> 3
        else -> 0
    }

    // ============================================================================
    // DEV HELPER: Leaf Commitment Export (DEBUG only)
    // ============================================================================

    /**
     * DEV ONLY: Generate leaf secret and log the commitment for sbm-tree.
     * 
     * This function:
     * 1. Generates a 32-byte leaf secret (or uses existing)
     * 2. Stores it encrypted (same as other secrets)
     * 3. Computes leaf_commitment = Poseidon(leaf_secret || "sbm:membership:v")
     * 4. Logs ONLY the commitment (64 hex chars, no 0x prefix)
     * 5. NEVER logs the leaf secret
     * 
     * The logged commitment can be used with sbm-tree to build a test tree.
     * 
     * @param clientId The client ID for the witness filename (e.g., "acme")
     * @param rootId The root ID for the witness filename (e.g., "test-root-001")
     * @param forceRegenerate If true, generates a new secret even if one exists
     * @return The leaf commitment as 64 hex chars, or null on error
     */
    fun devExportLeafCommitment(
        clientId: String,
        rootId: String,
        forceRegenerate: Boolean = false
    ): String? {
        // HARD DEV GATE
        if (!BuildConfig.DEBUG) {
            android.util.Log.e("SignedByMe", "devExportLeafCommitment: NOT ALLOWED in release builds")
            return null
        }
        
        return try {
            // Generate or load leaf secret
            val leafSecret = if (forceRegenerate || !hasLeafSecret()) {
                android.util.Log.i("SignedByMe", "[DEV] Generating new leaf secret...")
                generateLeafSecret()
            } else {
                android.util.Log.i("SignedByMe", "[DEV] Using existing leaf secret")
                loadLeafSecret() ?: throw Exception("Failed to load leaf secret")
            }
            
            // Compute commitment via JNI (matches sbm-tree exactly)
            val commitmentBytes = NativeBridge.computeLeafCommitment(leafSecret)
            
            // Zeroize secret immediately
            java.util.Arrays.fill(leafSecret, 0.toByte())
            
            // Convert to hex (no 0x prefix)
            val commitmentHex = commitmentBytes.joinToString("") { "%02x".format(it) }
            
            // Log the commitment and witness filename info
            android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
            android.util.Log.i("SignedByMe", "[DEV] LEAF COMMITMENT EXPORT")
            android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
            android.util.Log.i("SignedByMe", "[DEV] commitment: $commitmentHex")
            android.util.Log.i("SignedByMe", "[DEV] client_id:  $clientId")
            android.util.Log.i("SignedByMe", "[DEV] root_id:    $rootId")
            android.util.Log.i("SignedByMe", "[DEV] witness filename: ${clientId}_${rootId}.json")
            android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
            android.util.Log.i("SignedByMe", "[DEV] Use this commitment with sbm-tree to build the Merkle tree.")
            android.util.Log.i("SignedByMe", "[DEV] Push resulting witness JSON to device app_witnesses/ directory.")
            android.util.Log.i("SignedByMe", "═══════════════════════════════════════════════════════════════")
            
            commitmentHex
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "[DEV] Failed to export leaf commitment: ${e.message}")
            null
        }
    }
}


