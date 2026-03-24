// NostrManager.kt - NOSTR client management for SignedByMe (Phase 9)
//
// Key architectural decisions (binding, from Bible):
// - DECISION 1: Global npub. nsec = Poseidon2(leaf_secret[0..2]), NO client_id
// - Server has ZERO NOSTR involvement. Phone publishes all events.
// - NOSTR is invisible to user. No npub displayed, no relay settings.

package com.signedby.app

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import org.json.JSONObject

/**
 * Manages NOSTR connections and event publishing for SignedByMe audit trail.
 * 
 * NOSTR is invisible to the user - no npub displayed, no relay settings.
 * All operations happen in the background during login flow.
 */
class NostrManager(private val context: Context) {

    companion object {
        private const val TAG = "NostrManager"
        
        // Event kinds for SignedByMe audit trail
        const val KIND_PROOF_EVENT = 28101
        const val KIND_PAYMENT_RECEIPT = 28102
        const val KIND_LOGIN_COMPLETE = 28103
        
        // Default relays (SignedByMe audit relay is primary)
        val DEFAULT_RELAYS = listOf(
            "wss://relay.privacy-lion.com",  // SignedByMe audit relay (primary)
            "wss://relay.damus.io",          // Public relay (redundancy)
            "wss://nos.lol"                  // Public relay (redundancy)
        )
    }

    // Connection state
    private var isConnected = false
    private var connectionJob: Job? = null
    
    // Current session's npub (derived from leaf_secret)
    private var currentNpub: String? = null

    /**
     * Initialize NOSTR identity from leaf_secret.
     * Derives nsec/npub using Poseidon2(leaf_secret[0..2]).
     * 
     * DECISION 1: Global npub - same across all enterprises.
     * 
     * @param leafSecret The 32-byte leaf secret from secure storage
     * @return The npub (bech32 string), or null on error
     */
    fun initializeIdentity(leafSecret: ByteArray): String? {
        require(leafSecret.size == 32) { "leaf_secret must be 32 bytes" }
        
        // Convert 32-byte leaf_secret to 160 bytes (5 x 32-byte Fr elements)
        // Split 32 bytes into 5 chunks of ~6 bytes each, padded to 32 bytes each
        // This matches buildGroth16InputJson: [0..6), [6..12), [12..18), [18..24), [24..32)
        val paddedLeafSecret = ByteArray(160)
        
        val chunks = listOf(
            leafSecret.sliceArray(0 until 6),
            leafSecret.sliceArray(6 until 12),
            leafSecret.sliceArray(12 until 18),
            leafSecret.sliceArray(18 until 24),
            leafSecret.sliceArray(24 until 32)
        )
        
        // Pack each chunk into a 32-byte field element (right-padded with zeros)
        for (i in chunks.indices) {
            System.arraycopy(chunks[i], 0, paddedLeafSecret, i * 32 + (32 - chunks[i].size), chunks[i].size)
        }
        
        return try {
            // Initialize the NOSTR client with our keys (Step 9.4: real client)
            val initialized = NativeBridge.nostrInitClient(paddedLeafSecret)
            if (!initialized) {
                Log.e(TAG, "Failed to initialize NOSTR client")
                return null
            }
            
            // Get npub from the initialized client
            val npub = NativeBridge.nostrGetNpub()
            if (npub.isEmpty() || npub.startsWith("error:")) {
                Log.e(TAG, "Failed to get npub: ${npub.take(20)}")
                null
            } else {
                currentNpub = npub
                Log.i(TAG, "NOSTR identity initialized: ${npub.take(20)}...")
                npub
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception initializing NOSTR identity: ${e.message}")
            null
        } finally {
            // Zeroize padded copy
            paddedLeafSecret.fill(0)
        }
    }

    /**
     * Connect to NOSTR relays.
     * Called on QR scan / login start.
     * 
     * Non-blocking: connection happens in background.
     * If connection fails to ALL relays within 3 seconds, show warning but don't block login.
     * 
     * @param scope CoroutineScope for async work
     * @param onConnected Callback when at least one relay connects
     * @param onFailed Callback if all relays fail (login should still proceed)
     */
    fun connectToRelays(
        scope: CoroutineScope,
        onConnected: () -> Unit = {},
        onFailed: () -> Unit = {}
    ) {
        connectionJob?.cancel()
        connectionJob = scope.launch(Dispatchers.IO) {
            Log.i(TAG, "Connecting to NOSTR relays...")
            
            try {
                // Step 9.4: Real connection via Rust nostr-sdk
                // The Rust side handles the 3-second timeout
                val connected = NativeBridge.nostrConnect()
                
                if (connected) {
                    isConnected = true
                    withContext(Dispatchers.Main) {
                        Log.i(TAG, "Connected to NOSTR relays")
                        onConnected()
                    }
                } else {
                    Log.w(TAG, "NOSTR relay connection failed - login will proceed without audit trail")
                    withContext(Dispatchers.Main) {
                        onFailed()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NOSTR relay connection exception: ${e.message}")
                withContext(Dispatchers.Main) {
                    onFailed()
                }
            }
        }
    }

    /**
     * Disconnect from all relays.
     * Called after login completes.
     */
    fun disconnect() {
        connectionJob?.cancel()
        
        // Disconnect from NOSTR relays via Rust
        try {
            NativeBridge.nostrDisconnect()
        } catch (e: Exception) {
            Log.w(TAG, "Exception during NOSTR disconnect: ${e.message}")
        }
        
        isConnected = false
        currentNpub = null
        
        Log.i(TAG, "Disconnected from NOSTR relays")
    }

    /**
     * Check if connected to at least one relay.
     */
    fun isConnected(): Boolean {
        // Check both local state and Rust state
        return isConnected && try {
            NativeBridge.nostrIsConnected()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get the current npub (proof identity).
     */
    fun getNpub(): String? {
        // Prefer cached value, fall back to Rust
        return currentNpub ?: try {
            val npub = NativeBridge.nostrGetNpub()
            if (npub.isNotEmpty() && !npub.startsWith("error:")) {
                currentNpub = npub
                npub
            } else null
        } catch (e: Exception) {
            null
        }
    }
    /**
     * Publish proof_event to all connected relays.
     * 
     * @param nonce Session nonce from QR
     * @param clientId Enterprise client_id
     * @param proofHex Groth16 proof bytes as hex
     * @param merkleRoot Merkle root from proof public outputs
     * @param userInvoice BOLT11 invoice for user's 90%
     * @param operatorInvoice BOLT11 invoice for operator's 10%
     * @return Event ID if published successfully, null otherwise
     */
    suspend fun publishProofEvent(
        nonce: String,
        clientId: String,
        proofHex: String,
        merkleRoot: String,
        userInvoice: String,
        operatorInvoice: String
    ): String? = withContext(Dispatchers.IO) {
        if (!isConnected()) {
            Log.w(TAG, "Not connected to relays - proof_event not published")
            return@withContext null
        }
        
        Log.i(TAG, "Publishing proof_event for nonce=$nonce, client=$clientId")
        
        try {
            // Step 9.4: Real publishing via Rust nostr-sdk
            val result = NativeBridge.nostrPublishProofEvent(
                nonce,
                clientId,
                proofHex,
                merkleRoot,
                userInvoice,
                operatorInvoice
            )
            
            if (result.startsWith("error:")) {
                Log.e(TAG, "Failed to publish proof_event: $result")
                null
            } else {
                Log.i(TAG, "proof_event published: $result")
                result
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception publishing proof_event: ${e.message}")
            null
        }
    }

    /**
     * Publish payment_receipt (kind 28102) after receiving payment.
     */
    suspend fun publishPaymentReceipt(
        nonce: String,
        paymentHash: String,
        preimageHex: String,
        amountSats: Long
    ): String? = withContext(Dispatchers.IO) {
        if (!isConnected()) {
            Log.w(TAG, "Not connected to relays - payment_receipt not published")
            return@withContext null
        }
        
        Log.i(TAG, "Publishing payment_receipt for nonce=$nonce")
        
        try {
            // Step 9.4: Real publishing via Rust nostr-sdk
            val result = NativeBridge.nostrPublishPaymentReceipt(
                nonce,
                paymentHash,
                preimageHex,
                amountSats
            )
            
            if (result.startsWith("error:")) {
                Log.e(TAG, "Failed to publish payment_receipt: $result")
                null
            } else {
                Log.i(TAG, "payment_receipt published: $result")
                result
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception publishing payment_receipt: ${e.message}")
            null
        }
    }

    /**
     * Publish login_complete (kind 28103) after successful authentication.
     */
    suspend fun publishLoginComplete(
        nonce: String,
        clientId: String
    ): String? = withContext(Dispatchers.IO) {
        if (!isConnected()) {
            Log.w(TAG, "Not connected to relays - login_complete not published")
            return@withContext null
        }
        
        Log.i(TAG, "Publishing login_complete for nonce=$nonce")
        
        try {
            // Step 9.4: Real publishing via Rust nostr-sdk
            val result = NativeBridge.nostrPublishLoginComplete(nonce, clientId)
            
            if (result.startsWith("error:")) {
                Log.e(TAG, "Failed to publish login_complete: $result")
                null
            } else {
                Log.i(TAG, "login_complete published: $result")
                result
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception publishing login_complete: ${e.message}")
            null
        }
    }

    // =============================================================================
    // Phase 26.9: Enrollment Authorization Event Polling
    // =============================================================================

    /**
     * Poll for kind 28200 (enrollment_authorization) event by author, match nonce client-side.
     * Used in enrollment flow - enterprise publishes this event.
     * 
     * strfry relay doesn't index multi-character tags, so we filter by author
     * and match the nonce tag client-side.
     * 
     * @param nonce Enrollment session nonce
     * @param enterprisePubkeyHex Enterprise pubkey in hex format (from NIP-05)
     * @return The complete NOSTR event as JSONObject if found, null otherwise
     */
    suspend fun pollForEnrollmentAuthEvent(nonce: String, enterprisePubkeyHex: String): JSONObject? = withContext(Dispatchers.IO) {
        if (!isConnected()) {
            Log.d(TAG, "Not connected - cannot poll for enrollment auth event")
            return@withContext null
        }
        
        try {
            // Poll via Rust nostr-sdk for kind 28200 by author, match nonce client-side
            val result = NativeBridge.nostrPollForEventByAuthor(
                kind = 28200,
                authorHex = enterprisePubkeyHex,
                tagName = "nonce",
                tagValue = nonce
            )
            
            if (result.isEmpty() || result.startsWith("error:")) {
                Log.d(TAG, "No enrollment auth event found for nonce: ${nonce.take(8)}...")
                null
            } else {
                try {
                    Log.i(TAG, "Found enrollment auth event for nonce: ${nonce.take(8)}...")
                    JSONObject(result)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse enrollment auth event: ${e.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception polling for enrollment auth event: ${e.message}")
            null
        }
    }

    // =============================================================================
    // Phase 26.5: KYC Enrollment Event Polling
    // =============================================================================

    /**
     * Poll for kind 28201 (kyc_verification) event tagged with nonce.
     * Used in KYC enrollment flow.
     * 
     * @param nonce Enrollment session nonce
     * @return JSONObject with event content if found, null otherwise
     */
    suspend fun pollForKycEvent(nonce: String): JSONObject? = withContext(Dispatchers.IO) {
        if (!isConnected()) {
            Log.d(TAG, "Not connected - cannot poll for KYC event")
            return@withContext null
        }
        
        try {
            // Poll via Rust nostr-sdk for kind 28201 tagged with nonce
            val result = NativeBridge.nostrPollForEvent(
                kind = 28201,
                tagName = "nonce",
                tagValue = nonce
            )
            
            if (result.isEmpty() || result.startsWith("error:")) {
                null
            } else {
                try {
                    JSONObject(result)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse KYC event: ${e.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception polling for KYC event: ${e.message}")
            null
        }
    }

    // =============================================================================
    // Phase 26.7: Mobile-to-Mobile Login (Poll for kind 28200 by author, match npub)
    // =============================================================================

    /**
     * Poll for kind 28200 (enrollment_authorization) event by author, match npub client-side.
     * Used for mobile-to-mobile login - enterprise publishes event addressed to user.
     * 
     * strfry relay doesn't index multi-character tags, so we filter by author
     * and match the npub tag client-side against the user's derived npub.
     * 
     * @param enterprisePubkeyHex Enterprise pubkey in hex format (from NIP-05)
     * @return JSONObject with full event if found (includes nonce), null otherwise
     */
    suspend fun pollForM2MLoginEvent(enterprisePubkeyHex: String): JSONObject? = withContext(Dispatchers.IO) {
        if (!isConnected()) {
            Log.d(TAG, "Not connected - cannot poll for M2M event")
            return@withContext null
        }
        
        val npub = getNpub()
        if (npub == null) {
            Log.w(TAG, "No npub available for M2M polling")
            return@withContext null
        }
        
        // Convert npub to hex pubkey for tag matching
        val pubkeyHex = npubToHex(npub)
        if (pubkeyHex == null) {
            Log.e(TAG, "Failed to convert npub to hex")
            return@withContext null
        }
        
        try {
            // Poll via Rust nostr-sdk for kind 28200 by author, match npub client-side
            val result = NativeBridge.nostrPollForEventByAuthor(
                kind = 28200,
                authorHex = enterprisePubkeyHex,
                tagName = "npub",
                tagValue = pubkeyHex
            )
            
            if (result.isEmpty() || result.startsWith("error:")) {
                null
            } else {
                try {
                    JSONObject(result)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse M2M event: ${e.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception polling for M2M event: ${e.message}")
            null
        }
    }

    /**
     * Convert bech32 npub to hex pubkey.
     */
    private fun npubToHex(npub: String): String? {
        if (!npub.startsWith("npub1")) return null
        
        return try {
            // Bech32 decode
            val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
            val data = npub.substring(5) // Skip "npub1"
            
            val values = data.map { CHARSET.indexOf(it) }
            if (values.any { it < 0 }) return null
            
            // Remove checksum (last 6)
            val dataValues = values.dropLast(6)
            
            // Convert 5-bit to 8-bit
            var acc = 0
            var bits = 0
            val result = mutableListOf<Byte>()
            
            for (v in dataValues) {
                acc = (acc shl 5) or v
                bits += 5
                while (bits >= 8) {
                    bits -= 8
                    result.add(((acc shr bits) and 0xFF).toByte())
                }
            }
            
            result.toByteArray().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.e(TAG, "npub decode error: ${e.message}")
            null
        }
    }
}
