// NostrManager.kt - NOSTR client management for SignedByMe (Phase 9)
//
// Key architectural decisions (binding, from Bible):
// - DECISION 1: Global npub. nsec = Poseidon2(leaf_secret[0..2]), NO client_id
// - DECISION 2: Ephemeral NWC keypair per login session. Proof npub NEVER touches Strike.
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
    
    // Ephemeral keypair for NWC (DECISION 2 - never use proof npub for NWC)
    private var ephemeralNwcNsecHex: String? = null
    private var ephemeralNwcNpub: String? = null

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
        // Each Fr element is the same 32 bytes padded (for the JNI interface)
        // Actually: the Rust side expects 5 field elements, but we only have 32 bytes
        // The Poseidon2 uses leaf_secret[0..2] which are the first 3 elements
        // For now, we'll pad the 32 bytes into 160 bytes by repeating/zeroing
        
        // TODO: Match the exact format from DidWalletManager's leaf_secret storage
        // For Phase 9, we'll derive npub directly from the 32-byte secret
        val paddedLeafSecret = ByteArray(160)
        
        // Split 32 bytes into 5 chunks of ~6 bytes each, padded to 32 bytes each
        // This matches buildGroth16InputJson: [0..6), [6..12), [12..18), [18..24), [24..32)
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
            val npub = NativeBridge.deriveNpubFromLeafSecret(paddedLeafSecret)
            if (npub.startsWith("error:")) {
                Log.e(TAG, "Failed to derive npub: $npub")
                null
            } else {
                currentNpub = npub
                Log.i(TAG, "NOSTR identity initialized: ${npub.take(20)}...")
                npub
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception deriving npub: ${e.message}")
            null
        } finally {
            // Zeroize padded copy
            paddedLeafSecret.fill(0)
        }
    }

    /**
     * Generate ephemeral keypair for NWC communication.
     * 
     * DECISION 2: The proof npub NEVER touches Strike.
     * Use this ephemeral keypair for all NWC make_invoice and payment notifications.
     * Discard after preimage is received.
     */
    fun generateEphemeralNwcKeypair(): Pair<String, String>? {
        return try {
            val json = NativeBridge.generateEphemeralNwcKeypair()
            val obj = JSONObject(json)
            val nsecHex = obj.getString("ephemeral_nsec_hex")
            val npub = obj.getString("ephemeral_npub")
            
            ephemeralNwcNsecHex = nsecHex
            ephemeralNwcNpub = npub
            
            Log.i(TAG, "Generated ephemeral NWC keypair: ${npub.take(20)}...")
            Pair(nsecHex, npub)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate ephemeral NWC keypair: ${e.message}")
            null
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
            
            // TODO: Implement actual WebSocket connections via Rust nostr-sdk
            // For Phase 9 MVP, we'll stub this and add real connections in Phase 9.4
            
            try {
                // Simulate connection attempt with timeout
                withTimeout(3000) {
                    // In production: call into Rust to connect
                    // For now: simulate success
                    delay(100)
                    isConnected = true
                }
                
                withContext(Dispatchers.Main) {
                    Log.i(TAG, "Connected to NOSTR relays")
                    onConnected()
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "NOSTR relay connection timed out - login will proceed without audit trail")
                withContext(Dispatchers.Main) {
                    onFailed()
                }
            } catch (e: Exception) {
                Log.e(TAG, "NOSTR relay connection failed: ${e.message}")
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
        isConnected = false
        
        // Discard ephemeral NWC keypair (DECISION 2)
        ephemeralNwcNsecHex = null
        ephemeralNwcNpub = null
        
        Log.i(TAG, "Disconnected from NOSTR relays, ephemeral keys discarded")
    }

    /**
     * Check if connected to at least one relay.
     */
    fun isConnected(): Boolean = isConnected

    /**
     * Get the current npub (proof identity).
     */
    fun getNpub(): String? = currentNpub

    /**
     * Build a proof_event (kind 28101) for publishing.
     * 
     * Contains: proof bytes, merkle_root, npub, both BOLT11 invoices
     * Tags: nonce, client_id
     * 
     * @return JSON string representing the event content
     */
    fun buildProofEvent(
        nonce: String,
        clientId: String,
        proofHex: String,
        merkleRoot: String,
        npub: String,
        userInvoice: String,
        operatorInvoice: String
    ): String {
        return JSONObject().apply {
            put("kind", KIND_PROOF_EVENT)
            put("nonce", nonce)
            put("client_id", clientId)
            put("proof", proofHex)
            put("merkle_root", merkleRoot)
            put("npub", npub)
            put("user_invoice", userInvoice)
            put("operator_invoice", operatorInvoice)
            put("timestamp", System.currentTimeMillis() / 1000)
        }.toString()
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
        val npub = currentNpub ?: run {
            Log.e(TAG, "Cannot publish proof_event: no npub initialized")
            return@withContext null
        }
        
        if (!isConnected) {
            Log.w(TAG, "Not connected to relays - proof_event not published")
            return@withContext null
        }
        
        val eventContent = buildProofEvent(
            nonce, clientId, proofHex, merkleRoot, npub, userInvoice, operatorInvoice
        )
        
        Log.i(TAG, "Publishing proof_event for nonce=$nonce, client=$clientId")
        
        // TODO: Call into Rust nostr-sdk to actually publish the event
        // For Phase 9.3, we're setting up the structure
        // Real publishing will be wired in Phase 9.4
        
        // Return stub event ID for now
        val stubEventId = "event_${System.currentTimeMillis()}"
        Log.i(TAG, "proof_event published (stub): $stubEventId")
        stubEventId
    }

    /**
     * Publish payment_receipt (kind 28102) after receiving payment via NWC.
     */
    suspend fun publishPaymentReceipt(
        nonce: String,
        paymentHash: String,
        preimageHex: String,
        amountSats: Long
    ): String? = withContext(Dispatchers.IO) {
        if (!isConnected) {
            Log.w(TAG, "Not connected to relays - payment_receipt not published")
            return@withContext null
        }
        
        val eventContent = JSONObject().apply {
            put("kind", KIND_PAYMENT_RECEIPT)
            put("nonce", nonce)
            put("payment_hash", paymentHash)
            put("preimage", preimageHex)
            put("amount_sats", amountSats)
            put("timestamp", System.currentTimeMillis() / 1000)
        }.toString()
        
        Log.i(TAG, "Publishing payment_receipt for nonce=$nonce")
        
        // TODO: Real publishing via Rust nostr-sdk
        val stubEventId = "event_${System.currentTimeMillis()}"
        Log.i(TAG, "payment_receipt published (stub): $stubEventId")
        stubEventId
    }

    /**
     * Publish login_complete (kind 28103) after successful authentication.
     */
    suspend fun publishLoginComplete(
        nonce: String,
        clientId: String
    ): String? = withContext(Dispatchers.IO) {
        val npub = currentNpub
        
        if (!isConnected) {
            Log.w(TAG, "Not connected to relays - login_complete not published")
            return@withContext null
        }
        
        val eventContent = JSONObject().apply {
            put("kind", KIND_LOGIN_COMPLETE)
            put("nonce", nonce)
            put("client_id", clientId)
            put("npub", npub ?: "")
            put("status", "complete")
            put("timestamp", System.currentTimeMillis() / 1000)
        }.toString()
        
        Log.i(TAG, "Publishing login_complete for nonce=$nonce")
        
        // TODO: Real publishing via Rust nostr-sdk
        val stubEventId = "event_${System.currentTimeMillis()}"
        Log.i(TAG, "login_complete published (stub): $stubEventId")
        stubEventId
    }
}
