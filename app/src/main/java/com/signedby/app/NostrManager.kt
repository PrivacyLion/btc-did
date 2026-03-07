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
    
    // NWC connection state
    private var nwcConnected = false
    
    // NWC connection string (MVP: hardcoded, production: from secure storage)
    // TODO: Move to BuildConfig or secure storage
    private val NWC_CONNECTION_STRING = "nostr+walletconnect://0f556eb33d73b6a93b88ecff855dacefed2da1036d0842091e974e27fbca3b20?relay=wss://relay.privacy-lion.com&secret=f954e9f1a590fdfecff0c30d198eaa8e475763561c61cff258bc8d59dcc45d37"

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
                Log.e(TAG, "Failed to get npub: $npub")
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

    // =========================================================================
    // NWC (NOSTR Wallet Connect) - Step 9.5
    // =========================================================================

    /**
     * Initialize NWC client with connection string.
     * Creates ephemeral keypair internally (DECISION 2).
     * 
     * @return true if initialized
     */
    fun initNwc(): Boolean {
        return try {
            val initialized = NativeBridge.nwcInit(NWC_CONNECTION_STRING)
            if (initialized) {
                Log.i(TAG, "NWC client initialized")
            } else {
                Log.e(TAG, "Failed to initialize NWC client")
            }
            initialized
        } catch (e: Exception) {
            Log.e(TAG, "Exception initializing NWC: ${e.message}")
            false
        }
    }

    /**
     * Connect NWC client to relay.
     * Called after initNwc().
     * 
     * @param scope CoroutineScope for async work
     * @param onConnected Callback on success
     * @param onFailed Callback on failure
     */
    fun connectNwc(
        scope: CoroutineScope,
        onConnected: () -> Unit = {},
        onFailed: () -> Unit = {}
    ) {
        scope.launch(Dispatchers.IO) {
            Log.i(TAG, "Connecting NWC client...")
            
            try {
                val connected = NativeBridge.nwcConnect()
                
                if (connected) {
                    nwcConnected = true
                    withContext(Dispatchers.Main) {
                        Log.i(TAG, "NWC connected to relay")
                        onConnected()
                    }
                } else {
                    Log.e(TAG, "NWC connection failed")
                    withContext(Dispatchers.Main) {
                        onFailed()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NWC connection exception: ${e.message}")
                withContext(Dispatchers.Main) {
                    onFailed()
                }
            }
        }
    }

    /**
     * Generate login invoices (90% user, 10% operator).
     * 
     * @param totalSats Total amount from QR code
     * @param clientId Enterprise client_id
     * @return Pair of (userInvoice, operatorInvoice), or null on error
     */
    suspend fun generateLoginInvoices(
        totalSats: Long,
        clientId: String
    ): Pair<String, String>? = withContext(Dispatchers.IO) {
        if (!nwcConnected) {
            Log.e(TAG, "Cannot generate invoices: NWC not connected")
            return@withContext null
        }
        
        try {
            val resultJson = NativeBridge.nwcGenerateLoginInvoices(totalSats, clientId)
            val result = JSONObject(resultJson)
            
            if (result.has("error")) {
                Log.e(TAG, "NWC invoice generation error: ${result.getString("error")}")
                return@withContext null
            }
            
            val userInvoice = result.getString("user_invoice")
            val operatorInvoice = result.getString("operator_invoice")
            
            Log.i(TAG, "Generated login invoices: user=${userInvoice.take(30)}..., op=${operatorInvoice.take(30)}...")
            Pair(userInvoice, operatorInvoice)
        } catch (e: Exception) {
            Log.e(TAG, "Exception generating invoices: ${e.message}")
            null
        }
    }

    /**
     * Make a single invoice via NWC.
     */
    suspend fun makeInvoice(
        amountSats: Long,
        description: String,
        expirySecs: Long = 600
    ): String? = withContext(Dispatchers.IO) {
        if (!nwcConnected) {
            Log.e(TAG, "Cannot make invoice: NWC not connected")
            return@withContext null
        }
        
        try {
            val result = NativeBridge.nwcMakeInvoice(amountSats, description, expirySecs)
            
            if (result.startsWith("error:")) {
                Log.e(TAG, "NWC make_invoice error: $result")
                return@withContext null
            }
            
            Log.i(TAG, "Generated invoice: ${result.take(30)}...")
            result
        } catch (e: Exception) {
            Log.e(TAG, "Exception making invoice: ${e.message}")
            null
        }
    }

    /**
     * Get wallet balance in satoshis.
     */
    suspend fun getWalletBalance(): Long? = withContext(Dispatchers.IO) {
        if (!nwcConnected) {
            Log.w(TAG, "Cannot get balance: NWC not connected")
            return@withContext null
        }
        
        try {
            val result = NativeBridge.nwcGetBalance()
            
            if (result.startsWith("error:")) {
                Log.e(TAG, "NWC get_balance error: $result")
                return@withContext null
            }
            
            result.toLongOrNull()
        } catch (e: Exception) {
            Log.e(TAG, "Exception getting balance: ${e.message}")
            null
        }
    }

    /**
     * Wait for payment (poll for preimage).
     * 
     * @param paymentHash Payment hash to watch for (hex)
     * @param timeoutSecs Maximum time to wait (default 120 = 2 minutes)
     * @return Preimage hex on success, null on failure/timeout
     */
    suspend fun waitForPayment(
        paymentHash: String,
        timeoutSecs: Long = 120
    ): String? = withContext(Dispatchers.IO) {
        if (!nwcConnected) {
            Log.e(TAG, "Cannot wait for payment: NWC not connected")
            return@withContext null
        }
        
        Log.i(TAG, "Waiting for payment: $paymentHash (timeout=${timeoutSecs}s)")
        
        try {
            val result = NativeBridge.nwcWaitForPayment(paymentHash, timeoutSecs)
            
            if (result.startsWith("error:")) {
                Log.e(TAG, "NWC wait_for_payment error: $result")
                return@withContext null
            }
            
            Log.i(TAG, "Payment received! Preimage: ${result.take(16)}...")
            result
        } catch (e: Exception) {
            Log.e(TAG, "Exception waiting for payment: ${e.message}")
            null
        }
    }

    /**
     * Disconnect NWC and discard ephemeral keys.
     * Called after payment received.
     */
    fun disconnectNwc() {
        try {
            NativeBridge.nwcDisconnect()
            nwcConnected = false
            Log.i(TAG, "NWC disconnected, ephemeral keys discarded")
        } catch (e: Exception) {
            Log.w(TAG, "Exception disconnecting NWC: ${e.message}")
        }
    }

    /**
     * Check if NWC is connected.
     */
    fun isNwcConnected(): Boolean = nwcConnected

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
     * Disconnect from all relays and NWC.
     * Called after login completes.
     */
    fun disconnect() {
        connectionJob?.cancel()
        
        // Disconnect NWC first (DECISION 2 - discard ephemeral keys)
        disconnectNwc()
        
        // Step 9.4: Real NOSTR disconnect via Rust
        try {
            NativeBridge.nostrDisconnect()
        } catch (e: Exception) {
            Log.w(TAG, "Exception during NOSTR disconnect: ${e.message}")
        }
        
        isConnected = false
        currentNpub = null
        
        // Discard ephemeral NWC keypair references
        ephemeralNwcNsecHex = null
        ephemeralNwcNpub = null
        
        Log.i(TAG, "Disconnected from NOSTR + NWC, ephemeral keys discarded")
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
     * Publish payment_receipt (kind 28102) after receiving payment via NWC.
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
}
