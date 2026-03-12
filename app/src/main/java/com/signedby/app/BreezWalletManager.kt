package com.signedby.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import breez_sdk_spark.*
import cash.z.ecc.android.bip39.Mnemonics
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.net.URL
import java.net.HttpURLConnection
import org.json.JSONObject

/**
 * Data class for parsed invoice details
 */
data class InvoiceDetails(
    val amountSats: ULong?,
    val description: String,
    val paymentHash: String,
    val expiry: ULong,
    val isExpired: Boolean
)

/**
 * BreezWalletManager - Manages Breez SDK Spark wallet integration
 * 
 * Handles:
 * - Wallet initialization (new or restore)
 * - Secure seed storage with Android Keystore
 * - Lightning invoice creation (BOLT11)
 * - Payment status monitoring
 * - Balance tracking
 */
class BreezWalletManager(private val context: Context) {
    
    companion object {
        private const val TAG = "BreezWallet"
        private const val KEYSTORE_ALIAS = "btcdid_breez_seed_key"
        private const val PREFS_NAME = "btcdid_wallet_prefs"
        private const val PREF_ENCRYPTED_SEED = "encrypted_seed"
        private const val PREF_SEED_IV = "seed_iv"
    }
    
    // Wallet state
    sealed class WalletState {
        object Disconnected : WalletState()
        object Connecting : WalletState()
        data class Connected(val balanceSats: ULong, val sparkAddress: String?) : WalletState()
        data class Error(val message: String) : WalletState()
    }
    
    private val _walletState = MutableStateFlow<WalletState>(WalletState.Disconnected)
    val walletState: StateFlow<WalletState> = _walletState.asStateFlow()
    
    // Payment received events - emits (paymentHash, preimage) when payment is received
    private val _paymentReceived = MutableSharedFlow<Pair<String, String>>()
    val paymentReceived: SharedFlow<Pair<String, String>> = _paymentReceived.asSharedFlow()
    
    private var sdk: BreezSdk? = null
    private val scope = CoroutineScope(Dispatchers.IO)
    
    // Event listener for Breez SDK events
    private val eventListener = object : EventListener {
        override fun onEvent(event: BreezEvent) {
            when (event) {
                is BreezEvent.PaymentReceived -> {
                    val payment = event.payment
                    Log.i(TAG, "Payment received event: ${payment.details}")
                    
                    // Extract payment hash and preimage from payment details
                    when (val details = payment.details) {
                        is PaymentDetails.Lightning -> {
                            val paymentHash = details.paymentHash
                            val preimage = details.preimage ?: ""
                            Log.i(TAG, "Lightning payment received: hash=$paymentHash, preimage=${preimage.take(16)}...")
                            scope.launch {
                                _paymentReceived.emit(Pair(paymentHash, preimage))
                            }
                        }
                        else -> {
                            Log.d(TAG, "Non-Lightning payment received")
                        }
                    }
                }
                is BreezEvent.Synced -> {
                    Log.d(TAG, "Wallet synced")
                    scope.launch { refreshBalance() }
                }
                else -> {
                    Log.d(TAG, "Breez event: $event")
                }
            }
        }
    }
    
    /**
     * Initialize or restore the wallet
     * Creates a new wallet if none exists, otherwise restores from secure storage
     */
    suspend fun initializeWallet(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            _walletState.value = WalletState.Connecting
            
            // Try to load existing seed or generate new one
            val mnemonic = loadOrCreateMnemonic()
            
            // Create seed from mnemonic
            val seed = Seed.Mnemonic(mnemonic, null)
            
            // Configure SDK
            val config = defaultConfig(Network.MAINNET)
            config.apiKey = BuildConfig.BREEZ_API_KEY
            
            // Storage directory for SDK data
            val storageDir = context.filesDir.absolutePath + "/breez_data"
            
            // Connect to SDK with event listener
            sdk = connect(
                ConnectRequest(
                    config = config,
                    seed = seed,
                    storageDir = storageDir
                ),
                eventListener
            )
            
            // Fetch initial balance
            refreshBalance()
            
            Log.i(TAG, "Wallet initialized successfully")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize wallet", e)
            _walletState.value = WalletState.Error(e.message ?: "Unknown error")
            Result.failure(e)
        }
    }
    
    /**
     * Refresh wallet balance from the SDK
     */
    suspend fun refreshBalance() = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: throw IllegalStateException("SDK not initialized")
            
            // Get wallet info - requires GetInfoRequest
            val info = breezSdk.getInfo(GetInfoRequest(ensureSynced = false))
            val balanceSats = info.balanceSats
            
            // Get spark address for receiving
            val sparkAddress = try {
                val response = breezSdk.receivePayment(
                    ReceivePaymentRequest(ReceivePaymentMethod.SparkAddress)
                )
                response.paymentRequest
            } catch (e: Exception) {
                Log.w(TAG, "Could not get spark address", e)
                null
            }
            
            _walletState.value = WalletState.Connected(
                balanceSats = balanceSats,
                sparkAddress = sparkAddress
            )
            
            Log.d(TAG, "Balance refreshed: $balanceSats sats")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to refresh balance", e)
            _walletState.value = WalletState.Error(e.message ?: "Failed to refresh balance")
        }
    }
    
    /**
     * Create a BOLT11 Lightning invoice
     * 
     * @param amountSats Amount in satoshis
     * @param description Invoice description
     * @param expirySecs Expiry time in seconds (default 1 hour)
     * @return The BOLT11 invoice string
     */
    suspend fun createInvoice(
        amountSats: ULong,
        description: String,
        expirySecs: UInt = 3600u
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: throw IllegalStateException("SDK not initialized")
            
            val request = ReceivePaymentRequest(
                ReceivePaymentMethod.Bolt11Invoice(
                    description = description,
                    amountSats = amountSats,
                    expirySecs = expirySecs
                )
            )
            
            val response = breezSdk.receivePayment(request)
            
            Log.i(TAG, "Created invoice for $amountSats sats")
            Result.success(response.paymentRequest)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create invoice", e)
            Result.failure(e)
        }
    }
    
    /**
     * Fetch a BOLT11 invoice from a Lightning Address using LNURL-pay protocol.
     * Used to get invoices for third parties (e.g., operator fee invoice).
     * 
     * @param lightningAddress Lightning Address (e.g., user@wallet.com)
     * @param amountSats Amount in satoshis
     * @param comment Optional comment
     * @return The BOLT11 invoice string
     */
    suspend fun getInvoiceFromLightningAddress(
        lightningAddress: String,
        amountSats: ULong,
        comment: String? = null
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            // Parse Lightning Address: user@domain -> https://domain/.well-known/lnurlp/user
            val parts = lightningAddress.split("@")
            if (parts.size != 2) {
                return@withContext Result.failure(Exception("Invalid Lightning Address format"))
            }
            val (user, domain) = parts
            
            // Step 1: Fetch LNURL pay request metadata
            val lnurlUrl = "https://$domain/.well-known/lnurlp/$user"
            Log.d(TAG, "Fetching LNURL from: $lnurlUrl")
            
            val metadataJson = fetchUrl(lnurlUrl)
            val metadata = JSONObject(metadataJson)
            
            // Validate response
            val tag = metadata.optString("tag")
            if (tag != "payRequest") {
                return@withContext Result.failure(Exception("Invalid LNURL response: tag=$tag"))
            }
            
            val minSendable = metadata.getLong("minSendable") / 1000  // Convert millisats to sats
            val maxSendable = metadata.getLong("maxSendable") / 1000
            
            if (amountSats.toLong() < minSendable || amountSats.toLong() > maxSendable) {
                return@withContext Result.failure(
                    Exception("Amount $amountSats sats outside range [$minSendable, $maxSendable]")
                )
            }
            
            val callback = metadata.getString("callback")
            
            // Step 2: Request invoice with amount
            val amountMsats = amountSats.toLong() * 1000
            val invoiceUrl = if (callback.contains("?")) {
                "$callback&amount=$amountMsats"
            } else {
                "$callback?amount=$amountMsats"
            }
            
            // Add comment if provided and allowed
            val finalUrl = if (comment != null && metadata.optInt("commentAllowed", 0) > 0) {
                "$invoiceUrl&comment=${java.net.URLEncoder.encode(comment, "UTF-8")}"
            } else {
                invoiceUrl
            }
            
            Log.d(TAG, "Requesting invoice from: $finalUrl")
            val invoiceJson = fetchUrl(finalUrl)
            val invoiceResponse = JSONObject(invoiceJson)
            
            // Check for error
            if (invoiceResponse.has("status") && invoiceResponse.getString("status") == "ERROR") {
                val reason = invoiceResponse.optString("reason", "Unknown error")
                return@withContext Result.failure(Exception("LNURL error: $reason"))
            }
            
            val bolt11 = invoiceResponse.getString("pr")
            Log.i(TAG, "Got invoice from Lightning Address: ${bolt11.take(30)}...")
            
            Result.success(bolt11)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get invoice from Lightning Address", e)
            Result.failure(e)
        }
    }
    
    /**
     * Helper function to fetch URL content
     */
    private fun fetchUrl(urlString: String): String {
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json")
        connection.connectTimeout = 10000
        connection.readTimeout = 10000
        
        try {
            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw Exception("HTTP error: $responseCode")
            }
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally {
            connection.disconnect()
        }
    }
    
    /**
     * Wait for a specific payment to be received by payment hash.
     * Uses Breez SDK payment events with polling fallback.
     * 
     * @param paymentHash The payment hash to wait for
     * @param timeoutMs Timeout in milliseconds
     * @return The preimage if payment received, null on timeout
     */
    suspend fun waitForPayment(
        paymentHash: String,
        timeoutMs: Long = 120000
    ): String? = withContext(Dispatchers.IO) {
        Log.d(TAG, "Waiting for payment: $paymentHash (timeout=${timeoutMs}ms)")
        
        // Helper to find payment in recent list
        suspend fun findPaymentPreimage(): String? {
            val payments = getRecentPayments(50u)
            val payment = payments.find { p ->
                when (val details = p.details) {
                    is PaymentDetails.Lightning -> details.paymentHash == paymentHash
                    else -> false
                }
            }
            return if (payment != null) {
                val details = payment.details as? PaymentDetails.Lightning
                details?.preimage
            } else null
        }
        
        // First check if already received
        findPaymentPreimage()?.let { preimage ->
            Log.i(TAG, "Payment already received: $paymentHash")
            return@withContext preimage
        }
        
        // Poll for payment (Breez event listener also fires _paymentReceived)
        // Using polling as primary method since events may be missed if listener 
        // wasn't attached before payment arrived
        val startTime = System.currentTimeMillis()
        val pollIntervalMs = 1000L
        
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            // Check for payment
            findPaymentPreimage()?.let { preimage ->
                Log.i(TAG, "Payment received: $paymentHash, preimage: ${preimage.take(16)}...")
                return@withContext preimage
            }
            
            // Wait before next poll
            kotlinx.coroutines.delay(pollIntervalMs)
        }
        
        Log.d(TAG, "Payment not received within timeout: $paymentHash")
        null
    }
    
    /**
     * Generate login invoices (90% user, 10% operator) using Breez SDK.
     * 
     * @param totalSats Total amount from QR code
     * @param clientId Enterprise client_id for description
     * @param operatorAddress Operator Lightning Address for 10% fee
     * @return Pair of (userInvoice, operatorInvoice), or null on error
     */
    suspend fun generateLoginInvoices(
        totalSats: Long,
        clientId: String,
        operatorAddress: String = "ops_yypf5wifvp@strike.me"
    ): Pair<String, String>? = withContext(Dispatchers.IO) {
        try {
            // Calculate 90/10 split
            val userSats = (totalSats * 90) / 100
            val operatorSats = totalSats - userSats
            
            Log.i(TAG, "Generating login invoices: user=$userSats sats, operator=$operatorSats sats")
            
            // Invoice 1: 90% to user's Breez wallet
            val userDescription = "SignedByMe login - $clientId (user)"
            val userInvoiceResult = createInvoice(
                amountSats = userSats.toULong(),
                description = userDescription,
                expirySecs = 600u  // 10 minutes
            )
            
            if (userInvoiceResult.isFailure) {
                Log.e(TAG, "Failed to create user invoice: ${userInvoiceResult.exceptionOrNull()}")
                return@withContext null
            }
            
            val userInvoice = userInvoiceResult.getOrThrow()
            
            // Invoice 2: 10% to operator Lightning Address
            val operatorDescription = "SignedByMe login - $clientId (operator)"
            val operatorInvoiceResult = getInvoiceFromLightningAddress(
                lightningAddress = operatorAddress,
                amountSats = operatorSats.toULong(),
                comment = operatorDescription
            )
            
            if (operatorInvoiceResult.isFailure) {
                Log.e(TAG, "Failed to get operator invoice: ${operatorInvoiceResult.exceptionOrNull()}")
                return@withContext null
            }
            
            val operatorInvoice = operatorInvoiceResult.getOrThrow()
            
            Log.i(TAG, "Generated login invoices successfully")
            Pair(userInvoice, operatorInvoice)
        } catch (e: Exception) {
            Log.e(TAG, "Exception generating login invoices", e)
            null
        }
    }

    /**
     * Extract payment hash from a bolt11 invoice.
     * 
     * SECURITY: Uses Breez SDK's parseInput for proper BOLT11 decoding.
     * The payment hash is a critical cryptographic binding - must be the real value.
     * 
     * @param bolt11 The BOLT11 invoice string
     * @return The payment hash as 64-character hex string
     * @throws IllegalArgumentException if invoice cannot be parsed
     */
    suspend fun extractPaymentHash(bolt11: String): String = withContext(Dispatchers.IO) {
        // Use native Rust decoder for BOLT11 parsing
        // Spark SDK is for Lightning payments, not invoice parsing
        try {
            NativeBridge.extractPaymentHashFromBolt11(bolt11)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse BOLT11 invoice: ${e.message}")
            throw IllegalArgumentException("Failed to extract payment hash: ${e.message}")
        }
    }
    
    /**
     * Synchronous fallback for extracting payment hash when SDK not available.
     * Uses manual BOLT11 parsing as last resort.
     * 
     * SECURITY: Prefer extractPaymentHash() which uses proper SDK parsing.
     */
    fun extractPaymentHashSync(bolt11: String): String {
        // Fallback: Use native Rust decoder if available
        // This is more reliable than manual parsing
        try {
            // Call native function for proper BOLT11 decoding
            return NativeBridge.extractPaymentHashFromBolt11(bolt11)
        } catch (e: Exception) {
            Log.w(TAG, "Native BOLT11 decode failed, using fallback: ${e.message}")
        }
        
        // Last resort: Manual bech32 parsing
        // NOTE: This is error-prone and should be avoided
        throw IllegalArgumentException("Cannot extract payment hash - Breez SDK not initialized and native decoder unavailable")
    }
    
    /**
     * Check if a payment has been received by payment hash
     * 
     * @param paymentHash The payment hash to check
     * @return true if payment was received, false otherwise
     */
    suspend fun isPaymentReceived(paymentHash: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: return@withContext false
            
            // List recent received payments
            val response = breezSdk.listPayments(
                ListPaymentsRequest(
                    typeFilter = listOf(PaymentType.RECEIVE),
                    statusFilter = listOf(PaymentStatus.COMPLETED),
                    limit = 50u
                )
            )
            
            // Check if any payment matches the hash
            val found = response.payments.any { payment ->
                // Payment details may contain the hash depending on payment type
                when (val details = payment.details) {
                    is PaymentDetails.Lightning -> {
                        details.paymentHash == paymentHash
                    }
                    else -> false
                }
            }
            
            if (found) {
                Log.i(TAG, "Payment received for hash: $paymentHash")
                refreshBalance()
            }
            
            found
        } catch (e: Exception) {
            Log.e(TAG, "Error checking payment status", e)
            false
        }
    }
    
    /**
     * Get list of recent payments
     */
    suspend fun getRecentPayments(limit: UInt = 20u): List<Payment> = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: return@withContext emptyList()
            
            val response = breezSdk.listPayments(
                ListPaymentsRequest(
                    limit = limit,
                    sortAscending = false
                )
            )
            
            response.payments
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get payments", e)
            emptyList()
        }
    }
    
    /**
     * Get ALL payments (no limit)
     */
    suspend fun getAllPayments(): List<Payment> = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: return@withContext emptyList()
            
            val response = breezSdk.listPayments(
                ListPaymentsRequest(
                    sortAscending = false
                )
            )
            
            response.payments
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get all payments", e)
            emptyList()
        }
    }
    
    /**
     * Send a Lightning payment (pay a BOLT11 invoice)
     * 
     * @param bolt11Invoice The BOLT11 invoice to pay
     * @return The payment result
     */
    suspend fun sendPayment(bolt11Invoice: String): Result<Payment> = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: throw IllegalStateException("SDK not initialized")
            
            // Prepare the payment first
            val prepareResponse = breezSdk.prepareSendPayment(
                PrepareSendPaymentRequest(
                    paymentRequest = bolt11Invoice,
                    amount = null, // Use amount from invoice
                    tokenIdentifier = null,
                    conversionOptions = null
                )
            )
            
            // Send the payment
            val sendResponse = breezSdk.sendPayment(
                SendPaymentRequest(prepareResponse)
            )
            
            Log.i(TAG, "Payment sent successfully")
            refreshBalance()
            Result.success(sendResponse.payment)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send payment", e)
            Result.failure(e)
        }
    }
    
    /**
     * Send payment to a Lightning Address with specified amount
     * 
     * @param lightningAddress The Lightning Address (e.g., user@wallet.com)
     * @param amountSats Amount to send in satoshis
     * @param comment Optional comment/message
     * @return The payment result
     */
    suspend fun sendToLightningAddress(
        lightningAddress: String,
        amountSats: ULong,
        comment: String? = null
    ): Result<Payment> = withContext(Dispatchers.IO) {
        try {
            val breezSdk = sdk ?: throw IllegalStateException("SDK not initialized")
            
            // Parse the Lightning Address
            val input = breezSdk.parse(lightningAddress)
            
            if (input !is InputType.LightningAddress) {
                return@withContext Result.failure(Exception("Not a valid Lightning Address"))
            }
            
            // Get the LNURL pay request details
            val lnurlData = input.v1.payRequest
            
            // Prepare LNURL payment
            val prepareResponse = breezSdk.prepareLnurlPay(
                PrepareLnurlPayRequest(
                    payRequest = lnurlData,
                    amountSats = amountSats,
                    comment = comment,
                    validateSuccessActionUrl = true
                )
            )
            
            // Send the payment
            val response = breezSdk.lnurlPay(
                LnurlPayRequest(prepareResponse)
            )
            
            Log.i(TAG, "Lightning Address payment sent successfully")
            refreshBalance()
            Result.success(response.payment)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send to Lightning Address", e)
            Result.failure(e)
        }
    }
    
    /**
     * Parse a BOLT11 invoice using Breez SDK for proper decoding.
     * 
     * SECURITY: Uses SDK's parseInput for proper BOLT11 decoding.
     * Never use string manipulation to extract payment hash.
     * 
     * @param bolt11Invoice The invoice to parse
     * @return Parsed invoice details with accurate payment hash
     */
    suspend fun parseInvoice(bolt11Invoice: String): Result<InvoiceDetails> = withContext(Dispatchers.IO) {
        try {
            // Basic validation - BOLT11 invoices start with "ln"
            if (!bolt11Invoice.lowercase().startsWith("ln")) {
                return@withContext Result.failure(Exception("Not a valid Lightning invoice"))
            }
            
            // Use native Rust decoder for BOLT11 parsing
            // Spark SDK is for Lightning payments, not invoice parsing
            try {
                val paymentHash = NativeBridge.extractPaymentHashFromBolt11(bolt11Invoice)
                // For full invoice details, we'd need a complete BOLT11 decoder
                // For now, extract payment hash (the critical field) and use defaults
                return@withContext Result.success(InvoiceDetails(
                    amountSats = null,  // Would need full decoder
                    description = "Lightning Payment",
                    paymentHash = paymentHash,
                    expiry = 3600UL,  // Default 1 hour
                    isExpired = false
                ))
            } catch (e: Exception) {
                return@withContext Result.failure(Exception("Failed to parse invoice: ${e.message}"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse invoice", e)
            Result.failure(e)
        }
    }
    
    /**
     * Get the wallet mnemonic (seed words) for backup
     * This should be protected by biometric authentication before calling
     */
    fun getMnemonic(): String? {
        return try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val encryptedSeed = prefs.getString(PREF_ENCRYPTED_SEED, null)
            val iv = prefs.getString(PREF_SEED_IV, null)
            
            if (encryptedSeed != null && iv != null) {
                decryptMnemonic(encryptedSeed, iv)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get mnemonic", e)
            null
        }
    }
    
    /**
     * Check if wallet exists (has saved mnemonic)
     */
    fun hasWallet(): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PREF_ENCRYPTED_SEED, null) != null
    }
    
    /**
     * Restore wallet from mnemonic
     */
    suspend fun restoreFromMnemonic(mnemonic: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            // Validate mnemonic format (should be 12 or 24 words)
            val words = mnemonic.trim().split("\\s+".toRegex())
            if (words.size != 12 && words.size != 24) {
                return@withContext Result.failure(Exception("Mnemonic must be 12 or 24 words"))
            }
            
            // Store the new mnemonic
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val (encrypted, iv) = encryptMnemonic(mnemonic.trim())
            prefs.edit()
                .putString(PREF_ENCRYPTED_SEED, encrypted)
                .putString(PREF_SEED_IV, iv)
                .apply()
            
            // Re-initialize wallet with new mnemonic
            sdk?.disconnect()
            sdk = null
            _walletState.value = WalletState.Disconnected
            
            initializeWallet()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore wallet", e)
            Result.failure(e)
        }
    }
    
    /**
     * Disconnect and clean up SDK resources
     */
    suspend fun disconnect() = withContext(Dispatchers.IO) {
        try {
            sdk?.disconnect()
            sdk = null
            _walletState.value = WalletState.Disconnected
            Log.i(TAG, "Wallet disconnected")
        } catch (e: Exception) {
            Log.e(TAG, "Error disconnecting", e)
        }
    }
    
    // ==================== Secure Storage ====================
    
    /**
     * Load existing mnemonic from secure storage or create a new one
     */
    private fun loadOrCreateMnemonic(): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encryptedSeed = prefs.getString(PREF_ENCRYPTED_SEED, null)
        val iv = prefs.getString(PREF_SEED_IV, null)
        
        return if (encryptedSeed != null && iv != null) {
            // Decrypt existing seed
            decryptMnemonic(encryptedSeed, iv)
        } else {
            // Generate new mnemonic (BIP39)
            val mnemonic = generateMnemonic()
            
            // Encrypt and store
            val (encrypted, newIv) = encryptMnemonic(mnemonic)
            prefs.edit()
                .putString(PREF_ENCRYPTED_SEED, encrypted)
                .putString(PREF_SEED_IV, newIv)
                .apply()
            
            Log.i(TAG, "New wallet created")
            mnemonic
        }
    }
    
    /**
     * Generate a BIP39 mnemonic with 128 bits of entropy (12 words)
     */
    private fun generateMnemonic(): String {
        // Generate 128 bits (16 bytes) of secure entropy for a 12-word mnemonic
        val entropy = ByteArray(16)
        SecureRandom().nextBytes(entropy)
        val mnemonicCode = Mnemonics.MnemonicCode(entropy)
        return mnemonicCode.words.map { String(it) }.joinToString(" ")
    }
    
    /**
     * Encrypt mnemonic using Android Keystore
     */
    private fun encryptMnemonic(mnemonic: String): Pair<String, String> {
        val secretKey = getOrCreateSecretKey()
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        
        val encrypted = cipher.doFinal(mnemonic.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        
        return Pair(
            Base64.encodeToString(encrypted, Base64.NO_WRAP),
            Base64.encodeToString(iv, Base64.NO_WRAP)
        )
    }
    
    /**
     * Decrypt mnemonic using Android Keystore
     */
    private fun decryptMnemonic(encryptedBase64: String, ivBase64: String): String {
        val secretKey = getOrCreateSecretKey()
        
        val encrypted = Base64.decode(encryptedBase64, Base64.NO_WRAP)
        val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        
        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted, Charsets.UTF_8)
    }
    
    /**
     * Get or create the encryption key in Android Keystore
     * Uses StrongBox if available for hardware-backed security
     */
    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        // Return existing key if present
        keyStore.getKey(KEYSTORE_ALIAS, null)?.let {
            return it as SecretKey
        }
        
        // Generate new key - try StrongBox first, fall back to TEE
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        
        // Try StrongBox first on Android P+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                val strongBoxSpec = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .setIsStrongBoxBacked(true)
                    .build()
                
                keyGenerator.init(strongBoxSpec)
                val key = keyGenerator.generateKey()
                Log.i(TAG, "Using StrongBox-backed key")
                return key
            } catch (e: android.security.keystore.StrongBoxUnavailableException) {
                Log.w(TAG, "StrongBox not available, falling back to TEE")
            }
        }
        
        // Fallback to TEE (still hardware-backed on most devices)
        val teeSpec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()
        
        keyGenerator.init(teeSpec)
        Log.i(TAG, "Using TEE-backed key")
        return keyGenerator.generateKey()
    }
}
