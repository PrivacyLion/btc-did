package com.signedby.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.*
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.signedby.app.ui.theme.SignedByMeTheme
import kotlinx.coroutines.*
import androidx.lifecycle.lifecycleScope
import org.json.JSONObject
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.common.BitMatrix
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Extract Groth16 assets from APK assets to filesystem.
 * Assets in assets/groth16/ are copied to the target directory.
 * Large files (zkey) are sideloaded to internal storage via adb, not bundled.
 */
private fun extractGroth16Assets(context: Context, targetDir: java.io.File) {
    try {
        if (!targetDir.exists()) {
            targetDir.mkdirs()
        }
        
        // Assets to extract (zkey is sideloaded separately - too big for APK)
        val assetFiles = listOf(
            "membership.dat",   // 4.5MB circuit data
            "membership"        // ARM64 witness calculator binary (if bundled)
        )
        
        for (filename in assetFiles) {
            val targetFile = java.io.File(targetDir, filename)
            
            // Skip if already extracted and same size
            if (targetFile.exists() && targetFile.length() > 0) {
                android.util.Log.i("SignedByMe", "Groth16 asset exists: $filename (${targetFile.length()} bytes)")
                continue
            }
            
            try {
                context.assets.open("groth16/$filename").use { input ->
                    targetFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                
                // Make binary executable
                if (filename == "membership") {
                    targetFile.setExecutable(true, false)
                }
                
                android.util.Log.i("SignedByMe", "Extracted Groth16 asset: $filename (${targetFile.length()} bytes)")
            } catch (e: java.io.FileNotFoundException) {
                // Not an error for optional files like witness calculator
                android.util.Log.d("SignedByMe", "Groth16 asset not bundled: $filename (will fail if needed)")
            }
        }
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to extract Groth16 assets: ${e.message}")
    }
}

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Enable StrictMode in debug builds to detect resource leaks
        if (BuildConfig.DEBUG) {
            android.os.StrictMode.setVmPolicy(
                android.os.StrictMode.VmPolicy.Builder()
                    .detectLeakedClosableObjects()
                    .detectLeakedRegistrationObjects()
                    .detectLeakedSqlLiteObjects()
                    .penaltyLog()
                    .build()
            )
            android.os.StrictMode.setThreadPolicy(
                android.os.StrictMode.ThreadPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build()
            )
        }
        
        val didMgr = DidWalletManager(applicationContext)
        // Initialize native library paths for Groth16
        NativeBridge.initNativeLibPath(applicationInfo.nativeLibraryDir)
        
        // Copy bundled test witnesses and initialize prover asynchronously
        lifecycleScope.launch(Dispatchers.IO) {
            didMgr.copyWitnessesFromAssets()
            
            // Extract groth16 assets (membership.dat, membership) from APK
            val groth16Dir = java.io.File(applicationContext.filesDir, "groth16")
            extractGroth16Assets(applicationContext, groth16Dir)
            
            // Initialize Groth16 prover with:
            // - witness calculator from jniLibs or extracted assets
            // - membership.dat from extracted assets
            // - zkey from internal storage (filesDir/groth16/, sideloaded via adb, 85MB)
            val initialized = didMgr.initGroth16Prover(
                nativeLibDir = applicationInfo.nativeLibraryDir,
                groth16Dir = groth16Dir,
                externalFilesDir = applicationContext.getExternalFilesDir(null)
            )
            android.util.Log.i("SignedByMe", "Groth16 prover ready: $initialized")
        }
        
        // Initialize NWC wallet manager (replaces Breez)
        val nwcMgr = NwcWalletManager(applicationContext)
        
        // Initialize NOSTR manager (Phase 9)
        val nostrMgr = NostrManager(applicationContext)
        
        // Parse deep link from intent
        val initialLoginSession = parseLoginIntent(intent)

        setContent {
            SignedByMeTheme {
                SignedByMeApp(didMgr, nwcMgr, nostrMgr, initialLoginSession)
            }
        }
    }
    
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // Re-parse when app receives new intent while running
        // Note: For full implementation, use a ViewModel or state holder
    }
    
    private fun parseLoginIntent(intent: Intent?): LoginSession? {
        val uri = intent?.data ?: return null
        
        // Handle both signedby.me:// and https://signedby.me/login
        if (uri.scheme == "signedby.me" || 
            (uri.scheme == "https" && uri.host == "signedby.me")) {
            
            // New stateless flow: token parameter contains signed JWT
            val token = uri.getQueryParameter("token")
            if (token != null) {
                return parseSessionToken(token)
            }
            
            // Legacy flow: separate parameters (for backwards compatibility)
            val sessionId = uri.getQueryParameter("session")
            val enterprise = uri.getQueryParameter("enterprise") 
                ?: uri.getQueryParameter("employer")  // Fallback for old QR codes
            val amountStr = uri.getQueryParameter("amount")
            val amount = amountStr?.toULongOrNull() ?: 100UL
            // v3 parameters
            val nonce = uri.getQueryParameter("nonce")  // 16 bytes hex = 32 chars
            val expiresStr = uri.getQueryParameter("expires")
            val expiresAt = expiresStr?.toLongOrNull()
            
            if (sessionId != null && enterprise != null) {
                return LoginSession(
                    sessionToken = null,
                    sessionId = sessionId,
                    enterpriseName = enterprise,
                    amountSats = amount,
                    nonce = nonce,
                    expiresAt = expiresAt
                )
            }
        }
        return null
    }
    
    /**
     * Parse a signed session token (JWT) to extract enterprise info.
     * The token is a JWT with payload containing enterprise_name, amount_sats, etc.
     */
    private fun parseSessionToken(token: String): LoginSession? {
        return try {
            // JWT format: header.payload.signature
            val parts = token.split(".")
            if (parts.size != 3) return null
            
            // Decode payload (Base64URL)
            val payloadJson = String(
                android.util.Base64.decode(
                    parts[1].replace('-', '+').replace('_', '/'),
                    android.util.Base64.DEFAULT
                ),
                Charsets.UTF_8
            )
            
            val payload = JSONObject(payloadJson)
            
            LoginSession(
                sessionToken = token,
                sessionId = payload.optString("session_id", ""),
                enterpriseName = payload.optString("enterprise_name", "Unknown"),
                amountSats = payload.optLong("amount_sats", 100).toULong(),
                nonce = payload.optString("nonce", "").ifEmpty { null },
                expiresAt = if (payload.has("expires_at")) payload.optLong("expires_at") else null,
                // Membership fields (v4)
                clientId = payload.optString("client_id", "").ifEmpty { null },
                requiredRootId = payload.optString("required_root_id", "").ifEmpty { null },
                purposeId = payload.optInt("purpose_id", 0)
            )
        } catch (e: Exception) {
            android.util.Log.e("SignedByMe", "Failed to parse session token: ${e.message}")
            null
        }
    }
}

// Data class for login session from deep link / QR
data class LoginSession(
    val sessionToken: String?,  // Full JWT token for stateless API
    val sessionId: String,
    val enterpriseName: String,
    val amountSats: ULong = 100UL,
    val nonce: String? = null,       // v3: 16-byte session nonce (32 hex chars)
    val expiresAt: Long? = null,     // v3: Unix timestamp when session expires
    // Membership fields (v4)
    val clientId: String? = null,         // Enterprise client ID for root lookup
    val requiredRootId: String? = null,   // If set, user MUST prove membership
    val purposeId: Int = 0                // 0=none, 1=allowlist, 2=issuer_batch, 3=revocation
)

// API Configuration
private const val API_BASE_URL = "https://api.beta.privacy-lion.com"
private const val STRIKE_API_BASE = "https://api.strike.me"

// Membership enrollment API key (beta - treated as public, scoped via clients.json)
// Production: will be passed via QR/deep link with short-lived tokens
private const val MEMBERSHIP_API_KEY = "acme-test-key-2026"

/**
 * Send the Lightning invoice to the API (stateless flow).
 * 
 * API will verify the session_token signature, verify STWO proof,
 * then call the enterprise's callback URL with the invoice.
 * Enterprise pays, user gets sats.
 * 
 * Returns true if successful, false otherwise.
 */
private fun sendInvoiceToApi(
    sessionToken: String?,  // JWT from QR code (new stateless flow)
    sessionId: String,      // Legacy fallback
    invoice: String,
    did: String,
    enterpriseName: String,
    amountSats: Long? = null,  // v3: amount binding
    stwoproof: String? = null,
    bindingSignature: String? = null,
    nonce: String? = null
): Boolean {
    return try {
        // Use new stateless endpoint if we have a session token
        val endpoint = if (sessionToken != null) "/v1/login/submit" else "/v1/login/invoice"
        val url = java.net.URL("$API_BASE_URL$endpoint")
        
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10000
            readTimeout = 10000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }
        
        val payload = JSONObject().apply {
            if (sessionToken != null) {
                // New stateless API
                put("session_token", sessionToken)
            } else {
                // Legacy API fallback
                put("session_id", sessionId)
                put("enterprise", enterpriseName)
            }
            put("invoice", invoice)
            put("did", did)
            
            // v3: Include amount for binding verification
            if (amountSats != null) {
                put("amount_sats", amountSats)
            }
            
            // Include STWO proof if available
            if (stwoproof != null) {
                put("stwo_proof", stwoproof)
            }
            if (bindingSignature != null) {
                put("binding_signature", bindingSignature)
            }
            if (nonce != null) {
                put("nonce", nonce)
            }
        }.toString()
        
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
        
        val responseCode = conn.responseCode
        conn.disconnect()
        
        // Success if 2xx response
        responseCode in 200..299
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to send invoice to API: ${e.message}")
        false
    }
}

/**
 * Notify API that payment was settled and DLC completed.
 * Returns the session token for the enterprise.
 */
private fun notifyApiOfSettlement(
    sessionId: String,
    paymentHash: String,
    attestation: DlcManager.OracleAttestation?,
    receipt: DlcManager.SettlementReceipt?
): Boolean {
    return try {
        val url = java.net.URL("$API_BASE_URL/v1/login/session/$sessionId/settled")
        
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10000
            readTimeout = 10000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }
        
        val payload = JSONObject().apply {
            put("session_id", sessionId)
            put("payment_hash", paymentHash)
            put("settled_at", System.currentTimeMillis() / 1000)
            
            if (attestation != null) {
                put("oracle_attestation", JSONObject().apply {
                    put("outcome", attestation.outcome)
                    put("signature_hex", attestation.signatureHex)
                    put("pubkey_hex", attestation.pubkeyHex)
                    put("timestamp", attestation.timestamp)
                })
            }
            
            if (receipt != null) {
                put("receipt", JSONObject().apply {
                    put("audit_hash", receipt.auditHash)
                    put("user_amount_sats", receipt.userAmountSats)
                    put("operator_amount_sats", receipt.operatorAmountSats)
                    put("contract_id", receipt.contractId)
                })
            }
        }.toString()
        
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
        
        val responseCode = conn.responseCode
        conn.disconnect()
        
        android.util.Log.i("SignedByMe", "Settlement notification: $responseCode")
        responseCode in 200..299
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to notify settlement: ${e.message}")
        false
    }
}

/**
 * Membership proof bundle for API submission.
 */
data class MembershipBundle(
    val rootId: String,
    val purpose: String,
    val proofBase64: String
)

/**
 * Result of API call - success flag + optional error message
 */
data class ApiResult(val success: Boolean, val errorMessage: String? = null, val responseBody: String? = null)

private fun sendInvoiceToApiWithDlc(
    sessionToken: String?,
    sessionId: String,
    invoice: String,
    did: String,
    enterpriseName: String,
    amountSats: Long,
    stwoproof: String?,
    nonce: String,
    dlcContractJson: String?,
    membership: MembershipBundle? = null,
    walletAddress: String? = null
): ApiResult {
    return try {
        val endpoint = if (sessionToken != null) "/v1/login/submit" else "/v1/login/invoice"
        val url = java.net.URL("$API_BASE_URL$endpoint")
        
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10000
            readTimeout = 10000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }
        
        val payload = JSONObject().apply {
            if (sessionToken != null) {
                put("session_token", sessionToken)
            } else {
                put("session_id", sessionId)
                put("enterprise", enterpriseName)
            }
            put("invoice", invoice)
            put("did", did)
            put("amount_sats", amountSats)
            put("nonce", nonce)
            
            // Wallet address for binding hash (critical for membership proof)
            if (walletAddress != null) {
                put("wallet_address", walletAddress)
            }
            
            // STWO proof
            if (stwoproof != null) {
                put("stwo_proof", stwoproof)
            }
            
            // DLC contract metadata for 90/10 split
            if (dlcContractJson != null) {
                put("dlc_contract", JSONObject(dlcContractJson))
            }
            
            // Membership proof bundle (v4)
            if (membership != null) {
                put("membership", JSONObject().apply {
                    put("root_id", membership.rootId)
                    put("purpose", membership.purpose)
                    put("proof", membership.proofBase64)
                })
            }
        }.toString()
        
        android.util.Log.i("SignedByMe", "Sending to API: ${payload.take(500)}...")
        
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
        
        val responseCode = conn.responseCode
        val responseBody = try {
            if (responseCode in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: ""
            }
        } catch (e: Exception) { "" }
        
        conn.disconnect()
        
        android.util.Log.i("SignedByMe", "API response: $responseCode - $responseBody")
        
        if (responseCode in 200..299) {
            ApiResult(success = true, responseBody = responseBody)
        } else {
            // Parse error detail from JSON response
            val errorDetail = try {
                JSONObject(responseBody).optString("detail", "Request failed ($responseCode)")
            } catch (e: Exception) {
                "Request failed ($responseCode)"
            }
            ApiResult(success = false, errorMessage = errorDetail)
        }
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to send invoice to API: ${e.message}")
        ApiResult(success = false, errorMessage = "Network error: ${e.message}")
    }
}

/**
 * Fetch current BTC price in USD from CoinGecko API
 */
private suspend fun fetchBtcPrice(): Double = withContext(Dispatchers.IO) {
    try {
        val url = java.net.URL("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd")
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10000
            readTimeout = 10000
        }
        
        val response = conn.inputStream.bufferedReader().readText()
        conn.disconnect()
        
        val json = JSONObject(response)
        json.getJSONObject("bitcoin").getDouble("usd")
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to fetch BTC price: ${e.message}")
        0.0
    }
}

/**
 * Convert satoshis to USD string
 */
fun satsToUsd(sats: Long, btcPrice: Double): String {
    if (btcPrice <= 0) return ""
    val btc = sats / 100_000_000.0
    val usd = btc * btcPrice
    return String.format(Locale.US, "~$%.2f USD", usd)
}

/**
 * Format satoshis with commas
 */
fun formatSats(sats: Long): String {
    return NumberFormat.getNumberInstance(Locale.US).format(sats)
}

@Composable
fun SignedByMeApp(
    didMgr: DidWalletManager, 
    nwcMgr: NwcWalletManager,
    nostrMgr: NostrManager,
    initialLoginSession: LoginSession? = null
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // ===== State =====
    // DID loaded async to avoid blocking main thread
    var did by remember { mutableStateOf<String?>(null) }
    var didErr by remember { mutableStateOf<String?>(null) }
    var step1Complete by remember { mutableStateOf(false) }
    
    // Load DID on IO thread
    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            runCatching { didMgr.getPublicDID() }
                .onSuccess { loadedDid ->
                    did = loadedDid ?: ""
                    step1Complete = loadedDid?.isNotEmpty() == true
                }
                .onFailure { e ->
                    didErr = e.message ?: "Failed to load DID"
                    did = ""  // Mark as loaded (empty)
                }
        }
    }
    
    // Step 2: NWC wallet setup (replaces Breez)
    var step2Complete by remember { mutableStateOf(nwcMgr.hasWallet()) }
    var step3Complete by remember { mutableStateOf(false) }
    
    // Strike wallet onboarding state (Step 2)
    var strikeEmail by remember { mutableStateOf("") }
    var strikeDob by remember { mutableStateOf("") }
    var strikeCountry by remember { mutableStateOf("") }
    var strikeTosAccepted by remember { mutableStateOf(false) }
    var isWalletOnboarding by remember { mutableStateOf(false) }
    var walletOnboardingError by remember { mutableStateOf("") }
    var awaitingEmailVerification by remember { mutableStateOf(false) }
    
    // Login session state (from deep link, QR scan, or demo)
    var loginSession by remember { mutableStateOf(initialLoginSession) }

    // Login/API state
    var lastNonce by remember { mutableStateOf("") }
    var lastLoginId by remember { mutableStateOf("") }
    var lastPreimage by remember { mutableStateOf("") }
    var lastClaimJson by remember { mutableStateOf("") }
    var lastSigHex by remember { mutableStateOf("") }
    var lastPrpJson by remember { mutableStateOf("") }
    var lastInvoice by remember { mutableStateOf("") }
    var lastOperatorInvoice by remember { mutableStateOf("") }
    var lastPaymentHash by remember { mutableStateOf("") }
    
    // DLC state
    var lastDlcContract by remember { mutableStateOf<DlcManager.AuthDlcContract?>(null) }
    var lastSettlementReceipt by remember { mutableStateOf<DlcManager.SettlementReceipt?>(null) }
    val dlcManager = remember { DlcManager() }

    // Login state
    var isLoginActive by remember { mutableStateOf(false) }
    var isCreatingInvoice by remember { mutableStateOf(false) }
    var isPollingPayment by remember { mutableStateOf(false) }
    var paymentReceived by remember { mutableStateOf(false) }
    var showInvoiceDialog by remember { mutableStateOf(false) }
    var invoiceAmountSats by remember { mutableStateOf(100UL) }

    // UI state
    var statusMessage by remember { mutableStateOf("") }
    var showIdDialog by remember { mutableStateOf(false) }
    var showWalletInfoDialog by remember { mutableStateOf(false) }
    var showVccResult by remember { mutableStateOf(false) }
    var vccResult by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var vccId by remember { mutableStateOf("") }
    
    // BTC price for display
    var btcPriceUsd by remember { mutableStateOf(0.0) }

    // Check if onboarding is complete (with delayed transition)
    val onboardingComplete = step1Complete && step2Complete && step3Complete
    var showLoginScreen by remember { mutableStateOf(false) }
    
    // Delay transition to login screen so user sees Step 3 complete
    LaunchedEffect(onboardingComplete) {
        if (onboardingComplete && !showLoginScreen) {
            delay(1500) // 1.5 second delay to see completion
            showLoginScreen = true
        }
    }

    // Poll for payment when invoice is active
    LaunchedEffect(isPollingPayment, lastPaymentHash) {
        if (isPollingPayment && lastPaymentHash.isNotEmpty()) {
            while (isPollingPayment && !paymentReceived) {
                // Poll NWC for payment (3 second timeout per poll)
                val preimage = if (nostrMgr.isNwcConnected()) {
                    nostrMgr.waitForPayment(lastPaymentHash, timeoutSecs = 3)
                } else {
                    null
                }
                val received = preimage != null
                if (received) {
                    val receivedPreimage = preimage ?: ""
                    paymentReceived = true
                    isPollingPayment = false
                    isLoginActive = false
                    
                    // Complete DLC flow
                    try {
                        val attestation = dlcManager.requestOracleSignature(DlcManager.OUTCOME_AUTH_VERIFIED)
                        android.util.Log.i("SignedByMe", "Oracle attestation received: ${attestation.signatureHex.take(16)}...")
                        
                        if (lastDlcContract != null) {
                            lastSettlementReceipt = dlcManager.buildSettlementReceipt(
                                contract = lastDlcContract!!,
                                paymentHash = lastPaymentHash,
                                preimageHex = receivedPreimage.ifEmpty { null },
                                attestation = attestation
                            )
                            
                            val (userAmt, opAmt) = dlcManager.calculatePayouts(lastDlcContract!!.amountSats)
                            statusMessage = "✅ Login verified! You received $userAmt sats (90%)"
                            
                            android.util.Log.i("SignedByMe", "Settlement receipt: ${lastSettlementReceipt?.auditHash}")
                            
                            scope.launch(Dispatchers.IO) {
                                notifyApiOfSettlement(
                                    sessionId = lastLoginId,
                                    paymentHash = lastPaymentHash,
                                    attestation = attestation,
                                    receipt = lastSettlementReceipt
                                )
                                
                                if (nostrMgr.isConnected()) {
                                    nostrMgr.publishPaymentReceipt(
                                        nonce = loginSession?.nonce ?: lastLoginId,
                                        paymentHash = lastPaymentHash,
                                        preimageHex = receivedPreimage,
                                        amountSats = userAmt
                                    )
                                    
                                    nostrMgr.publishLoginComplete(
                                        nonce = loginSession?.nonce ?: lastLoginId,
                                        clientId = loginSession?.clientId ?: "demo"
                                    )
                                    
                                    nostrMgr.disconnect()
                                }
                            }
                        } else {
                            statusMessage = "✅ Payment received! Log In verified."
                            
                            scope.launch(Dispatchers.IO) {
                                if (nostrMgr.isConnected()) {
                                    nostrMgr.publishLoginComplete(
                                        nonce = loginSession?.nonce ?: lastLoginId,
                                        clientId = loginSession?.clientId ?: "demo"
                                    )
                                    nostrMgr.disconnect()
                                }
                            }
                        }
                    } catch (e: Exception) {
                        android.util.Log.e("SignedByMe", "DLC completion error: ${e.message}")
                        statusMessage = "✅ Payment received! Log In verified."
                    }
                    
                    showInvoiceDialog = false
                }
            }
        }
    }
    
    // Fetch BTC price from CoinGecko on start and periodically
    LaunchedEffect(Unit) {
        while (true) {
            try {
                val price = fetchBtcPrice()
                if (price > 0) {
                    btcPriceUsd = price
                }
            } catch (e: Exception) {
                android.util.Log.e("SignedByMe", "Failed to fetch BTC price: ${e.message}")
            }
            delay(60000) // Refresh every minute
        }
    }

    // ===== Screen Routing =====
    // Gate on DID loading state
    if (did == null && didErr == null) {
        // Loading state
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(
                    modifier = Modifier.size(48.dp),
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text("Loading…", style = MaterialTheme.typography.bodyLarge)
            }
        }
    } else if (didErr != null) {
        // Error state
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "Failed to load identity",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = didErr ?: "Unknown error",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(16.dp))
                Button(onClick = {
                    didErr = null
                    did = null
                    scope.launch(Dispatchers.IO) {
                        runCatching { didMgr.getPublicDID() }
                            .onSuccess { loadedDid ->
                                did = loadedDid ?: ""
                                step1Complete = loadedDid?.isNotEmpty() == true
                            }
                            .onFailure { e ->
                                didErr = e.message ?: "Failed to load DID"
                                did = ""
                            }
                    }
                }) {
                    Icon(Icons.Default.Refresh, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Retry")
                }
            }
        }
    } else if (showLoginScreen) {
        // Show Login Screen
        LoginScreen(
            did = did!!,
            vccId = vccId,
            vccResult = vccResult,
            lastInvoice = lastInvoice,
            isCreatingInvoice = isCreatingInvoice,
            isPollingPayment = isPollingPayment,
            paymentReceived = paymentReceived,
            showInvoiceDialog = showInvoiceDialog,
            invoiceAmountSats = loginSession?.amountSats ?: 100UL,
            statusMessage = statusMessage,
            loginSession = loginSession,
            onLoginSessionReceived = { session ->
                loginSession = session
                android.util.Log.i("SignedByMe", "Session received: id=${session.sessionId}, client=${session.clientId}, root=${session.requiredRootId}")
            },
            onCreateDemoSession = {
                scope.launch(Dispatchers.IO) {
                    try {
                        val url = java.net.URL("$API_BASE_URL/v1/login/start")
                        val conn = url.openConnection() as java.net.HttpURLConnection
                        conn.requestMethod = "POST"
                        conn.setRequestProperty("Content-Type", "application/json")
                        conn.setRequestProperty("X-API-Key", "acme-test-key-2026")
                        conn.doOutput = true
                        conn.outputStream.write("""{"client_id":"acme","enterprise":"Acme Corp","amount_sats":100}""".toByteArray())
                        val response = conn.inputStream.bufferedReader().readText()
                        val json = org.json.JSONObject(response)
                        withContext(Dispatchers.Main) {
                            loginSession = LoginSession(
                                sessionToken = null,
                                sessionId = json.getString("session_id"),
                                enterpriseName = json.optString("enterprise", "Acme Corp"),
                                amountSats = json.getLong("amount_sats").toULong(),
                                nonce = json.optString("nonce", ""),
                                clientId = if (json.has("client_id") && !json.isNull("client_id")) json.getString("client_id") else null,
                                requiredRootId = if (json.has("required_root_id") && !json.isNull("required_root_id")) json.getString("required_root_id") else null,
                                purposeId = json.optInt("purpose_id", 0),
                                expiresAt = if (json.has("expires_at")) json.getLong("expires_at") else null
                            )
                        }
                        android.util.Log.i("SignedByMe", "Demo session created: ${json.getString("session_id")}")
                    } catch (e: Exception) {
                        android.util.Log.e("SignedByMe", "Failed to create demo session: ${e.message}")
                    }
                }
            },
            onStartLogin = {
                scope.launch {
                    isCreatingInvoice = true
                    statusMessage = ""
                    
                    // Initialize NOSTR + NWC
                    val leafSecret = didMgr.loadLeafSecret()
                    if (leafSecret != null) {
                        nostrMgr.initializeIdentity(leafSecret)
                        java.util.Arrays.fill(leafSecret, 0.toByte())
                        
                        nostrMgr.generateEphemeralNwcKeypair()
                        
                        nostrMgr.connectToRelays(
                            scope = scope,
                            onConnected = {
                                android.util.Log.i("SignedByMe", "NOSTR relays connected")
                            },
                            onFailed = {
                                android.util.Log.w("SignedByMe", "NOSTR relay connection failed")
                            }
                        )
                        
                        if (nostrMgr.initNwc()) {
                            nostrMgr.connectNwc(
                                scope = scope,
                                onConnected = {
                                    android.util.Log.i("SignedByMe", "NWC connected")
                                },
                                onFailed = {
                                    android.util.Log.w("SignedByMe", "NWC connection failed")
                                }
                            )
                        }
                    } else {
                        android.util.Log.w("SignedByMe", "No leaf_secret - NOSTR/NWC not initialized")
                    }
                    
                    val sessionId = loginSession?.sessionId ?: "demo_${System.currentTimeMillis()}"
                    lastLoginId = sessionId
                    
                    val amountSats = loginSession?.amountSats ?: 100UL
                    val clientId = loginSession?.clientId ?: "demo"
                    
                    // Generate invoices via NWC
                    var userInvoice: String? = null
                    var operatorInvoice: String? = null
                    
                    if (nostrMgr.isNwcConnected()) {
                        val invoices = nostrMgr.generateLoginInvoices(
                            totalSats = amountSats.toLong(),
                            clientId = clientId
                        )
                        if (invoices != null) {
                            userInvoice = invoices.first
                            operatorInvoice = invoices.second
                            android.util.Log.i("SignedByMe", "NWC invoices generated")
                        }
                    }
                    
                    if (userInvoice == null) {
                        statusMessage = "Error: Could not generate invoice. Check wallet connection."
                        isCreatingInvoice = false
                        return@launch
                    }
                    
                    val invoice = userInvoice
                    lastInvoice = invoice
                    lastOperatorInvoice = operatorInvoice ?: ""
                    lastPaymentHash = NativeBridge.extractPaymentHashFromBolt11(invoice)
                    
                    isLoginActive = true
                    isPollingPayment = true
                    
                    // Send to API
                    launch(Dispatchers.IO) {
                        try {
                            val walletAddress = "nwc-wallet"
                                
                            val sessionNonce = loginSession?.nonce?.takeIf { it.length == 32 }
                                ?: run {
                                    val bytes = ByteArray(16)
                                    java.security.SecureRandom().nextBytes(bytes)
                                    bytes.joinToString("") { "%02x".format(it) }
                                }
                            val sessionAmount = loginSession?.amountSats?.toLong() ?: 100L
                            val enterpriseDomain = loginSession?.enterpriseName ?: "demo.signedby.me"
                            
                            val stwoproof = try {
                                didMgr.generateLoginProofV3(
                                    walletAddress = walletAddress,
                                    paymentHashHex = lastPaymentHash,
                                    amountSats = sessionAmount,
                                    eaDomain = enterpriseDomain,
                                    nonceHex = sessionNonce,
                                    expiryMinutes = 5
                                )
                            } catch (e: Exception) {
                                android.util.Log.e("SignedByMe", "Failed to generate v3 login proof: ${e.message}")
                                null
                            }
                            
                            val dlcContract = try {
                                dlcManager.buildAuthContract(
                                    loginId = sessionId,
                                    did = did!!,
                                    amountSats = sessionAmount
                                )
                            } catch (e: Exception) {
                                android.util.Log.e("SignedByMe", "Failed to build DLC contract: ${e.message}")
                                null
                            }

                            withContext(Dispatchers.Main) {
                                lastDlcContract = dlcContract
                            }
                            
                            // Generate membership proof if required
                            var membershipBundle: MembershipBundle? = null
                            val requiredRootId = loginSession?.requiredRootId
                            val requiredClientId = loginSession?.clientId
                            
                            if (requiredRootId != null && requiredClientId != null) {
                                android.util.Log.i("SignedByMe", "Membership required: client=$requiredClientId, root=$requiredRootId")
                                
                                val witness = didMgr.loadWitness(requiredClientId, requiredRootId)
                                if (witness != null) {
                                    val didPubkeyHex = did!!.removePrefix("did:btcr:")
                                    val didPubkeyBytes = didPubkeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                    val paymentHashBytes = lastPaymentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                    val nonceBytes = sessionNonce.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                    
                                    val bindingHash = NativeBridge.computeBindingHashV4(
                                        didPubkey = didPubkeyBytes,
                                        walletAddress = walletAddress,
                                        clientId = requiredClientId,
                                        sessionId = sessionId,
                                        paymentHash = paymentHashBytes,
                                        amountSats = sessionAmount,
                                        expiresAt = loginSession?.expiresAt ?: (System.currentTimeMillis() / 1000 + 300),
                                        nonce = nonceBytes,
                                        eaDomain = enterpriseDomain,
                                        purposeId = witness.purposeId,
                                        rootId = requiredRootId
                                    )
                                    
                                    val sessionIdDecoded = android.util.Base64.decode(
                                        sessionId, 
                                        android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING
                                    )
                                    val sessionIdBytes = ByteArray(32)
                                    sessionIdDecoded.copyInto(sessionIdBytes, 0, 0, minOf(sessionIdDecoded.size, 32))
                                    val proofBase64 = didMgr.generateMembershipProof(witness, bindingHash, sessionIdBytes)
                                    if (proofBase64 != null) {
                                        membershipBundle = MembershipBundle(
                                            rootId = requiredRootId,
                                            purpose = didMgr.purposeIdToString(witness.purposeId),
                                            proofBase64 = proofBase64
                                        )
                                        android.util.Log.i("SignedByMe", "Membership proof generated successfully")
                                    } else {
                                        android.util.Log.e("SignedByMe", "Failed to generate membership proof")
                                        withContext(Dispatchers.Main) {
                                            statusMessage = "Error: Could not generate membership proof."
                                        }
                                        return@launch
                                    }
                                } else {
                                    android.util.Log.e("SignedByMe", "No witness found for client=$requiredClientId, root=$requiredRootId")
                                    withContext(Dispatchers.Main) {
                                        statusMessage = "Error: Not enrolled with this employer."
                                    }
                                    return@launch
                                }
                            }
                            
                            // Publish proof_event to NOSTR
                            if (nostrMgr.isConnected()) {
                                val proofHex = membershipBundle?.proofBase64 ?: ""
                                val merkleRoot = ""
                                val npub = nostrMgr.getNpub() ?: ""
                                
                                scope.launch(Dispatchers.IO) {
                                    nostrMgr.publishProofEvent(
                                        nonce = sessionNonce,
                                        clientId = clientId,
                                        proofHex = proofHex,
                                        merkleRoot = merkleRoot,
                                        userInvoice = invoice,
                                        operatorInvoice = lastOperatorInvoice
                                    )
                                }
                            }
                            
                            // Submit to API
                            val apiResult = sendInvoiceToApiWithDlc(
                                sessionToken = loginSession?.sessionToken,
                                sessionId = sessionId,
                                invoice = invoice,
                                did = did!!,
                                enterpriseName = enterpriseDomain,
                                amountSats = sessionAmount,
                                stwoproof = stwoproof,
                                nonce = sessionNonce,
                                dlcContractJson = dlcContract?.toJson(),
                                membership = membershipBundle,
                                walletAddress = walletAddress
                            )
                            
                            withContext(Dispatchers.Main) {
                                if (!apiResult.success) {
                                    statusMessage = "Error: ${apiResult.errorMessage ?: "Could not reach API"}"
                                }
                            }
                        } catch (e: Exception) {
                            withContext(Dispatchers.Main) {
                                statusMessage = "API error: ${e.message}"
                            }
                        }
                    }
                    
                    isCreatingInvoice = false
                }
            },
            onShowInvoiceDialog = { showInvoiceDialog = true },
            onDismissInvoiceDialog = { showInvoiceDialog = false },
            onCopyInvoice = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Lightning Invoice", lastInvoice))
                Toast.makeText(context, "Invoice copied!", Toast.LENGTH_SHORT).show()
            },
            onShareInvoice = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, lastInvoice)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share Invoice"))
            },
            onResetLogin = {
                lastInvoice = ""
                lastOperatorInvoice = ""
                lastPaymentHash = ""
                lastLoginId = ""
                lastDlcContract = null
                lastSettlementReceipt = null
                isLoginActive = false
                isPollingPayment = false
                paymentReceived = false
                showInvoiceDialog = false
                statusMessage = ""
                loginSession = null
            },
            onCopyVcc = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("VCC", vccResult))
                Toast.makeText(context, "VCC copied!", Toast.LENGTH_SHORT).show()
            },
            onShareVcc = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, vccResult)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share VCC"))
            },
            onDevExportLeafCommitment = if (BuildConfig.DEBUG) {
                {
                    val cid = loginSession?.clientId
                    val rid = loginSession?.requiredRootId
                    if (cid != null && rid != null) {
                        scope.launch {
                            val commitment = withContext(Dispatchers.IO) {
                                didMgr.devExportLeafCommitment(cid, rid)
                            }
                            if (commitment != null) {
                                Toast.makeText(context, "Leaf commitment exported to logcat", Toast.LENGTH_LONG).show()
                            } else {
                                Toast.makeText(context, "Failed to export commitment", Toast.LENGTH_SHORT).show()
                            }
                        }
                    } else {
                        Toast.makeText(context, "No active session - scan a QR first", Toast.LENGTH_SHORT).show()
                    }
                }
            } else null,
            btcPriceUsd = btcPriceUsd,
            strikeEmail = nwcMgr.getStrikeEmail()
        )
    } else {
        // Show Onboarding Screen
        OnboardingScreen(
            did = did!!,
            step1Complete = step1Complete,
            step2Complete = step2Complete,
            step3Complete = step3Complete,
            isWalletOnboarding = isWalletOnboarding,
            walletOnboardingError = walletOnboardingError,
            awaitingEmailVerification = awaitingEmailVerification,
            strikeEmail = strikeEmail,
            strikeDob = strikeDob,
            strikeCountry = strikeCountry,
            strikeTosAccepted = strikeTosAccepted,
            isLoading = isLoading,
            statusMessage = statusMessage,
            showIdDialog = showIdDialog,
            showWalletInfoDialog = showWalletInfoDialog,
            showVccResult = showVccResult,
            vccResult = vccResult,
            onGenerateDid = {
                did = didMgr.createDid()
                step1Complete = true
            },
            onShowIdDialog = { showIdDialog = true },
            onDismissIdDialog = { showIdDialog = false },
            onRegenerateDid = {
                did = didMgr.regenerateKeyPair()
                step1Complete = true
                step2Complete = false
                step3Complete = false
            },
            onCopyDid = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("DID", did!!))
                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
            },
            // Step 2: Strike wallet onboarding
            onStrikeEmailChange = { strikeEmail = it },
            onStrikeDobChange = { strikeDob = it },
            onStrikeCountryChange = { strikeCountry = it },
            onStrikeTosChange = { strikeTosAccepted = it },
            onSubmitStrikeOnboarding = {
                // Validate inputs
                if (strikeEmail.isEmpty() || !strikeEmail.contains("@")) {
                    walletOnboardingError = "Please enter a valid email address"
                    return@OnboardingScreen
                }
                if (strikeDob.isEmpty()) {
                    walletOnboardingError = "Please enter your date of birth"
                    return@OnboardingScreen
                }
                if (strikeCountry.isEmpty()) {
                    walletOnboardingError = "Please select your country"
                    return@OnboardingScreen
                }
                if (!strikeTosAccepted) {
                    walletOnboardingError = "Please accept Strike's Terms of Service"
                    return@OnboardingScreen
                }
                
                walletOnboardingError = ""
                isWalletOnboarding = true
                
                // Record ToS acceptance
                nwcMgr.recordTosAcceptance(strikeEmail)
                
                scope.launch(Dispatchers.IO) {
                    try {
                        // TODO: Call Strike partner API to provision embedded wallet
                        // For now, simulate the flow
                        // Strike will send verification email to user
                        // App handles deep link callback when user taps email link
                        
                        // Simulate API call delay
                        delay(2000)
                        
                        withContext(Dispatchers.Main) {
                            awaitingEmailVerification = true
                            isWalletOnboarding = false
                            statusMessage = "Check your email to verify your Strike wallet"
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            walletOnboardingError = "Error: ${e.message}"
                            isWalletOnboarding = false
                        }
                    }
                }
            },
            onStrikeCallbackReceived = { nwcConnectionString ->
                // Called when deep link callback returns with NWC connection string
                scope.launch {
                    try {
                        nwcMgr.storeNwcConnectionString(nwcConnectionString)
                        step2Complete = true
                        awaitingEmailVerification = false
                        statusMessage = "Wallet connected!"
                    } catch (e: Exception) {
                        walletOnboardingError = "Failed to save wallet: ${e.message}"
                    }
                }
            },
            onShowWalletInfoDialog = { showWalletInfoDialog = true },
            onDismissWalletInfoDialog = { showWalletInfoDialog = false },
            onGenerateSignature = {
                isLoading = true
                scope.launch(Dispatchers.IO) {
                    try {
                        var preimage = lastPreimage
                        if (preimage.isEmpty()) {
                            val bytes = ByteArray(32)
                            java.security.SecureRandom().nextBytes(bytes)
                            preimage = bytes.joinToString("") { "%02x".format(it) }
                            withContext(Dispatchers.Main) { lastPreimage = preimage }
                        }

                        val claimJson = didMgr.buildOwnershipClaimJson(
                            did = did!!,
                            nonce = lastNonce.ifEmpty { "android-${System.currentTimeMillis()}" },
                            walletType = "nwc",
                            withdrawTo = "nwc-wallet",
                            preimage = preimage
                        )

                        val sigHex = didMgr.signOwnershipClaim(claimJson)

                        val preBytes = preimage.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        val md = java.security.MessageDigest.getInstance("SHA-256")
                        val preShaHex = md.digest(preBytes).joinToString("") { "%02x".format(it) }

                        val prpJson = didMgr.buildPrpJson(
                            loginId = lastLoginId.ifEmpty { "android-${System.currentTimeMillis()}" },
                            did = did!!,
                            preimageSha256Hex = preShaHex
                        )
                        
                        val groth16Result = didMgr.generateGroth16Proof(
                            clientId = "default",
                            rootId = "default"
                        )
                        val groth16Json = JSONObject(groth16Result)
                        val proofHash = if (groth16Json.optBoolean("success", false)) {
                            val md2 = java.security.MessageDigest.getInstance("SHA-256")
                            md2.digest(groth16Result.toByteArray(Charsets.UTF_8))
                                .joinToString("") { "%02x".format(it) }
                        } else {
                            android.util.Log.w("SignedByMe", "Groth16 proof stub: ${groth16Json.optString("error", "unknown")}")
                            "stub_proof_${System.currentTimeMillis()}"
                        }

                        val generatedVccId = "vcc_${System.currentTimeMillis()}_${did!!.takeLast(8)}"
                        val vcc = JSONObject().apply {
                            put("schema", "signedby.me/vcc/3")
                            put("id", generatedVccId)
                            put("did", did!!)
                            put("wallet_address", "nwc-wallet")
                            put("content_hash", "sha256_demo_${System.currentTimeMillis()}")
                            put("proof_hash", preShaHex)
                            put("groth16_proof_hash", proofHash)
                            put("wallet_type", "nwc")
                            put("timestamp", System.currentTimeMillis())
                            put("expires_at", System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000)
                            put("signature", sigHex)
                        }.toString()

                        // Auto-enroll for membership
                        if (!didMgr.hasEnrollment()) {
                            try {
                                val enrollment = didMgr.enrollMembership(
                                    apiBaseUrl = API_BASE_URL,
                                    apiKey = MEMBERSHIP_API_KEY,
                                    did = did!!,
                                    purpose = "allowlist"
                                )
                                if (enrollment != null) {
                                    android.util.Log.i("SignedByMe", "Auto-enrolled for membership: ${enrollment.enrollmentId}")
                                }
                            } catch (e: Exception) {
                                android.util.Log.w("SignedByMe", "Membership enrollment error (non-blocking): ${e.message}")
                            }
                        }

                        withContext(Dispatchers.Main) {
                            lastClaimJson = claimJson
                            lastSigHex = sigHex
                            lastPrpJson = prpJson
                            vccResult = vcc
                            vccId = generatedVccId
                            step3Complete = true
                            showVccResult = true
                            isLoading = false
                            statusMessage = "Signature generated!"
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            statusMessage = "Error: ${e.message}"
                            isLoading = false
                        }
                    }
                }
            },
            onCopyVcc = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("VCC", vccResult))
                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
            },
            onShareVcc = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, vccResult)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share VCC"))
            }
        )
    }

    // Dialogs
    if (showIdDialog) {
        DIDInfoDialog(
            did = did!!,
            onDismiss = { showIdDialog = false },
            onRegenerate = {
                did = didMgr.regenerateKeyPair()
                step1Complete = true
                step2Complete = false
                step3Complete = false
            },
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("DID", did!!))
                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (showWalletInfoDialog) {
        WalletInfoDialog(
            strikeEmail = nwcMgr.getStrikeEmail() ?: "",
            isConnected = nwcMgr.isConnected(),
            onDismiss = { showWalletInfoDialog = false }
        )
    }
}

// ===== Onboarding Screen =====
@Composable
fun OnboardingScreen(
    did: String,
    step1Complete: Boolean,
    step2Complete: Boolean,
    step3Complete: Boolean,
    isWalletOnboarding: Boolean,
    walletOnboardingError: String,
    awaitingEmailVerification: Boolean,
    strikeEmail: String,
    strikeDob: String,
    strikeCountry: String,
    strikeTosAccepted: Boolean,
    isLoading: Boolean,
    statusMessage: String,
    showIdDialog: Boolean,
    showWalletInfoDialog: Boolean,
    showVccResult: Boolean,
    vccResult: String,
    onGenerateDid: () -> Unit,
    onShowIdDialog: () -> Unit,
    onDismissIdDialog: () -> Unit,
    onRegenerateDid: () -> Unit,
    onCopyDid: () -> Unit,
    onStrikeEmailChange: (String) -> Unit,
    onStrikeDobChange: (String) -> Unit,
    onStrikeCountryChange: (String) -> Unit,
    onStrikeTosChange: (Boolean) -> Unit,
    onSubmitStrikeOnboarding: () -> Unit,
    onStrikeCallbackReceived: (String) -> Unit,
    onShowWalletInfoDialog: () -> Unit,
    onDismissWalletInfoDialog: () -> Unit,
    onGenerateSignature: () -> Unit,
    onCopyVcc: () -> Unit,
    onShareVcc: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    colors = listOf(
                        Color(0xFFF7FAFF),
                        Color(0xFFF0F5FE),
                        Color(0xFFE6F0FC)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Header
            Text(
                text = "SignedByMe",
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
                style = LocalTextStyle.current.copy(
                    brush = Brush.linearGradient(
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6))
                    )
                )
            )

            Text(
                text = "Start by pressing the button below in Step 1",
                fontSize = 16.sp,
                color = Color.Gray,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            // Step 1: Create
            StepCard(
                stepNumber = 1,
                title = "Create",
                isComplete = step1Complete,
                isEnabled = true
            ) {
                if (!step1Complete) {
                    Text(
                        "Press button below to start",
                        color = Color.Gray,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    GradientButton(
                        text = "Generate",
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                        onClick = onGenerateDid
                    )
                } else {
                    CompletedStepContent(
                        message = "Signature created ✓",
                        onInfoClick = onShowIdDialog
                    )
                }
            }

            // Step 2: Connect (Strike Wallet)
            StepCard(
                stepNumber = 2,
                title = "Connect",
                isComplete = step2Complete,
                isEnabled = step1Complete
            ) {
                if (!step2Complete) {
                    if (awaitingEmailVerification) {
                        // Waiting for email verification
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text("📧", fontSize = 48.sp)
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                "Check your email",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "We sent a verification link to $strikeEmail. Tap the link to connect your wallet.",
                                fontSize = 14.sp,
                                color = Color.Gray,
                                textAlign = TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(16.dp))
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                color = Color(0xFF3B82F6),
                                strokeWidth = 2.dp
                            )
                        }
                    } else {
                        // Strike wallet onboarding form
                        Text(
                            "Set up your Lightning wallet with Strike",
                            color = Color.Gray,
                            fontSize = 14.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        Box(
                            modifier = Modifier.fillMaxWidth(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(text = "⚡", fontSize = 48.sp)
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        // Email field
                        OutlinedTextField(
                            value = strikeEmail,
                            onValueChange = onStrikeEmailChange,
                            label = { Text("Email address") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            enabled = !isWalletOnboarding,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email)
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        // Date of birth field
                        OutlinedTextField(
                            value = strikeDob,
                            onValueChange = onStrikeDobChange,
                            label = { Text("Date of birth (MM/DD/YYYY)") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            enabled = !isWalletOnboarding,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        // Country dropdown (simplified as text field for now)
                        OutlinedTextField(
                            value = strikeCountry,
                            onValueChange = onStrikeCountryChange,
                            label = { Text("Country of residence") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            enabled = !isWalletOnboarding
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        // ToS checkbox
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable(enabled = !isWalletOnboarding) { 
                                    onStrikeTosChange(!strikeTosAccepted) 
                                },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = strikeTosAccepted,
                                onCheckedChange = { onStrikeTosChange(it) },
                                enabled = !isWalletOnboarding
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "I agree to Strike's Terms of Service",
                                fontSize = 14.sp,
                                color = if (strikeTosAccepted) Color.Black else Color.Gray
                            )
                        }

                        // Error message
                        if (walletOnboardingError.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                walletOnboardingError,
                                color = Color(0xFFEF4444),
                                fontSize = 12.sp,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        if (isWalletOnboarding) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(40.dp),
                                    color = Color(0xFF3B82F6)
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Text("Setting up wallet...", fontSize = 14.sp, color = Color.Gray)
                            }
                        } else {
                            GradientButton(
                                text = "Set Up Wallet",
                                colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                                onClick = onSubmitStrikeOnboarding
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        // Recovery info
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF3C7)),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.Top
                            ) {
                                Text("🔒", fontSize = 14.sp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "Your wallet is recovered via your Strike email. No seed words needed.",
                                    fontSize = 12.sp,
                                    color = Color(0xFF92400E)
                                )
                            }
                        }
                    }
                } else {
                    CompletedStepContent(
                        message = "Wallet connected ✓",
                        onInfoClick = onShowWalletInfoDialog
                    )
                }
            }

            // Step 3: Prove
            StepCard(
                stepNumber = 3,
                title = "Prove",
                isComplete = step3Complete,
                isEnabled = step1Complete && step2Complete
            ) {
                if (!step3Complete) {
                    Text(
                        "Press button below to generate your Signature",
                        fontSize = 14.sp,
                        color = Color.Gray,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    if (isLoading) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(40.dp),
                                color = Color(0xFFEF4444)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("Generating...", fontSize = 14.sp, color = Color.Gray)
                        }
                    } else {
                        GradientButton(
                            text = "Generate Signature",
                            colors = listOf(Color(0xFFEF4444), Color(0xFFF97316)),
                            enabled = step2Complete,
                            onClick = onGenerateSignature
                        )
                    }
                } else {
                    StatusPill("Signature Verified ✓", Color(0xFF10B981))
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    Text(
                        "Setup complete! You're ready to use SignedByMe.",
                        fontSize = 14.sp,
                        color = Color(0xFF10B981),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }

            // Status message
            if (statusMessage.isNotEmpty()) {
                Text(
                    text = statusMessage,
                    fontSize = 12.sp,
                    color = Color.Gray,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(40.dp))
        }
    }
}

// ===== Login Screen (Simplified - No Wallet UI) =====
@Composable
fun LoginScreen(
    did: String,
    vccId: String,
    vccResult: String,
    lastInvoice: String,
    isCreatingInvoice: Boolean,
    isPollingPayment: Boolean,
    paymentReceived: Boolean,
    showInvoiceDialog: Boolean,
    invoiceAmountSats: ULong,
    statusMessage: String,
    loginSession: LoginSession?,
    onLoginSessionReceived: (LoginSession) -> Unit,
    onCreateDemoSession: () -> Unit,
    onStartLogin: () -> Unit,
    onShowInvoiceDialog: () -> Unit,
    onDismissInvoiceDialog: () -> Unit,
    onCopyInvoice: () -> Unit,
    onShareInvoice: () -> Unit,
    onResetLogin: () -> Unit,
    onCopyVcc: () -> Unit,
    onShareVcc: () -> Unit,
    onDevExportLeafCommitment: (() -> Unit)? = null,
    btcPriceUsd: Double,
    strikeEmail: String?
) {
    var showQrScanner by remember { mutableStateOf(false) }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    colors = listOf(
                        Color(0xFFF7FAFF),
                        Color(0xFFF0F5FE),
                        Color(0xFFE6F0FC)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(40.dp))

            // Header
            Text(
                text = "SignedByMe",
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
                style = LocalTextStyle.current.copy(
                    brush = Brush.linearGradient(
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6))
                    )
                )
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Ready to Log In",
                fontSize = 16.sp,
                color = Color.Gray
            )

            Spacer(modifier = Modifier.height(32.dp))

            // Login Section Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(8.dp, RoundedCornerShape(24.dp)),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    // Employer badge
                    if (loginSession != null && !paymentReceived) {
                        Row(
                            modifier = Modifier
                                .align(Alignment.TopStart)
                                .padding(12.dp)
                                .background(
                                    Color(0xFF10B981).copy(alpha = 0.1f),
                                    RoundedCornerShape(20.dp)
                                )
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFF10B981),
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = loginSession.enterpriseName,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFF10B981)
                            )
                        }
                    }
                    
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp)
                            .padding(top = if (loginSession != null && !paymentReceived) 24.dp else 0.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (paymentReceived) {
                            // Success state
                            Box(
                                modifier = Modifier
                                    .size(64.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFF10B981).copy(alpha = 0.1f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = Color(0xFF10B981),
                                    modifier = Modifier.size(40.dp)
                                )
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            Text(
                                "Log In Verified!",
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF10B981)
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                if (loginSession != null) 
                                    "You're now logged in to ${loginSession.enterpriseName}"
                                else 
                                    "Your identity has been verified.",
                                fontSize = 14.sp,
                                color = Color.Gray,
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            OutlinedButton(onClick = onResetLogin) {
                                Text("Start New Log In")
                            }

                        } else if (lastInvoice.isNotEmpty()) {
                            // Awaiting payment state
                            Text("⏳", fontSize = 48.sp)

                            Spacer(modifier = Modifier.height(12.dp))

                            Text(
                                "Awaiting Payment",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFFF59E0B)
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            if (loginSession != null) {
                                Text(
                                    "Waiting for ${loginSession.enterpriseName} to confirm",
                                    fontSize = 14.sp,
                                    color = Color.Gray,
                                    textAlign = TextAlign.Center
                                )
                            }

                            if (isPollingPayment) {
                                Spacer(modifier = Modifier.height(12.dp))
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.Center
                                ) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = Color(0xFFF59E0B)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        "Checking for payment...",
                                        fontSize = 12.sp,
                                        color = Color.Gray
                                    )
                                }
                            }
                            
                            // Debug buttons
                            if (BuildConfig.DEBUG) {
                                Spacer(modifier = Modifier.height(16.dp))
                                OutlinedButton(
                                    onClick = onShowInvoiceDialog,
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = Color.Gray
                                    )
                                ) {
                                    Text("View Invoice (Debug)", fontSize = 12.sp)
                                }
                                
                                if (onDevExportLeafCommitment != null) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    OutlinedButton(
                                        onClick = onDevExportLeafCommitment,
                                        colors = ButtonDefaults.outlinedButtonColors(
                                            contentColor = Color.Gray
                                        )
                                    ) {
                                        Text("Export Leaf Commitment (Debug)", fontSize = 12.sp)
                                    }
                                }
                            }

                        } else {
                            // Ready to start login
                            if (loginSession != null) {
                                Text("🔐", fontSize = 48.sp)

                                Spacer(modifier = Modifier.height(12.dp))

                                Text(
                                    "Ready to Log In",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.SemiBold
                                )

                                Spacer(modifier = Modifier.height(8.dp))

                                Text(
                                    "Press button below to start your Log In with your Signature",
                                    fontSize = 14.sp,
                                    color = Color.Gray,
                                    textAlign = TextAlign.Center
                                )

                                Spacer(modifier = Modifier.height(20.dp))

                                if (isCreatingInvoice) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(40.dp),
                                        color = Color(0xFF3B82F6)
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text("Creating invoice...", fontSize = 13.sp, color = Color.Gray)
                                } else {
                                    GradientButton(
                                        text = "Start Log In",
                                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                                        onClick = onStartLogin
                                    )
                                }
                            } else {
                                // No session yet - show scan QR option
                                Text("📷", fontSize = 48.sp)

                                Spacer(modifier = Modifier.height(12.dp))

                                Text(
                                    "Scan Log In QR Code",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.SemiBold
                                )

                                Spacer(modifier = Modifier.height(8.dp))

                                Text(
                                    "Scan the QR Code on your computer to Log In",
                                    fontSize = 14.sp,
                                    color = Color.Gray,
                                    textAlign = TextAlign.Center
                                )

                                Spacer(modifier = Modifier.height(20.dp))

                                GradientButton(
                                    text = "Scan QR Code",
                                    colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                                    onClick = { showQrScanner = true }
                                )

                                Spacer(modifier = Modifier.height(16.dp))

                                OutlinedButton(onClick = onCreateDemoSession) {
                                    Text("Demo: Acme Corp Log In (100 sats)", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }

            // Wallet info card
            if (strikeEmail != null) {
                Spacer(modifier = Modifier.height(16.dp))
                
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.8f))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("⚡", fontSize = 24.sp)
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                "Strike Wallet",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                strikeEmail,
                                fontSize = 12.sp,
                                color = Color.Gray
                            )
                        }
                    }
                }
            }

            // VCC Section
            if (vccResult.isNotEmpty()) {
                Spacer(modifier = Modifier.height(24.dp))
                
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(8.dp, RoundedCornerShape(24.dp)),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp)
                    ) {
                        Text(
                            "Your Verified Content Claim (VCC)",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            "Use your VCC to prove your content is yours.",
                            fontSize = 13.sp,
                            color = Color.Gray,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        StatusPill("Verified Content Claim", Color(0xFF10B981))
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Text(
                            text = vccResult.take(60) + "...",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Gray,
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF3F4F6), RoundedCornerShape(8.dp))
                                .padding(12.dp)
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            OutlinedButton(
                                onClick = onCopyVcc,
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("📋 Copy")
                            }
                            
                            OutlinedButton(
                                onClick = onShareVcc,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Share")
                            }
                        }
                    }
                }
            }

            // Status message
            if (statusMessage.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = statusMessage,
                    fontSize = 12.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(40.dp))
        }
    }

    // Invoice Dialog
    if (showInvoiceDialog && lastInvoice.isNotEmpty()) {
        InvoiceDialog(
            invoice = lastInvoice,
            amountSats = invoiceAmountSats.toLong(),
            isPolling = isPollingPayment,
            onDismiss = onDismissInvoiceDialog,
            onCopy = onCopyInvoice,
            onShare = onShareInvoice
        )
    }
    
    // QR Scanner Dialog
    if (showQrScanner) {
        QrScannerDialog(
            onQrScanned = { qrContent ->
                showQrScanner = false
                try {
                    val uri = android.net.Uri.parse(qrContent)
                    
                    val token = uri.getQueryParameter("token")
                    if (token != null) {
                        val parts = token.split(".")
                        if (parts.size == 3) {
                            val payloadJson = String(
                                android.util.Base64.decode(
                                    parts[1].replace('-', '+').replace('_', '/'),
                                    android.util.Base64.DEFAULT
                                ),
                                Charsets.UTF_8
                            )
                            val payload = org.json.JSONObject(payloadJson)
                            onLoginSessionReceived(LoginSession(
                                sessionToken = token,
                                sessionId = payload.optString("session_id", ""),
                                enterpriseName = payload.optString("enterprise_name", "Unknown"),
                                amountSats = payload.optLong("amount_sats", 100).toULong(),
                                nonce = payload.optString("nonce", "").ifEmpty { null },
                                expiresAt = if (payload.has("expires_at")) payload.optLong("expires_at") else null
                            ))
                            return@QrScannerDialog
                        }
                    }
                    
                    val sessionId = uri.getQueryParameter("session")
                    val enterprise = uri.getQueryParameter("enterprise")
                        ?: uri.getQueryParameter("employer")
                    val amountStr = uri.getQueryParameter("amount")
                    val amount = amountStr?.toULongOrNull() ?: 100UL
                    val nonce = uri.getQueryParameter("nonce")
                    val expiresStr = uri.getQueryParameter("expires")
                    val expiresAt = expiresStr?.toLongOrNull()
                    
                    if (sessionId != null && enterprise != null) {
                        onLoginSessionReceived(LoginSession(
                            sessionToken = null,
                            sessionId = sessionId,
                            enterpriseName = enterprise,
                            amountSats = amount,
                            nonce = nonce,
                            expiresAt = expiresAt
                        ))
                    }
                } catch (e: Exception) {
                    // Invalid QR format
                }
            },
            onDismiss = { showQrScanner = false }
        )
    }
}

// ===== QR Scanner Dialog =====
@Composable
fun QrScannerDialog(
    onQrScanned: (String) -> Unit,
    onDismiss: () -> Unit,
    title: String = "Scan Log In QR Code",
    subtitle: String = "Point your camera at the QR Code on your computer screen"
) {
    val context = LocalContext.current
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    var hasCameraPermission by remember {
        mutableStateOf(
            androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.CAMERA
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        )
    }
    
    var cameraProviderRef by remember { mutableStateOf<androidx.camera.lifecycle.ProcessCameraProvider?>(null) }
    val analysisExecutor = remember { java.util.concurrent.Executors.newSingleThreadExecutor() }
    var barcodeScanner by remember { mutableStateOf<com.google.mlkit.vision.barcode.BarcodeScanner?>(null) }
    var isDisposed by remember { mutableStateOf(false) }
    
    LaunchedEffect(Unit) {
        barcodeScanner = withContext(Dispatchers.IO) {
            com.google.mlkit.vision.barcode.BarcodeScanning.getClient()
        }
    }
    
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }
    
    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(android.Manifest.permission.CAMERA)
        }
    }
    
    DisposableEffect(Unit) {
        onDispose {
            isDisposed = true
            cameraProviderRef?.unbindAll()
            analysisExecutor.shutdown()
            barcodeScanner?.close()
        }
    }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(0.8f),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    title,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    subtitle,
                    fontSize = 13.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                if (hasCameraPermission) {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color.Black)
                    ) {
                        AndroidView(
                            factory = { ctx ->
                                val previewView = androidx.camera.view.PreviewView(ctx)
                                val cameraProviderFuture = androidx.camera.lifecycle.ProcessCameraProvider.getInstance(ctx)
                                
                                cameraProviderFuture.addListener({
                                    val cameraProvider = cameraProviderFuture.get()
                                    
                                    val preview = androidx.camera.core.Preview.Builder().build().also {
                                        it.setSurfaceProvider(previewView.surfaceProvider)
                                    }
                                    
                                    val imageAnalysis = androidx.camera.core.ImageAnalysis.Builder()
                                        .setBackpressureStrategy(androidx.camera.core.ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                        .build()
                                        .also { analysis ->
                                            analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                                                @androidx.camera.core.ExperimentalGetImage
                                                val mediaImage = imageProxy.image
                                                val scanner = barcodeScanner
                                                if (mediaImage != null && scanner != null) {
                                                    val inputImage = com.google.mlkit.vision.common.InputImage.fromMediaImage(
                                                        mediaImage, imageProxy.imageInfo.rotationDegrees
                                                    )
                                                    
                                                    scanner.process(inputImage)
                                                        .addOnSuccessListener { barcodes ->
                                                            if (isDisposed) return@addOnSuccessListener
                                                            for (barcode in barcodes) {
                                                                barcode.rawValue?.let { value ->
                                                                    if (value.contains("session=") && value.contains("enterprise=")) {
                                                                        onQrScanned(value)
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        .addOnCompleteListener {
                                                            imageProxy.close()
                                                        }
                                                } else {
                                                    imageProxy.close()
                                                }
                                            }
                                        }
                                    
                                    if (isDisposed) return@addListener
                                    
                                    try {
                                        cameraProvider.unbindAll()
                                        cameraProviderRef = cameraProvider
                                        cameraProvider.bindToLifecycle(
                                            lifecycleOwner,
                                            androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA,
                                            preview,
                                            imageAnalysis
                                        )
                                    } catch (e: Exception) {
                                        e.printStackTrace()
                                    }
                                }, androidx.core.content.ContextCompat.getMainExecutor(ctx))
                                
                                previewView
                            },
                            modifier = Modifier.fillMaxSize()
                        )
                        
                        // Scanning frame overlay
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(40.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(200.dp)
                                    .border(3.dp, Color.White, RoundedCornerShape(12.dp))
                            )
                        }
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "Camera permission required",
                            color = Color.Gray
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}

// ===== Components =====

@Composable
fun StepCard(
    stepNumber: Int,
    title: String,
    isComplete: Boolean,
    isEnabled: Boolean,
    content: @Composable ColumnScope.() -> Unit
) {
    val alphaValue = if (isEnabled) 1f else 0.6f

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .alpha(alphaValue)
            .shadow(
                elevation = if (isEnabled) 12.dp else 4.dp,
                shape = RoundedCornerShape(24.dp),
                ambientColor = Color.Black.copy(alpha = 0.08f)
            ),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.85f))
    ) {
        Column(modifier = Modifier.padding(24.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(
                            if (isComplete) {
                                Brush.linearGradient(listOf(Color(0xFF10B981), Color(0xFF34D399)))
                            } else if (isEnabled) {
                                Brush.linearGradient(listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)))
                            } else {
                                Brush.linearGradient(listOf(Color.Gray, Color.Gray))
                            }
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    if (isComplete) {
                        Icon(
                            Icons.Default.Check,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(28.dp)
                        )
                    } else {
                        Text(
                            text = "$stepNumber",
                            color = Color.White,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.width(16.dp))

                Text(
                    text = title,
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (isEnabled) Color.Black else Color.Gray
                )
            }

            if (isEnabled || isComplete) {
                Spacer(modifier = Modifier.height(20.dp))
                content()
            }
        }
    }
}

@Composable
fun GradientButton(
    text: String,
    colors: List<Color>,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .height(56.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        contentPadding = PaddingValues(0.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    if (enabled) Brush.linearGradient(colors)
                    else Brush.linearGradient(listOf(Color.Gray, Color.Gray))
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = text,
                color = Color.White,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
fun StatusPill(text: String, color: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color.White, RoundedCornerShape(12.dp))
            .border(1.dp, Color.Black.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = text,
            fontWeight = FontWeight.SemiBold,
            fontSize = 16.sp
        )
    }
}

@Composable
fun CompletedStepContent(
    message: String,
    onInfoClick: (() -> Unit)?
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color.White.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
            .border(1.dp, Color.Gray.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = message,
            fontSize = 14.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f)
        )
        if (onInfoClick != null) {
            IconButton(onClick = onInfoClick) {
                Icon(
                    Icons.Default.Info,
                    contentDescription = "Info",
                    tint = Color(0xFF3B82F6)
                )
            }
        }
    }
}

@Composable
fun DIDInfoDialog(
    did: String,
    onDismiss: () -> Unit,
    onRegenerate: () -> Unit,
    onCopy: () -> Unit
) {
    val qrBitmap = remember(did) { generateQRCode(did, 400) }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Your Signature",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold
                )

                Spacer(modifier = Modifier.height(16.dp))

                Box(
                    modifier = Modifier
                        .size(200.dp)
                        .background(Color.White, RoundedCornerShape(8.dp))
                        .border(1.dp, Color.Gray, RoundedCornerShape(8.dp))
                        .padding(8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (qrBitmap != null) {
                        Image(
                            bitmap = qrBitmap.asImageBitmap(),
                            contentDescription = "QR Code for DID",
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Text("Error generating QR", color = Color.Gray)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "${did.take(12)}...${did.takeLast(6)}",
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = did,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 100.dp)
                        .verticalScroll(rememberScrollState())
                )

                Spacer(modifier = Modifier.height(16.dp))

                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(onClick = onCopy) {
                        Text("📋 Copy ID")
                    }

                    Button(
                        onClick = {
                            onRegenerate()
                            onDismiss()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444))
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Regenerate")
                    }
                }
            }
        }
    }
}

@Composable
fun WalletInfoDialog(
    strikeEmail: String,
    isConnected: Boolean,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("⚡", fontSize = 48.sp)
                
                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    "Strike Wallet",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Email
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF3B82F6).copy(alpha = 0.1f)
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            "Connected Email",
                            fontSize = 14.sp,
                            color = Color.Gray
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            strikeEmail.ifEmpty { "Not connected" },
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color(0xFF3B82F6)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Status
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(
                                if (isConnected) Color(0xFF10B981) else Color(0xFFEF4444)
                            )
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        if (isConnected) "Connected" else "Disconnected",
                        fontSize = 14.sp,
                        color = Color.Gray
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                ) {
                    Text("Done")
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Recovery note
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF3C7)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text("🔒", fontSize = 14.sp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Recover your wallet anytime via your Strike email. No seed words needed.",
                            fontSize = 12.sp,
                            color = Color(0xFF92400E)
                        )
                    }
                }
            }
        }
    }
}

private fun generateQRCode(content: String, size: Int): Bitmap? {
    return try {
        val writer = QRCodeWriter()
        val bitMatrix: BitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
        
        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
            }
        }
        
        bitmap
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}

@Composable
fun InvoiceDialog(
    invoice: String,
    amountSats: Long,
    isPolling: Boolean,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit
) {
    val qrBitmap = remember(invoice) { generateQRCode(invoice, 400) }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("⚡", fontSize = 40.sp)
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Lightning Invoice",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    "$amountSats sats",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFFF59E0B)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Box(
                    modifier = Modifier
                        .size(220.dp)
                        .background(Color.White, RoundedCornerShape(12.dp))
                        .border(2.dp, Color(0xFFF59E0B), RoundedCornerShape(12.dp))
                        .padding(12.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (qrBitmap != null) {
                        Image(
                            bitmap = qrBitmap.asImageBitmap(),
                            contentDescription = "QR Code for Lightning Invoice",
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Text("Error generating QR", color = Color.Gray)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "${invoice.take(25)}...${invoice.takeLast(10)}",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(16.dp))

                if (isPolling) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFFFEF3C7)
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = Color(0xFFF59E0B)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                "Waiting for payment...",
                                fontSize = 14.sp,
                                color = Color(0xFF92400E)
                            )
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopy,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("📋 Copy")
                    }
                    
                    OutlinedButton(
                        onClick = onShare,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Share")
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                ) {
                    Text("Done")
                }

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    "Share this invoice with your enterprise.\nThey will pay it to verify your identity.",
                    fontSize = 12.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}
