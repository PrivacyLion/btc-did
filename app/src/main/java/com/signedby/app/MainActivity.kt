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
import breez_sdk_spark.Payment
import breez_sdk_spark.PaymentType
import breez_sdk_spark.PaymentStatus
import breez_sdk_spark.PaymentDetails

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
        
        // Initialize Breez wallet manager (replaces Strike)
        val breezMgr = BreezWalletManager(applicationContext)
        
        // Initialize NWC wallet manager (for enterprise payment flow - untouched)
        val nwcMgr = NwcWalletManager(applicationContext)
        
        // Initialize NOSTR manager (Phase 9)
        val nostrMgr = NostrManager(applicationContext)
        
        // Parse deep link from intent
        val initialLoginSession = parseLoginIntent(intent)

        setContent {
            SignedByMeTheme {
                SignedByMeApp(didMgr, breezMgr, nwcMgr, nostrMgr, initialLoginSession)
            }
        }
    }
    
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // Re-parse when app receives new intent while running
        // Note: For full implementation, use a ViewModel or state holder
    }
    
    override fun onResume() {
        super.onResume()
        // Layer 1: Check if we need to re-authenticate after inactivity
        if (isOnboardingComplete(this) && shouldRequireReauth(this)) {
            android.util.Log.i("SignedByMe", "Layer 1: 2-minute inactivity timeout - requiring re-auth")
            // Restart SplashActivity which will handle authentication
            val intent = Intent(this, SplashActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
            return
        }
        // Update last activity timestamp
        updateLastActivity(this)
    }
    
    override fun onPause() {
        super.onPause()
        // Update last activity when app goes to background
        updateLastActivity(this)
    }
    
    /**
     * Parse deep link intent (signedby://{client_id}/{nonce}/{amount_sats})
     * Bible Decision 10: Enterprise generates QR locally, no server call.
     */
    private fun parseLoginIntent(intent: Intent?): LoginSession? {
        val uri = intent?.data ?: return null
        
        // Bible format: signedby://{client_id}/{nonce}/{amount_sats}
        // Example: signedby://acme/a3f9bc12d7/100
        if (uri.scheme == "signedby") {
            val clientId = uri.host ?: return null
            val pathSegments = uri.pathSegments
            val nonce = pathSegments.getOrNull(0) ?: return null
            val amountSats = pathSegments.getOrNull(1)?.toULongOrNull() ?: 100UL
            
            return LoginSession(
                clientId = clientId,
                nonce = nonce,
                amountSats = amountSats
            )
        }
        return null
    }
}

/**
 * Login session from QR code.
 * Bible format: signedby://{client_id}/{nonce}/{amount_sats}
 * 
 * Enterprise generates nonce locally, displays QR, subscribes to NOSTR relay.
 * App scans, generates invoices + proof, publishes to relay.
 * Enterprise catches proof, pays invoices, calls /v1/login/verify.
 */
data class LoginSession(
    val clientId: String,             // Enterprise client ID (e.g., "acme")
    val nonce: String,                // Random nonce generated by enterprise
    val amountSats: ULong = 100UL     // Payment amount in sats
)

// API Configuration
private const val API_BASE_URL = "https://api.beta.privacy-lion.com"

/**
 * Send the Lightning invoice to the API (stateless flow).
 */
private fun sendInvoiceToApi(
    sessionToken: String?,
    sessionId: String,
    invoice: String,
    did: String,
    enterpriseName: String,
    amountSats: Long? = null,
    stwoproof: String? = null,
    bindingSignature: String? = null,
    nonce: String? = null
): Boolean {
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
            
            if (amountSats != null) {
                put("amount_sats", amountSats)
            }
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
        
        responseCode in 200..299
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to send invoice to API: ${e.message}")
        false
    }
}

/**
 * Notify API that payment was settled and DLC completed.
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
 * Result of API call
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
            
            if (walletAddress != null) {
                put("wallet_address", walletAddress)
            }
            if (stwoproof != null) {
                put("stwo_proof", stwoproof)
            }
            if (dlcContractJson != null) {
                put("dlc_contract", JSONObject(dlcContractJson))
            }
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
        
        android.util.Log.i("SignedByMe", "API response: $responseCode")
        
        if (responseCode in 200..299) {
            ApiResult(success = true, responseBody = responseBody)
        } else {
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
    breezMgr: BreezWalletManager,
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
    
    // Step 2: Breez wallet setup
    var step2Complete by remember { mutableStateOf(false) }
    var step3Complete by remember { mutableStateOf(false) }
    
    // Breez wallet state
    val breezWalletState by breezMgr.walletState.collectAsState()
    var isWalletInitializing by remember { mutableStateOf(false) }
    var walletInitError by remember { mutableStateOf("") }
    
    // Check if wallet already exists
    LaunchedEffect(Unit) {
        val hasWallet = breezMgr.hasWallet()
        if (hasWallet) {
            step2Complete = true
        }
    }
    
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
    var isLoading by remember { mutableStateOf(false) }
    
    // BTC price for display
    var btcPriceUsd by remember { mutableStateOf(0.0) }

    // Check if onboarding is complete (with delayed transition)
    val onboardingComplete = step1Complete && step2Complete && step3Complete
    var showLoginScreen by remember { mutableStateOf(false) }
    var showSecuritySetup by remember { mutableStateOf(false) }
    var securitySetupDone by remember { mutableStateOf(isOnboardingComplete(context)) }
    
    // Track background enrollment status - MUST be true before allowing QR scan
    var backgroundEnrollmentSucceeded by remember { mutableStateOf(false) }
    
    // Delay transition to login screen so user sees Step 3 complete
    LaunchedEffect(onboardingComplete) {
        if (onboardingComplete && !showLoginScreen) {
            // Start enrollment in background - MUST complete before proof generation
            launch(Dispatchers.IO) {
                try {
                    val success = didMgr.performEnrollment(
                        apiBaseUrl = API_BASE_URL,
                        apiKey = "acme-test-key-2026"
                    )
                    if (success) {
                        android.util.Log.i("SignedByMe", "Background enrollment succeeded - proof generation now allowed")
                        backgroundEnrollmentSucceeded = true
                    } else {
                        android.util.Log.w("SignedByMe", "Background enrollment failed - will retry on next launch")
                    }
                } catch (e: Exception) {
                    android.util.Log.e("SignedByMe", "Background enrollment error: ${e.message}")
                }
            }
            
            delay(1500)
            
            // Show security setup if not done yet
            if (!securitySetupDone) {
                showSecuritySetup = true
            } else {
                showLoginScreen = true
            }
        }
    }
    
    // Check if enrollment already completed on previous launch
    LaunchedEffect(showLoginScreen) {
        if (showLoginScreen && !backgroundEnrollmentSucceeded) {
            // Check if we have leaf_secret from a previous enrollment
            val hasSecret = withContext(Dispatchers.IO) { didMgr.hasLeafSecret() }
            val hasWitness = withContext(Dispatchers.IO) { 
                val enrollment = didMgr.loadEnrollment()
                enrollment != null && didMgr.loadWitness(enrollment.clientId, "default") != null
            }
            if (hasSecret && hasWitness) {
                android.util.Log.i("SignedByMe", "Previous enrollment detected - proof generation allowed")
                backgroundEnrollmentSucceeded = true
            }
        }
    }
    
    // Security Setup Dialog (Layer 1)
    if (showSecuritySetup) {
        SecuritySetupDialog(
            onComplete = { selectedMode ->
                saveLockMode(context, selectedMode)
                markOnboardingComplete(context)
                securitySetupDone = true
                showSecuritySetup = false
                showLoginScreen = true
                android.util.Log.i("SignedByMe", "Security setup complete: $selectedMode")
            }
        )
    }

    // Poll for payment when invoice is active
    // Phase 9B: Uses Breez SDK payment events instead of NWC polling
    LaunchedEffect(isPollingPayment, lastPaymentHash) {
        if (isPollingPayment && lastPaymentHash.isNotEmpty()) {
            while (isPollingPayment && !paymentReceived) {
                // Wait for payment via Breez SDK (3 second poll intervals)
                val breezState = breezMgr.walletState.value
                val preimage = if (breezState is BreezWalletManager.WalletState.Connected) {
                    breezMgr.waitForPayment(lastPaymentHash, timeoutMs = 3000)
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
    
    // Fetch BTC price
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
            delay(60000)
        }
    }

    // ===== Screen Routing =====
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
            lastInvoice = lastInvoice,
            isCreatingInvoice = isCreatingInvoice,
            isPollingPayment = isPollingPayment,
            paymentReceived = paymentReceived,
            showInvoiceDialog = showInvoiceDialog,
            invoiceAmountSats = loginSession?.amountSats ?: 100UL,
            statusMessage = statusMessage,
            loginSession = loginSession,
            isEnrollmentReady = backgroundEnrollmentSucceeded,
            onLoginSessionReceived = { session ->
                loginSession = session
                android.util.Log.i("SignedByMe", "QR scanned: client=${session.clientId}, nonce=${session.nonce}, amount=${session.amountSats}")
            },
            onStartLogin = {
                scope.launch {
                    isCreatingInvoice = true
                    statusMessage = ""
                    
                    // Bible login flow:
                    // 1. Generate 2 NWC invoices (90/10 split)
                    // 2. Generate Groth16 proof
                    // 3. Publish proof_event (kind 28101) to NOSTR
                    // 4. Wait for payment (enterprise catches event, pays, calls /v1/login/verify)
                    
                    val clientId = loginSession?.clientId ?: "demo"
                    val nonce = loginSession?.nonce ?: run {
                        val bytes = ByteArray(16)
                        java.security.SecureRandom().nextBytes(bytes)
                        bytes.joinToString("") { "%02x".format(it) }
                    }
                    val amountSats = loginSession?.amountSats ?: 100UL
                    
                    lastLoginId = nonce  // Use nonce as login identifier
                    
                    // Initialize NOSTR + NWC
                    val leafSecret = didMgr.loadLeafSecret()
                    if (leafSecret != null) {
                        nostrMgr.initializeIdentity(leafSecret)
                        java.util.Arrays.fill(leafSecret, 0.toByte())
                        
                        nostrMgr.generateEphemeralNwcKeypair()
                        
                        nostrMgr.connectToRelays(
                            scope = scope,
                            onConnected = { android.util.Log.i("SignedByMe", "NOSTR relays connected") },
                            onFailed = { android.util.Log.w("SignedByMe", "NOSTR relay connection failed") }
                        )
                        
                        // NWC no longer used for invoices - Breez SDK handles this
                        // NwcWalletManager kept in place but unused in login path
                    } else {
                        android.util.Log.w("SignedByMe", "No leaf_secret - NOSTR not initialized")
                    }
                    
                    // Step 1: Generate invoices via Breez SDK (90/10 split)
                    // Phase 9B: Replaces nwcGenerateLoginInvoices
                    var userInvoice: String? = null
                    var operatorInvoice: String? = null
                    
                    val breezState = breezMgr.walletState.value
                    if (breezState is BreezWalletManager.WalletState.Connected) {
                        val invoices = breezMgr.generateLoginInvoices(
                            totalSats = amountSats.toLong(),
                            clientId = clientId
                        )
                        if (invoices != null) {
                            userInvoice = invoices.first
                            operatorInvoice = invoices.second
                            android.util.Log.i("SignedByMe", "Breez invoices generated (90/10 split)")
                        }
                    } else {
                        android.util.Log.w("SignedByMe", "Breez wallet not connected, state: $breezState")
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
                    
                    // Step 2 + 3: Generate Groth16 proof and publish to NOSTR
                    launch(Dispatchers.IO) {
                        try {
                            // GUARD: Proof must NOT fire unless leaf_secret exists
                            if (!didMgr.hasLeafSecret()) {
                                android.util.Log.e("SignedByMe", "GUARD BLOCKED: Proof generation attempted without leaf_secret!")
                                withContext(Dispatchers.Main) {
                                    statusMessage = "Error: Setup incomplete. Please wait and try again."
                                    isCreatingInvoice = false
                                    isLoginActive = false
                                    isPollingPayment = false
                                }
                                return@launch
                            }
                            
                            // Generate Groth16 membership proof
                            android.util.Log.i("SignedByMe", "Generating Groth16 proof for client=$clientId")
                            val proofResult = didMgr.generateGroth16Proof(clientId, "default")
                            val proofJson = org.json.JSONObject(proofResult)
                            
                            val proofHex = if (proofJson.optBoolean("success", false)) {
                                android.util.Base64.encodeToString(
                                    proofResult.toByteArray(Charsets.UTF_8),
                                    android.util.Base64.NO_WRAP
                                )
                            } else {
                                android.util.Log.e("SignedByMe", "Proof generation failed: ${proofJson.optString("error")}")
                                withContext(Dispatchers.Main) {
                                    statusMessage = "Error: ${proofJson.optString("error", "Proof failed")}"
                                }
                                return@launch
                            }
                            
                            android.util.Log.i("SignedByMe", "Groth16 proof generated successfully")
                            
                            // Publish proof_event (kind 28101) to NOSTR relay
                            // Enterprise subscription will catch this by nonce + client_id
                            if (nostrMgr.isConnected()) {
                                nostrMgr.publishProofEvent(
                                    nonce = nonce,
                                    clientId = clientId,
                                    proofHex = proofHex,
                                    merkleRoot = "",
                                    userInvoice = invoice,
                                    operatorInvoice = lastOperatorInvoice
                                )
                                android.util.Log.i("SignedByMe", "proof_event published to NOSTR (nonce=$nonce)")
                            }
                            
                            withContext(Dispatchers.Main) {
                                statusMessage = "Waiting for payment..."
                                isCreatingInvoice = false
                            }
                            
                            // No API call here! Enterprise catches NOSTR event, pays invoices,
                            // and calls /v1/login/verify themselves (Bible Decision 10)
                            
                        } catch (e: Exception) {
                            android.util.Log.e("SignedByMe", "Login flow error: ${e.message}")
                            withContext(Dispatchers.Main) {
                                statusMessage = "Error: ${e.message}"
                                isCreatingInvoice = false
                            }
                        }
                    }
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
            onDevExportLeafCommitment = if (BuildConfig.DEBUG) {
                {
                    val cid = loginSession?.clientId
                    if (cid != null) {
                        scope.launch {
                            val commitment = withContext(Dispatchers.IO) {
                                didMgr.devExportLeafCommitment(cid, "default")
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
            breezMgr = breezMgr
        )
    } else {
        // Show Onboarding Screen
        OnboardingScreen(
            did = did!!,
            step1Complete = step1Complete,
            step2Complete = step2Complete,
            step3Complete = step3Complete,
            isWalletInitializing = isWalletInitializing,
            walletInitError = walletInitError,
            breezWalletState = breezWalletState,
            isLoading = isLoading,
            statusMessage = statusMessage,
            onGenerateDid = {
                scope.launch(Dispatchers.IO) {
                    val newDid = didMgr.createDid()
                    withContext(Dispatchers.Main) {
                        did = newDid
                        step1Complete = true
                    }
                }
            },
            // Step 2: Breez wallet setup - auto-complete on success
            onInitializeWallet = {
                isWalletInitializing = true
                walletInitError = ""
                scope.launch {
                    val result = breezMgr.initializeWallet()
                    isWalletInitializing = false
                    if (result.isSuccess) {
                        step2Complete = true
                    } else {
                        walletInitError = result.exceptionOrNull()?.message ?: "Failed to initialize wallet"
                    }
                }
            },
            onGenerateSignature = {
                isLoading = true
                scope.launch(Dispatchers.IO) {
                    try {
                        val groth16Result = didMgr.generateGroth16Proof(
                            clientId = "test-client",
                            rootId = "default"
                        )
                        val groth16Json = JSONObject(groth16Result)
                        val proofSuccess = groth16Json.optBoolean("success", false)
                        
                        if (proofSuccess) {
                            android.util.Log.i("SignedByMe", "Groth16 proof generated successfully")
                        } else {
                            android.util.Log.w("SignedByMe", "Groth16 proof: ${groth16Json.optString("error", "unknown")}")
                        }

                        withContext(Dispatchers.Main) {
                            step3Complete = true
                            isLoading = false
                            statusMessage = "Signature ready!"
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            statusMessage = "Error: ${e.message}"
                            isLoading = false
                        }
                    }
                }
            }
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
    isWalletInitializing: Boolean,
    walletInitError: String,
    breezWalletState: BreezWalletManager.WalletState,
    isLoading: Boolean,
    statusMessage: String,
    onGenerateDid: () -> Unit,
    onInitializeWallet: () -> Unit,
    onGenerateSignature: () -> Unit
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
                        onInfoClick = null
                    )
                }
            }

            // Step 2: Connect (Breez Wallet)
            StepCard(
                stepNumber = 2,
                title = "Connect",
                isComplete = step2Complete,
                isEnabled = step1Complete
            ) {
                if (!step2Complete) {
                    // Wallet initialization screen
                    Text(
                        "Set up your Lightning wallet",
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

                    if (walletInitError.isNotEmpty()) {
                        Text(
                            walletInitError,
                            color = Color(0xFFEF4444),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                    }

                    if (isWalletInitializing) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(40.dp),
                                color = Color(0xFF3B82F6)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("Initializing wallet...", fontSize = 14.sp, color = Color.Gray)
                        }
                    } else {
                        GradientButton(
                            text = "Set Up Wallet",
                            colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                            onClick = onInitializeWallet
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFDCFCE7)),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text("⚡", fontSize = 14.sp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "Breez Spark wallet — fast, nodeless Lightning. Payments arrive in your wallet.",
                                fontSize = 12.sp,
                                color = Color(0xFF166534)
                            )
                        }
                    }
                } else {
                    CompletedStepContent(
                        message = "Wallet ready ✓",
                        onInfoClick = null
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
                    CompletedStepContent(
                        message = "Signature Verified ✓",
                        onInfoClick = null
                    )
                    
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

// ===== Wallet Screen (Send/Receive/Transactions) =====
@Composable
fun WalletScreen(
    breezMgr: BreezWalletManager,
    btcPriceUsd: Double,
    onBack: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    
    val walletState by breezMgr.walletState.collectAsState()
    var payments by remember { mutableStateOf<List<Payment>>(emptyList()) }
    var isRefreshing by remember { mutableStateOf(false) }
    
    // Receive state
    var showReceiveDialog by remember { mutableStateOf(false) }
    var receiveAmountInput by remember { mutableStateOf("") }
    var receiveInvoice by remember { mutableStateOf("") }
    var isGeneratingInvoice by remember { mutableStateOf(false) }
    
    // Send state
    var showSendDialog by remember { mutableStateOf(false) }
    var sendInvoiceInput by remember { mutableStateOf("") }
    var isSending by remember { mutableStateOf(false) }
    var sendError by remember { mutableStateOf("") }
    
    // Load payments
    LaunchedEffect(Unit) {
        payments = breezMgr.getRecentPayments(50u)
    }
    
    fun refreshWallet() {
        isRefreshing = true
        scope.launch {
            breezMgr.refreshBalance()
            payments = breezMgr.getRecentPayments(50u)
            isRefreshing = false
        }
    }
    
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
                .padding(24.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Text("←", fontSize = 24.sp)
                }
                Text(
                    "Wallet",
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                IconButton(onClick = { refreshWallet() }) {
                    if (isRefreshing) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Balance Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(8.dp, RoundedCornerShape(24.dp)),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("⚡", fontSize = 40.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    val balanceSats = when (val state = walletState) {
                        is BreezWalletManager.WalletState.Connected -> state.balanceSats.toLong()
                        else -> 0L
                    }
                    
                    Text(
                        text = "${formatSats(balanceSats)} sats",
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Bold
                    )
                    
                    if (btcPriceUsd > 0) {
                        Text(
                            text = satsToUsd(balanceSats, btcPriceUsd),
                            fontSize = 16.sp,
                            color = Color.Gray
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(24.dp))
                    
                    // Send/Receive buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Button(
                            onClick = { showReceiveDialog = true },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                        ) {
                            Text("Receive")
                        }
                        Button(
                            onClick = { showSendDialog = true },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                        ) {
                            Text("Send")
                        }
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Transaction History
            Text(
                "Recent Transactions",
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            if (payments.isEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.8f))
                ) {
                    Text(
                        "No transactions yet",
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        textAlign = TextAlign.Center,
                        color = Color.Gray
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(payments) { payment ->
                        PaymentRow(payment = payment, btcPriceUsd = btcPriceUsd)
                    }
                }
            }
        }
    }
    
    // Receive Dialog
    if (showReceiveDialog) {
        Dialog(onDismissRequest = { showReceiveDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("Receive", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    if (receiveInvoice.isEmpty()) {
                        OutlinedTextField(
                            value = receiveAmountInput,
                            onValueChange = { if (it.all { c -> c.isDigit() }) receiveAmountInput = it },
                            label = { Text("Amount (sats)") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        if (isGeneratingInvoice) {
                            CircularProgressIndicator(modifier = Modifier.size(32.dp))
                        } else {
                            Button(
                                onClick = {
                                    val amount = receiveAmountInput.toULongOrNull() ?: 0UL
                                    if (amount > 0UL) {
                                        isGeneratingInvoice = true
                                        scope.launch {
                                            val result = breezMgr.createInvoice(amount, "SignedByMe Receive")
                                            isGeneratingInvoice = false
                                            if (result.isSuccess) {
                                                receiveInvoice = result.getOrNull()!!
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Generate Invoice")
                            }
                        }
                    } else {
                        val qrBitmap = remember(receiveInvoice) { generateQRCode(receiveInvoice, 300) }
                        if (qrBitmap != null) {
                            Image(
                                bitmap = qrBitmap.asImageBitmap(),
                                contentDescription = "Invoice QR",
                                modifier = Modifier.size(200.dp)
                            )
                        }
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Text(
                            "${receiveInvoice.take(20)}...${receiveInvoice.takeLast(10)}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Gray
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedButton(onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("Invoice", receiveInvoice))
                                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
                            }) {
                                Text("Copy")
                            }
                            Button(onClick = {
                                receiveInvoice = ""
                                receiveAmountInput = ""
                                showReceiveDialog = false
                            }) {
                                Text("Done")
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    TextButton(onClick = { 
                        receiveInvoice = ""
                        receiveAmountInput = ""
                        showReceiveDialog = false 
                    }) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
    
    // Send Dialog
    if (showSendDialog) {
        Dialog(onDismissRequest = { showSendDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("Send", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    OutlinedTextField(
                        value = sendInvoiceInput,
                        onValueChange = { sendInvoiceInput = it },
                        label = { Text("Paste Lightning invoice") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(120.dp),
                        enabled = !isSending
                    )
                    
                    if (sendError.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(sendError, color = Color(0xFFEF4444), fontSize = 12.sp)
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    if (isSending) {
                        CircularProgressIndicator(modifier = Modifier.size(32.dp))
                    } else {
                        Button(
                            onClick = {
                                if (sendInvoiceInput.isNotEmpty()) {
                                    isSending = true
                                    sendError = ""
                                    scope.launch {
                                        val result = breezMgr.sendPayment(sendInvoiceInput)
                                        isSending = false
                                        if (result.isSuccess) {
                                            sendInvoiceInput = ""
                                            showSendDialog = false
                                            refreshWallet()
                                            Toast.makeText(context, "Payment sent!", Toast.LENGTH_SHORT).show()
                                        } else {
                                            sendError = result.exceptionOrNull()?.message ?: "Payment failed"
                                        }
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Send Payment")
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    TextButton(onClick = { 
                        sendInvoiceInput = ""
                        sendError = ""
                        showSendDialog = false 
                    }) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
}

@Composable
fun PaymentRow(payment: Payment, btcPriceUsd: Double) {
    val isReceive = payment.paymentType == PaymentType.RECEIVE
    val amountSats = payment.amount.toLong()
    val timestamp = payment.timestamp.toLong() * 1000L
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.9f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(
                        if (isReceive) Color(0xFF10B981).copy(alpha = 0.1f)
                        else Color(0xFF3B82F6).copy(alpha = 0.1f)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (isReceive) "↓" else "↑",
                    fontSize = 20.sp,
                    color = if (isReceive) Color(0xFF10B981) else Color(0xFF3B82F6)
                )
            }
            
            Spacer(modifier = Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (isReceive) "Received" else "Sent",
                    fontWeight = FontWeight.Medium
                )
                Text(
                    SimpleDateFormat("MMM d, h:mm a", Locale.US).format(Date(timestamp)),
                    fontSize = 12.sp,
                    color = Color.Gray
                )
            }
            
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    "${if (isReceive) "+" else "-"}${formatSats(amountSats)} sats",
                    fontWeight = FontWeight.SemiBold,
                    color = if (isReceive) Color(0xFF10B981) else Color.Black
                )
                if (btcPriceUsd > 0) {
                    Text(
                        satsToUsd(amountSats, btcPriceUsd),
                        fontSize = 12.sp,
                        color = Color.Gray
                    )
                }
            }
        }
    }
}

// ===== Login Screen =====
@Composable
fun LoginScreen(
    did: String,
    lastInvoice: String,
    isCreatingInvoice: Boolean,
    isPollingPayment: Boolean,
    paymentReceived: Boolean,
    showInvoiceDialog: Boolean,
    invoiceAmountSats: ULong,
    statusMessage: String,
    loginSession: LoginSession?,
    isEnrollmentReady: Boolean,  // Guard: must be true before QR scan allowed
    onLoginSessionReceived: (LoginSession) -> Unit,
    onStartLogin: () -> Unit,
    onShowInvoiceDialog: () -> Unit,
    onDismissInvoiceDialog: () -> Unit,
    onCopyInvoice: () -> Unit,
    onShareInvoice: () -> Unit,
    onResetLogin: () -> Unit,
    onDevExportLeafCommitment: (() -> Unit)? = null,
    btcPriceUsd: Double,
    breezMgr: BreezWalletManager
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var showQrScanner by remember { mutableStateOf(false) }
    
    // Wallet state
    val walletState by breezMgr.walletState.collectAsState()
    var payments by remember { mutableStateOf<List<Payment>>(emptyList()) }
    var isRefreshing by remember { mutableStateOf(false) }
    
    // Receive state
    var showReceiveDialog by remember { mutableStateOf(false) }
    var receiveAmountInput by remember { mutableStateOf("") }
    var receiveInvoice by remember { mutableStateOf("") }
    var isGeneratingInvoice by remember { mutableStateOf(false) }
    
    // Send state
    var showSendDialog by remember { mutableStateOf(false) }
    var sendInvoiceInput by remember { mutableStateOf("") }
    var isSending by remember { mutableStateOf(false) }
    var sendError by remember { mutableStateOf("") }
    
    // Seed words state
    var showSeedWordsDialog by remember { mutableStateOf(false) }
    var seedWords by remember { mutableStateOf<List<String>>(emptyList()) }
    
    // Load payments on start
    LaunchedEffect(Unit) {
        payments = breezMgr.getRecentPayments(20u)
    }
    
    fun refreshWallet() {
        isRefreshing = true
        scope.launch {
            breezMgr.refreshBalance()
            payments = breezMgr.getRecentPayments(20u)
            isRefreshing = false
        }
    }
    
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
                                text = loginSession.clientId,
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
                                    "You're now logged in to ${loginSession.clientId}"
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
                                    "Waiting for ${loginSession.clientId} to confirm",
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
                                // No session yet - show scan QR option (or "Setting up..." if enrollment not ready)
                                if (!isEnrollmentReady) {
                                    // Guard: Enrollment still in progress - block QR scan
                                    Text("⏳", fontSize = 48.sp)

                                    Spacer(modifier = Modifier.height(12.dp))

                                    Text(
                                        "Setting up...",
                                        fontSize = 18.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color(0xFFF59E0B)
                                    )

                                    Spacer(modifier = Modifier.height(8.dp))

                                    Text(
                                        "Please wait while we finish setting up your signature",
                                        fontSize = 14.sp,
                                        color = Color.Gray,
                                        textAlign = TextAlign.Center
                                    )

                                    Spacer(modifier = Modifier.height(20.dp))

                                    CircularProgressIndicator(
                                        modifier = Modifier.size(32.dp),
                                        color = Color(0xFFF59E0B),
                                        strokeWidth = 3.dp
                                    )
                                } else {
                                    // Enrollment ready - show scan QR option
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
                                }
                            }
                        }
                    }
                }
            }

            // ===== Inline Wallet Section =====
            Spacer(modifier = Modifier.height(24.dp))
            
            // Balance Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(8.dp, RoundedCornerShape(24.dp)),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("⚡ Wallet", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                        IconButton(onClick = { refreshWallet() }) {
                            if (isRefreshing) {
                                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    val balanceSats = when (val state = walletState) {
                        is BreezWalletManager.WalletState.Connected -> state.balanceSats.toLong()
                        else -> 0L
                    }
                    
                    Text(
                        text = "${formatSats(balanceSats)} sats",
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Bold
                    )
                    
                    if (btcPriceUsd > 0) {
                        Text(
                            text = satsToUsd(balanceSats, btcPriceUsd),
                            fontSize = 14.sp,
                            color = Color.Gray
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    // Send/Receive buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = { showReceiveDialog = true },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                        ) {
                            Text("Receive")
                        }
                        Button(
                            onClick = { showSendDialog = true },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                        ) {
                            Text("Send")
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    // View Seed Words
                    TextButton(
                        onClick = {
                            val mnemonic = breezMgr.getMnemonic()
                            if (mnemonic != null) {
                                seedWords = mnemonic.split(" ")
                                showSeedWordsDialog = true
                            } else {
                                Toast.makeText(context, "Could not retrieve seed words", Toast.LENGTH_SHORT).show()
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("🔑 View Seed Words", fontSize = 13.sp, color = Color(0xFF3B82F6))
                    }
                }
            }
            
            // Transaction History
            if (payments.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    "Recent Transactions",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.fillMaxWidth()
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                payments.take(5).forEach { payment ->
                    PaymentRow(payment = payment, btcPriceUsd = btcPriceUsd)
                    Spacer(modifier = Modifier.height(8.dp))
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
    
    // Receive Dialog (LoginScreen)
    if (showReceiveDialog) {
        Dialog(onDismissRequest = { showReceiveDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("Receive", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    if (receiveInvoice.isEmpty()) {
                        OutlinedTextField(
                            value = receiveAmountInput,
                            onValueChange = { if (it.all { c -> c.isDigit() }) receiveAmountInput = it },
                            label = { Text("Amount (sats)") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        if (isGeneratingInvoice) {
                            CircularProgressIndicator(modifier = Modifier.size(32.dp))
                        } else {
                            Button(
                                onClick = {
                                    val amount = receiveAmountInput.toULongOrNull() ?: 0UL
                                    if (amount > 0UL) {
                                        isGeneratingInvoice = true
                                        scope.launch {
                                            val result = breezMgr.createInvoice(amount, "SignedByMe Receive")
                                            isGeneratingInvoice = false
                                            if (result.isSuccess) {
                                                receiveInvoice = result.getOrNull()!!
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Generate Invoice")
                            }
                        }
                    } else {
                        val qrBitmap = remember(receiveInvoice) { generateQRCode(receiveInvoice, 300) }
                        if (qrBitmap != null) {
                            Image(
                                bitmap = qrBitmap.asImageBitmap(),
                                contentDescription = "Invoice QR",
                                modifier = Modifier.size(200.dp)
                            )
                        }
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Text(
                            "${receiveInvoice.take(20)}...${receiveInvoice.takeLast(10)}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Black,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally)
                        ) {
                            OutlinedButton(onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("Invoice", receiveInvoice))
                                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
                            }) {
                                Text("Copy")
                            }
                            Button(onClick = {
                                receiveInvoice = ""
                                receiveAmountInput = ""
                                showReceiveDialog = false
                            }) {
                                Text("Done")
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    TextButton(onClick = { 
                        receiveInvoice = ""
                        receiveAmountInput = ""
                        showReceiveDialog = false 
                    }) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
    
    // Seed Words Dialog
    if (showSeedWordsDialog) {
        SeedWordsDialog(
            seedWords = seedWords,
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Seed Words", seedWords.joinToString(" ")))
                Toast.makeText(context, "Seed words copied!", Toast.LENGTH_SHORT).show()
            },
            onDismiss = { 
                showSeedWordsDialog = false
                seedWords = emptyList()
            }
        )
    }
    
    // Send Dialog
    if (showSendDialog) {
        Dialog(onDismissRequest = { showSendDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("Send", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    OutlinedTextField(
                        value = sendInvoiceInput,
                        onValueChange = { sendInvoiceInput = it },
                        label = { Text("Paste Lightning invoice") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(120.dp),
                        enabled = !isSending
                    )
                    
                    if (sendError.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(sendError, color = Color(0xFFEF4444), fontSize = 12.sp)
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    if (isSending) {
                        CircularProgressIndicator(modifier = Modifier.size(32.dp))
                    } else {
                        Button(
                            onClick = {
                                if (sendInvoiceInput.isNotEmpty()) {
                                    isSending = true
                                    sendError = ""
                                    scope.launch {
                                        val result = breezMgr.sendPayment(sendInvoiceInput)
                                        isSending = false
                                        if (result.isSuccess) {
                                            sendInvoiceInput = ""
                                            showSendDialog = false
                                            refreshWallet()
                                            Toast.makeText(context, "Payment sent!", Toast.LENGTH_SHORT).show()
                                        } else {
                                            sendError = result.exceptionOrNull()?.message ?: "Payment failed"
                                        }
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Send Payment")
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    TextButton(onClick = { 
                        sendInvoiceInput = ""
                        sendError = ""
                        showSendDialog = false 
                    }) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
    
    // QR Scanner Dialog
    if (showQrScanner) {
        QRScannerDialog(
            onQrScanned = { qrContent ->
                showQrScanner = false
                try {
                    // Bible format: signedby://{client_id}/{nonce}/{amount_sats}
                    // Example: signedby://acme/a3f9bc12d7/100
                    val uri = android.net.Uri.parse(qrContent)
                    
                    if (uri.scheme == "signedby") {
                        val pathSegments = uri.pathSegments
                        // Host is client_id, path segments are nonce and amount
                        // signedby://acme/a3f9bc12d7/100 -> host=acme, path=[a3f9bc12d7, 100]
                        val clientId = uri.host ?: return@QRScannerDialog
                        val nonce = pathSegments.getOrNull(0) ?: return@QRScannerDialog
                        val amountSats = pathSegments.getOrNull(1)?.toULongOrNull() ?: 100UL
                        
                        android.util.Log.i("SignedByMe", "QR parsed: client_id=$clientId, nonce=$nonce, amount=$amountSats")
                        
                        onLoginSessionReceived(LoginSession(
                            clientId = clientId,
                            nonce = nonce,
                            amountSats = amountSats
                        ))
                    } else {
                        android.util.Log.w("SignedByMe", "QR not in signedby:// format: ${uri.scheme}")
                    }
                } catch (e: Exception) {
                    android.util.Log.e("SignedByMe", "QR parse error: ${e.message}")
                }
            },
            onDismiss = { showQrScanner = false }
        )
    }
}

// QR Scanner moved to QRScannerDialog.kt with Layer 2 biometric

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

// ===== Seed Words Dialog =====
@Composable
fun SeedWordsDialog(
    seedWords: List<String>,
    onCopy: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier.padding(24.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Your Recovery Words",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Text("✕", fontSize = 18.sp, color = Color.Gray)
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Warning
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF3C7)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text("⚠️", fontSize = 16.sp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Write these down and keep safe! Anyone with these words can access your wallet.",
                            fontSize = 13.sp,
                            color = Color(0xFF92400E)
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(20.dp))
                
                // Seed words grid
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    for (i in seedWords.indices step 2) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            SeedWordChip(
                                number = i + 1,
                                word = seedWords[i],
                                modifier = Modifier.weight(1f)
                            )
                            if (i + 1 < seedWords.size) {
                                SeedWordChip(
                                    number = i + 2,
                                    word = seedWords[i + 1],
                                    modifier = Modifier.weight(1f)
                                )
                            } else {
                                Spacer(modifier = Modifier.weight(1f))
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(20.dp))
                
                Button(
                    onClick = onCopy,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                ) {
                    Text("📋 Copy All")
                }
            }
        }
    }
}

@Composable
fun SeedWordChip(
    number: Int,
    word: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF3F4F6)),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "$number.",
                fontSize = 12.sp,
                color = Color.Gray,
                modifier = Modifier.width(24.dp)
            )
            Text(
                word,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

// ===== Security Setup Dialog (Layer 1 Configuration) =====

/**
 * Dialog shown after onboarding to configure app lock (Layer 1).
 * 
 * Options:
 * - Biometric (default): Fingerprint or Face ID
 * - Passcode: 6-digit PIN (for devices without biometric)
 * - Both: Maximum security
 */
@Composable
fun SecuritySetupDialog(
    onComplete: (LockMode) -> Unit
) {
    val context = LocalContext.current
    var selectedMode by remember { mutableStateOf(LockMode.BIOMETRIC) }
    
    // Check biometric availability
    val biometricManager = remember { BiometricManager.from(context) }
    val canUseBiometric = remember {
        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == 
            BiometricManager.BIOMETRIC_SUCCESS
    }
    val canUseDeviceCredential = remember {
        biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }
    
    // Default to passcode if no biometric available
    LaunchedEffect(canUseBiometric) {
        if (!canUseBiometric && canUseDeviceCredential) {
            selectedMode = LockMode.PASSCODE
        }
    }
    
    Dialog(onDismissRequest = { /* Cannot dismiss - must choose */ }) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Shield icon
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.linearGradient(
                                listOf(Color(0xFF10B981), Color(0xFF34D399))
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text("🛡️", fontSize = 28.sp)
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    "Secure Your Wallet",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Choose how to protect your SignedByMe identity.\nThis will be required every time you open the app.",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Option: Biometric
                if (canUseBiometric) {
                    SecurityOptionCard(
                        icon = "👆",
                        title = "Biometric",
                        description = "Use fingerprint or face recognition",
                        isSelected = selectedMode == LockMode.BIOMETRIC,
                        onClick = { selectedMode = LockMode.BIOMETRIC }
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))
                }
                
                // Option: Passcode
                if (canUseDeviceCredential) {
                    SecurityOptionCard(
                        icon = "🔢",
                        title = "Device PIN/Password",
                        description = "Use your device lock screen",
                        isSelected = selectedMode == LockMode.PASSCODE,
                        onClick = { selectedMode = LockMode.PASSCODE }
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))
                }
                
                // Option: Both (maximum security)
                if (canUseBiometric && canUseDeviceCredential) {
                    SecurityOptionCard(
                        icon = "🔐",
                        title = "Biometric + PIN",
                        description = "Maximum security (recommended)",
                        isSelected = selectedMode == LockMode.BOTH,
                        onClick = { selectedMode = LockMode.BOTH },
                        isRecommended = true
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Warning if no security available
                if (!canUseBiometric && !canUseDeviceCredential) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF3C7)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("⚠️", fontSize = 20.sp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "No lock screen set up. Please set up a PIN or biometric in your device settings.",
                                fontSize = 13.sp,
                                color = Color(0xFF92400E)
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(24.dp))
                
                Button(
                    onClick = { onComplete(selectedMode) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = canUseBiometric || canUseDeviceCredential,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF3B82F6)
                    )
                ) {
                    Text("Continue", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}

@Composable
private fun SecurityOptionCard(
    icon: String,
    title: String,
    description: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    isRecommended: Boolean = false
) {
    val borderColor = if (isSelected) Color(0xFF3B82F6) else Color(0xFFE5E7EB)
    val backgroundColor = if (isSelected) Color(0xFFEFF6FF) else Color.White
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = backgroundColor),
        border = BorderStroke(2.dp, borderColor),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(icon, fontSize = 28.sp)
            
            Spacer(modifier = Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        title,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    if (isRecommended) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF10B981)),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                "BEST",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        }
                    }
                }
                Text(
                    description,
                    fontSize = 13.sp,
                    color = Color.Gray
                )
            }
            
            if (isSelected) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = "Selected",
                    tint = Color(0xFF3B82F6)
                )
            }
        }
    }
}
