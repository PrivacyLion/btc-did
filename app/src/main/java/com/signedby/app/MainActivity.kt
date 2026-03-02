package com.signedby.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
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
import breez_sdk_spark.Payment
import breez_sdk_spark.PaymentType
import breez_sdk_spark.PaymentStatus
import breez_sdk_spark.PaymentDetails
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
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.common.api.ApiException
import androidx.compose.ui.text.input.PasswordVisualTransformation

/**
 * Extract Groth16 assets from APK assets to filesystem.
 * Assets in assets/groth16/ are copied to the target directory.
 * Large files (zkey) are sideloaded to Downloads, not bundled.
 */
private fun extractGroth16Assets(context: Context, targetDir: java.io.File) {
    try {
        if (!targetDir.exists()) {
            targetDir.mkdirs()
        }
        
        // Assets to extract (zkey is sideloaded separately - too big for APK)
        val assetFiles = listOf(
            "membership.dat",   // 4.5MB circuit data
            "membership"        // 5.7MB witness calculator (ARM64)
        )
        
        for (filename in assetFiles) {
            val targetFile = java.io.File(targetDir, filename)
            
            // Skip if already extracted
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
                    targetFile.setExecutable(true)
                }
                
                android.util.Log.i("SignedByMe", "Extracted Groth16 asset: $filename (${targetFile.length()} bytes)")
            } catch (e: java.io.FileNotFoundException) {
                // Not an error - asset may be bundled elsewhere (e.g., jniLibs)
                android.util.Log.d("SignedByMe", "Groth16 asset not in assets/: $filename")
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
            
            // Extract groth16 assets (membership.dat) from APK
            val groth16Dir = java.io.File(applicationContext.filesDir, "groth16")
            extractGroth16Assets(applicationContext, groth16Dir)
            
            // Initialize Groth16 prover with:
            // - witness calculator from jniLibs (nativeLibraryDir)
            // - membership.dat from extracted assets
            // - zkey from Downloads (sideloaded)
            val initialized = didMgr.initGroth16Prover(
                nativeLibDir = applicationInfo.nativeLibraryDir,
                groth16Dir = groth16Dir
            )
            android.util.Log.i("SignedByMe", "Groth16 prover ready: $initialized")
        }
        val breezMgr = BreezWalletManager(applicationContext)
        
        // Parse deep link from intent
        val initialLoginSession = parseLoginIntent(intent)

        setContent {
            SignedByMeTheme {
                SignedByMeApp(didMgr, breezMgr, initialLoginSession)
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
                nonce = payload.optString("nonce", null),
                expiresAt = if (payload.has("expires_at")) payload.optLong("expires_at") else null,
                // Membership fields (v4)
                clientId = payload.optString("client_id", null),
                requiredRootId = payload.optString("required_root_id", null),
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
 * Send the Lightning invoice to the API with DLC contract metadata.
 * 
 * This is the production flow:
 * 1. STWO proof verifies identity (ZK)
 * 2. DLC contract specifies 90/10 payout split
 * 3. Oracle will sign "auth_verified" after payment
 * 4. DLC enforces the split
 */
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
    breezMgr: BreezWalletManager,
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
    val walletState by breezMgr.walletState.collectAsState()
    var step2Complete by remember { mutableStateOf(walletState is BreezWalletManager.WalletState.Connected) }
    var step3Complete by remember { mutableStateOf(false) }
    
    // Login session state (from deep link, QR scan, or demo)
    var loginSession by remember { mutableStateOf(initialLoginSession) }

    // Breez wallet state - derive from WalletState
    val balanceSats = when (val state = walletState) {
        is BreezWalletManager.WalletState.Connected -> state.balanceSats.toLong()
        else -> 0L
    }
    var isWalletInitializing by remember { mutableStateOf(false) }
    var walletSparkAddress by remember { mutableStateOf("") }

    // Login/API state
    var lastNonce by remember { mutableStateOf("") }
    var lastLoginId by remember { mutableStateOf("") }
    var lastPreimage by remember { mutableStateOf("") }
    var lastClaimJson by remember { mutableStateOf("") }
    var lastSigHex by remember { mutableStateOf("") }
    var lastPrpJson by remember { mutableStateOf("") }
    var lastInvoice by remember { mutableStateOf("") }
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
    var invoiceAmountSats by remember { mutableStateOf(100UL) } // Default 100 sats for demo

    // UI state
    var statusMessage by remember { mutableStateOf("") }
    var showIdDialog by remember { mutableStateOf(false) }
    var showWalletInfoDialog by remember { mutableStateOf(false) }
    var showVccResult by remember { mutableStateOf(false) }
    var vccResult by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var vccId by remember { mutableStateOf("") }
    
    // Wallet Section State (Screen 2)
    var btcPriceUsd by remember { mutableStateOf(0.0) }
    var transactions by remember { mutableStateOf<List<Payment>>(emptyList()) }
    var showReceiveDialog by remember { mutableStateOf(false) }
    var showSendDialog by remember { mutableStateOf(false) }
    var showTransactionDetail by remember { mutableStateOf<Payment?>(null) }
    var showSeedWordsDialog by remember { mutableStateOf(false) }
    var seedWords by remember { mutableStateOf<List<String>>(emptyList()) }
    var receiveInvoice by remember { mutableStateOf("") }
    var isCreatingReceiveInvoice by remember { mutableStateOf(false) }
    var sendInvoiceText by remember { mutableStateOf("") }
    var parsedInvoice by remember { mutableStateOf<InvoiceDetails?>(null) }
    var isSendingPayment by remember { mutableStateOf(false) }
    var sendError by remember { mutableStateOf("") }
    var walletSyncStatus by remember { mutableStateOf("Connected") }
    
    // Google Drive Backup State
    val googleDriveManager = remember { GoogleDriveBackupManager(context) }
    var showBackupPasswordDialog by remember { mutableStateOf(false) }
    var backupPassword by remember { mutableStateOf("") }
    var backupPasswordConfirm by remember { mutableStateOf("") }
    var isBackingUp by remember { mutableStateOf(false) }
    var backupError by remember { mutableStateOf("") }
    var isGoogleSignedIn by remember { mutableStateOf<Boolean?>(null) }
    
    // Google Drive Restore State
    var showRestorePasswordDialog by remember { mutableStateOf(false) }
    var restorePassword by remember { mutableStateOf("") }
    var isRestoring by remember { mutableStateOf(false) }
    var restoreError by remember { mutableStateOf("") }
    var hasCloudBackup by remember { mutableStateOf<Boolean?>(null) }
    var isCheckingBackup by remember { mutableStateOf(false) }
    var restoreMode by remember { mutableStateOf(false) }  // When true, sign-in is for restore
    
    // Backup Prompt State (deferred backup after first login)
    val backupStateManager = remember { BackupStateManager(context) }
    var showBackupPrompt by remember { mutableStateOf(false) }
    var backupPromptSatsEarned by remember { mutableStateOf(0L) }
    
    // Load Google Sign-In state asynchronously to avoid disk I/O on main thread
    LaunchedEffect(Unit) {
        isGoogleSignedIn = withContext(Dispatchers.IO) {
            googleDriveManager.isSignedIn()
        }
    }
    
    // Google Sign-In launcher
    val googleSignInLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
        try {
            val account = task.getResult(ApiException::class.java)
            scope.launch {
                val success = googleDriveManager.handleSignInResult(account)
                if (success) {
                    isGoogleSignedIn = true
                    if (restoreMode) {
                        // Check if backup exists before showing password dialog
                        isCheckingBackup = true
                        val hasBackup = withContext(Dispatchers.IO) {
                            googleDriveManager.hasBackup()
                        }
                        isCheckingBackup = false
                        hasCloudBackup = hasBackup
                        if (hasBackup) {
                            showRestorePasswordDialog = true
                        } else {
                            Toast.makeText(context, "No backup found for this Google account", Toast.LENGTH_LONG).show()
                        }
                        restoreMode = false
                    } else {
                        showBackupPasswordDialog = true
                    }
                } else {
                    Toast.makeText(context, "Failed to connect to Google Drive", Toast.LENGTH_SHORT).show()
                    restoreMode = false
                }
            }
        } catch (e: ApiException) {
            Toast.makeText(context, "Google Sign-In failed: ${e.message}", Toast.LENGTH_SHORT).show()
            restoreMode = false
        }
    }

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

    // Auto-initialize wallet if already set up
    LaunchedEffect(step2Complete) {
        if (step2Complete && walletState is BreezWalletManager.WalletState.Disconnected) {
            breezMgr.initializeWallet()
        }
    }

    // Update step2Complete when wallet becomes ready
    LaunchedEffect(walletState) {
        when (val state = walletState) {
            is BreezWalletManager.WalletState.Connected -> {
                walletSparkAddress = state.sparkAddress ?: ""
                step2Complete = true
                isWalletInitializing = false
            }
            is BreezWalletManager.WalletState.Error -> {
                statusMessage = "Wallet error: ${state.message}"
                isWalletInitializing = false
            }
            is BreezWalletManager.WalletState.Connecting -> {
                isWalletInitializing = true
            }
            else -> {}
        }
    }

    // Poll for payment when invoice is active
    LaunchedEffect(isPollingPayment, lastPaymentHash) {
        if (isPollingPayment && lastPaymentHash.isNotEmpty()) {
            while (isPollingPayment && !paymentReceived) {
                val received = breezMgr.isPaymentReceived(lastPaymentHash)
                if (received) {
                    paymentReceived = true
                    isPollingPayment = false
                    isLoginActive = false
                    
                    // Complete DLC flow
                    try {
                        // 1. Request oracle signature for auth_verified
                        val attestation = dlcManager.requestOracleSignature(DlcManager.OUTCOME_AUTH_VERIFIED)
                        android.util.Log.i("SignedByMe", "Oracle attestation received: ${attestation.signatureHex.take(16)}...")
                        
                        // 2. Build settlement receipt
                        if (lastDlcContract != null) {
                            lastSettlementReceipt = dlcManager.buildSettlementReceipt(
                                contract = lastDlcContract!!,
                                paymentHash = lastPaymentHash,
                                preimageHex = null, // Would come from payment details
                                attestation = attestation
                            )
                            
                            val (userAmt, opAmt) = dlcManager.calculatePayouts(lastDlcContract!!.amountSats)
                            statusMessage = "✅ Login verified! You received $userAmt sats (90%)"
                            
                            android.util.Log.i("SignedByMe", "Settlement receipt: ${lastSettlementReceipt?.auditHash}")
                            
                            // 3. Notify API of settlement (async, don't block)
                            scope.launch(Dispatchers.IO) {
                                notifyApiOfSettlement(
                                    sessionId = lastLoginId,
                                    paymentHash = lastPaymentHash,
                                    attestation = attestation,
                                    receipt = lastSettlementReceipt
                                )
                            }
                        } else {
                            statusMessage = "✅ Payment received! Log In verified."
                        }
                    } catch (e: Exception) {
                        android.util.Log.e("SignedByMe", "DLC completion error: ${e.message}")
                        statusMessage = "✅ Payment received! Log In verified."
                    }
                    
                    // Close the invoice dialog
                    showInvoiceDialog = false
                    // Refresh transactions
                    transactions = breezMgr.getAllPayments()
                    
                    // Trigger backup prompt after first successful login
                    backupStateManager.recordSuccessfulLogin()
                    if (backupStateManager.shouldShowBackupPrompt()) {
                        // Get the amount earned for the prompt
                        backupPromptSatsEarned = invoiceAmountSats.toLong()
                        // Delay to let user see the success message first
                        delay(2000)
                        showBackupPrompt = true
                    }
                }
                delay(3000) // Poll every 3 seconds
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
    
    // Load transactions when wallet connects
    LaunchedEffect(walletState) {
        if (walletState is BreezWalletManager.WalletState.Connected) {
            transactions = breezMgr.getAllPayments()
        }
    }

    // ===== Screen Routing =====
    // Gate on DID loading state
    if (did == null && didErr == null) {
        // Loading state - show minimal placeholder
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
        // Error state - show retry option
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
                    // Retry loading DID
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
            balanceSats = balanceSats,
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
                // Demo session creation in stable parent scope
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
                        android.util.Log.i("SignedByMe", "Demo session created: ${json.getString("session_id")} (client=${json.optString("client_id")}, root=${json.optString("required_root_id")})")
                    } catch (e: Exception) {
                        android.util.Log.e("SignedByMe", "Failed to create demo session: ${e.message}")
                    }
                }
            },
            onStartLogin = {
                scope.launch {
                    isCreatingInvoice = true
                    statusMessage = ""
                    
                    // Use session ID from login session, or generate one for demo
                    val sessionId = loginSession?.sessionId ?: "demo_${System.currentTimeMillis()}"
                    lastLoginId = sessionId
                    
                    // Use amount from login session (set by enterprise in QR/link)
                    val amountSats = loginSession?.amountSats ?: 100UL
                    
                    // Create invoice using Breez SDK
                    val result = breezMgr.createInvoice(
                        amountSats = amountSats,
                        description = "SignedByMe Log In: ${loginSession?.enterpriseName ?: "Demo"} - $sessionId"
                    )
                    
                    result.onSuccess { invoice ->
                        lastInvoice = invoice
                        lastPaymentHash = breezMgr.extractPaymentHash(invoice)
                        isLoginActive = true
                        isPollingPayment = true
                        
                        // Send invoice to API for enterprise to pay (with STWO proof + DLC)
                        launch(Dispatchers.IO) {
                            try {
                                // Get wallet address for the login proof
                                val walletAddress = (breezMgr.walletState.value as? BreezWalletManager.WalletState.Connected)?.sparkAddress ?: "unknown"
                                
                                // v3 only: Use session nonce from QR, or generate random for demo
                                val sessionNonce = loginSession?.nonce?.takeIf { it.length == 32 }
                                    ?: run {
                                        // Generate random 16-byte nonce for demo mode (32 hex chars)
                                        val bytes = ByteArray(16)
                                        java.security.SecureRandom().nextBytes(bytes)
                                        bytes.joinToString("") { "%02x".format(it) }
                                    }
                                val sessionAmount = loginSession?.amountSats?.toLong() ?: 100L
                                val enterpriseDomain = loginSession?.enterpriseName ?: "demo.signedby.me"
                                
                                android.util.Log.i("SignedByMe", "Generating v3 proof: domain=$enterpriseDomain, amount=$sessionAmount")
                                
                                // 1. Generate STWO v3 proof
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
                                
                                // 2. Build DLC contract for 90/10 split
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
                                
                                // Store DLC contract for later (when payment is received)
                                withContext(Dispatchers.Main) {
                                    lastDlcContract = dlcContract
                                }
                                
                                android.util.Log.i("SignedByMe", "DLC contract built: ${dlcContract?.contractId}")
                                
                                // 2.5. Generate membership proof if required
                                var membershipBundle: MembershipBundle? = null
                                val requiredRootId = loginSession?.requiredRootId
                                val clientId = loginSession?.clientId
                                
                                if (requiredRootId != null && clientId != null) {
                                    android.util.Log.i("SignedByMe", "Membership required: client=$clientId, root=$requiredRootId")
                                    
                                    val witness = didMgr.loadWitness(clientId, requiredRootId)
                                    if (witness != null) {
                                        // Get DID pubkey bytes for binding hash
                                        val didPubkeyHex = did!!.removePrefix("did:btcr:")
                                        val didPubkeyBytes = didPubkeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                        val paymentHashBytes = lastPaymentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                        val nonceBytes = sessionNonce.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                        
                                        // Compute V4 binding hash (must match server)
                                        val bindingHash = NativeBridge.computeBindingHashV4(
                                            didPubkey = didPubkeyBytes,
                                            walletAddress = walletAddress,
                                            clientId = clientId,
                                            sessionId = sessionId,
                                            paymentHash = paymentHashBytes,
                                            amountSats = sessionAmount,
                                            expiresAt = loginSession?.expiresAt ?: (System.currentTimeMillis() / 1000 + 300),
                                            nonce = nonceBytes,
                                            eaDomain = enterpriseDomain,
                                            purposeId = witness.purposeId,
                                            rootId = requiredRootId
                                        )
                                        
                                        // Generate membership proof
                                        // sessionId is base64url-encoded 16 bytes - decode and zero-pad to 32
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
                                                statusMessage = "Error: Could not generate membership proof. Please re-enroll with this employer."
                                            }
                                            return@launch
                                        }
                                    } else {
                                        android.util.Log.e("SignedByMe", "No witness found for client=$clientId, root=$requiredRootId")
                                        withContext(Dispatchers.Main) {
                                            statusMessage = "Error: Not enrolled with this employer. Contact your admin."
                                        }
                                        return@launch
                                    }
                                }
                                
                                // 3. Submit to API with proof + DLC metadata + membership
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
                    }.onFailure { e ->
                        statusMessage = "Failed to create invoice: ${e.message}"
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
            // DEV: Export leaf commitment for membership testing
            onDevExportLeafCommitment = if (BuildConfig.DEBUG) {
                {
                    // Use real session values if available, otherwise show error
                    val clientId = loginSession?.clientId
                    val rootId = loginSession?.requiredRootId
                    if (clientId != null && rootId != null) {
                        scope.launch {
                            val commitment = withContext(Dispatchers.IO) {
                                didMgr.devExportLeafCommitment(clientId, rootId)
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
            // Wallet Section parameters
            btcPriceUsd = btcPriceUsd,
            transactions = transactions,
            walletSyncStatus = walletSyncStatus,
            showReceiveDialog = showReceiveDialog,
            showSendDialog = showSendDialog,
            showTransactionDetail = showTransactionDetail,
            showSeedWordsDialog = showSeedWordsDialog,
            seedWords = seedWords,
            receiveInvoice = receiveInvoice,
            isCreatingReceiveInvoice = isCreatingReceiveInvoice,
            sendInvoiceText = sendInvoiceText,
            parsedInvoice = parsedInvoice,
            isSendingPayment = isSendingPayment,
            sendError = sendError,
            onRefreshWallet = {
                scope.launch {
                    walletSyncStatus = "Syncing..."
                    breezMgr.refreshBalance()
                    transactions = breezMgr.getAllPayments()
                    walletSyncStatus = "Connected"
                }
            },
            onShowReceiveDialog = { showReceiveDialog = true },
            onDismissReceiveDialog = { 
                showReceiveDialog = false
                receiveInvoice = ""
            },
            onCreateReceiveInvoice = { amountSats, memo ->
                scope.launch {
                    isCreatingReceiveInvoice = true
                    val result = breezMgr.createInvoice(
                        amountSats = amountSats.toULong(),
                        description = memo.ifEmpty { "SignedByMe Receive" }
                    )
                    result.onSuccess { invoice ->
                        receiveInvoice = invoice
                    }.onFailure { e ->
                        Toast.makeText(context, "Failed: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                    isCreatingReceiveInvoice = false
                }
            },
            onCopyReceiveInvoice = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Lightning Invoice", receiveInvoice))
                Toast.makeText(context, "Invoice copied!", Toast.LENGTH_SHORT).show()
            },
            onShareReceiveInvoice = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, receiveInvoice)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share Invoice"))
            },
            onShowSendDialog = { showSendDialog = true },
            onDismissSendDialog = {
                showSendDialog = false
                sendInvoiceText = ""
                parsedInvoice = null
                sendError = ""
            },
            onSendInvoiceTextChange = { text ->
                sendInvoiceText = text
                sendError = ""
                // Try to parse the invoice
                if (text.isNotEmpty()) {
                    scope.launch {
                        val result = breezMgr.parseInvoice(text)
                        result.onSuccess { details ->
                            parsedInvoice = details
                            sendError = ""
                        }.onFailure {
                            parsedInvoice = null
                        }
                    }
                } else {
                    parsedInvoice = null
                }
            },
            onSendPayment = {
                scope.launch {
                    isSendingPayment = true
                    sendError = ""
                    val result = breezMgr.sendPayment(sendInvoiceText)
                    result.onSuccess {
                        Toast.makeText(context, "Payment sent!", Toast.LENGTH_SHORT).show()
                        showSendDialog = false
                        sendInvoiceText = ""
                        parsedInvoice = null
                        transactions = breezMgr.getAllPayments()
                    }.onFailure { e ->
                        sendError = e.message ?: "Payment failed"
                    }
                    isSendingPayment = false
                }
            },
            onSendLightningAddress = { address, amount, comment ->
                scope.launch {
                    isSendingPayment = true
                    sendError = ""
                    val result = breezMgr.sendToLightningAddress(
                        lightningAddress = address,
                        amountSats = amount.toULong(),
                        comment = comment
                    )
                    result.onSuccess {
                        Toast.makeText(context, "Payment sent to $address!", Toast.LENGTH_SHORT).show()
                        showSendDialog = false
                        transactions = breezMgr.getAllPayments()
                    }.onFailure { e ->
                        sendError = e.message ?: "Payment to Lightning Address failed"
                    }
                    isSendingPayment = false
                }
            },
            onShowTransactionDetail = { payment -> showTransactionDetail = payment },
            onDismissTransactionDetail = { showTransactionDetail = null },
            onShowSeedWords = {
                // Get mnemonic from wallet manager
                val mnemonic = breezMgr.getMnemonic()
                if (mnemonic != null) {
                    seedWords = mnemonic.split(" ")
                    showSeedWordsDialog = true
                } else {
                    Toast.makeText(context, "Could not retrieve seed words", Toast.LENGTH_SHORT).show()
                }
            },
            onDismissSeedWords = { 
                showSeedWordsDialog = false
                seedWords = emptyList()
            },
            onCopySeedWords = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Seed Words", seedWords.joinToString(" ")))
                Toast.makeText(context, "Seed words copied!", Toast.LENGTH_SHORT).show()
            },
            onBackupToCloud = {
                if (isGoogleSignedIn == true) {
                    // Already signed in, show password dialog
                    backupPassword = ""
                    backupPasswordConfirm = ""
                    backupError = ""
                    showBackupPasswordDialog = true
                } else {
                    // Need to sign in first (or still checking)
                    googleSignInLauncher.launch(googleDriveManager.getSignInIntent())
                }
            }
        )
        
        // Google Drive Backup Password Dialog
        if (showBackupPasswordDialog) {
            BackupPasswordDialog(
                password = backupPassword,
                passwordConfirm = backupPasswordConfirm,
                error = backupError,
                isBackingUp = isBackingUp,
                onPasswordChange = { backupPassword = it },
                onPasswordConfirmChange = { backupPasswordConfirm = it },
                onBackup = {
                    if (backupPassword.length < 8) {
                        backupError = "Password must be at least 8 characters"
                    } else if (backupPassword != backupPasswordConfirm) {
                        backupError = "Passwords don't match"
                    } else {
                        val mnemonic = breezMgr.getMnemonic()
                        if (mnemonic != null) {
                            isBackingUp = true
                            backupError = ""
                            scope.launch {
                                val result = googleDriveManager.backupMnemonic(mnemonic, backupPassword)
                                result.onSuccess {
                                    Toast.makeText(context, "Wallet backed up to Google Drive!", Toast.LENGTH_LONG).show()
                                    backupStateManager.markBackupCompleted()
                                    showBackupPasswordDialog = false
                                    showSeedWordsDialog = false
                                }.onFailure { e ->
                                    backupError = e.message ?: "Backup failed"
                                }
                                isBackingUp = false
                            }
                        } else {
                            backupError = "Could not access wallet seed"
                        }
                    }
                },
                onDismiss = { showBackupPasswordDialog = false }
            )
        }
        // Google Drive Restore Password Dialog
        if (showRestorePasswordDialog) {
            RestorePasswordDialog(
                password = restorePassword,
                error = restoreError,
                isRestoring = isRestoring,
                onPasswordChange = { restorePassword = it },
                onRestore = {
                    if (restorePassword.isEmpty()) {
                        restoreError = "Please enter your backup password"
                    } else {
                        isRestoring = true
                        restoreError = ""
                        scope.launch {
                            val result = googleDriveManager.restoreMnemonic(restorePassword)
                            result.onSuccess { mnemonic ->
                                // Restore the wallet with the mnemonic
                                val restoreResult = breezMgr.restoreFromMnemonic(mnemonic)
                                restoreResult.onSuccess {
                                    Toast.makeText(context, "Wallet restored successfully!", Toast.LENGTH_LONG).show()
                                    showRestorePasswordDialog = false
                                    step2Complete = true
                                }.onFailure { e ->
                                    restoreError = e.message ?: "Failed to restore wallet"
                                }
                            }.onFailure { e ->
                                restoreError = when {
                                    e.message?.contains("Incorrect password") == true -> "Incorrect password"
                                    else -> e.message ?: "Restore failed"
                                }
                            }
                            isRestoring = false
                        }
                    }
                },
                onDismiss = { 
                    showRestorePasswordDialog = false
                    restorePassword = ""
                    restoreError = ""
                }
            )
        }
        
        // Backup Prompt Bottom Sheet (shown after first successful login)
        if (showBackupPrompt) {
            BackupPromptBottomSheet(
                satsEarned = backupPromptSatsEarned,
                onBackupNow = {
                    showBackupPrompt = false
                    if (isGoogleSignedIn == true) {
                        // Already signed in, show password dialog
                        backupPassword = ""
                        backupPasswordConfirm = ""
                        backupError = ""
                        showBackupPasswordDialog = true
                    } else {
                        // Need to sign in first
                        googleSignInLauncher.launch(googleDriveManager.getSignInIntent())
                    }
                },
                onRemindLater = {
                    backupStateManager.recordPromptDismissed()
                    showBackupPrompt = false
                },
                onDismiss = {
                    backupStateManager.recordPromptDismissed()
                    showBackupPrompt = false
                }
            )
        }
    } else {
        // Show Onboarding Screen
        OnboardingScreen(
            did = did!!,
            step1Complete = step1Complete,
            step2Complete = step2Complete,
            step3Complete = step3Complete,
            walletState = walletState,
            balanceSats = balanceSats,
            isWalletInitializing = isWalletInitializing,
            isRestoring = isRestoring || isCheckingBackup,
            walletSparkAddress = walletSparkAddress,
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
            onSetupWallet = {
                scope.launch {
                    isWalletInitializing = true
                    statusMessage = ""
                    val result = breezMgr.initializeWallet()
                    result.onFailure { e ->
                        statusMessage = "Error: ${e.message}"
                    }
                }
            },
            onRestoreWallet = {
                if (isGoogleSignedIn == true) {
                    // Already signed in, check for backup
                    scope.launch {
                        isCheckingBackup = true
                        val hasBackup = withContext(Dispatchers.IO) {
                            googleDriveManager.hasBackup()
                        }
                        isCheckingBackup = false
                        hasCloudBackup = hasBackup
                        if (hasBackup) {
                            restorePassword = ""
                            restoreError = ""
                            showRestorePasswordDialog = true
                        } else {
                            Toast.makeText(context, "No backup found for this Google account", Toast.LENGTH_LONG).show()
                        }
                    }
                } else {
                    // Need to sign in first
                    restoreMode = true
                    googleSignInLauncher.launch(googleDriveManager.getSignInIntent())
                }
            },
            onShowWalletInfoDialog = { showWalletInfoDialog = true },
            onDismissWalletInfoDialog = { showWalletInfoDialog = false },
            onCopySparkAddress = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Spark Address", walletSparkAddress))
                Toast.makeText(context, "Spark Address copied!", Toast.LENGTH_SHORT).show()
            },
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
                            walletType = "breez",
                            withdrawTo = walletSparkAddress.ifEmpty { "lightning-wallet" },
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
                        
                        // Generate Groth16 Membership Proof (replaces STWO)
                        // Uses leaf_secret + Merkle witness to prove membership
                        val groth16Result = didMgr.generateGroth16Proof(
                            clientId = "default",  // TODO: get from session
                            rootId = "default"     // TODO: get from session
                        )
                        val groth16Json = JSONObject(groth16Result)
                        val proofHash = if (groth16Json.optBoolean("success", false)) {
                            // Hash the actual proof for VCC
                            val md = java.security.MessageDigest.getInstance("SHA-256")
                            md.digest(groth16Result.toByteArray(Charsets.UTF_8))
                                .joinToString("") { "%02x".format(it) }
                        } else {
                            // Stub proof - use placeholder hash
                            android.util.Log.w("SignedByMe", "Groth16 proof stub: ${groth16Json.optString("error", "unknown")}")
                            "stub_proof_${System.currentTimeMillis()}"
                        }

                        val generatedVccId = "vcc_${System.currentTimeMillis()}_${did!!.takeLast(8)}"
                        val vcc = JSONObject().apply {
                            put("schema", "signedby.me/vcc/3")  // Updated schema with Groth16
                            put("id", generatedVccId)
                            put("did", did!!)
                            put("wallet_address", walletSparkAddress)
                            put("content_hash", "sha256_demo_${System.currentTimeMillis()}")
                            put("proof_hash", preShaHex)
                            put("groth16_proof_hash", proofHash)  // Groth16 proof hash
                            put("wallet_type", "breez")
                            put("timestamp", System.currentTimeMillis())
                            put("expires_at", System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000)
                            put("signature", sigHex)
                        }.toString()

                        // Auto-enroll for membership (silent, UI-less)
                        // This generates leaf_secret if not exists and calls enrollment API
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
                                } else {
                                    android.util.Log.w("SignedByMe", "Membership enrollment failed (non-blocking)")
                                }
                            } catch (e: Exception) {
                                android.util.Log.w("SignedByMe", "Membership enrollment error (non-blocking): ${e.message}")
                            }
                        } else {
                            android.util.Log.i("SignedByMe", "Already enrolled for membership")
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

}

// ===== Onboarding Screen =====
@Composable
fun OnboardingScreen(
    did: String,
    step1Complete: Boolean,
    step2Complete: Boolean,
    step3Complete: Boolean,
    walletState: BreezWalletManager.WalletState,
    balanceSats: Long,
    isWalletInitializing: Boolean,
    isRestoring: Boolean,
    walletSparkAddress: String,
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
    onSetupWallet: () -> Unit,
    onRestoreWallet: () -> Unit,
    onShowWalletInfoDialog: () -> Unit,
    onDismissWalletInfoDialog: () -> Unit,
    onCopySparkAddress: () -> Unit,
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

            // Step 2: Connect
            StepCard(
                stepNumber = 2,
                title = "Connect",
                isComplete = step2Complete && walletState is BreezWalletManager.WalletState.Connected,
                isEnabled = step1Complete
            ) {
                if (!step2Complete || walletState !is BreezWalletManager.WalletState.Connected) {
                    Text(
                        "Press button below to set up your wallet",
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

                    if (isWalletInitializing || isRestoring) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(40.dp),
                                color = Color(0xFF3B82F6)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                if (isRestoring) "Restoring wallet..." else "Setting up wallet...",
                                fontSize = 14.sp,
                                color = Color.Gray
                            )
                        }
                    } else {
                        // Show both buttons only when no wallet exists
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            GradientButton(
                                text = "Set Up New Wallet",
                                colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                                onClick = onSetupWallet
                            )
                            
                            // Restore from backup button
                            OutlinedButton(
                                onClick = onRestoreWallet,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(50.dp),
                                shape = RoundedCornerShape(12.dp),
                                border = BorderStroke(1.dp, Color(0xFF3B82F6))
                            ) {
                                Text(
                                    "Restore from Backup",
                                    color = Color(0xFF3B82F6),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }

                    if (walletState is BreezWalletManager.WalletState.Error) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            (walletState as BreezWalletManager.WalletState.Error).message,
                            color = Color(0xFFEF4444),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
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
                isEnabled = step1Complete && step2Complete && walletState is BreezWalletManager.WalletState.Connected
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
                            enabled = walletState is BreezWalletManager.WalletState.Connected,
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

    // Dialogs
    if (showIdDialog) {
        DIDInfoDialog(
            did = did!!,
            onDismiss = onDismissIdDialog,
            onRegenerate = onRegenerateDid,
            onCopy = onCopyDid
        )
    }

    if (showWalletInfoDialog) {
        WalletInfoDialog(
            sparkAddress = walletSparkAddress,
            balanceSats = balanceSats,
            onDismiss = onDismissWalletInfoDialog,
            onCopySparkAddress = onCopySparkAddress
        )
    }
}

// ===== Login Screen =====
@Composable
fun LoginScreen(
    did: String,
    balanceSats: Long,
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
    onCreateDemoSession: () -> Unit,  // Create demo session with stable scope
    onStartLogin: () -> Unit,
    onShowInvoiceDialog: () -> Unit,
    onDismissInvoiceDialog: () -> Unit,
    onCopyInvoice: () -> Unit,
    onShareInvoice: () -> Unit,
    onResetLogin: () -> Unit,
    onCopyVcc: () -> Unit,
    onShareVcc: () -> Unit,
    // DEV: Leaf commitment export for membership testing
    onDevExportLeafCommitment: (() -> Unit)? = null,
    // Wallet Section parameters
    btcPriceUsd: Double,
    transactions: List<Payment>,
    walletSyncStatus: String,
    showReceiveDialog: Boolean,
    showSendDialog: Boolean,
    showTransactionDetail: Payment?,
    showSeedWordsDialog: Boolean,
    seedWords: List<String>,
    receiveInvoice: String,
    isCreatingReceiveInvoice: Boolean,
    sendInvoiceText: String,
    parsedInvoice: InvoiceDetails?,
    isSendingPayment: Boolean,
    sendError: String,
    onRefreshWallet: () -> Unit,
    onShowReceiveDialog: () -> Unit,
    onDismissReceiveDialog: () -> Unit,
    onCreateReceiveInvoice: (Long, String) -> Unit,
    onCopyReceiveInvoice: () -> Unit,
    onShareReceiveInvoice: () -> Unit,
    onShowSendDialog: () -> Unit,
    onDismissSendDialog: () -> Unit,
    onSendInvoiceTextChange: (String) -> Unit,
    onSendPayment: () -> Unit,
    onSendLightningAddress: (String, Long, String?) -> Unit,
    onShowTransactionDetail: (Payment) -> Unit,
    onDismissTransactionDetail: () -> Unit,
    onShowSeedWords: () -> Unit,
    onDismissSeedWords: () -> Unit,
    onCopySeedWords: () -> Unit,
    onBackupToCloud: () -> Unit
) {
    // QR Scanner state
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

            // Login Section
            // Login Section Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(8.dp, RoundedCornerShape(24.dp)),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    // Employer badge in upper left when session exists (hide after login complete)
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
                            Text(
                                "⏳",
                                fontSize = 48.sp
                            )

                            Spacer(modifier = Modifier.height(12.dp))

                            Text(
                                "Awaiting Payment",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFFF59E0B)
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            // Show enterprise name if we have it
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
                            
                            // Debug-only: View Invoice button (for testing payments)
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
                                
                                // Debug-only: Export leaf commitment for membership testing
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
                                // Has a session from QR/deep link - ready to login
                                Text(
                                    "🔐",
                                    fontSize = 48.sp
                                )

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
                                Text(
                                    "📷",
                                    fontSize = 48.sp
                                )

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

                                // Demo button for testing - calls real API
                                // Uses stable parent scope via callback to avoid "coroutine scope left composition"
                                OutlinedButton(onClick = onCreateDemoSession) {
                                    Text("Demo: Acme Corp Log In (100 sats)", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }

            // ===== WALLET SECTION =====
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
                    // Header with refresh button
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("⚡", fontSize = 24.sp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "Your Wallet",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        IconButton(onClick = onRefreshWallet) {
                            Icon(
                                Icons.Default.Refresh,
                                contentDescription = "Refresh",
                                tint = Color(0xFF3B82F6)
                            )
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Balance display
                    Text(
                        "${formatSats(balanceSats)} sats",
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF1F2937)
                    )
                    
                    if (btcPriceUsd > 0) {
                        Text(
                            satsToUsd(balanceSats, btcPriceUsd),
                            fontSize = 16.sp,
                            color = Color.Gray
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    // Connection status
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(
                                    if (walletSyncStatus == "Connected") Color(0xFF10B981)
                                    else Color(0xFFF59E0B)
                                )
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            walletSyncStatus,
                            fontSize = 12.sp,
                            color = Color.Gray
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    // Send & Receive buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Receive button
                        Button(
                            onClick = onShowReceiveDialog,
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF10B981)
                            ),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(
                                Icons.Default.KeyboardArrowDown,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Receive")
                        }
                        
                        // Send button
                        Button(
                            onClick = onShowSendDialog,
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF3B82F6)
                            ),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(
                                Icons.Default.KeyboardArrowUp,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Send")
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    // Backup & Seed buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        TextButton(
                            onClick = onBackupToCloud,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("☁️ Backup", fontSize = 13.sp, color = Color(0xFF3B82F6))
                        }
                        TextButton(
                            onClick = onShowSeedWords,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("🔑 View Seed", fontSize = 13.sp, color = Color(0xFF3B82F6))
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Transaction History
                    Text(
                        "Transaction History",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    if (transactions.isEmpty()) {
                        Text(
                            "No transactions yet",
                            fontSize = 14.sp,
                            color = Color.Gray,
                            modifier = Modifier.fillMaxWidth(),
                            textAlign = TextAlign.Center
                        )
                    } else {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            transactions.forEach { payment ->
                                TransactionRow(
                                    payment = payment,
                                    btcPriceUsd = btcPriceUsd,
                                    onClick = { onShowTransactionDetail(payment) }
                                )
                            }
                        }
                    }
                }
            }
            // ===== END WALLET SECTION =====

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
                            "Use your VCC to prove your content is yours. This VCC is cryptographically tied to your Signature.",
                            fontSize = 13.sp,
                            color = Color.Gray,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        StatusPill("Verified Content Claim", Color(0xFF10B981))
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        // VCC preview
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
                        
                        // Copy / Share buttons
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
                // Parse the QR content - supports both new (token=) and legacy (session=&enterprise=) formats
                try {
                    val uri = android.net.Uri.parse(qrContent)
                    
                    // New stateless flow: token parameter contains signed JWT
                    val token = uri.getQueryParameter("token")
                    if (token != null) {
                        // Parse JWT to extract enterprise info
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
                                nonce = payload.optString("nonce", null),
                                expiresAt = if (payload.has("expires_at")) payload.optLong("expires_at") else null
                            ))
                            return@QrScannerDialog
                        }
                    }
                    
                    // Legacy flow: session + enterprise parameters
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
    
    // Receive Dialog
    if (showReceiveDialog) {
        ReceiveDialog(
            invoice = receiveInvoice,
            isCreating = isCreatingReceiveInvoice,
            btcPriceUsd = btcPriceUsd,
            onCreateInvoice = onCreateReceiveInvoice,
            onCopy = onCopyReceiveInvoice,
            onShare = onShareReceiveInvoice,
            onDismiss = onDismissReceiveDialog
        )
    }
    
    // Send Dialog
    if (showSendDialog) {
        SendDialog(
            invoiceText = sendInvoiceText,
            parsedInvoice = parsedInvoice,
            isSending = isSendingPayment,
            error = sendError,
            btcPriceUsd = btcPriceUsd,
            onInvoiceTextChange = onSendInvoiceTextChange,
            onSendInvoice = onSendPayment,
            onSendLightningAddress = onSendLightningAddress,
            onDismiss = onDismissSendDialog
        )
    }
    
    // Transaction Detail Dialog
    if (showTransactionDetail != null) {
        TransactionDetailDialog(
            payment = showTransactionDetail!!,
            btcPriceUsd = btcPriceUsd,
            onDismiss = onDismissTransactionDetail
        )
    }
    
    // Seed Words Dialog
    if (showSeedWordsDialog) {
        SeedWordsDialog(
            seedWords = seedWords,
            onCopy = onCopySeedWords,
            onBackup = onBackupToCloud,
            onDismiss = onDismissSeedWords
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
    
    // Track camera provider, executor, and scanner for cleanup
    var cameraProviderRef by remember { mutableStateOf<androidx.camera.lifecycle.ProcessCameraProvider?>(null) }
    val analysisExecutor = remember { java.util.concurrent.Executors.newSingleThreadExecutor() }
    var barcodeScanner by remember { mutableStateOf<com.google.mlkit.vision.barcode.BarcodeScanner?>(null) }
    var isDisposed by remember { mutableStateOf(false) }
    
    // Initialize barcode scanner off the main thread to avoid StrictMode disk I/O
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
    
    // Cleanup camera, executor, and scanner on dismiss
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
                    // Camera preview with QR scanning
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
                                    
                                    // Guard against binding after disposal
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

// ===== Wallet Components =====

@Composable
fun TransactionRow(
    payment: Payment,
    btcPriceUsd: Double,
    onClick: () -> Unit
) {
    val isReceived = payment.paymentType == PaymentType.RECEIVE
    val details = payment.details
    
    // Extract description from Lightning payment details
    val description = if (details is PaymentDetails.Lightning) {
        details.description ?: "Lightning Payment"
    } else {
        "Payment"
    }
    
    // Get amount and timestamp from Payment object
    val amountSats = payment.amount.toLong()
    val timestamp = payment.timestamp
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF9FAFB))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                // Direction indicator
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(
                            if (isReceived) Color(0xFF10B981).copy(alpha = 0.1f)
                            else Color(0xFF3B82F6).copy(alpha = 0.1f)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        if (isReceived) Icons.Default.KeyboardArrowDown 
                        else Icons.Default.KeyboardArrowUp,
                        contentDescription = null,
                        tint = if (isReceived) Color(0xFF10B981) else Color(0xFF3B82F6),
                        modifier = Modifier.size(20.dp)
                    )
                }
                
                Spacer(modifier = Modifier.width(12.dp))
                
                Column {
                    Text(
                        if (isReceived) "Received" else "Sent",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium
                    )
                    if (description.isNotEmpty()) {
                        Text(
                            description.take(30) + if (description.length > 30) "..." else "",
                            fontSize = 12.sp,
                            color = Color.Gray,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        formatTimestamp(timestamp),
                        fontSize = 11.sp,
                        color = Color.Gray
                    )
                }
            }
            
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    "${if (isReceived) "+" else "-"}${formatSats(amountSats)} sats",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = if (isReceived) Color(0xFF10B981) else Color(0xFF1F2937)
                )
                if (btcPriceUsd > 0) {
                    Text(
                        satsToUsd(amountSats, btcPriceUsd),
                        fontSize = 11.sp,
                        color = Color.Gray
                    )
                }
            }
        }
    }
}

fun formatTimestamp(timestamp: ULong): String {
    val date = Date(timestamp.toLong() * 1000)
    val now = System.currentTimeMillis()
    val diff = now - date.time
    
    return when {
        diff < 60_000 -> "Just now"
        diff < 3600_000 -> "${diff / 60_000} min ago"
        diff < 86400_000 -> "${diff / 3600_000} hours ago"
        diff < 172800_000 -> "Yesterday"
        else -> SimpleDateFormat("MMM d", Locale.US).format(date)
    }
}

// Generate QR code bitmap for invoice
fun generateQrCodeBitmap(content: String, size: Int = 512): Bitmap? {
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
        null
    }
}

// ===== Wallet Dialogs =====

@Composable
fun ReceiveDialog(
    invoice: String,
    isCreating: Boolean,
    btcPriceUsd: Double,
    onCreateInvoice: (Long, String) -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit,
    onDismiss: () -> Unit
) {
    var amountText by remember { mutableStateOf("") }
    var memoText by remember { mutableStateOf("") }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Receive Sats",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Text("✕", fontSize = 18.sp, color = Color.Gray)
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                if (invoice.isEmpty()) {
                    // Input form
                    OutlinedTextField(
                        value = amountText,
                        onValueChange = { amountText = it.filter { c -> c.isDigit() } },
                        label = { Text("Amount (sats)") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    // Show USD equivalent
                    if (amountText.isNotEmpty() && btcPriceUsd > 0) {
                        val sats = amountText.toLongOrNull() ?: 0
                        Text(
                            satsToUsd(sats, btcPriceUsd),
                            fontSize = 12.sp,
                            color = Color.Gray,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    OutlinedTextField(
                        value = memoText,
                        onValueChange = { memoText = it },
                        label = { Text("Memo (optional)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    Button(
                        onClick = {
                            val amount = amountText.toLongOrNull() ?: 0
                            if (amount > 0) {
                                onCreateInvoice(amount, memoText)
                            }
                        },
                        enabled = !isCreating && amountText.isNotEmpty() && (amountText.toLongOrNull() ?: 0) > 0,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isCreating) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text("Generate Invoice")
                        }
                    }
                } else {
                    // Show generated invoice
                    val amountSats = amountText.toLongOrNull() ?: 0
                    
                    Text(
                        "${formatSats(amountSats)} sats",
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Bold
                    )
                    
                    if (btcPriceUsd > 0) {
                        Text(
                            satsToUsd(amountSats, btcPriceUsd),
                            fontSize = 14.sp,
                            color = Color.Gray
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // QR Code
                    val qrBitmap = remember(invoice) { generateQrCodeBitmap(invoice) }
                    qrBitmap?.let {
                        Image(
                            bitmap = it.asImageBitmap(),
                            contentDescription = "Invoice QR Code",
                            modifier = Modifier
                                .size(200.dp)
                                .clip(RoundedCornerShape(12.dp))
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    // Invoice text (truncated)
                    Text(
                        invoice.take(30) + "...",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Color.Gray
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
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
                            Text("📤 Share")
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SendDialog(
    invoiceText: String,
    parsedInvoice: InvoiceDetails?,
    isSending: Boolean,
    error: String,
    btcPriceUsd: Double,
    onInvoiceTextChange: (String) -> Unit,
    onSendInvoice: () -> Unit,
    onSendLightningAddress: (String, Long, String?) -> Unit,
    onDismiss: () -> Unit
) {
    var showScanner by remember { mutableStateOf(false) }
    val context = LocalContext.current
    
    // Mode: 0 = Invoice, 1 = Lightning Address
    var selectedMode by remember { mutableStateOf(0) }
    
    // Lightning Address state
    var lightningAddress by remember { mutableStateOf("") }
    var addressAmount by remember { mutableStateOf("") }
    var addressComment by remember { mutableStateOf("") }
    var addressError by remember { mutableStateOf("") }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Send Sats",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Text("✕", fontSize = 18.sp, color = Color.Gray)
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Mode selector tabs
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color(0xFFF3F4F6)),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    listOf("Invoice", "Lightning Address").forEachIndexed { index, label ->
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(8.dp))
                                .background(
                                    if (selectedMode == index) Color.White
                                    else Color.Transparent
                                )
                                .clickable { selectedMode = index }
                                .padding(vertical = 10.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                label,
                                fontSize = 13.sp,
                                fontWeight = if (selectedMode == index) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (selectedMode == index) Color(0xFF3B82F6) else Color.Gray
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                if (selectedMode == 0) {
                    // ===== INVOICE MODE =====
                    OutlinedTextField(
                        value = invoiceText,
                        onValueChange = onInvoiceTextChange,
                        label = { Text("Lightning Invoice") },
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 3,
                        placeholder = { Text("lnbc...", color = Color.Gray) }
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = clipboard.primaryClip
                                if (clip != null && clip.itemCount > 0) {
                                    val pastedText = clip.getItemAt(0).text?.toString() ?: ""
                                    onInvoiceTextChange(pastedText)
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("📋 Paste")
                        }
                        OutlinedButton(
                            onClick = { showScanner = true },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("📷 Scan")
                        }
                    }
                    
                    // Parsed invoice preview
                    if (parsedInvoice != null) {
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFF0FDF4)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text("Amount:", color = Color.Gray, fontSize = 14.sp)
                                    Column(horizontalAlignment = Alignment.End) {
                                        Text(
                                            "${formatSats(parsedInvoice.amountSats?.toLong() ?: 0)} sats",
                                            fontWeight = FontWeight.SemiBold,
                                            fontSize = 14.sp
                                        )
                                        if (btcPriceUsd > 0 && parsedInvoice.amountSats != null) {
                                            Text(
                                                satsToUsd(parsedInvoice.amountSats.toLong(), btcPriceUsd),
                                                fontSize = 12.sp,
                                                color = Color.Gray
                                            )
                                        }
                                    }
                                }
                                if (parsedInvoice.description.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text("To:", color = Color.Gray, fontSize = 14.sp)
                                    Text(
                                        parsedInvoice.description.take(30),
                                        fontSize = 14.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            if (parsedInvoice.isExpired) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    "⚠️ Invoice expired",
                                    color = Color(0xFFEF4444),
                                    fontSize = 12.sp
                                )
                            }
                        }
                    }
                    }
                    
                    // Error message for invoice mode
                    if (error.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            error,
                            color = Color(0xFFEF4444),
                            fontSize = 12.sp
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    Button(
                        onClick = onSendInvoice,
                        enabled = !isSending && parsedInvoice != null && !parsedInvoice.isExpired,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isSending) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text("Confirm & Send")
                        }
                    }
                } else {
                    // ===== LIGHTNING ADDRESS MODE =====
                    OutlinedTextField(
                        value = lightningAddress,
                        onValueChange = { 
                            lightningAddress = it
                            addressError = ""
                        },
                        label = { Text("Lightning Address") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        placeholder = { Text("user@wallet.com", color = Color.Gray) }
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    OutlinedTextField(
                        value = addressAmount,
                        onValueChange = { addressAmount = it.filter { c -> c.isDigit() } },
                        label = { Text("Amount (sats)") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    // Show USD equivalent
                    if (addressAmount.isNotEmpty() && btcPriceUsd > 0) {
                        val sats = addressAmount.toLongOrNull() ?: 0
                        Text(
                            satsToUsd(sats, btcPriceUsd),
                            fontSize = 12.sp,
                            color = Color.Gray,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    OutlinedTextField(
                        value = addressComment,
                        onValueChange = { addressComment = it },
                        label = { Text("Comment (optional)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    // Error message for Lightning Address mode
                    if (addressError.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            addressError,
                            color = Color(0xFFEF4444),
                            fontSize = 12.sp
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    Button(
                        onClick = {
                            val amount = addressAmount.toLongOrNull() ?: 0
                            if (lightningAddress.isEmpty()) {
                                addressError = "Please enter a Lightning Address"
                            } else if (!lightningAddress.contains("@")) {
                                addressError = "Invalid format. Use: user@wallet.com"
                            } else if (amount <= 0) {
                                addressError = "Please enter an amount"
                            } else {
                                onSendLightningAddress(
                                    lightningAddress,
                                    amount,
                                    addressComment.ifEmpty { null }
                                )
                            }
                        },
                        enabled = !isSending && lightningAddress.isNotEmpty() && addressAmount.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isSending) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text("Send to Address")
                        }
                    }
                }
            }
        }
    }
    
    // QR Scanner for invoice
    if (showScanner) {
        QrScannerDialog(
            onQrScanned = { scanned ->
                showScanner = false
                onInvoiceTextChange(scanned)
            },
            onDismiss = { showScanner = false },
            title = "Scan Invoice QR Code",
            subtitle = "Point your camera at the recipient's Lightning invoice"
        )
    }
}

@Composable
fun TransactionDetailDialog(
    payment: Payment,
    btcPriceUsd: Double,
    onDismiss: () -> Unit
) {
    val isReceived = payment.paymentType == PaymentType.RECEIVE
    val status = payment.status
    val details = payment.details
    
    // Extract description and hash from Lightning payment details
    val description = if (details is PaymentDetails.Lightning) {
        details.description ?: "Lightning Payment"
    } else {
        "Payment"
    }
    
    val paymentHash = if (details is PaymentDetails.Lightning) {
        details.paymentHash
    } else {
        ""
    }
    
    // Get amount and timestamp from Payment object
    val amountSats = payment.amount.toLong()
    val timestamp = payment.timestamp
    val feesSats = payment.fees.toLong()
    
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
                        "Transaction Details",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Text("✕", fontSize = 18.sp, color = Color.Gray)
                    }
                }
                
                Spacer(modifier = Modifier.height(20.dp))
                
                // Status
                DetailRow("Status", when (status) {
                    PaymentStatus.COMPLETED -> "✓ Complete"
                    PaymentStatus.PENDING -> "⏳ Pending"
                    PaymentStatus.FAILED -> "✗ Failed"
                    else -> "Unknown"
                })
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Type
                DetailRow("Type", if (isReceived) "Received" else "Sent")
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Amount
                DetailRow(
                    "Amount",
                    "${if (isReceived) "+" else "-"}${formatSats(amountSats)} sats" +
                        if (btcPriceUsd > 0) " (${satsToUsd(amountSats, btcPriceUsd)})" else ""
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Date
                val date = Date(timestamp.toLong() * 1000)
                val dateFormat = SimpleDateFormat("MMM d, yyyy h:mm a", Locale.US)
                DetailRow("Date", dateFormat.format(date))
                
                if (description.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    DetailRow("Description", description)
                }
                
                if (paymentHash.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    Text("Payment Hash:", fontSize = 12.sp, color = Color.Gray)
                    Spacer(modifier = Modifier.height(4.dp))
                    
                    val context = LocalContext.current
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            paymentHash.take(20) + "..." + paymentHash.takeLast(8),
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Payment Hash", paymentHash))
                            Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
                        }) {
                            Text("Copy", fontSize = 12.sp)
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(20.dp))
                
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Close")
                }
            }
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 14.sp, color = Color.Gray)
        Text(value, fontSize = 14.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
fun SeedWordsDialog(
    seedWords: List<String>,
    onCopy: () -> Unit,
    onBackup: () -> Unit,
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
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopy,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("📋 Copy All")
                    }
                    Button(
                        onClick = onBackup,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                    ) {
                        Text("☁️ Backup")
                    }
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
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Step badge
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

            // Content
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

                // QR Code
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

                // Truncated DID
                Text(
                    text = "${did.take(12)}...${did.takeLast(6)}",
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Full DID (scrollable)
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
    sparkAddress: String,
    balanceSats: Long,
    onDismiss: () -> Unit,
    onCopySparkAddress: () -> Unit
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
                // Lightning icon
                Text("⚡", fontSize = 48.sp)
                
                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    "Lightning Wallet",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Balance card
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
                            "Balance",
                            fontSize = 14.sp,
                            color = Color.Gray
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "$balanceSats sats",
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF3B82F6)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Spark Address
                Text(
                    "Spark Address",
                    fontSize = 14.sp,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (sparkAddress.length > 20) "${sparkAddress.take(10)}...${sparkAddress.takeLast(10)}" else sparkAddress.ifEmpty { "Not available" },
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Black
                )

                Spacer(modifier = Modifier.height(20.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopySparkAddress,
                        modifier = Modifier.weight(1f),
                        enabled = sparkAddress.isNotEmpty()
                    ) {
                        Text("📋 Copy Address")
                    }
                    
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                    ) {
                        Text("Done")
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Security note
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
                            "Your wallet keys are stored securely on this device using hardware-backed encryption.",
                            fontSize = 12.sp,
                            color = Color(0xFF92400E)
                        )
                    }
                }
            }
        }
    }
}

/**
 * Generate a QR code bitmap from a string.
 */
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
                // Header
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

                // QR Code
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

                // Invoice preview (truncated)
                Text(
                    text = "${invoice.take(25)}...${invoice.takeLast(10)}",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Polling status
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

                // Action buttons
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

                // Done button
                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                ) {
                    Text("Done")
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Instructions
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

@Composable
fun BackupPasswordDialog(
    password: String,
    passwordConfirm: String,
    error: String,
    isBackingUp: Boolean,
    onPasswordChange: (String) -> Unit,
    onPasswordConfirmChange: (String) -> Unit,
    onBackup: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Backup to Google Drive",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Text("✕", fontSize = 18.sp, color = Color.Gray)
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Create a password to encrypt your backup. You'll need this password to restore your wallet.",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(20.dp))
                
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    label = { Text("Password") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !isBackingUp
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                OutlinedTextField(
                    value = passwordConfirm,
                    onValueChange = onPasswordConfirmChange,
                    label = { Text("Confirm Password") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !isBackingUp
                )
                
                if (error.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        error,
                        color = Color(0xFFEF4444),
                        fontSize = 12.sp
                    )
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "⚠️ Keep this password safe! Without it, you cannot restore your wallet from this backup.",
                    fontSize = 12.sp,
                    color = Color(0xFFF59E0B),
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(20.dp))
                
                Button(
                    onClick = onBackup,
                    enabled = !isBackingUp && password.isNotEmpty() && passwordConfirm.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    if (isBackingUp) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Backing up...")
                    } else {
                        Text("☁️ Backup Now")
                    }
                }
            }
        }
    }
}

@Composable
fun RestorePasswordDialog(
    password: String,
    error: String,
    isRestoring: Boolean,
    onPasswordChange: (String) -> Unit,
    onRestore: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Restore from Backup",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Text("✕", fontSize = 18.sp, color = Color.Gray)
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Enter the password you used when backing up your wallet.",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(20.dp))
                
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    label = { Text("Backup Password") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !isRestoring
                )
                
                if (error.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        error,
                        color = Color(0xFFEF4444),
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center
                    )
                }
                
                Spacer(modifier = Modifier.height(20.dp))
                
                Button(
                    onClick = onRestore,
                    enabled = !isRestoring && password.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    if (isRestoring) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Restoring...")
                    } else {
                        Text("🔐 Restore Wallet")
                    }
                }
            }
        }
    }
}

/**
 * Bottom sheet prompt shown after first successful login to encourage wallet backup.
 * 
 * Appears with a celebration moment - user just earned sats, now secure them.
 */
@Composable
fun BackupPromptBottomSheet(
    satsEarned: Long,
    onBackupNow: () -> Unit,
    onRemindLater: () -> Unit,
    onDismiss: () -> Unit
) {
    // Full screen overlay with bottom sheet
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.5f))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onDismiss
            )
    ) {
        // Bottom sheet card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.BottomCenter)
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = {} // Prevent clicks from dismissing
                ),
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E32))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Handle bar
                Box(
                    modifier = Modifier
                        .width(40.dp)
                        .height(4.dp)
                        .background(Color(0xFF444444), RoundedCornerShape(2.dp))
                )
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Icon
                Text(
                    "🔐",
                    fontSize = 48.sp
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Title
                Text(
                    "Secure Your Earnings",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Description
                Text(
                    "You just earned $satsEarned sats! Back up your wallet to Google Drive so you never lose your earnings — even if you lose your phone.",
                    fontSize = 15.sp,
                    color = Color(0xFF999999),
                    textAlign = TextAlign.Center,
                    lineHeight = 22.sp
                )
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Backup button with gradient
                Button(
                    onClick = onBackupNow,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                brush = Brush.horizontalGradient(
                                    colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6))
                                ),
                                shape = RoundedCornerShape(12.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Text(
                                "☁️",
                                fontSize = 18.sp
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "Back Up to Google Drive",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Remind later link
                Text(
                    "Remind me later",
                    fontSize = 15.sp,
                    color = Color(0xFF666666),
                    modifier = Modifier
                        .clickable { onRemindLater() }
                        .padding(8.dp)
                )
                
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}
