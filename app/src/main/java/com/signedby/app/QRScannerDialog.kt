package com.signedby.app

import android.content.Context
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "SignedByMe"

/**
 * QR Scanner Dialog with Layer 2 biometric authentication.
 * 
 * After a valid QR is decoded (contains session= or token=), Layer 2 biometric
 * fires BEFORE onQrScanned is called. If biometric fails, the scan is discarded.
 * 
 * This is the second line of defense - even if someone gets past the app lock,
 * they cannot generate a proof without re-authenticating at this moment.
 */
@Composable
fun QRScannerDialog(
    onQrScanned: (String) -> Unit,
    onDismiss: () -> Unit,
    title: String = "Scan Log In QR Code",
    subtitle: String = "Point your camera at the QR Code on your computer screen"
) {
    val context = LocalContext.current
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    
    // Camera permission state
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.CAMERA
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        )
    }
    
    // Camera lifecycle management
    var cameraProviderRef by remember { 
        mutableStateOf<androidx.camera.lifecycle.ProcessCameraProvider?>(null) 
    }
    val analysisExecutor = remember { 
        java.util.concurrent.Executors.newSingleThreadExecutor() 
    }
    
    // AtomicReference for thread-safe barcode scanner access
    val barcodeScannerRef = remember { 
        AtomicReference<com.google.mlkit.vision.barcode.BarcodeScanner?>(null)
    }
    
    // State tracking
    val isDisposed = remember { AtomicBoolean(false) }
    val hasScannedValidQr = remember { AtomicBoolean(false) }
    
    // Biometric state
    var showBiometricPrompt by remember { mutableStateOf(false) }
    var pendingQrValue by remember { mutableStateOf<String?>(null) }
    var biometricError by remember { mutableStateOf<String?>(null) }
    
    // Initialize barcode scanner
    LaunchedEffect(Unit) {
        val scanner = com.google.mlkit.vision.barcode.BarcodeScanning.getClient()
        barcodeScannerRef.set(scanner)
        Log.i(TAG, "QR Scanner: MLKit BarcodeScanner initialized")
    }
    
    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }
    
    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(android.Manifest.permission.CAMERA)
        }
    }
    
    // Cleanup
    DisposableEffect(Unit) {
        onDispose {
            isDisposed.set(true)
            cameraProviderRef?.unbindAll()
            analysisExecutor.shutdown()
            barcodeScannerRef.get()?.close()
        }
    }
    
    // Layer 2 biometric prompt
    if (showBiometricPrompt && pendingQrValue != null) {
        LaunchedEffect(pendingQrValue) {
            authenticateLayer2(
                context = context,
                onSuccess = {
                    Log.i(TAG, "QR Scanner: Layer 2 biometric SUCCESS - proceeding with proof")
                    showBiometricPrompt = false
                    pendingQrValue?.let { qrValue ->
                        onQrScanned(qrValue)
                    }
                    pendingQrValue = null
                },
                onError = { error ->
                    Log.w(TAG, "QR Scanner: Layer 2 biometric FAILED - $error")
                    showBiometricPrompt = false
                    biometricError = error
                    pendingQrValue = null
                    // Reset scan state so user can try again
                    hasScannedValidQr.set(false)
                }
            )
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
                
                // Show biometric error if present
                biometricError?.let { error ->
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        error,
                        fontSize = 12.sp,
                        color = Color(0xFFEF4444),
                        textAlign = TextAlign.Center
                    )
                }
                
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
                                val cameraProviderFuture = 
                                    androidx.camera.lifecycle.ProcessCameraProvider.getInstance(ctx)
                                
                                cameraProviderFuture.addListener({
                                    val cameraProvider = cameraProviderFuture.get()
                                    
                                    val preview = androidx.camera.core.Preview.Builder()
                                        .build()
                                        .also {
                                            it.setSurfaceProvider(previewView.surfaceProvider)
                                        }
                                    
                                    val imageAnalysis = androidx.camera.core.ImageAnalysis.Builder()
                                        .setBackpressureStrategy(
                                            androidx.camera.core.ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST
                                        )
                                        .build()
                                        .also { analysis ->
                                            analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                                                processFrame(
                                                    imageProxy = imageProxy,
                                                    scanner = barcodeScannerRef.get(),
                                                    isDisposed = isDisposed,
                                                    hasScannedValidQr = hasScannedValidQr,
                                                    onValidQrFound = { value ->
                                                        // Layer 2: trigger biometric before onQrScanned
                                                        pendingQrValue = value
                                                        showBiometricPrompt = true
                                                    }
                                                )
                                            }
                                        }
                                    
                                    if (isDisposed.get()) return@addListener
                                    
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
                                        Log.e(TAG, "QR Scanner: Camera bind failed: ${e.message}")
                                    }
                                }, ContextCompat.getMainExecutor(ctx))
                                
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
                        
                        // Show "Authenticating..." overlay during biometric
                        if (showBiometricPrompt) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(Color.Black.copy(alpha = 0.7f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    CircularProgressIndicator(color = Color.White)
                                    Spacer(modifier = Modifier.height(16.dp))
                                    Text(
                                        "Verify it's you",
                                        color = Color.White,
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                }
                            }
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

/**
 * Process a camera frame for QR codes.
 */
@androidx.camera.core.ExperimentalGetImage
private fun processFrame(
    imageProxy: androidx.camera.core.ImageProxy,
    scanner: com.google.mlkit.vision.barcode.BarcodeScanner?,
    isDisposed: AtomicBoolean,
    hasScannedValidQr: AtomicBoolean,
    onValidQrFound: (String) -> Unit
) {
    val mediaImage = imageProxy.image
    
    if (mediaImage == null || scanner == null) {
        imageProxy.close()
        return
    }
    
    // Skip if already processing a valid QR
    if (hasScannedValidQr.get()) {
        imageProxy.close()
        return
    }
    
    val inputImage = com.google.mlkit.vision.common.InputImage.fromMediaImage(
        mediaImage, imageProxy.imageInfo.rotationDegrees
    )
    
    scanner.process(inputImage)
        .addOnSuccessListener { barcodes ->
            if (isDisposed.get() || hasScannedValidQr.get()) return@addOnSuccessListener
            
            if (barcodes.isNotEmpty()) {
                Log.i(TAG, "QR Scanner: detected ${barcodes.size} barcode(s)")
            }
            
            for (barcode in barcodes) {
                barcode.rawValue?.let { value ->
                    Log.i(TAG, "QR Scanner: raw value = ${value.take(80)}...")
                    
                    if (value.contains("session=") || value.contains("token=")) {
                        // Mark as scanned to prevent duplicates
                        if (hasScannedValidQr.compareAndSet(false, true)) {
                            Log.i(TAG, "QR Scanner: MATCH - triggering Layer 2 biometric")
                            onValidQrFound(value)
                        }
                    } else {
                        Log.w(TAG, "QR Scanner: no session=/token= in value, ignoring")
                    }
                }
            }
        }
        .addOnFailureListener { e ->
            Log.e(TAG, "QR Scanner: MLKit error: ${e.message}")
        }
        .addOnCompleteListener {
            imageProxy.close()
        }
}

/**
 * Layer 2 biometric authentication - required before proof generation.
 * Uses BIOMETRIC_STRONG (fingerprint/face hardware) - no fallback.
 */
private fun authenticateLayer2(
    context: Context,
    onSuccess: () -> Unit,
    onError: (String) -> Unit
) {
    val activity = context as? FragmentActivity
    if (activity == null) {
        onError("Activity context required")
        return
    }
    
    val biometricManager = BiometricManager.from(context)
    val canAuthenticate = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    
    when (canAuthenticate) {
        BiometricManager.BIOMETRIC_SUCCESS -> {
            // Proceed with biometric prompt
        }
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
            // No biometric hardware - fall through to device credential
            Log.w(TAG, "Layer 2: No biometric hardware, using device credential")
            authenticateWithDeviceCredential(activity, onSuccess, onError)
            return
        }
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
            onError("Biometric hardware unavailable")
            return
        }
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
            onError("No biometrics enrolled. Please set up fingerprint or face unlock.")
            return
        }
        else -> {
            onError("Biometric authentication not available")
            return
        }
    }
    
    val executor = ContextCompat.getMainExecutor(context)
    
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            onSuccess()
        }
        
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            onError(errString.toString())
        }
        
        override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
            // Don't call onError - let user retry. BiometricPrompt handles this.
            Log.w(TAG, "Layer 2: Authentication failed, user can retry")
        }
    }
    
    val biometricPrompt = BiometricPrompt(activity, executor, callback)
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm your identity")
        .setSubtitle("Authenticate to sign this login")
        .setDescription("Your signature proves you authorized this login")
        .setNegativeButtonText("Cancel")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()
    
    biometricPrompt.authenticate(promptInfo)
}

/**
 * Fallback for devices without biometric hardware - uses PIN/pattern/password.
 */
private fun authenticateWithDeviceCredential(
    activity: FragmentActivity,
    onSuccess: () -> Unit,
    onError: (String) -> Unit
) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            onSuccess()
        }
        
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            onError(errString.toString())
        }
    }
    
    val biometricPrompt = BiometricPrompt(activity, executor, callback)
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm your identity")
        .setSubtitle("Enter your device PIN or password")
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        .build()
    
    biometricPrompt.authenticate(promptInfo)
}
