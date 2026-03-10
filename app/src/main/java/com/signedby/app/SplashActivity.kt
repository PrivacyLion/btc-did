package com.signedby.app

import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.res.ResourcesCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.delay

private const val TAG = "SignedByMe"
private const val PREFS_NAME = "signedby_security"
private const val KEY_LOCK_MODE = "lock_mode"
private const val KEY_ONBOARDING_COMPLETE = "onboarding_complete"

/**
 * Lock modes for Layer 1 app lock.
 */
enum class LockMode(val value: Int) {
    NONE(0),          // No lock (first launch / onboarding not complete)
    BIOMETRIC(1),     // Biometric only (default)
    PASSCODE(2),      // Device PIN/password only
    BOTH(3);          // Biometric + Passcode (maximum security)
    
    companion object {
        fun fromInt(value: Int) = entries.firstOrNull { it.value == value } ?: BIOMETRIC
    }
}

/**
 * Splash screen with Layer 1 biometric app lock.
 * 
 * Flow:
 * 1. Show animated cursive "S" 
 * 2. After animation, check if onboarding is complete
 * 3. If complete: require biometric/passcode before showing MainActivity
 * 4. If not complete: go directly to MainActivity for onboarding
 * 
 * UX sequence: [App launch] → [Animation] → [Biometric Layer 1] → [Home screen]
 */
class SplashActivity : FragmentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            SplashScreen(
                onAnimationComplete = {
                    checkAndAuthenticate()
                }
            )
        }
    }
    
    private fun checkAndAuthenticate() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val onboardingComplete = prefs.getBoolean(KEY_ONBOARDING_COMPLETE, false)
        val lockMode = LockMode.fromInt(prefs.getInt(KEY_LOCK_MODE, LockMode.BIOMETRIC.value))
        
        Log.i(TAG, "Layer 1: onboardingComplete=$onboardingComplete, lockMode=$lockMode")
        
        if (!onboardingComplete || lockMode == LockMode.NONE) {
            // First launch or lock disabled - go straight to MainActivity
            proceedToMain()
            return
        }
        
        // Layer 1: Require authentication before showing app
        authenticateLayer1(lockMode)
    }
    
    private fun authenticateLayer1(lockMode: LockMode) {
        val biometricManager = BiometricManager.from(this)
        
        // Determine which authenticators to allow based on lock mode
        val authenticators = when (lockMode) {
            LockMode.BIOMETRIC -> BiometricManager.Authenticators.BIOMETRIC_STRONG
            LockMode.PASSCODE -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
            LockMode.BOTH -> BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
            LockMode.NONE -> {
                proceedToMain()
                return
            }
        }
        
        val canAuthenticate = biometricManager.canAuthenticate(authenticators)
        
        when (canAuthenticate) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                showBiometricPrompt(authenticators)
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                // No biometrics enrolled - allow device credential as fallback
                Log.w(TAG, "Layer 1: No biometrics enrolled, using device credential")
                showBiometricPrompt(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                // No biometric hardware - use device credential
                Log.w(TAG, "Layer 1: No biometric hardware, using device credential")
                showBiometricPrompt(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            }
            else -> {
                // Can't authenticate at all - proceed (shouldn't happen on modern devices)
                Log.e(TAG, "Layer 1: Cannot authenticate, proceeding anyway")
                proceedToMain()
            }
        }
    }
    
    private fun showBiometricPrompt(authenticators: Int) {
        val executor = ContextCompat.getMainExecutor(this)
        
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.i(TAG, "Layer 1: Authentication SUCCESS")
                proceedToMain()
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.w(TAG, "Layer 1: Authentication error: $errString (code=$errorCode)")
                
                when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED -> {
                        // User cancelled - close app (don't allow bypass)
                        finish()
                    }
                    BiometricPrompt.ERROR_LOCKOUT,
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                        // Too many attempts - close app
                        finish()
                    }
                    else -> {
                        // Other errors - retry
                        authenticateLayer1(LockMode.BIOMETRIC)
                    }
                }
            }
            
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "Layer 1: Authentication failed, user can retry")
                // Don't finish - let user retry via BiometricPrompt
            }
        }
        
        val biometricPrompt = BiometricPrompt(this, executor, callback)
        
        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock SignedByMe")
            .setSubtitle("Verify your identity to access the app")
            .setAllowedAuthenticators(authenticators)
        
        // Only set negative button if not using device credential
        if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
            promptInfoBuilder.setNegativeButtonText("Cancel")
        }
        
        biometricPrompt.authenticate(promptInfoBuilder.build())
    }
    
    private fun proceedToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
    }
}

@Composable
fun SplashScreen(onAnimationComplete: () -> Unit) {
    val context = LocalContext.current
    
    // Load Dancing Script font
    val dancingScriptTypeface = remember {
        try {
            ResourcesCompat.getFont(context, R.font.dancing_script)
                ?: Typeface.create("cursive", Typeface.NORMAL)
        } catch (e: Exception) {
            Typeface.create("cursive", Typeface.NORMAL)
        }
    }
    
    // Animation progress 0 -> 1
    var startAnimation by remember { mutableStateOf(false) }
    
    val progress by animateFloatAsState(
        targetValue = if (startAnimation) 1f else 0f,
        animationSpec = tween(
            durationMillis = 2500,
            easing = FastOutSlowInEasing
        ),
        label = "drawProgress"
    )
    
    // Start animation after short delay
    LaunchedEffect(Unit) {
        delay(300)
        startAnimation = true
    }
    
    // Navigate after animation completes
    LaunchedEffect(progress) {
        if (progress >= 1f) {
            delay(600)
            onAnimationComplete()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF3B82F6),
                        Color(0xFF8B5CF6)
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY)
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        CursiveSDrawing(
            typeface = dancingScriptTypeface,
            progress = progress,
            modifier = Modifier.size(350.dp)
        )
    }
}

@Composable
fun CursiveSDrawing(
    typeface: Typeface,
    progress: Float,
    modifier: Modifier = Modifier
) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val cx = w / 2f
        val cy = h / 2f
        val scale = minOf(w, h) * 0.84f
        
        // CURSIVE CAPITAL S path
        val path = Path().apply {
            moveTo(cx - scale * 0.25f, cy + scale * 0.6f)
            
            cubicTo(
                cx - scale * 0.1f, cy + scale * 0.2f,
                cx + scale * 0.1f, cy - scale * 0.3f,
                cx + scale * 0.2f, cy - scale * 0.6f
            )
            
            cubicTo(
                cx + scale * 0.25f, cy - scale * 0.9f,
                cx - scale * 0.35f, cy - scale * 0.9f,
                cx - scale * 0.3f, cy - scale * 0.55f
            )
            
            cubicTo(
                cx - scale * 0.25f, cy - scale * 0.2f,
                cx + scale * 0.05f, cy + scale * 0.05f,
                cx + scale * 0.3f, cy + scale * 0.3f
            )
            
            cubicTo(
                cx + scale * 0.45f, cy + scale * 0.5f,
                cx + scale * 0.35f, cy + scale * 0.8f,
                cx, cy + scale * 0.75f
            )
            
            quadraticBezierTo(
                cx + scale * 0.15f, cy + scale * 0.65f,
                cx + scale * 0.4f, cy + scale * 0.7f
            )
        }
        
        val pathMeasure = android.graphics.PathMeasure(path.asAndroidPath(), false)
        val pathLength = pathMeasure.length
        
        val strokeWidth = minOf(w, h) * 0.07f
        
        // Glow effect
        drawPath(
            path = path,
            color = Color.White.copy(alpha = 0.4f),
            style = Stroke(
                width = strokeWidth * 2f,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength * 2f),
                    phase = 0f
                )
            )
        )
        
        // Main stroke
        drawPath(
            path = path,
            color = Color.White,
            style = Stroke(
                width = strokeWidth,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength * 2f),
                    phase = 0f
                )
            )
        )
    }
}

// ============================================================================
// Security Settings Helpers (for onboarding and settings UI)
// ============================================================================

/**
 * Save the user's preferred lock mode.
 */
fun saveLockMode(context: Context, mode: LockMode) {
    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putInt(KEY_LOCK_MODE, mode.value)
        .apply()
    Log.i(TAG, "Lock mode saved: $mode")
}

/**
 * Get the current lock mode.
 */
fun getLockMode(context: Context): LockMode {
    val value = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getInt(KEY_LOCK_MODE, LockMode.BIOMETRIC.value)
    return LockMode.fromInt(value)
}

/**
 * Mark onboarding as complete.
 * After this, Layer 1 lock will be required on app launch.
 */
fun markOnboardingComplete(context: Context) {
    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(KEY_ONBOARDING_COMPLETE, true)
        .apply()
    Log.i(TAG, "Onboarding marked complete - Layer 1 lock now active")
}

/**
 * Check if onboarding is complete.
 */
fun isOnboardingComplete(context: Context): Boolean {
    return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getBoolean(KEY_ONBOARDING_COMPLETE, false)
}

/**
 * Get the last activity timestamp for inactivity timeout.
 */
private const val KEY_LAST_ACTIVITY = "last_activity_ms"

fun updateLastActivity(context: Context) {
    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putLong(KEY_LAST_ACTIVITY, System.currentTimeMillis())
        .apply()
}

fun getLastActivity(context: Context): Long {
    return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getLong(KEY_LAST_ACTIVITY, System.currentTimeMillis())
}

/**
 * Check if we should require re-authentication (2-minute inactivity timeout).
 */
fun shouldRequireReauth(context: Context): Boolean {
    val lastActivity = getLastActivity(context)
    val now = System.currentTimeMillis()
    val twoMinutesMs = 2 * 60 * 1000L
    return (now - lastActivity) > twoMinutesMs
}
