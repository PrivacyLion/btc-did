// KycEnrollmentManager.kt - KYC Enrollment State Machine (Phase 26.5)
//
// Handles KYC-gated enrollment flow:
// 1. NOT_ENROLLED: No witness for client_id, verification required
// 2. HANDOFF: Opened external KYC provider (Persona/Jumio)
// 3. POLLING: Waiting for kind 28201 event on relay
// 4. PASSED: KYC passed, auto-commit leaf
// 5. FAILED: KYC failed, show error
// 6. EXPIRED: Session expired, offer restart

package com.signedby.app

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONObject

/**
 * Manages KYC enrollment state machine per Phase 26.5.
 * 
 * NOSTR invisible to user per Section 9.3.
 */
class KycEnrollmentManager {

    companion object {
        private const val TAG = "KycEnrollment"
        
        // Event kinds for enrollment flow
        const val KIND_ENROLLMENT_AUTH = 28200    // Enterprise-signed enrollment authorization
        const val KIND_KYC_VERIFICATION = 28201   // Server-signed KYC result
        
        // Timeouts
        const val QR_EXPIRY_SECONDS = 90          // QR code refresh interval
        const val SESSION_EXPIRY_SECONDS = 600    // 10 minutes for KYC completion
    }

    /**
     * KYC enrollment states per Phase 26.5.
     */
    enum class EnrollmentState {
        /** Initial state - no enrollment in progress */
        IDLE,
        /** No witness for client_id, verification required */
        NOT_ENROLLED,
        /** Opened external KYC provider (Persona/Jumio) */
        HANDOFF,
        /** Waiting for kind 28201 event on relay */
        POLLING,
        /** KYC passed, auto-commit leaf */
        PASSED,
        /** KYC failed, show error */
        FAILED,
        /** Session expired, offer restart */
        EXPIRED
    }

    /**
     * Enrollment policy from clients.json.
     */
    data class EnrollmentPolicy(
        val verificationRequired: Boolean = false,
        val verificationProvider: String? = null,    // "persona" | "jumio"
        val verificationType: String? = null         // "age_18_plus" | "identity_verified"
    )

    /**
     * Enrollment session data.
     */
    data class EnrollmentSession(
        val clientId: String,
        val clientName: String?,
        val nonce: String,
        val expiresAt: Long,                          // Unix timestamp
        val policy: EnrollmentPolicy,
        val verificationUrl: String? = null           // URL to open in external browser
    )

    // Current state
    private val _state = MutableStateFlow(EnrollmentState.IDLE)
    val state: StateFlow<EnrollmentState> = _state

    // Current session
    private var currentSession: EnrollmentSession? = null
    
    // Polling job
    private var pollingJob: Job? = null

    /**
     * Start KYC enrollment flow.
     * 
     * @param clientId Enterprise client ID
     * @param clientName Enterprise display name
     * @param nonce Session nonce from QR
     * @param expiresAt Expiry timestamp
     * @param policy Enrollment policy
     * @param verificationUrl URL to open for KYC
     */
    fun startEnrollment(
        clientId: String,
        clientName: String?,
        nonce: String,
        expiresAt: Long,
        policy: EnrollmentPolicy,
        verificationUrl: String?
    ) {
        currentSession = EnrollmentSession(
            clientId = clientId,
            clientName = clientName,
            nonce = nonce,
            expiresAt = expiresAt,
            policy = policy,
            verificationUrl = verificationUrl
        )
        
        _state.value = EnrollmentState.NOT_ENROLLED
        Log.i(TAG, "Enrollment started for $clientId, nonce=$nonce")
    }

    /**
     * User tapped "Begin Verification" - transition to HANDOFF.
     * Caller should open verificationUrl in external browser.
     */
    fun transitionToHandoff() {
        if (_state.value != EnrollmentState.NOT_ENROLLED) {
            Log.w(TAG, "Cannot transition to HANDOFF from ${_state.value}")
            return
        }
        
        _state.value = EnrollmentState.HANDOFF
        Log.i(TAG, "Transitioned to HANDOFF - user opening external KYC")
    }

    /**
     * Start polling for kind 28201 KYC verification event.
     * Called when user returns from external KYC provider.
     * 
     * @param scope CoroutineScope for polling
     * @param nostrManager NostrManager instance for relay subscription
     * @param onPassed Callback when KYC passes
     * @param onFailed Callback when KYC fails
     * @param onExpired Callback when session expires
     */
    fun startPolling(
        scope: CoroutineScope,
        nostrManager: NostrManager,
        onPassed: () -> Unit,
        onFailed: () -> Unit,
        onExpired: () -> Unit
    ) {
        if (_state.value != EnrollmentState.HANDOFF) {
            Log.w(TAG, "Cannot start polling from ${_state.value}")
            return
        }
        
        val session = currentSession ?: return
        
        _state.value = EnrollmentState.POLLING
        Log.i(TAG, "Polling for kind 28201 with nonce=${session.nonce}")
        
        pollingJob?.cancel()
        pollingJob = scope.launch(Dispatchers.IO) {
            var attempts = 0
            val maxAttempts = (SESSION_EXPIRY_SECONDS / 3).coerceAtMost(200) // Poll every 3s
            
            while (isActive && attempts < maxAttempts) {
                // Check expiry
                if (System.currentTimeMillis() / 1000 > session.expiresAt) {
                    withContext(Dispatchers.Main) {
                        _state.value = EnrollmentState.EXPIRED
                        onExpired()
                    }
                    return@launch
                }
                
                // Poll relay for kind 28201 tagged with nonce
                val event = nostrManager.pollForKycEvent(session.nonce)
                
                if (event != null) {
                    val passed = event.optBoolean("passed", false)
                    
                    withContext(Dispatchers.Main) {
                        if (passed) {
                            _state.value = EnrollmentState.PASSED
                            onPassed()
                        } else {
                            _state.value = EnrollmentState.FAILED
                            onFailed()
                        }
                    }
                    return@launch
                }
                
                attempts++
                delay(3000) // Poll every 3 seconds
            }
            
            // Timed out
            withContext(Dispatchers.Main) {
                _state.value = EnrollmentState.EXPIRED
                onExpired()
            }
        }
    }

    /**
     * Cancel polling and reset state.
     */
    fun cancelPolling() {
        pollingJob?.cancel()
        pollingJob = null
    }

    /**
     * Reset enrollment state to IDLE.
     */
    fun reset() {
        cancelPolling()
        currentSession = null
        _state.value = EnrollmentState.IDLE
        Log.i(TAG, "Enrollment state reset")
    }

    /**
     * Get current session info.
     */
    fun getSession(): EnrollmentSession? = currentSession

    /**
     * Get remaining time in seconds.
     */
    fun getRemainingTime(): Long {
        val session = currentSession ?: return 0
        val remaining = session.expiresAt - (System.currentTimeMillis() / 1000)
        return remaining.coerceAtLeast(0)
    }

    /**
     * Format remaining time as MM:SS.
     */
    fun formatRemainingTime(): String {
        val remaining = getRemainingTime()
        val minutes = remaining / 60
        val seconds = remaining % 60
        return String.format("%d:%02d", minutes, seconds)
    }
}
