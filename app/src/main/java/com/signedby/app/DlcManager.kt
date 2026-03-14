package com.signedby.app

import android.util.Log
import org.json.JSONObject

/**
 * DlcManager - Manages Discreet Log Contracts for SignedByMe login
 * 
 * In the Enterprise Login flow (Section B), the DLC enforces a 90/10 payout split:
 * - 90% goes to the user (for proving their identity)
 * - 10% goes to the operator (SignedByMe platform fee)
 * 
 * The Oracle signs the "auth_verified" outcome when login is successful,
 * which allows the DLC to execute the split.
 */
class DlcManager {
    
    companion object {
        private const val TAG = "DlcManager"
        
        // Default payout split percentages
        const val DEFAULT_USER_PCT = 90
        const val DEFAULT_OPERATOR_PCT = 10
        
        // Standard outcomes
        const val OUTCOME_AUTH_VERIFIED = "auth_verified"
        const val OUTCOME_REFUND = "refund"
        const val OUTCOME_PAID = "paid=true"
        
        // DLC timeout (10 minutes)
        const val TIMEOUT_SECS = 600L
    }
    
    /**
     * DLC contract data for login authentication
     * 
     * Phase 11: Settlement based on Breez SDK preimage receipt.
     * SHA256(preimage) == paymentHash is the cryptographic proof of payment.
     */
    data class AuthDlcContract(
        val contractId: String,
        val loginId: String,
        val did: String,
        val userPubkeyHex: String,
        val oraclePubkeyHex: String,
        val oracleName: String,
        val outcome: String,
        val userPct: Int,
        val operatorPct: Int,
        val amountSats: Long,
        val createdAt: Long,
        val adaptorPointHex: String?,
        val scriptHashHex: String?,
        // Phase 11 fields
        val paymentHashHex: String? = null,
        val timeoutAt: Long = 0,
        var status: String = "pending",
        var preimageHex: String? = null,
        var settledAt: Long? = null
    ) {
        fun toJson(): String {
            return JSONObject().apply {
                put("contract_id", contractId)
                put("login_id", loginId)
                put("did", did)
                put("user_pubkey_hex", userPubkeyHex)
                put("oracle", JSONObject().apply {
                    put("name", oracleName)
                    put("pubkey_hex", oraclePubkeyHex)
                })
                put("outcome", outcome)
                put("payout_split", JSONObject().apply {
                    put("user_pct", userPct)
                    put("operator_pct", operatorPct)
                })
                put("amount_sats", amountSats)
                put("created_at", createdAt)
                if (adaptorPointHex != null) put("adaptor_point_hex", adaptorPointHex)
                if (scriptHashHex != null) put("script_hash_hex", scriptHashHex)
            }.toString()
        }
        
        companion object {
            fun fromJson(json: String): AuthDlcContract? {
                return try {
                    val obj = JSONObject(json)
                    val oracle = obj.optJSONObject("oracle")
                    val split = obj.optJSONObject("payout_split")
                    AuthDlcContract(
                        contractId = obj.getString("contract_id"),
                        loginId = obj.optString("login_id", ""),
                        did = obj.getString("did"),
                        userPubkeyHex = obj.getString("user_pubkey_hex"),
                        oraclePubkeyHex = oracle?.getString("pubkey_hex") ?: "",
                        oracleName = oracle?.getString("name") ?: "local_oracle",
                        outcome = obj.getString("outcome"),
                        userPct = split?.getInt("user_pct") ?: DEFAULT_USER_PCT,
                        operatorPct = split?.getInt("operator_pct") ?: DEFAULT_OPERATOR_PCT,
                        amountSats = obj.getLong("amount_sats"),
                        createdAt = obj.getLong("created_at"),
                        adaptorPointHex = obj.optString("adaptor_point_hex", null),
                        scriptHashHex = obj.optString("script_hash_hex", null)
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse DLC contract: ${e.message}")
                    null
                }
            }
        }
    }
    
    /**
     * Oracle attestation for a DLC outcome
     */
    data class OracleAttestation(
        val outcome: String,
        val signatureHex: String,
        val pubkeyHex: String,
        val timestamp: Long
    ) {
        fun toJson(): String {
            return JSONObject().apply {
                put("outcome", outcome)
                put("signature_hex", signatureHex)
                put("pubkey_hex", pubkeyHex)
                put("timestamp", timestamp)
            }.toString()
        }
        
        companion object {
            fun fromJson(json: String): OracleAttestation? {
                return try {
                    val obj = JSONObject(json)
                    OracleAttestation(
                        outcome = obj.getString("outcome"),
                        signatureHex = obj.getString("signature_hex"),
                        pubkeyHex = obj.getString("pubkey_hex"),
                        timestamp = obj.getLong("timestamp")
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse oracle attestation: ${e.message}")
                    null
                }
            }
        }
    }
    
    /**
     * Settlement receipt from a completed login
     */
    data class SettlementReceipt(
        val loginId: String,
        val contractId: String,
        val did: String,
        val paymentHash: String,
        val preimageHex: String?,
        val amountSats: Long,
        val userAmountSats: Long,
        val operatorAmountSats: Long,
        val attestation: OracleAttestation?,
        val settledAt: Long,
        val auditHash: String
    ) {
        fun toJson(): String {
            return JSONObject().apply {
                put("login_id", loginId)
                put("contract_id", contractId)
                put("did", did)
                put("payment_hash", paymentHash)
                if (preimageHex != null) put("preimage_hex", preimageHex)
                put("amount_sats", amountSats)
                put("user_amount_sats", userAmountSats)
                put("operator_amount_sats", operatorAmountSats)
                if (attestation != null) put("attestation", JSONObject(attestation.toJson()))
                put("settled_at", settledAt)
                put("audit_hash", auditHash)
            }.toString()
        }
    }
    
    /**
     * Policy acknowledgment from oracle
     */
    data class PolicyAcknowledgment(
        val contractId: String,
        val outcome: String,
        val oraclePubkeyHex: String,
        val commitmentHex: String,
        val acknowledgedAt: Long
    )
    
    /**
     * Build a DLC contract for login authentication.
     * 
     * Phase 11 Architecture:
     * - Settlement condition: phone receives 90% preimage via Breez SDK
     * - DLC encodes: nonce, payment_hash, timeout (10 min), payout split (90/10)
     * - Server has ZERO knowledge of this DLC
     * 
     * @param loginId Session login ID (nonce from QR)
     * @param did User's DID
     * @param amountSats Payment amount in satoshis
     * @param paymentHashHex Payment hash for user's 90% invoice (optional, set later)
     * @param userPct User's percentage (default 90)
     * @param operatorPct Operator's percentage (default 10)
     * @return DLC contract ready for settlement
     */
    fun buildAuthContract(
        loginId: String,
        did: String,
        amountSats: Long,
        paymentHashHex: String? = null,
        userPct: Int = DEFAULT_USER_PCT,
        operatorPct: Int = DEFAULT_OPERATOR_PCT
    ): AuthDlcContract {
        require(userPct + operatorPct == 100) { "Payout percentages must sum to 100" }
        
        val didPubkeyHex = did.removePrefix("did:btcr:")
        val oraclePubkeyHex = NativeBridge.oraclePubkeyHex()
        
        // Build DLC contract via Rust
        val payoutsJson = """{"user_pct":$userPct,"operator_pct":$operatorPct}"""
        val oracleJson = """{"name":"signedby_oracle","pubkey_hex":"$oraclePubkeyHex"}"""
        
        val contractJson = NativeBridge.createDlcContract(
            OUTCOME_AUTH_VERIFIED,
            payoutsJson,
            oracleJson
        )
        
        Log.i(TAG, "Built DLC contract for login $loginId")
        
        // Parse contract response
        val contractObj = JSONObject(contractJson)
        val contractId = contractObj.optString("contract_id", "dlc_${System.currentTimeMillis()}")
        
        // Calculate timeout (10 minutes from now)
        val createdAt = System.currentTimeMillis() / 1000
        val timeoutAt = createdAt + TIMEOUT_SECS
        
        return AuthDlcContract(
            contractId = contractId,
            loginId = loginId,
            did = did,
            userPubkeyHex = didPubkeyHex,
            oraclePubkeyHex = oraclePubkeyHex,
            oracleName = "signedby_oracle",
            outcome = OUTCOME_AUTH_VERIFIED,
            userPct = userPct,
            operatorPct = operatorPct,
            amountSats = amountSats,
            createdAt = createdAt,
            adaptorPointHex = contractObj.optString("adaptor_point_hex", null),
            scriptHashHex = contractObj.optString("script_hash_hex", null),
            // Phase 11 fields
            paymentHashHex = paymentHashHex,
            timeoutAt = timeoutAt,
            status = "pending",
            preimageHex = null,
            settledAt = null
        )
    }
    
    /**
     * Request oracle to acknowledge signing policy (steps 7-8)
     * The oracle commits to signing a specific outcome when conditions are met.
     */
    fun requestPolicyAcknowledgment(outcome: String, contractId: String): PolicyAcknowledgment? {
        return try {
            val ackJson = NativeBridge.oracleAcknowledgePolicy(outcome, contractId)
            val obj = JSONObject(ackJson)
            
            if (obj.optString("status") != "ok") {
                Log.e(TAG, "Policy acknowledgment failed: ${obj.optString("error")}")
                return null
            }
            
            PolicyAcknowledgment(
                contractId = obj.getString("contract_id"),
                outcome = obj.getString("outcome"),
                oraclePubkeyHex = obj.getString("oracle_pubkey_hex"),
                commitmentHex = obj.getString("commitment_hex"),
                acknowledgedAt = obj.getLong("acknowledged_at")
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get policy acknowledgment: ${e.message}")
            null
        }
    }
    
    /**
     * Request oracle signature for auth_verified outcome.
     * Called after payment is confirmed to complete the DLC.
     * 
     * In production, this would call the SignedByMe oracle API.
     * For now, we use the local oracle (temporary).
     * 
     * @param outcome The outcome to sign (e.g., "auth_verified")
     * @return Oracle attestation with Schnorr signature
     */
    fun requestOracleSignature(outcome: String = OUTCOME_AUTH_VERIFIED): OracleAttestation {
        val signatureJson = NativeBridge.signDlcOutcome(outcome)
        Log.i(TAG, "Oracle signature for '$outcome': $signatureJson")
        
        val sigObj = JSONObject(signatureJson)
        
        return OracleAttestation(
            outcome = outcome,
            signatureHex = sigObj.optString("signature", sigObj.optString("signature_hex", "")),
            pubkeyHex = NativeBridge.oraclePubkeyHex(),
            timestamp = System.currentTimeMillis() / 1000
        )
    }
    
    /**
     * Calculate payout amounts from total
     */
    fun calculatePayouts(totalSats: Long, userPct: Int = DEFAULT_USER_PCT): Pair<Long, Long> {
        val userAmount = (totalSats * userPct) / 100
        val operatorAmount = totalSats - userAmount
        return Pair(userAmount, operatorAmount)
    }
    
    /**
     * Build a settlement receipt after successful login payment
     * 
     * @param contract The DLC contract
     * @param paymentHash Lightning payment hash
     * @param preimageHex Payment preimage (if available)
     * @param attestation Oracle attestation
     * @return Settlement receipt for audit trail
     */
    fun buildSettlementReceipt(
        contract: AuthDlcContract,
        paymentHash: String,
        preimageHex: String? = null,
        attestation: OracleAttestation? = null
    ): SettlementReceipt {
        val (userAmount, operatorAmount) = calculatePayouts(contract.amountSats, contract.userPct)
        
        // Create audit hash from all components
        val auditData = "${contract.contractId}|${contract.loginId}|${contract.did}|$paymentHash|${System.currentTimeMillis()}"
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val auditHash = md.digest(auditData.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        
        return SettlementReceipt(
            loginId = contract.loginId,
            contractId = contract.contractId,
            did = contract.did,
            paymentHash = paymentHash,
            preimageHex = preimageHex,
            amountSats = contract.amountSats,
            userAmountSats = userAmount,
            operatorAmountSats = operatorAmount,
            attestation = attestation,
            settledAt = System.currentTimeMillis() / 1000,
            auditHash = auditHash
        )
    }
    
    /**
     * Verify an oracle attestation signature using real Schnorr verification
     * 
     * @param attestation The attestation to verify
     * @return true if the Schnorr signature is valid
     */
    fun verifyAttestation(attestation: OracleAttestation): Boolean {
        return try {
            // Use real BIP340 Schnorr verification via Rust
            NativeBridge.oracleVerifyAttestation(
                attestation.outcome,
                attestation.signatureHex,
                attestation.pubkeyHex
            )
        } catch (e: Exception) {
            Log.e(TAG, "Attestation verification failed: ${e.message}")
            false
        }
    }
    
    // ========== Phase 11: Preimage-Based Settlement ==========
    
    /**
     * Settle a DLC contract with a preimage from Breez SDK.
     * 
     * This is the core settlement for Phase 11:
     * - Receives preimage from Breez SDK payment notification
     * - Verifies SHA256(preimage) == payment_hash
     * - If valid, marks contract as settled
     * 
     * @param contract The DLC contract to settle
     * @param preimageHex The preimage from Breez SDK (32 bytes, hex)
     * @return true if settlement succeeded, false otherwise
     */
    fun settleWithPreimage(contract: AuthDlcContract, preimageHex: String): Boolean {
        if (contract.status != "pending") {
            Log.w(TAG, "Cannot settle: contract status is ${contract.status}")
            return false
        }
        
        val paymentHash = contract.paymentHashHex
        if (paymentHash.isNullOrEmpty()) {
            Log.e(TAG, "Cannot settle: no payment_hash on contract")
            return false
        }
        
        // Verify: SHA256(preimage) == payment_hash
        val isValid = verifyPreimage(preimageHex, paymentHash)
        
        if (isValid) {
            contract.status = "settled"
            contract.preimageHex = preimageHex
            contract.settledAt = System.currentTimeMillis() / 1000
            Log.i(TAG, "DLC settled successfully: contract=${contract.contractId}")
            return true
        } else {
            contract.status = "failed"
            Log.e(TAG, "DLC settlement failed: invalid preimage")
            return false
        }
    }
    
    /**
     * Verify a preimage against a payment hash.
     * 
     * SHA256(preimage) == payment_hash is the cryptographic proof of payment.
     * 
     * @param preimageHex The preimage (32 bytes, hex)
     * @param paymentHashHex The expected payment hash (32 bytes, hex)
     * @return true if valid, false otherwise
     */
    fun verifyPreimage(preimageHex: String, paymentHashHex: String): Boolean {
        return try {
            // Use Rust for SHA256 verification
            NativeBridge.verifyPreimage(preimageHex, paymentHashHex)
        } catch (e: Exception) {
            // Fallback to Java SHA256
            try {
                val preimageBytes = hexToBytes(preimageHex)
                val md = java.security.MessageDigest.getInstance("SHA-256")
                val computedHash = md.digest(preimageBytes)
                val computedHashHex = bytesToHex(computedHash)
                computedHashHex.equals(paymentHashHex, ignoreCase = true)
            } catch (e2: Exception) {
                Log.e(TAG, "Preimage verification failed: ${e2.message}")
                false
            }
        }
    }
    
    /**
     * Check if a contract has timed out (10 minutes with no payment).
     */
    fun isTimedOut(contract: AuthDlcContract): Boolean {
        if (contract.status != "pending") return false
        val now = System.currentTimeMillis() / 1000
        return contract.timeoutAt > 0 && now > contract.timeoutAt
    }
    
    /**
     * Handle contract timeout - marks as refunded.
     */
    fun handleTimeout(contract: AuthDlcContract): Boolean {
        if (!isTimedOut(contract)) return false
        contract.status = "refunded"
        Log.i(TAG, "DLC timed out: contract=${contract.contractId}")
        return true
    }
    
    // ========== Helper Functions ==========
    
    private fun hexToBytes(hex: String): ByteArray {
        val cleanHex = hex.removePrefix("0x")
        return ByteArray(cleanHex.length / 2) { i ->
            cleanHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
