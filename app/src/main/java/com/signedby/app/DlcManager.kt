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
    }
    
    /**
     * DLC contract data for login authentication
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
        val scriptHashHex: String?
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
     * This contract specifies the 90/10 payout split that will be enforced
     * when the oracle signs the auth_verified outcome.
     * 
     * Steps 6-8 in the spec:
     * 6. Build DLC outcome auth_verified, payout 90/10
     * 7. Request outcome sign policy for auth_verified
     * 8. Oracle policy acknowledged
     * 
     * @param loginId Session login ID
     * @param did User's DID
     * @param amountSats Payment amount in satoshis
     * @param userPct User's percentage (default 90)
     * @param operatorPct Operator's percentage (default 10)
     * @return DLC contract ready for signing
     */
    fun buildAuthContract(
        loginId: String,
        did: String,
        amountSats: Long,
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
        
        Log.i(TAG, "Built DLC contract for login $loginId: $contractJson")
        
        // Parse contract response
        val contractObj = JSONObject(contractJson)
        val contractId = contractObj.optString("contract_id", "dlc_${System.currentTimeMillis()}")
        
        // Step 7-8: Request and receive oracle policy acknowledgment
        val policyAck = requestPolicyAcknowledgment(OUTCOME_AUTH_VERIFIED, contractId)
        Log.i(TAG, "Oracle policy acknowledged: ${policyAck?.commitmentHex?.take(16)}...")
        
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
            createdAt = System.currentTimeMillis() / 1000,
            adaptorPointHex = contractObj.optString("adaptor_point_hex", null),
            scriptHashHex = contractObj.optString("script_hash_hex", null)
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
     * For now, we use the local oracle stub.
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
}
