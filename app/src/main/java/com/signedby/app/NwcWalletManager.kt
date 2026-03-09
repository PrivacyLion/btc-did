package com.signedby.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * NwcWalletManager - Manages NWC (Nostr Wallet Connect) connection string storage
 * 
 * Replaces BreezWalletManager. This is a thin wrapper that:
 * - Stores the NWC connection string securely using Android Keystore (same pattern as DidWalletManager)
 * - Provides hasWallet() / isConnected() checks
 * - NO balance tracking, NO Spark address, NO mnemonic, NO BIP39, NO Google Drive
 * 
 * Recovery: Strike email only. User re-authenticates with Strike to get new NWC connection.
 */
class NwcWalletManager(private val context: Context) {
    
    companion object {
        private const val TAG = "NwcWallet"
        private const val KEYSTORE_ALIAS = "signedby_nwc_key"
        private const val PREFS_NAME = "signedby_nwc_prefs"
        private const val PREF_ENCRYPTED_NWC = "encrypted_nwc"
        private const val PREF_NWC_IV = "nwc_iv"
        private const val PREF_STRIKE_TOS_ACCEPTED = "strike_tos_accepted_at"
        private const val PREF_STRIKE_EMAIL = "strike_email"
    }
    
    /**
     * Check if wallet is set up (NWC connection string is stored)
     * WARNING: This does disk I/O. Use hasWalletAsync() from coroutines.
     */
    fun hasWallet(): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PREF_ENCRYPTED_NWC, null) != null
    }
    
    /**
     * Async version of hasWallet() - use from coroutines to avoid StrictMode violations
     */
    suspend fun hasWalletAsync(): Boolean = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        hasWallet()
    }
    
    /**
     * Check if wallet is connected and valid
     * For NWC, this is equivalent to hasWallet() - the connection string is the credential
     * WARNING: This does disk I/O. Use isConnectedAsync() from coroutines.
     */
    fun isConnected(): Boolean {
        return hasWallet() && getNwcConnectionString() != null
    }
    
    /**
     * Async version of isConnected() - use from coroutines to avoid StrictMode violations
     */
    suspend fun isConnectedAsync(): Boolean = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        isConnected()
    }
    
    /**
     * Store the NWC connection string securely
     * WARNING: This does Keystore I/O. Use storeNwcConnectionStringAsync() from coroutines.
     * 
     * @param connectionString The nostr+walletconnect:// URI from Strike
     */
    fun storeNwcConnectionString(connectionString: String) {
        require(connectionString.startsWith("nostr+walletconnect://")) {
            "Invalid NWC connection string format"
        }
        
        ensureKeystoreKey()
        
        val (encrypted, iv) = encrypt(connectionString)
        
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(PREF_ENCRYPTED_NWC, encrypted)
            .putString(PREF_NWC_IV, iv)
            .apply()
        
        Log.i(TAG, "NWC connection string stored securely")
    }
    
    /**
     * Async version of storeNwcConnectionString() - use from coroutines to avoid StrictMode violations
     */
    suspend fun storeNwcConnectionStringAsync(connectionString: String) = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        storeNwcConnectionString(connectionString)
    }
    
    /**
     * Retrieve the stored NWC connection string
     * 
     * @return The decrypted connection string, or null if not stored
     */
    fun getNwcConnectionString(): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encrypted = prefs.getString(PREF_ENCRYPTED_NWC, null) ?: return null
        val iv = prefs.getString(PREF_NWC_IV, null) ?: return null
        
        return try {
            decrypt(encrypted, iv)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt NWC connection string", e)
            null
        }
    }
    
    /**
     * Record Strike ToS acceptance timestamp
     */
    fun recordTosAcceptance(email: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putLong(PREF_STRIKE_TOS_ACCEPTED, System.currentTimeMillis())
            .putString(PREF_STRIKE_EMAIL, email)
            .apply()
        
        Log.i(TAG, "Strike ToS acceptance recorded for $email")
    }
    
    /**
     * Get the stored Strike email (for display/recovery info)
     */
    fun getStrikeEmail(): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PREF_STRIKE_EMAIL, null)
    }
    
    /**
     * Check if Strike ToS has been accepted
     */
    fun hasTosAcceptance(): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getLong(PREF_STRIKE_TOS_ACCEPTED, 0) > 0
    }
    
    /**
     * Clear all stored wallet data (for re-onboarding)
     */
    fun clearWallet() {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        Log.i(TAG, "Wallet data cleared")
    }
    
    // ==================== Secure Storage (Android Keystore) ====================
    
    private fun ensureKeystoreKey() {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(KEYSTORE_ALIAS)) return
            
            val specBuilder = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)
            
            // Try StrongBox on Android P+
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                try {
                    specBuilder.setIsStrongBoxBacked(true)
                } catch (_: Throwable) {
                    // StrongBox not available
                }
            }
            
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            kg.init(specBuilder.build())
            kg.generateKey()
            
            Log.i(TAG, "Keystore key created")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create keystore key", e)
            throw e
        }
    }
    
    private fun getSecretKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ks.getKey(KEYSTORE_ALIAS, null) as SecretKey
    }
    
    private fun encrypt(plaintext: String): Pair<String, String> {
        val secretKey = getSecretKey()
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        
        return Pair(
            Base64.encodeToString(encrypted, Base64.NO_WRAP),
            Base64.encodeToString(iv, Base64.NO_WRAP)
        )
    }
    
    private fun decrypt(encryptedBase64: String, ivBase64: String): String {
        val secretKey = getSecretKey()
        
        val encrypted = Base64.decode(encryptedBase64, Base64.NO_WRAP)
        val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        
        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted, Charsets.UTF_8)
    }
}
