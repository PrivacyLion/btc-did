package com.signedby.app

import android.content.Context
import android.content.Intent
import android.util.Log
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.Scope
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential
import com.google.api.client.http.ByteArrayContent
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.drive.Drive
import com.google.api.services.drive.DriveScopes
import com.google.api.services.drive.model.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import android.util.Base64

/**
 * Manages Google Drive backup and restore for wallet seed phrases.
 * 
 * Uses Google Drive's App Data folder which is:
 * - Hidden from the user's normal Drive view
 * - Only accessible by this app
 * - Automatically deleted when app is uninstalled
 * 
 * The seed is encrypted with a user-provided password before upload.
 */
class GoogleDriveBackupManager(private val context: Context) {
    
    companion object {
        private const val TAG = "GoogleDriveBackup"
        private const val BACKUP_FILENAME = "signedby_wallet_backup.enc"
        private const val BACKUP_MIME_TYPE = "application/octet-stream"
        
        // Encryption constants
        private const val KEY_DERIVATION_ITERATIONS = 100000
        private const val KEY_LENGTH = 256
        private const val GCM_TAG_LENGTH = 128
        private const val SALT_LENGTH = 32
        private const val IV_LENGTH = 12
    }
    
    private var googleSignInClient: GoogleSignInClient
    private var driveService: Drive? = null
    
    init {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestScopes(Scope(DriveScopes.DRIVE_APPDATA))
            .requestIdToken(BuildConfig.GOOGLE_WEB_CLIENT_ID)
            .build()
        
        googleSignInClient = GoogleSignIn.getClient(context, gso)
    }
    
    /**
     * Get the sign-in intent to launch Google Sign-In UI
     */
    fun getSignInIntent(): Intent = googleSignInClient.signInIntent
    
    /**
     * Handle the sign-in result and initialize Drive service
     */
    suspend fun handleSignInResult(account: GoogleSignInAccount): Boolean = withContext(Dispatchers.IO) {
        try {
            val credential = GoogleAccountCredential.usingOAuth2(
                context,
                listOf(DriveScopes.DRIVE_APPDATA)
            )
            credential.selectedAccount = account.account
            
            driveService = Drive.Builder(
                NetHttpTransport(),
                GsonFactory.getDefaultInstance(),
                credential
            )
                .setApplicationName("SignedByMe")
                .build()
            
            Log.i(TAG, "Drive service initialized for ${account.email}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Drive service", e)
            false
        }
    }
    
    /**
     * Check if user is already signed in
     */
    fun isSignedIn(): Boolean {
        val account = GoogleSignIn.getLastSignedInAccount(context)
        return account != null && GoogleSignIn.hasPermissions(account, Scope(DriveScopes.DRIVE_APPDATA))
    }
    
    /**
     * Get current signed-in account
     */
    fun getSignedInAccount(): GoogleSignInAccount? = GoogleSignIn.getLastSignedInAccount(context)
    
    /**
     * Sign out from Google
     */
    suspend fun signOut() = withContext(Dispatchers.IO) {
        googleSignInClient.signOut()
        driveService = null
        Log.i(TAG, "Signed out from Google")
    }
    
    /**
     * Backup the mnemonic to Google Drive (encrypted)
     * 
     * @param mnemonic The seed phrase to backup
     * @param password User-provided password for encryption
     * @return true if backup succeeded
     */
    suspend fun backupMnemonic(mnemonic: String, password: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val drive = driveService ?: return@withContext Result.failure(
                Exception("Not signed in to Google. Please sign in first.")
            )
            
            // Encrypt the mnemonic
            val encryptedData = encryptMnemonic(mnemonic, password)
            
            // Check if backup already exists
            val existingFileId = findBackupFile()
            
            if (existingFileId != null) {
                // Update existing backup
                val content = ByteArrayContent(BACKUP_MIME_TYPE, encryptedData)
                drive.files().update(existingFileId, null, content).execute()
                Log.i(TAG, "Backup updated successfully")
            } else {
                // Create new backup
                val fileMetadata = File().apply {
                    name = BACKUP_FILENAME
                    parents = listOf("appDataFolder")
                }
                val content = ByteArrayContent(BACKUP_MIME_TYPE, encryptedData)
                drive.files().create(fileMetadata, content)
                    .setFields("id")
                    .execute()
                Log.i(TAG, "Backup created successfully")
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to backup mnemonic", e)
            Result.failure(e)
        }
    }
    
    /**
     * Restore the mnemonic from Google Drive
     * 
     * @param password User-provided password for decryption
     * @return The decrypted mnemonic
     */
    suspend fun restoreMnemonic(password: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            val drive = driveService ?: return@withContext Result.failure(
                Exception("Not signed in to Google. Please sign in first.")
            )
            
            val fileId = findBackupFile() ?: return@withContext Result.failure(
                Exception("No backup found in Google Drive")
            )
            
            // Download the encrypted backup
            val outputStream = ByteArrayOutputStream()
            drive.files().get(fileId).executeMediaAndDownloadTo(outputStream)
            val encryptedData = outputStream.toByteArray()
            
            // Decrypt the mnemonic
            val mnemonic = decryptMnemonic(encryptedData, password)
            
            Log.i(TAG, "Backup restored successfully")
            Result.success(mnemonic)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore mnemonic", e)
            if (e.message?.contains("AEADBadTagException") == true || 
                e.message?.contains("Tag mismatch") == true) {
                Result.failure(Exception("Incorrect password"))
            } else {
                Result.failure(e)
            }
        }
    }
    
    /**
     * Check if a backup exists in Google Drive
     */
    suspend fun hasBackup(): Boolean = withContext(Dispatchers.IO) {
        findBackupFile() != null
    }
    
    /**
     * Delete the backup from Google Drive
     */
    suspend fun deleteBackup(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val drive = driveService ?: return@withContext Result.failure(
                Exception("Not signed in to Google")
            )
            
            val fileId = findBackupFile() ?: return@withContext Result.success(Unit)
            
            drive.files().delete(fileId).execute()
            Log.i(TAG, "Backup deleted successfully")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete backup", e)
            Result.failure(e)
        }
    }
    
    // --- Private helper methods ---
    
    private fun findBackupFile(): String? {
        return try {
            val drive = driveService ?: return null
            
            val result = drive.files().list()
                .setSpaces("appDataFolder")
                .setQ("name = '$BACKUP_FILENAME'")
                .setFields("files(id, name)")
                .execute()
            
            result.files?.firstOrNull()?.id
        } catch (e: Exception) {
            Log.e(TAG, "Failed to find backup file", e)
            null
        }
    }
    
    private fun encryptMnemonic(mnemonic: String, password: String): ByteArray {
        // Generate random salt and IV
        val salt = ByteArray(SALT_LENGTH)
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().apply {
            nextBytes(salt)
            nextBytes(iv)
        }
        
        // Derive key from password using PBKDF2
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, KEY_DERIVATION_ITERATIONS, KEY_LENGTH)
        val secretKey = SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        
        // Encrypt using AES-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        val encryptedBytes = cipher.doFinal(mnemonic.toByteArray(Charsets.UTF_8))
        
        // Combine: salt + iv + encrypted data
        return salt + iv + encryptedBytes
    }
    
    private fun decryptMnemonic(encryptedData: ByteArray, password: String): String {
        // Extract salt, IV, and encrypted bytes
        val salt = encryptedData.copyOfRange(0, SALT_LENGTH)
        val iv = encryptedData.copyOfRange(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
        val encryptedBytes = encryptedData.copyOfRange(SALT_LENGTH + IV_LENGTH, encryptedData.size)
        
        // Derive key from password using PBKDF2
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, KEY_DERIVATION_ITERATIONS, KEY_LENGTH)
        val secretKey = SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        
        // Decrypt using AES-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        
        return String(decryptedBytes, Charsets.UTF_8)
    }
}
