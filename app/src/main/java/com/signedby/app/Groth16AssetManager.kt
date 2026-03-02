package com.signedby.app

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * Manages Groth16 proving assets (witness calculator, circuit data, zkey).
 * 
 * Assets are extracted from APK to app data directory on first use.
 * The .zkey file (85MB) can be:
 * - Bundled in APK assets
 * - Sideloaded to /sdcard/Download/
 * - Downloaded from CDN
 */
object Groth16AssetManager {
    private const val TAG = "Groth16AssetManager"
    
    // Asset names in APK assets/groth16/
    private const val ASSET_DIR = "groth16"
    private const val WITNESS_CALC_NAME = "membership"
    private const val CIRCUIT_DAT_NAME = "membership.dat"
    private const val ZKEY_NAME = "membership_final.zkey"
    
    // Extracted file paths (set after extraction)
    var calculatorPath: String? = null
        private set
    var datPath: String? = null
        private set
    var zkeyPath: String? = null
        private set
    
    var isReady: Boolean = false
        private set
    
    /**
     * Initialize and extract all required assets.
     * Call this before using NativeBridge.initProver().
     * 
     * @return true if all assets are ready
     */
    fun initialize(context: Context): Boolean {
        // First, set native lib path for dlopen (required for rapidsnark FFI)
        val nativeLibDir = context.applicationInfo.nativeLibraryDir
        NativeBridge.initNativeLibPath(nativeLibDir)
        Log.i(TAG, "Native lib dir: $nativeLibDir")
        
        val dataDir = context.filesDir
        val groth16Dir = File(dataDir, "groth16")
        groth16Dir.mkdirs()
        
        // Extract witness calculator (must be executable)
        calculatorPath = extractAsset(context, WITNESS_CALC_NAME, groth16Dir, executable = true)
        if (calculatorPath == null) {
            Log.e(TAG, "Failed to extract witness calculator")
            return false
        }
        
        // Extract circuit data
        datPath = extractAsset(context, CIRCUIT_DAT_NAME, groth16Dir, executable = false)
        if (datPath == null) {
            Log.e(TAG, "Failed to extract circuit data")
            return false
        }
        
        // Handle zkey (may be bundled, sideloaded, or downloaded)
        zkeyPath = findOrExtractZkey(context, groth16Dir)
        if (zkeyPath == null) {
            Log.e(TAG, "zkey not found - must be sideloaded or downloaded")
            return false
        }
        
        isReady = true
        Log.i(TAG, "Groth16 assets ready:")
        Log.i(TAG, "  Calculator: $calculatorPath")
        Log.i(TAG, "  Dat: $datPath")
        Log.i(TAG, "  Zkey: $zkeyPath")
        
        return true
    }
    
    /**
     * Extract asset from APK to destination directory.
     */
    private fun extractAsset(
        context: Context,
        assetName: String,
        destDir: File,
        executable: Boolean
    ): String? {
        val destFile = File(destDir, assetName)
        
        // Check if already extracted
        if (destFile.exists() && destFile.length() > 0) {
            Log.d(TAG, "Asset already extracted: $assetName")
            if (executable) {
                destFile.setExecutable(true)
            }
            return destFile.absolutePath
        }
        
        return try {
            val assetPath = "$ASSET_DIR/$assetName"
            context.assets.open(assetPath).use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }
            
            if (executable) {
                destFile.setExecutable(true)
            }
            
            Log.i(TAG, "Extracted $assetName (${destFile.length()} bytes)")
            destFile.absolutePath
        } catch (e: IOException) {
            Log.e(TAG, "Failed to extract $assetName: ${e.message}")
            null
        }
    }
    
    /**
     * Find or extract zkey file.
     * 
     * Search order:
     * 1. Already in app data dir
     * 2. APK assets
     * 3. /sdcard/Download/ (sideloaded)
     */
    private fun findOrExtractZkey(context: Context, destDir: File): String? {
        val destFile = File(destDir, ZKEY_NAME)
        
        // 1. Already extracted
        if (destFile.exists() && destFile.length() > 0) {
            Log.d(TAG, "zkey already in data dir")
            return destFile.absolutePath
        }
        
        // 2. Try APK assets
        try {
            val assetPath = "$ASSET_DIR/$ZKEY_NAME"
            context.assets.open(assetPath).use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }
            Log.i(TAG, "Extracted zkey from APK (${destFile.length()} bytes)")
            return destFile.absolutePath
        } catch (e: IOException) {
            Log.d(TAG, "zkey not in APK assets")
        }
        
        // 3. Check sideload location
        val sideloadFile = File("/sdcard/Download/$ZKEY_NAME")
        if (sideloadFile.exists() && sideloadFile.length() > 0) {
            // Copy to app data dir for consistent access
            try {
                sideloadFile.inputStream().use { input ->
                    FileOutputStream(destFile).use { output ->
                        input.copyTo(output)
                    }
                }
                Log.i(TAG, "Copied zkey from Download (${destFile.length()} bytes)")
                return destFile.absolutePath
            } catch (e: IOException) {
                Log.e(TAG, "Failed to copy sideloaded zkey: ${e.message}")
            }
        }
        
        return null
    }
    
    /**
     * Initialize the native prover with extracted assets.
     * Call after initialize() returns true.
     */
    fun initializeProver(): Boolean {
        if (!isReady) {
            Log.e(TAG, "Assets not ready - call initialize() first")
            return false
        }
        
        return NativeBridge.initProver(zkeyPath!!, datPath!!, calculatorPath!!)
    }
    
    /**
     * Get the size of the zkey file (for progress indicators).
     */
    fun getZkeySize(): Long = 85_000_000L  // ~85MB
    
    /**
     * Check if zkey needs to be downloaded.
     */
    fun needsZkeyDownload(context: Context): Boolean {
        val dataDir = context.filesDir
        val zkeyFile = File(dataDir, "groth16/$ZKEY_NAME")
        if (zkeyFile.exists() && zkeyFile.length() > 80_000_000L) {
            return false
        }
        
        // Check if in APK assets
        return try {
            context.assets.open("$ASSET_DIR/$ZKEY_NAME").close()
            false  // Found in APK
        } catch (e: IOException) {
            // Check sideload
            val sideload = File("/sdcard/Download/$ZKEY_NAME")
            !sideload.exists()
        }
    }
}
