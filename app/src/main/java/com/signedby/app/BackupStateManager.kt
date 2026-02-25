package com.signedby.app

import android.content.Context
import android.content.SharedPreferences

/**
 * Manages backup state and reminder logic.
 * 
 * Tracks whether user has backed up their wallet and handles
 * the "remind me later" flow with progressive back-off.
 */
class BackupStateManager(context: Context) {
    
    companion object {
        private const val PREFS_NAME = "backup_state"
        private const val KEY_BACKUP_COMPLETED = "backup_completed"
        private const val KEY_FIRST_LOGIN_COMPLETED = "first_login_completed"
        private const val KEY_DISMISS_COUNT = "backup_prompt_dismiss_count"
        private const val KEY_LAST_DISMISSED_AT = "backup_prompt_last_dismissed_at"
        private const val KEY_TOTAL_LOGINS = "total_successful_logins"
        
        // Reminder thresholds
        private const val REMIND_AFTER_LOGINS_FIRST = 3   // After first dismiss, remind after 3 more logins
        private const val REMIND_AFTER_LOGINS_SECOND = 5  // After second dismiss, remind after 5 more logins
        private const val REMIND_AFTER_DAYS_FIRST = 3     // Or after 3 days
        private const val REMIND_AFTER_DAYS_SECOND = 7    // Or after 7 days
        private const val MAX_DISMISS_COUNT = 3           // Stop nagging after 3 dismisses
    }
    
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    
    /**
     * Check if backup has been completed
     */
    val isBackupCompleted: Boolean
        get() = prefs.getBoolean(KEY_BACKUP_COMPLETED, false)
    
    /**
     * Check if user has completed at least one successful login
     */
    val hasCompletedFirstLogin: Boolean
        get() = prefs.getBoolean(KEY_FIRST_LOGIN_COMPLETED, false)
    
    /**
     * Get total number of successful logins
     */
    val totalSuccessfulLogins: Int
        get() = prefs.getInt(KEY_TOTAL_LOGINS, 0)
    
    /**
     * Get number of times user has dismissed the backup prompt
     */
    val dismissCount: Int
        get() = prefs.getInt(KEY_DISMISS_COUNT, 0)
    
    /**
     * Mark backup as completed
     */
    fun markBackupCompleted() {
        prefs.edit().putBoolean(KEY_BACKUP_COMPLETED, true).apply()
    }
    
    /**
     * Record a successful login
     */
    fun recordSuccessfulLogin() {
        prefs.edit()
            .putBoolean(KEY_FIRST_LOGIN_COMPLETED, true)
            .putInt(KEY_TOTAL_LOGINS, totalSuccessfulLogins + 1)
            .apply()
    }
    
    /**
     * Record that user dismissed the backup prompt
     */
    fun recordPromptDismissed() {
        prefs.edit()
            .putInt(KEY_DISMISS_COUNT, dismissCount + 1)
            .putLong(KEY_LAST_DISMISSED_AT, System.currentTimeMillis())
            .putInt(KEY_TOTAL_LOGINS, 0) // Reset login counter for next reminder cycle
            .apply()
    }
    
    /**
     * Determine if we should show the backup prompt.
     * 
     * Logic:
     * - If backup completed: never show
     * - If first login just happened: always show
     * - If dismissed before: check if enough time/logins have passed
     * - If dismissed 3+ times: stop nagging
     */
    fun shouldShowBackupPrompt(): Boolean {
        // Already backed up - never show
        if (isBackupCompleted) return false
        
        // Dismissed too many times - stop nagging
        if (dismissCount >= MAX_DISMISS_COUNT) return false
        
        // First login ever - always show
        if (!hasCompletedFirstLogin) return false // Will be true after recordSuccessfulLogin()
        
        // Never dismissed - show immediately on first login
        if (dismissCount == 0) return true
        
        // Check if enough time or logins have passed since last dismiss
        val lastDismissedAt = prefs.getLong(KEY_LAST_DISMISSED_AT, 0)
        val daysSinceDismiss = (System.currentTimeMillis() - lastDismissedAt) / (1000 * 60 * 60 * 24)
        val loginsSinceDismiss = totalSuccessfulLogins
        
        return when (dismissCount) {
            1 -> daysSinceDismiss >= REMIND_AFTER_DAYS_FIRST || loginsSinceDismiss >= REMIND_AFTER_LOGINS_FIRST
            2 -> daysSinceDismiss >= REMIND_AFTER_DAYS_SECOND || loginsSinceDismiss >= REMIND_AFTER_LOGINS_SECOND
            else -> false
        }
    }
    
    /**
     * Check if we should show a subtle "not backed up" indicator.
     * Shows when backup not completed and prompt has been dismissed at least once.
     */
    fun shouldShowBackupIndicator(): Boolean {
        return !isBackupCompleted && dismissCount > 0
    }
    
    /**
     * Reset all backup state (for testing)
     */
    fun reset() {
        prefs.edit().clear().apply()
    }
}
