package com.example.ultravigilance.data

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

data class SuspiciousLinkItem(
    val id: String = UUID.randomUUID().toString(),
    val url: String,
    val verdict: String,
    val confidence: Double,
    val reasons: List<String> = emptyList(),
    val timestamp: Long = System.currentTimeMillis(),
    val userClaim: String = "UNREVIEWED" // "UNREVIEWED" | "CLAIMED_SAFE" | "CONFIRMED_THREAT"
)

object SecurityStatsManager {

    private const val PREFS_NAME = "ultra_vigilance_stats"
    private const val KEY_LINKS_SCANNED = "total_links_scanned"
    private const val KEY_MESSAGES_SCANNED = "total_messages_scanned"
    private const val KEY_THREATS_FOUND = "total_threats_found"
    private const val KEY_SUSPICIOUS_LINKS = "suspicious_links_json"
    private const val MAX_STORED_LINKS = 50

    private val gson = Gson()

    // Real-time notification flow for UI reactivity
    private val _updateNotifier = MutableStateFlow(System.currentTimeMillis())
    val updateNotifier: StateFlow<Long> = _updateNotifier.asStateFlow()

    private fun getPrefs(context: Context): SharedPreferences {
        return context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private fun notifyChanged() {
        _updateNotifier.value = System.currentTimeMillis()
    }

    // --- Metrics Getters ---

    fun getTotalLinksScanned(context: Context): Int {
        return getPrefs(context).getInt(KEY_LINKS_SCANNED, 0)
    }

    fun getTotalMessagesScanned(context: Context): Int {
        return getPrefs(context).getInt(KEY_MESSAGES_SCANNED, 0)
    }

    fun getTotalThreatsFound(context: Context): Int {
        // Active threats = unreviewed threats + confirmed threats (excluding items marked normal/safe by user)
        val list = getSuspiciousLinks(context)
        val activeThreats = list.count { it.userClaim != "CLAIMED_SAFE" }
        val rawThreats = getPrefs(context).getInt(KEY_THREATS_FOUND, 0)
        return if (list.isNotEmpty()) activeThreats else rawThreats
    }

    // --- Recording Events ---

    fun recordLinkScanned(
        context: Context,
        url: String,
        verdict: String,
        confidence: Double,
        reasons: List<String> = emptyList()
    ) {
        val prefs = getPrefs(context)
        val currentLinks = prefs.getInt(KEY_LINKS_SCANNED, 0) + 1
        val isThreat = verdict.equals("FRAUD", ignoreCase = true) || verdict.equals("SUSPICIOUS", ignoreCase = true)
        val currentThreats = if (isThreat) prefs.getInt(KEY_THREATS_FOUND, 0) + 1 else prefs.getInt(KEY_THREATS_FOUND, 0)

        val editor = prefs.edit()
        editor.putInt(KEY_LINKS_SCANNED, currentLinks)
        if (isThreat) {
            editor.putInt(KEY_THREATS_FOUND, currentThreats)
        }

        // If flagged as threat/suspicious, record to threats list
        if (isThreat && url.isNotBlank()) {
            val existingList = getSuspiciousLinks(context).toMutableList()
            val existingIndex = existingList.indexOfFirst { it.url.equals(url, ignoreCase = true) }
            val newItem = SuspiciousLinkItem(
                id = if (existingIndex >= 0) existingList[existingIndex].id else UUID.randomUUID().toString(),
                url = url,
                verdict = verdict.uppercase(),
                confidence = confidence,
                reasons = reasons,
                timestamp = System.currentTimeMillis(),
                userClaim = if (existingIndex >= 0) existingList[existingIndex].userClaim else "UNREVIEWED"
            )

            if (existingIndex >= 0) {
                existingList[existingIndex] = newItem
            } else {
                existingList.add(0, newItem)
            }

            val cappedList = if (existingList.size > MAX_STORED_LINKS) existingList.take(MAX_STORED_LINKS) else existingList
            editor.putString(KEY_SUSPICIOUS_LINKS, gson.toJson(cappedList))
        }

        editor.apply()
        notifyChanged()
    }

    fun recordMessageScanned(
        context: Context,
        sender: String,
        message: String,
        verdict: String,
        confidence: Double,
        reasons: List<String> = emptyList()
    ) {
        val prefs = getPrefs(context)
        val currentMsgs = prefs.getInt(KEY_MESSAGES_SCANNED, 0) + 1
        val isThreat = verdict.equals("FRAUD", ignoreCase = true) || verdict.equals("SUSPICIOUS", ignoreCase = true)
        val currentThreats = if (isThreat) prefs.getInt(KEY_THREATS_FOUND, 0) + 1 else prefs.getInt(KEY_THREATS_FOUND, 0)

        val editor = prefs.edit()
        editor.putInt(KEY_MESSAGES_SCANNED, currentMsgs)
        if (isThreat) {
            editor.putInt(KEY_THREATS_FOUND, currentThreats)
        }

        if (isThreat && message.isNotBlank()) {
            val existingList = getSuspiciousLinks(context).toMutableList()
            val newItem = SuspiciousLinkItem(
                url = if (sender.isNotBlank()) "SMS ($sender): $message" else message,
                verdict = verdict.uppercase(),
                confidence = confidence,
                reasons = reasons,
                timestamp = System.currentTimeMillis(),
                userClaim = "UNREVIEWED"
            )
            existingList.add(0, newItem)
            val cappedList = if (existingList.size > MAX_STORED_LINKS) existingList.take(MAX_STORED_LINKS) else existingList
            editor.putString(KEY_SUSPICIOUS_LINKS, gson.toJson(cappedList))
        }

        editor.apply()
        notifyChanged()
    }

    // --- Suspicious Links Retrieval & User Feedback Claims ---

    fun getSuspiciousLinks(context: Context): List<SuspiciousLinkItem> {
        val json = getPrefs(context).getString(KEY_SUSPICIOUS_LINKS, null) ?: return emptyList()
        return try {
            val type = object : TypeToken<List<SuspiciousLinkItem>>() {}.type
            gson.fromJson(json, type) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun updateUserClaim(context: Context, id: String, newClaim: String) {
        val list = getSuspiciousLinks(context).toMutableList()
        val index = list.indexOfFirst { it.id == id }
        if (index >= 0) {
            val item = list[index]
            list[index] = item.copy(userClaim = newClaim)
            getPrefs(context).edit().putString(KEY_SUSPICIOUS_LINKS, gson.toJson(list)).apply()
            notifyChanged()
        }
    }

    fun clearAllStats(context: Context) {
        getPrefs(context).edit().clear().apply()
        notifyChanged()
    }
}
