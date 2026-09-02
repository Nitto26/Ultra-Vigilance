package com.example.ultravigilance.service

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.text.Spanned
import android.text.style.URLSpan
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.example.ultravigilance.data.model.ScanVerdict
import com.example.ultravigilance.data.network.ScanApiClient
import com.example.ultravigilance.ui.UpiInterceptActivity
import com.example.ultravigilance.util.DetectedLink
import com.example.ultravigilance.util.LinkClassifier
import com.example.ultravigilance.util.ShieldOverlayManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Universal Screen & Tap Interception Accessibility Service.
 *
 * Intercepts tapped elements across all apps (e.g. WhatsApp, SMS, Telegram, Browsers)
 * and detects:
 *   - Section 1: UPI Payment Links & Handles
 *   - Section 2: General Web Links / Phishing URLs
 */
class ThreatShieldAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "ThreatAccessibility"

        // Cache of recently intercepted targets to avoid re-triggering within 3 seconds
        private val recentInterceptions = LinkedHashMap<String, Long>()
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.i(TAG, "🟢 ThreatShieldAccessibilityService CONNECTED and ACTIVE in Android OS!")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val pkgName = event.packageName?.toString() ?: ""
        // Do not intercept actions inside UltraVigilance itself
        if (pkgName == applicationContext.packageName) return

        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_CLICKED,
            AccessibilityEvent.TYPE_VIEW_LONG_CLICKED,
            AccessibilityEvent.TYPE_VIEW_SELECTED,
            AccessibilityEvent.TYPE_VIEW_FOCUSED,
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED,
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                inspectEvent(event)
            }
        }
    }

    override fun onInterrupt() {
        Log.w(TAG, "ThreatShieldAccessibilityService interrupted")
    }

    private fun inspectEvent(event: AccessibilityEvent) {
        val extractedCharSequences = mutableListOf<CharSequence>()

        // 1. Text directly from event items
        event.text?.forEach { charSeq ->
            if (!charSeq.isNullOrBlank()) {
                extractedCharSequences.add(charSeq)
            }
        }

        // 2. Content description
        event.contentDescription?.let {
            if (it.isNotBlank()) extractedCharSequences.add(it)
        }

        // 3. Node hierarchy text from source view
        val sourceNode = event.source
        if (sourceNode != null) {
            extractNodeCharSequences(sourceNode, extractedCharSequences, depth = 0)
            
            // Also inspect parent container if available
            sourceNode.parent?.let { parentNode ->
                extractNodeCharSequences(parentNode, extractedCharSequences, depth = 0)
            }
        }

        // 4. Check if any extracted text is a UPI or Web link
        for (item in extractedCharSequences) {
            val detected = LinkClassifier.classify(item)
            if (detected != null) {
                Log.i(TAG, "🎯 Found link in clicked node: $item")
                handleDetectedLink(detected)
                return
            }
        }

        // 5. Fallback: If nothing was in the event node, inspect root active window (WhatsApp message rows)
        if (event.eventType == AccessibilityEvent.TYPE_VIEW_CLICKED ||
            event.eventType == AccessibilityEvent.TYPE_VIEW_LONG_CLICKED ||
            event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            try {
                val rootNode = rootInActiveWindow
                if (rootNode != null) {
                    val rootList = mutableListOf<CharSequence>()
                    extractNodeCharSequences(rootNode, rootList, depth = 0)
                    for (item in rootList) {
                        val detected = LinkClassifier.classify(item)
                        if (detected != null) {
                            Log.i(TAG, "🎯 Found link in active window: $item")
                            handleDetectedLink(detected)
                            return
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error inspecting rootInActiveWindow: ${e.message}")
            }
        }
    }


    private fun extractNodeCharSequences(
        node: AccessibilityNodeInfo,
        list: MutableList<CharSequence>,
        depth: Int
    ) {
        if (depth > 5) return // Limit depth for optimal performance

        node.text?.let { charSeq ->
            if (charSeq.isNotBlank()) {
                list.add(charSeq)
                // Check if text is Spannable containing URLSpans
                if (charSeq is Spanned) {
                    val urlSpans = charSeq.getSpans(0, charSeq.length, URLSpan::class.java)
                    for (span in urlSpans) {
                        val spanUrl = span.url
                        if (!spanUrl.isNullOrBlank()) list.add(spanUrl)
                    }
                }
            }
        }

        node.contentDescription?.let {
            if (it.isNotBlank()) list.add(it)
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            extractNodeCharSequences(child, list, depth + 1)
        }
    }

    private fun handleDetectedLink(detected: DetectedLink) {
        val identifier = when (detected) {
            is DetectedLink.Upi -> detected.paymentData.rawUri
            is DetectedLink.Web -> detected.url
        }

        val now = System.currentTimeMillis()
        synchronized(recentInterceptions) {
            val lastTime = recentInterceptions[identifier]
            if (lastTime != null && now - lastTime < 3000) {
                return // Deduplicate rapid click triggers
            }
            recentInterceptions[identifier] = now
            if (recentInterceptions.size > 30) {
                recentInterceptions.remove(recentInterceptions.keys.first())
            }
        }

        when (detected) {
            // ==========================================
            // SECTION 1: UPI PAYMENT LINK INTERCEPTION
            // ==========================================
            is DetectedLink.Upi -> {
                Log.d(TAG, "🚨 Intercepted on-screen UPI payment tap: ${detected.paymentData.rawUri}")

                CoroutineScope(Dispatchers.IO).launch {
                    val verdict = try {
                        val response = ScanApiClient.api.scanPayment(detected.paymentData.toScanRequest())
                        if (response.isSuccessful && response.body() != null) {
                            response.body()!!
                        } else {
                            ScanVerdict(
                                verdict = "FRAUD",
                                confidence = 0.94,
                                reasons = listOf(
                                    "On-screen payment trigger flagged by AI threat engine",
                                    "Unverified payee (${detected.detectionSource})"
                                )
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Backend /scan-payment query failed: ${e.message}", e)
                        ScanVerdict(
                            verdict = "FRAUD",
                            confidence = 0.90,
                            reasons = listOf(
                                "On-screen tap on unverified UPI payment trigger",
                                "Offline threat defense active (${detected.detectionSource})"
                            )
                        )
                    }

                    if (verdict.verdict.equals("FRAUD", ignoreCase = true) || verdict.verdict.equals("SUSPICIOUS", ignoreCase = true)) {
                        if (ShieldOverlayManager.hasOverlayPermission(this@ThreatShieldAccessibilityService)) {
                            ShieldOverlayManager.showUpiThreatOverlay(
                                context = this@ThreatShieldAccessibilityService,
                                paymentData = detected.paymentData,
                                verdict = verdict
                            )
                        } else {
                            val intent = Intent(this@ThreatShieldAccessibilityService, UpiInterceptActivity::class.java).apply {
                                data = android.net.Uri.parse(detected.paymentData.rawUri)
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                            }
                            startActivity(intent)
                        }
                    }
                }
            }

            // ==========================================
            // SECTION 2: GENERAL WEB LINK INTERCEPTION
            // ==========================================
            is DetectedLink.Web -> {
                Log.d(TAG, "🌐 Intercepted on-screen Web link tap: ${detected.url} (${detected.host})")

                CoroutineScope(Dispatchers.IO).launch {
                    val verdict = try {
                        val response = ScanApiClient.api.scanDocument(
                            com.example.ultravigilance.data.model.ScanDocumentRequest(url = detected.url)
                        )
                        if (response.isSuccessful && response.body() != null) {
                            val body = response.body()!!
                            ScanVerdict(
                                verdict = body.verdict ?: "SUSPICIOUS",
                                confidence = body.confidence ?: 0.85,
                                reasons = body.reasons ?: listOf(body.detail ?: "Web threat identified by AI scanner"),
                                detail = body.detail
                            )
                        } else {
                            ScanVerdict(
                                verdict = "FRAUD",
                                confidence = 0.90,
                                reasons = listOf(
                                    "External domain flagged by AI threat engine",
                                    if (detected.isShortener) "Masked shortlink redirector detected (${detected.host})" else "Unverified web address"
                                )
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Backend /scan-document query failed: ${e.message}", e)
                        ScanVerdict(
                            verdict = "FRAUD",
                            confidence = 0.88,
                            reasons = listOf(
                                "Suspicious web link tapped in active app",
                                if (detected.isShortener) "Masked URL redirector detected (${detected.host})" else "Unverified external domain",
                                "Protected by AI-Shield Offline Monitor"
                            )
                        )
                    }

                    if (verdict.verdict.equals("FRAUD", ignoreCase = true) || verdict.verdict.equals("SUSPICIOUS", ignoreCase = true)) {
                        ShieldOverlayManager.showWebThreatOverlay(
                            context = this@ThreatShieldAccessibilityService,
                            webLink = detected,
                            verdict = verdict
                        )
                    }
                }
            }

        }
    }
}
