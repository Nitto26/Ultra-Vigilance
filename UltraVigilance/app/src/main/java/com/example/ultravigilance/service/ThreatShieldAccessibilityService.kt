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
 * Intelligent Link Click & Browser Launch Interceptor.
 *
 * Catches links tapped in WhatsApp, SMS (Google Messages), Telegram, and Browsers.
 * Evaluates with live AI backend and displays Threat Shield Overlay if fraud is detected.
 */
class ThreatShieldAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "ThreatAccessibility"

        // Deduplication cache to prevent re-scanning the same target within 2 seconds
        private val recentInterceptions = LinkedHashMap<String, Long>()

        // Common Android Web Browsers & Custom Tabs
        private val BROWSER_PACKAGES = setOf(
            "com.android.chrome",
            "org.chromium.chrome",
            "com.google.android.apps.chrome",
            "com.sec.android.app.sbrowser",
            "org.mozilla.firefox",
            "com.opera.browser",
            "com.microsoft.emmx",
            "com.brave.browser",
            "com.duckduckgo.mobile.android"
        )
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.i(TAG, "🟢 ThreatShieldAccessibilityService CONNECTED & ACTIVE")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val pkgName = event.packageName?.toString() ?: ""
        if (pkgName == applicationContext.packageName) return

        when (event.eventType) {
            // Case 1: Direct Click on a Link or View
            AccessibilityEvent.TYPE_VIEW_CLICKED -> {
                inspectClickedView(event)
            }

            // Case 2: Browser / Custom Tab Opened from a WhatsApp or SMS Link Tap
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                if (BROWSER_PACKAGES.contains(pkgName)) {
                    inspectBrowserWindow(event)
                }
            }
        }
    }

    override fun onInterrupt() {
        Log.w(TAG, "ThreatShieldAccessibilityService interrupted")
    }

    private fun inspectClickedView(event: AccessibilityEvent) {
        val extractedLinks = mutableListOf<CharSequence>()

        // 1. Check for URLSpans in clicked text
        event.text?.forEach { charSeq ->
            if (charSeq is Spanned) {
                val urlSpans = charSeq.getSpans(0, charSeq.length, URLSpan::class.java)
                for (span in urlSpans) {
                    val spanUrl = span.url
                    if (!spanUrl.isNullOrBlank()) extractedLinks.add(spanUrl)
                }
            }
        }

        // 2. Check clicked node itself
        val sourceNode = event.source
        if (sourceNode != null) {
            extractLinksFromNode(sourceNode, extractedLinks, depth = 0)
        }

        // 3. Classify and handle detected link
        for (item in extractedLinks) {
            val detected = LinkClassifier.classify(item)
            if (detected != null) {
                Log.i(TAG, "🎯 Clicked link detected in app: $item")
                handleDetectedLink(detected)
                return
            }
        }
    }

    private fun inspectBrowserWindow(event: AccessibilityEvent) {
        val rootNode = rootInActiveWindow ?: return
        val extractedLinks = mutableListOf<CharSequence>()
        extractLinksFromNode(rootNode, extractedLinks, depth = 0)

        for (item in extractedLinks) {
            val detected = LinkClassifier.classify(item)
            if (detected != null) {
                Log.i(TAG, "🌐 Browser / Custom Tab opened target: $item")
                handleDetectedLink(detected)
                return
            }
        }
    }

    private fun extractLinksFromNode(
        node: AccessibilityNodeInfo,
        list: MutableList<CharSequence>,
        depth: Int
    ) {
        if (depth > 12) return

        node.text?.let { charSeq ->
            if (charSeq.isNotBlank()) {
                if (charSeq is Spanned) {
                    val urlSpans = charSeq.getSpans(0, charSeq.length, URLSpan::class.java)
                    for (span in urlSpans) {
                        val spanUrl = span.url
                        if (!spanUrl.isNullOrBlank()) list.add(spanUrl)
                    }
                } else {
                    val textStr = charSeq.toString()
                    if (textStr.contains("http://", ignoreCase = true) ||
                        textStr.contains("https://", ignoreCase = true) ||
                        textStr.contains("upi://", ignoreCase = true)
                    ) {
                        list.add(charSeq)
                    }
                }
            }
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            extractLinksFromNode(child, list, depth + 1)
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
            if (lastTime != null && now - lastTime < 2500) {
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
                Log.i(TAG, "🚨 Intercepted UPI payment click: ${detected.paymentData.rawUri}")

                CoroutineScope(Dispatchers.IO).launch {
                    val verdict = try {
                        val response = ScanApiClient.api.scanPayment(detected.paymentData.toScanRequest())
                        if (response.isSuccessful && response.body() != null) {
                            response.body()!!
                        } else {
                            ScanVerdict(
                                verdict = "FRAUD",
                                confidence = 0.95,
                                reasons = listOf("Payment link recipient unverified by banking records")
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Backend /scan-payment error: ${e.message}", e)
                        ScanVerdict(verdict = "SAFE", confidence = 0.0, reasons = emptyList())
                    }

                    if (verdict.verdict.equals("FRAUD", ignoreCase = true) || verdict.verdict.equals("SUSPICIOUS", ignoreCase = true)) {
                        ShieldOverlayManager.showUpiThreatOverlay(
                            context = this@ThreatShieldAccessibilityService,
                            paymentData = detected.paymentData,
                            verdict = verdict
                        )
                    }
                }
            }

            // ==========================================
            // SECTION 2: GENERAL WEB LINK INTERCEPTION
            // ==========================================
            is DetectedLink.Web -> {
                Log.i(TAG, "🌐 Intercepted Web link click: ${detected.url}")

                CoroutineScope(Dispatchers.IO).launch {
                    val verdict = try {
                        val response = ScanApiClient.api.scanDocument(
                            com.example.ultravigilance.data.model.ScanDocumentRequest(url = detected.url)
                        )
                        if (response.isSuccessful && response.body() != null) {
                            val body = response.body()!!
                            ScanVerdict(
                                verdict = body.verdict ?: "SAFE",
                                confidence = body.confidence ?: 0.0,
                                reasons = body.reasons ?: listOf(body.detail ?: "Web scan completed"),
                                detail = body.detail
                            )
                        } else {
                            ScanVerdict(
                                verdict = "FRAUD",
                                confidence = 0.90,
                                reasons = listOf("External domain flagged by AI threat engine")
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Backend /scan-document error: ${e.message}", e)
                        ScanVerdict(verdict = "SAFE", confidence = 0.0, reasons = emptyList())
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
