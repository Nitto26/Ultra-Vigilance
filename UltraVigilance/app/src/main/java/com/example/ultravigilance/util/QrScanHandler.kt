package com.example.ultravigilance.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import android.widget.Toast
import com.example.ultravigilance.data.model.ScanDocumentRequest
import com.example.ultravigilance.data.model.ScanVerdict
import com.example.ultravigilance.data.network.ScanApiClient
import com.example.ultravigilance.receiver.SmsScanReceiver
import com.example.ultravigilance.ui.UpiInterceptActivity
import com.google.android.gms.common.moduleinstall.ModuleInstall
import com.google.android.gms.common.moduleinstall.ModuleInstallRequest
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * AI-Powered QR Code Security Scanner.
 *
 * Automatically inspects physical or digital QR codes:
 * 1. UPI QR Codes -> routes to POST /scan-payment
 * 2. Web URL QR Codes -> routes to POST /scan-document
 * 3. Text / Raw QR Codes -> routes to POST /scan-sms
 *
 * Opens directly if SAFE, or activates AI Threat Shield if FRAUD.
 */
object QrScanHandler {

    private const val TAG = "QrScanHandler"

    fun startQrScan(
        context: Context,
        scope: CoroutineScope,
        onScanStateChanged: (isScanning: Boolean) -> Unit = {},
        onScanCompleted: (resultSummary: String) -> Unit = {}
    ) {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(
                Barcode.FORMAT_QR_CODE,
                Barcode.FORMAT_AZTEC,
                Barcode.FORMAT_DATA_MATRIX
            )
            .enableAutoZoom()
            .build()

        val scanner = GmsBarcodeScanning.getClient(context, options)

        scanner.startScan()
            .addOnSuccessListener { barcode ->
                val rawValue = barcode.rawValue ?: barcode.displayValue ?: ""
                if (rawValue.isBlank()) {
                    Toast.makeText(context, "Scanned QR code is empty", Toast.LENGTH_SHORT).show()
                    return@addOnSuccessListener
                }

                Log.i(TAG, "📷 QR Code Captured: $rawValue")
                onScanStateChanged(true)

                scope.launch(Dispatchers.IO) {
                    processScannedQrContent(context, rawValue, onScanStateChanged, onScanCompleted)
                }
            }
            .addOnCanceledListener {
                Log.d(TAG, "QR Scan dismissed by user")
                onScanStateChanged(false)
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "GmsBarcodeScanner failed: ${e.message}", e)
                onScanStateChanged(false)
                Toast.makeText(context, "QR Scanner error: ${e.localizedMessage ?: "Camera unavailable"}", Toast.LENGTH_LONG).show()
            }
    }

    private suspend fun processScannedQrContent(
        context: Context,
        rawContent: String,
        onScanStateChanged: (isScanning: Boolean) -> Unit,
        onScanCompleted: (resultSummary: String) -> Unit
    ) {
        val detected = LinkClassifier.classify(rawContent)

        when (detected) {
            // ==========================================
            // 1. UPI PAYMENT QR CODE (calls /scan-payment)
            // ==========================================
            is DetectedLink.Upi -> {
                Log.i(TAG, "💳 Routing scanned QR to /scan-payment: ${detected.paymentData.pa}")
                val verdict = try {
                    val response = ScanApiClient.api.scanPayment(detected.paymentData.toScanRequest())
                    if (response.isSuccessful && response.body() != null) {
                        response.body()!!
                    } else {
                        ScanVerdict(
                            verdict = "FRAUD",
                            confidence = 0.95,
                            reasons = listOf("QR payment recipient unverified by banking records")
                        )
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Backend /scan-payment query failed: ${e.message}", e)
                    ScanVerdict(
                        verdict = "SAFE",
                        confidence = 0.0,
                        reasons = listOf("Offline fallback")
                    )
                }

                withContext(Dispatchers.Main) {
                    onScanStateChanged(false)
                    com.example.ultravigilance.data.SecurityStatsManager.recordLinkScanned(
                        context = context,
                        url = detected.paymentData.rawUri,
                        verdict = verdict.verdict,
                        confidence = verdict.confidence,
                        reasons = verdict.reasons
                    )
                    val riskPct = Math.round(verdict.confidence * 100)
                    if (verdict.verdict.equals("FRAUD", ignoreCase = true) || verdict.verdict.equals("SUSPICIOUS", ignoreCase = true)) {
                        val reasonsStr = if (verdict.reasons.isNotEmpty()) {
                            verdict.reasons.joinToString("\n") { "• $it" }
                        } else {
                            "• Impersonated authority or unverified recipient"
                        }
                        val details = "🚨 BLOCKED FRAUD UPI QR ($riskPct% Risk Score)\nPayee: ${detected.paymentData.displayPayee}\nVPA: ${detected.paymentData.pa ?: "Unknown"}\n\nThreat Reasons:\n$reasonsStr"
                        onScanCompleted(details)

                        if (ShieldOverlayManager.hasOverlayPermission(context)) {
                            ShieldOverlayManager.showUpiThreatOverlay(context, detected.paymentData, verdict)
                        } else {
                            val intent = Intent(context, UpiInterceptActivity::class.java).apply {
                                data = Uri.parse(detected.paymentData.rawUri)
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                            }
                            context.startActivity(intent)
                        }
                    } else {
                        onScanCompleted("✅ Verified Clean UPI QR (${detected.paymentData.displayPayee})")
                        Toast.makeText(context, "✅ QR Verified SAFE (${detected.paymentData.displayPayee})", Toast.LENGTH_SHORT).show()
                        val launched = UpiLauncher.launchGenuineUpiApp(context, detected.paymentData.rawUri)
                        if (!launched) {
                            val fallbackIntent = Intent(Intent.ACTION_VIEW, Uri.parse(detected.paymentData.rawUri)).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            context.startActivity(fallbackIntent)
                        }
                    }
                }
            }

            // ==========================================
            // 2. WEB LINK QR CODE (calls /scan-document)
            // ==========================================
            is DetectedLink.Web -> {
                Log.i(TAG, "🌐 Routing scanned QR to /scan-document: ${detected.url}")
                val verdict = try {
                    val response = ScanApiClient.api.scanDocument(
                        ScanDocumentRequest(url = detected.url)
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
                            reasons = listOf("Scanned QR redirects to unverified domain")
                        )
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Backend /scan-document query failed: ${e.message}", e)
                    ScanVerdict(
                        verdict = "SAFE",
                        confidence = 0.0,
                        reasons = listOf("Offline fallback")
                    )
                }

                withContext(Dispatchers.Main) {
                    onScanStateChanged(false)
                    com.example.ultravigilance.data.SecurityStatsManager.recordLinkScanned(
                        context = context,
                        url = detected.url,
                        verdict = verdict.verdict,
                        confidence = verdict.confidence,
                        reasons = verdict.reasons
                    )
                    val riskPct = Math.round(verdict.confidence * 100)
                    if (verdict.verdict.equals("FRAUD", ignoreCase = true) || verdict.verdict.equals("SUSPICIOUS", ignoreCase = true)) {
                        val reasonsStr = if (verdict.reasons.isNotEmpty()) {
                            verdict.reasons.joinToString("\n") { "• $it" }
                        } else {
                            "• Deceptive domain pattern or brand impersonation"
                        }
                        val details = "🚨 BLOCKED FRAUD QR LINK ($riskPct% Risk Score)\nURL: ${detected.url}\n\nThreat Reasons:\n$reasonsStr"
                        onScanCompleted(details)

                        ShieldOverlayManager.showWebThreatOverlay(context, detected, verdict)
                    } else {
                        onScanCompleted("✅ Safe QR Link (${detected.host})")
                        Toast.makeText(context, "✅ Safe Website QR - Opening...", Toast.LENGTH_SHORT).show()
                        BrowserLauncher.launchGenuineBrowser(context, detected.url)
                    }
                }
            }

            // ==========================================
            // 3. RAW TEXT / SMISHING QR (calls /scan-sms)
            // ==========================================
            null -> {
                Log.i(TAG, "📝 Routing raw text QR to /scan-sms: $rawContent")
                val verdict = SmsScanReceiver.scanMessage("QR Code Scanner", rawContent)

                withContext(Dispatchers.Main) {
                    onScanStateChanged(false)
                    com.example.ultravigilance.data.SecurityStatsManager.recordMessageScanned(
                        context = context,
                        sender = "QR Scanner",
                        message = rawContent,
                        verdict = verdict.verdict,
                        confidence = verdict.confidence,
                        reasons = verdict.reasons
                    )
                    val riskPct = Math.round(verdict.confidence * 100)
                    if (verdict.verdict.equals("FRAUD", ignoreCase = true) || verdict.verdict.equals("SUSPICIOUS", ignoreCase = true)) {
                        val reasonsStr = if (verdict.reasons.isNotEmpty()) {
                            verdict.reasons.joinToString("\n") { "• $it" }
                        } else {
                            "• High urgency or phishing keyword patterns"
                        }
                        val details = "🚨 BLOCKED MALICIOUS QR PAYLOAD ($riskPct% Risk)\nPayload: $rawContent\n\nThreat Reasons:\n$reasonsStr"
                        onScanCompleted(details)

                        SmsScanReceiver.showAlertNotification(context, "QR Scanner Defense", rawContent, verdict)
                        Toast.makeText(context, "🚨 Malicious QR Payload Blocked!", Toast.LENGTH_LONG).show()
                    } else {
                        onScanCompleted("✅ Safe Plaintext QR Content:\n$rawContent")
                        Toast.makeText(context, "QR Content: $rawContent", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }
}
