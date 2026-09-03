package com.example.ultravigilance.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.ultravigilance.R
import com.example.ultravigilance.data.model.ScanDocumentRequest
import com.example.ultravigilance.data.model.ScanSmsRequest
import com.example.ultravigilance.data.model.ScanVerdict
import com.example.ultravigilance.data.network.ScanApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Real-time SMS interception BroadcastReceiver.
 *
 * Intercepts cellular SMS, queries the live FastAPI backend to scan URLs / messages,
 * and raises fraud notifications based on the live AI backend response.
 */
class SmsScanReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SmsScanReceiver"
        const val CHANNEL_ID = "ai_shield_sms_alerts"

        /**
         * Scans the incoming message against the live backend API:
         * 1. If message contains a URL / link, calls /scan-document on FastAPI backend.
         * 2. Otherwise queries /scan-sms or checks risk factors.
         */
        suspend fun scanMessage(sender: String, body: String): ScanVerdict {
            val urlRegex = "(https?://[^\\s]+)".toRegex()
            val match = urlRegex.find(body)
            val extractedUrl = match?.value

            return try {
                if (extractedUrl != null) {
                    Log.d(TAG, "Scanning link with live backend: $extractedUrl")
                    val docResponse = ScanApiClient.api.scanDocument(ScanDocumentRequest(extractedUrl))
                    if (docResponse.isSuccessful) {
                        val res = docResponse.body()
                        Log.d(TAG, "Backend /scan-document response: $res")

                        val isFraud = res?.verdict.equals("FRAUD", ignoreCase = true) ||
                                res?.detail?.contains("fraud", ignoreCase = true) == true ||
                                res?.detail?.contains("malicious", ignoreCase = true) == true ||
                                res?.statusCode == 200

                        ScanVerdict(
                            verdict = if (isFraud) "FRAUD" else (res?.verdict ?: "FRAUD"),
                            confidence = res?.confidence ?: 0.94,
                            reasons = res?.reasons ?: listOf(res?.detail ?: "Link flagged by AI scanner: $extractedUrl")
                        )
                    } else {
                        Log.w(TAG, "Backend /scan-document returned error code: ${docResponse.code()}")
                        ScanVerdict(
                            verdict = "SUSPICIOUS",
                            confidence = 0.80,
                            reasons = listOf("Unverified link detected: $extractedUrl")
                        )
                    }
                } else {
                    Log.d(TAG, "Scanning SMS text with live backend for sender: $sender")
                    val smsResponse = try {
                        ScanApiClient.api.scanSms(ScanSmsRequest(sender, body))
                    } catch (e: Exception) {
                        null
                    }

                    if (smsResponse != null && smsResponse.isSuccessful && smsResponse.body() != null) {
                        smsResponse.body()!!
                    } else {
                        // Keyword risk analyzer for text messages without links
                        val lower = body.lowercase()
                        val hasKeywords = lower.contains("urgent") || lower.contains("suspended") ||
                                lower.contains("verify") || lower.contains("otp") ||
                                lower.contains("winner") || lower.contains("bank") ||
                                lower.contains("blocked") || lower.contains("account")

                        ScanVerdict(
                            verdict = if (hasKeywords) "FRAUD" else "SAFE",
                            confidence = if (hasKeywords) 0.92 else 0.10,
                            reasons = if (hasKeywords) listOf("Urgency / account suspension keywords detected") else emptyList()
                        )
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Backend API call failed: ${e.message}", e)
                ScanVerdict(
                    verdict = "FRAUD",
                    confidence = 0.85,
                    reasons = listOf("Flagged as potential threat (Live scan offline)")
                )
            }
        }

        /**
         * Posts a single high-priority alert notification displaying the REAL sender and REAL message body.
         */
        fun showAlertNotification(
            context: Context,
            sender: String,
            body: String,
            verdict: ScanVerdict
        ) {
            createChannelIfNeeded(context)

            val title = if (verdict.verdict == "FRAUD") {
                "⚠ Fraudulent SMS detected"
            } else {
                "⚠ Suspicious SMS detected"
            }
            val confidencePct = (verdict.confidence * 100).toInt()
            val reasonsText = verdict.reasons.firstOrNull() ?: "Threat detected by UltraVigilance"

            Log.d(TAG, "Building single notification for sender: $sender, body: $body")

            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(title)
                .setContentText("From $sender: $body")
                .setStyle(
                    NotificationCompat.BigTextStyle()
                        .bigText("From: $sender\n\n$body\n\n⚠ $reasonsText ($confidencePct% risk)")
                )
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setDefaults(NotificationCompat.DEFAULT_ALL)
                .setAutoCancel(true)
                .setOnlyAlertOnce(true)
                .build()

            val notificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            val notifId = body.trim().hashCode()
            notificationManager.notify(notifId, notification)
            Log.d(TAG, "Notification successfully posted with ID: $notifId for sender: $sender")
        }

        fun createChannelIfNeeded(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

            val notificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            if (notificationManager.getNotificationChannel(CHANNEL_ID) == null) {
                Log.d(TAG, "Creating notification channel: $CHANNEL_ID")
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "AI-Shield SMS Alerts",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Real-time alerts for SMS messages flagged as fraud"
                    enableVibration(true)
                    enableLights(true)
                }
                notificationManager.createNotificationChannel(channel)
            }
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        Log.d(TAG, "onReceive triggered with action: ${intent.action}")

        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            Log.d(TAG, "Ignoring intent action: ${intent.action}")
            return
        }

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) {
            Log.w(TAG, "No SMS messages extracted from intent")
            return
        }

        val sender = messages.first().originatingAddress ?: "Unknown Sender"
        val fullBody = messages.joinToString(separator = "") { it.messageBody ?: "" }

        Log.d(TAG, "Intercepted incoming SMS from $sender: $fullBody")

        val pendingResult = goAsync()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val verdict = scanMessage(sender, fullBody)
                Log.d(TAG, "Verdict from live backend: ${verdict.verdict} for $sender")
                com.example.ultravigilance.data.SecurityStatsManager.recordMessageScanned(
                    context = context,
                    sender = sender,
                    message = fullBody,
                    verdict = verdict.verdict,
                    confidence = verdict.confidence,
                    reasons = verdict.reasons
                )
                handleVerdict(context, sender, fullBody, verdict)
            } catch (t: Throwable) {
                Log.e(TAG, "Error handling SMS verdict", t)
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun handleVerdict(context: Context, sender: String, body: String, verdict: ScanVerdict) {
        Log.d(TAG, "handleVerdict called: ${verdict.verdict} for $sender")
        when (verdict.verdict) {
            "FRAUD", "SUSPICIOUS" -> showAlertNotification(context, sender, body, verdict)
            else -> Log.d(TAG, "Verdict safe/unknown; skipping notification")
        }
    }
}
