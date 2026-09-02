package com.example.ultravigilance.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.graphics.Color

import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.app.NotificationManager
import androidx.core.app.NotificationCompat
import com.example.ultravigilance.R

import com.example.ultravigilance.data.model.ScanVerdict
import com.example.ultravigilance.receiver.SmsScanReceiver

object ShieldOverlayManager {

    private const val TAG = "ShieldOverlayManager"

    private var activeOverlayView: View? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    fun hasOverlayPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Settings.canDrawOverlays(context)
        } else {
            true
        }
    }

    /**
     * Dismisses any active overlay on screen.
     */
    fun dismissOverlay(context: Context) {
        mainHandler.post {
            try {
                if (activeOverlayView != null) {
                    val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                    windowManager.removeView(activeOverlayView)
                    activeOverlayView = null
                    Log.d(TAG, "Shield overlay dismissed.")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error removing overlay view: ${e.message}", e)
                activeOverlayView = null
            }
        }
    }

    /**
     * Section 1: Shows floating overlay for intercepted UPI Payment Threats.
     */
    fun showUpiThreatOverlay(
        context: Context,
        paymentData: UpiPaymentData,
        verdict: ScanVerdict
    ) {
        if (!hasOverlayPermission(context)) {
            Log.w(TAG, "Overlay permission not granted. Launching foreground UpiInterceptActivity fallback.")
            try {
                val intent = Intent(context, com.example.ultravigilance.ui.UpiInterceptActivity::class.java).apply {
                    data = android.net.Uri.parse(paymentData.rawUri)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                }
                context.startActivity(intent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to launch fallback UpiInterceptActivity", e)
            }
            return
        }

        mainHandler.post {
            dismissOverlay(context)

            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val overlayType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_PHONE
            }

            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                overlayType,
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                        WindowManager.LayoutParams.FLAG_DIM_BEHIND,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.CENTER
                dimAmount = 0.65f
            }

            val cardView = buildUpiCardView(context, paymentData, verdict)
            try {
                windowManager.addView(cardView, params)
                activeOverlayView = cardView
                Log.d(TAG, "UPI Threat Shield overlay added to window.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to display UPI threat overlay: ${e.message}", e)
                // Fallback to activity if WindowManager fails
                try {
                    val intent = Intent(context, com.example.ultravigilance.ui.UpiInterceptActivity::class.java).apply {
                        data = android.net.Uri.parse(paymentData.rawUri)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(intent)
                } catch (_: Exception) {}
            }
        }
    }

    /**
     * Section 2: Shows floating overlay for intercepted General Web / Phishing Links.
     */
    fun showWebThreatOverlay(
        context: Context,
        webLink: DetectedLink.Web,
        verdict: ScanVerdict
    ) {
        if (!hasOverlayPermission(context)) {
            Log.w(TAG, "Overlay permission not granted. Showing high-priority notification alert.")
            postWebAlertNotification(context, webLink, verdict)
            return
        }


        mainHandler.post {
            dismissOverlay(context)

            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val overlayType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_PHONE
            }

            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                overlayType,
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                        WindowManager.LayoutParams.FLAG_DIM_BEHIND,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.CENTER
                dimAmount = 0.65f
            }

            val cardView = buildWebCardView(context, webLink, verdict)
            try {
                windowManager.addView(cardView, params)
                activeOverlayView = cardView
                Log.d(TAG, "Web Threat Shield overlay added to window.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to display web threat overlay: ${e.message}", e)
            }
        }
    }

    private fun buildUpiCardView(
        context: Context,
        paymentData: UpiPaymentData,
        verdict: ScanVerdict
    ): View {
        val rootLayout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val margin = dpToPx(context, 20)
            setPadding(margin, margin, margin, margin)
        }

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(context, 24)
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#FFF3F3"))
                cornerRadius = dpToPx(context, 20).toFloat()
                setStroke(dpToPx(context, 2), Color.parseColor("#D32F2F"))
            }
        }

        // Title Badge
        val titleText = TextView(context).apply {
            text = "🚨 AI-SHIELD: UPI PAYMENT BLOCKED"
            textSize = 17f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#B71C1C"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dpToPx(context, 6))
        }
        container.addView(titleText)

        val riskPct = (verdict.confidence * 100).toInt()
        val subText = TextView(context).apply {
            text = "Threat Detected: $riskPct% Risk Score"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#D32F2F"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dpToPx(context, 16))
        }
        container.addView(subText)

        // Payment details box
        val detailsBox = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(context, 14)
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dpToPx(context, 12).toFloat()
            }
        }

        addDetailRow(context, detailsBox, "Payee", paymentData.displayPayee)
        if (!paymentData.pa.isNullOrBlank()) {
            addDetailRow(context, detailsBox, "VPA Address", paymentData.pa)
        }
        addDetailRow(context, detailsBox, "Amount", paymentData.displayAmount)
        if (!paymentData.tn.isNullOrBlank()) {
            addDetailRow(context, detailsBox, "Note", paymentData.tn)
        }
        container.addView(detailsBox)

        // Threat reasons box
        val reasonsBox = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(context, 12)
            setPadding(pad, pad, pad, pad)
            val topMargin = dpToPx(context, 12)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, topMargin, 0, 0) }
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dpToPx(context, 12).toFloat()
            }
        }

        val reasonsHeader = TextView(context).apply {
            text = "THREAT ANALYSIS:"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#B71C1C"))
            setPadding(0, 0, 0, dpToPx(context, 4))
        }
        reasonsBox.addView(reasonsHeader)

        val reasons = if (verdict.reasons.isNotEmpty()) verdict.reasons else listOf("Fraudulent UPI link detected by AI Threat Shield")
        for (r in reasons) {
            val rText = TextView(context).apply {
                text = "• $r"
                textSize = 12f
                setTextColor(Color.parseColor("#37474F"))
                setPadding(0, dpToPx(context, 2), 0, dpToPx(context, 2))
            }
            reasonsBox.addView(rText)
        }
        container.addView(reasonsBox)

        // Action Button
        val blockButton = Button(context).apply {
            text = "🛡 Block & Return to Safety"
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#D32F2F"))
                cornerRadius = dpToPx(context, 12).toFloat()
            }
            val topMargin = dpToPx(context, 18)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPx(context, 50)
            ).apply { setMargins(0, topMargin, 0, 0) }
            setOnClickListener {
                dismissOverlay(context)
            }
        }
        container.addView(blockButton)

        rootLayout.addView(container)
        return rootLayout
    }

    private fun buildWebCardView(
        context: Context,
        webLink: DetectedLink.Web,
        verdict: ScanVerdict
    ): View {
        val rootLayout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val margin = dpToPx(context, 20)
            setPadding(margin, margin, margin, margin)
        }

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(context, 24)
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#FFF8E1"))
                cornerRadius = dpToPx(context, 20).toFloat()
                setStroke(dpToPx(context, 2), Color.parseColor("#FF8F00"))
            }
        }

        // Title Badge
        val titleText = TextView(context).apply {
            text = "🌐 AI-SHIELD: SUSPICIOUS LINK INTERCEPTED"
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#E65100"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dpToPx(context, 6))
        }
        container.addView(titleText)

        val riskPct = (verdict.confidence * 100).toInt()
        val subText = TextView(context).apply {
            text = "Phishing / Unverified Web Link ($riskPct% Risk Score)"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#E65100"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dpToPx(context, 16))
        }
        container.addView(subText)

        // Link details box
        val detailsBox = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(context, 14)
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dpToPx(context, 12).toFloat()
            }
        }

        addDetailRow(context, detailsBox, "Target Host", webLink.host)
        addDetailRow(context, detailsBox, "URL", webLink.url)
        if (webLink.isShortener) {
            addDetailRow(context, detailsBox, "Type", "URL Shortener / Redirector")
        }
        container.addView(detailsBox)

        // Threat reasons box
        val reasonsBox = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(context, 12)
            setPadding(pad, pad, pad, pad)
            val topMargin = dpToPx(context, 12)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, topMargin, 0, 0) }
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dpToPx(context, 12).toFloat()
            }
        }

        val reasonsHeader = TextView(context).apply {
            text = "RISK BREAKDOWN:"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#E65100"))
            setPadding(0, 0, 0, dpToPx(context, 4))
        }
        reasonsBox.addView(reasonsHeader)

        val reasons = if (verdict.reasons.isNotEmpty()) verdict.reasons else listOf("Potential phishing or fraudulent website detected")
        for (r in reasons) {
            val rText = TextView(context).apply {
                text = "• $r"
                textSize = 12f
                setTextColor(Color.parseColor("#37474F"))
                setPadding(0, dpToPx(context, 2), 0, dpToPx(context, 2))
            }
            reasonsBox.addView(rText)
        }
        container.addView(reasonsBox)

        // Action Button
        val blockButton = Button(context).apply {
            text = "🛡 Block Link Access"
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#E65100"))
                cornerRadius = dpToPx(context, 12).toFloat()
            }
            val topMargin = dpToPx(context, 18)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPx(context, 50)
            ).apply { setMargins(0, topMargin, 0, 0) }
            setOnClickListener {
                dismissOverlay(context)
            }
        }
        container.addView(blockButton)

        rootLayout.addView(container)
        return rootLayout
    }

    private fun addDetailRow(context: Context, container: LinearLayout, label: String, value: String) {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dpToPx(context, 3), 0, dpToPx(context, 3))
        }

        val labelView = TextView(context).apply {
            text = "$label: "
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#546E7A"))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f)
        }

        val valueView = TextView(context).apply {
            text = value
            textSize = 12f
            setTextColor(Color.parseColor("#263238"))
            maxLines = 2
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 2.0f)
        }

        row.addView(labelView)
        row.addView(valueView)
        container.addView(row)
    }

    private fun dpToPx(context: Context, dp: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            context.resources.displayMetrics
        ).toInt()
    }

    private fun postWebAlertNotification(
        context: Context,
        webLink: DetectedLink.Web,
        verdict: ScanVerdict
    ) {
        try {
            SmsScanReceiver.createChannelIfNeeded(context)
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val reasonsText = verdict.reasons.firstOrNull() ?: "Phishing or malicious website detected"
            val riskPct = (verdict.confidence * 100).toInt()

            val notification = NotificationCompat.Builder(context, SmsScanReceiver.CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle("🚨 Suspicious Link Intercepted: ${webLink.host}")
                .setContentText("Threat detected ($riskPct% risk): $reasonsText")
                .setStyle(
                    NotificationCompat.BigTextStyle()
                        .bigText("Target: ${webLink.url}\n\nHost: ${webLink.host}\n\n⚠ Risk: $reasonsText ($riskPct% score)")
                )
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setDefaults(NotificationCompat.DEFAULT_ALL)
                .setAutoCancel(true)
                .build()

            notificationManager.notify(webLink.url.hashCode(), notification)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to post web threat notification: ${e.message}", e)
        }
    }
}

