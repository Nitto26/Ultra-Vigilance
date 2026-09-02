package com.example.ultravigilance.util

import android.net.Uri
import android.text.Spanned
import android.text.style.URLSpan
import java.net.URI
import java.util.regex.Pattern

sealed class DetectedLink {
    data class Upi(
        val paymentData: UpiPaymentData,
        val originalText: String,
        val detectionSource: String // "SCHEME" | "VENDOR_LINK" | "VPA_HANDLE"
    ) : DetectedLink()

    data class Web(
        val url: String,
        val host: String,
        val isShortener: Boolean,
        val originalText: String
    ) : DetectedLink()
}

object LinkClassifier {

    private val UPI_SCHEME_REGEX = Pattern.compile(
        "(upi://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+)",
        Pattern.CASE_INSENSITIVE
    )

    private val UPI_VPA_REGEX = Pattern.compile(
        "\\b([a-zA-Z0-9.\\-_]{2,100}@(okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|apl|upi|postbank|sbi|icici|hdfcbank|barodampay|federal|allbank|indus|pnb|axisbank|kotak))\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val URL_REGEX = Pattern.compile(
        "(https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+)",
        Pattern.CASE_INSENSITIVE
    )

    private val SHORTENER_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rb.gy"
    )

    private val UPI_VENDOR_DOMAINS = setOf(
        "gpay.app.goo.gl", "phon.pe", "p.paytm.me", "pay.google.com"
    )

    private val DOMAIN_REGEX = Pattern.compile(
        "\\b((?:gpay\\.app\\.goo\\.gl|phon\\.pe|p\\.paytm\\.me|pay\\.google\\.com|bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd)[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)",
        Pattern.CASE_INSENSITIVE
    )


    /**
     * Inspects a CharSequence or clicked content to classify into UPI or Web Link.
     */
    fun classify(rawCharSequence: CharSequence?): DetectedLink? {
        if (rawCharSequence == null || rawCharSequence.isBlank()) return null

        // 1. Check for URLSpan in Spannable text (common in WhatsApp & SMS bubbles)
        if (rawCharSequence is Spanned) {
            val urlSpans = rawCharSequence.getSpans(0, rawCharSequence.length, URLSpan::class.java)
            for (span in urlSpans) {
                val spanUrl = span.url
                if (!spanUrl.isNullOrBlank()) {
                    val result = classifyString(spanUrl)
                    if (result != null) return result
                }
            }
        }

        return classifyString(rawCharSequence.toString())
    }

    private fun classifyString(rawText: String): DetectedLink? {
        val trimmed = rawText.trim()

        // 1. Search for upi:// URI anywhere in the string
        val upiMatcher = UPI_SCHEME_REGEX.matcher(trimmed)
        if (upiMatcher.find()) {
            val matchedUpi = cleanUrl(upiMatcher.group(1) ?: trimmed)
            val parsed = UpiParser.parse(matchedUpi)
            return DetectedLink.Upi(
                paymentData = parsed,
                originalText = matchedUpi,
                detectionSource = "SCHEME"
            )
        }

        // 2. Search for HTTP/HTTPS URLs anywhere in the string
        val urlMatcher = URL_REGEX.matcher(trimmed)
        if (urlMatcher.find()) {
            val matchedUrl = cleanUrl(urlMatcher.group(1) ?: trimmed)
            val host = extractHost(matchedUrl).lowercase()

            // 2a. Known UPI vendor shortlink / gateway
            if (UPI_VENDOR_DOMAINS.contains(host) || matchedUrl.contains("upi://", ignoreCase = true)) {
                val parsed = UpiParser.parse(matchedUrl)
                return DetectedLink.Upi(
                    paymentData = parsed,
                    originalText = matchedUrl,
                    detectionSource = "VENDOR_LINK"
                )
            }

            // 2b. General Web Link
            val isShortener = SHORTENER_DOMAINS.contains(host)
            return DetectedLink.Web(
                url = matchedUrl,
                host = host,
                isShortener = isShortener,
                originalText = matchedUrl
            )
        }

        // 2c. Check for domain-style vendor or web links without scheme (e.g. gpay.app.goo.gl/... or bit.ly/...)
        val domainMatcher = DOMAIN_REGEX.matcher(trimmed)
        if (domainMatcher.find()) {
            val matchedDomain = cleanUrl(domainMatcher.group(1) ?: trimmed)
            val fullUrl = "https://$matchedDomain"
            val host = extractHost(fullUrl).lowercase()

            if (UPI_VENDOR_DOMAINS.contains(host)) {
                val parsed = UpiParser.parse(fullUrl)
                return DetectedLink.Upi(
                    paymentData = parsed,
                    originalText = matchedDomain,
                    detectionSource = "VENDOR_LINK"
                )
            }

            return DetectedLink.Web(
                url = fullUrl,
                host = host,
                isShortener = SHORTENER_DOMAINS.contains(host),
                originalText = matchedDomain
            )
        }

        // 3. Search for standalone UPI VPA handles (e.g. "Send money to fraudster@okaxis")
        val vpaMatcher = UPI_VPA_REGEX.matcher(trimmed)

        if (vpaMatcher.find()) {
            val vpa = vpaMatcher.group(1)
            val mockUpiUri = "upi://pay?pa=$vpa&pn=${vpa?.substringBefore('@') ?: "Payee"}"
            val parsed = UpiParser.parse(mockUpiUri)
            return DetectedLink.Upi(
                paymentData = parsed,
                originalText = trimmed,
                detectionSource = "VPA_HANDLE"
            )
        }

        return null
    }

    private fun cleanUrl(url: String): String {
        return url.trimEnd('.', ',', ';', ')', ']', '>', '"', '\'')
    }

    private fun extractHost(url: String): String {
        return try {
            val uri = URI(url)
            uri.host ?: Uri.parse(url).host ?: url
        } catch (e: Exception) {
            try {
                Uri.parse(url).host ?: url
            } catch (ex: Exception) {
                url
            }
        }
    }
}
