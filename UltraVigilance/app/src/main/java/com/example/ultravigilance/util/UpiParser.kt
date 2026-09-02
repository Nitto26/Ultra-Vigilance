package com.example.ultravigilance.util

import android.net.Uri
import com.example.ultravigilance.data.model.ScanPaymentRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Structured representation of a UPI payment intent URI.
 */
data class UpiPaymentData(
    val rawUri: String,
    val pa: String? = null,  // Payee VPA address (e.g., merchant@okhdfcbank)
    val pn: String? = null,  // Payee Name (e.g., Merchant Store)
    val am: String? = null,  // Transaction Amount (e.g., 500.00)
    val cu: String? = null,  // Currency (defaults to INR)
    val tn: String? = null,  // Transaction Note / Description
    val mc: String? = null,  // Merchant Code
    val tr: String? = null,  // Transaction Reference ID
    val url: String? = null  // Reference URL
) {
    /**
     * Converts to backend API request payload.
     */
    fun toScanRequest(): ScanPaymentRequest {
        return ScanPaymentRequest(
            upiId = pa ?: "",
            gatewayUrl = rawUri,
            upiUri = rawUri,
            pa = pa,
            pn = pn,
            am = am,
            cu = cu ?: "INR",
            tn = tn
        )
    }


    /**
     * Display title for UI previews.
     */
    val displayPayee: String
        get() = pn?.takeIf { it.isNotBlank() } ?: pa?.takeIf { it.isNotBlank() } ?: "Unknown Payee"

    /**
     * Formatted amount with currency.
     */
    val displayAmount: String
        get() = if (!am.isNullOrBlank()) {
            val currencySymbol = if (cu == null || cu.equals("INR", ignoreCase = true)) "₹" else "$cu "
            "$currencySymbol$am"
        } else {
            "Amount unspecified"
        }
}

/**
 * Parser for `upi://pay?...` URIs.
 */
object UpiParser {

    /**
     * Checks if the given URI string or scheme is a UPI payment URI.
     */
    fun isUpiUri(uriString: String?): Boolean {
        if (uriString.isNullOrBlank()) return false
        val trimmed = uriString.trim()
        return trimmed.startsWith("upi://", ignoreCase = true)
    }

    /**
     * Parses a raw UPI URI string into a [UpiPaymentData] object.
     */
    fun parse(rawUriString: String): UpiPaymentData {
        val trimmed = rawUriString.trim()
        val queryParams = mutableMapOf<String, String>()

        try {
            val uri = Uri.parse(trimmed)
            val query = uri.query

            if (!query.isNullOrBlank()) {
                val pairs = query.split("&")
                for (pair in pairs) {
                    val idx = pair.indexOf("=")
                    if (idx > 0) {
                        val key = decode(pair.substring(0, idx))
                        val value = if (idx < pair.length - 1) decode(pair.substring(idx + 1)) else ""
                        queryParams[key.lowercase()] = value
                    } else if (pair.isNotEmpty()) {
                        queryParams[decode(pair).lowercase()] = ""
                    }
                }
            } else {
                // Fallback custom query parameter parser if Uri.query is null
                parseQueryFallback(trimmed, queryParams)
            }
        } catch (e: Exception) {
            parseQueryFallback(trimmed, queryParams)
        }

        return UpiPaymentData(
            rawUri = trimmed,
            pa = queryParams["pa"],
            pn = queryParams["pn"],
            am = queryParams["am"],
            cu = queryParams["cu"] ?: "INR",
            tn = queryParams["tn"],
            mc = queryParams["mc"],
            tr = queryParams["tr"],
            url = queryParams["url"]
        )
    }

    private fun parseQueryFallback(uriString: String, params: MutableMap<String, String>) {
        val queryIdx = uriString.indexOf("?")
        if (queryIdx != -1 && queryIdx < uriString.length - 1) {
            val queryString = uriString.substring(queryIdx + 1)
            val pairs = queryString.split("&")
            for (pair in pairs) {
                val idx = pair.indexOf("=")
                if (idx > 0) {
                    val key = decode(pair.substring(0, idx))
                    val value = if (idx < pair.length - 1) decode(pair.substring(idx + 1)) else ""
                    params[key.lowercase()] = value
                }
            }
        }
    }

    private fun decode(value: String): String {
        return try {
            URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        } catch (e: Exception) {
            value
        }
    }
}
