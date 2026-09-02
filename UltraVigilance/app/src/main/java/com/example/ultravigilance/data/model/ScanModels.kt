package com.example.ultravigilance.data.model

import com.google.gson.annotations.SerializedName

// Request body sent to /scan-document
data class ScanDocumentRequest(
    val url: String
)

// Response received from /scan-document
data class ScanDocumentResponse(
    @SerializedName("status_code")
    val statusCode: Int? = null,
    val detail: String? = null,
    val verdict: String? = null,
    val confidence: Double? = null,
    val reasons: List<String>? = null
)

// Request body sent to /scan-sms
data class ScanSmsRequest(
    val sender: String,
    val message: String
)

// Request body sent to /scan-payment
data class ScanPaymentRequest(
    @SerializedName("upi_id")
    val upiId: String = "",
    @SerializedName("gateway_url")
    val gatewayUrl: String = "",
    @SerializedName("upi_uri")
    val upiUri: String = "",
    val pa: String? = null,
    val pn: String? = null,
    val am: String? = null,
    val cu: String? = null,
    val tn: String? = null
)

// Shared verdict schema
data class ScanVerdict(
    val verdict: String,       // "SAFE" | "SUSPICIOUS" | "FRAUD" | "UNKNOWN"
    val confidence: Double,
    val reasons: List<String> = emptyList(),
    val detail: String? = null
)


