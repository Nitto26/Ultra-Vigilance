package com.example.ultravigilance.ui

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.lifecycleScope
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ultravigilance.data.model.ScanVerdict
import com.example.ultravigilance.data.network.ScanApiClient
import com.example.ultravigilance.ui.theme.UltraVigilanceTheme
import com.example.ultravigilance.util.UpiLauncher
import com.example.ultravigilance.util.UpiParser
import com.example.ultravigilance.util.UpiPaymentData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed class UpiScanUiState {
    object Idle : UpiScanUiState()
    data class Scanning(val paymentData: UpiPaymentData) : UpiScanUiState()
    data class Safe(val paymentData: UpiPaymentData, val verdict: ScanVerdict) : UpiScanUiState()
    data class Threat(val paymentData: UpiPaymentData, val verdict: ScanVerdict) : UpiScanUiState()
    data class Error(val message: String, val paymentData: UpiPaymentData?) : UpiScanUiState()
}

class UpiInterceptActivity : ComponentActivity() {

    companion object {
        private const val TAG = "UpiInterceptActivity"
    }

    private var uiState by mutableStateOf<UpiScanUiState>(UpiScanUiState.Idle)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        handleIntent(intent)

        setContent {
            UltraVigilanceTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    UpiInterceptScreen(
                        modifier = Modifier.padding(innerPadding),
                        state = uiState,
                        onProceedPayment = { paymentData ->
                            proceedToPaymentApp(paymentData.rawUri)
                        },
                        onDismiss = {
                            finish()
                        },
                        onRetry = { paymentData ->
                            scanPayment(paymentData)
                        }
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val uriString = intent?.dataString ?: intent?.data?.toString()
        Log.d(TAG, "Intercepted intent with URI: $uriString")

        if (uriString.isNullOrBlank() || !UpiParser.isUpiUri(uriString)) {
            Log.w(TAG, "Invalid or missing UPI URI: $uriString")
            uiState = UpiScanUiState.Error(
                message = "Invalid UPI link. Expected 'upi://pay?...'",
                paymentData = null
            )
            return
        }

        val parsedData = UpiParser.parse(uriString)
        Log.d(TAG, "Parsed UPI payment details: $parsedData")
        scanPayment(parsedData)
    }

    private fun scanPayment(paymentData: UpiPaymentData) {
        uiState = UpiScanUiState.Scanning(paymentData)

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "Querying live backend https://mugwumpian-scottie-homely.ngrok-free.dev/scan-payment for: ${paymentData.rawUri}")
                val response = ScanApiClient.api.scanPayment(paymentData.toScanRequest())

                if (response.isSuccessful && response.body() != null) {
                    val verdict = response.body()!!
                    Log.d(TAG, "Backend returned verdict: ${verdict.verdict} (${verdict.confidence})")

                    withContext(Dispatchers.Main) {
                        if (verdict.verdict.equals("SAFE", ignoreCase = true)) {
                            uiState = UpiScanUiState.Safe(paymentData, verdict)
                            proceedToPaymentApp(paymentData.rawUri)
                        } else {
                            uiState = UpiScanUiState.Threat(paymentData, verdict)
                        }
                    }
                } else {
                    Log.w(TAG, "Backend returned non-success code: ${response.code()}")
                    withContext(Dispatchers.Main) {
                        val fallbackVerdict = ScanVerdict(
                            verdict = "FRAUD",
                            confidence = 0.90,
                            reasons = listOf(
                                "Unverified payment destination (Backend HTTP ${response.code()})",
                                "AI-Shield offline safety guard active"
                            )
                        )
                        uiState = UpiScanUiState.Threat(paymentData, fallbackVerdict)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Backend /scan-payment error: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    val fallbackVerdict = ScanVerdict(
                        verdict = "FRAUD",
                        confidence = 0.88,
                        reasons = listOf(
                            "Offline threat shield: Destination could not be verified",
                            "High risk of unauthenticated transaction"
                        )
                    )
                    uiState = UpiScanUiState.Threat(paymentData, fallbackVerdict)
                }
            }
        }
    }

    private fun proceedToPaymentApp(rawUri: String) {
        val launched = UpiLauncher.launchGenuineUpiApp(this, rawUri)
        if (!launched) {
            Toast.makeText(
                this,
                "No external UPI payment apps (GPay, PhonePe, Paytm, etc.) found.",
                Toast.LENGTH_LONG
            ).show()
        }
        finish()
    }
}

@Composable
fun UpiInterceptScreen(
    modifier: Modifier = Modifier,
    state: UpiScanUiState,
    onProceedPayment: (UpiPaymentData) -> Unit,
    onDismiss: () -> Unit,
    onRetry: (UpiPaymentData) -> Unit
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(20.dp),
        contentAlignment = Alignment.Center
    ) {
        when (state) {
            is UpiScanUiState.Idle -> {
                CircularProgressIndicator()
            }

            is UpiScanUiState.Scanning -> {
                ScanningCard(state.paymentData)
            }

            is UpiScanUiState.Safe -> {
                SafeVerdictCard(
                    paymentData = state.paymentData,
                    verdict = state.verdict,
                    onProceed = { onProceedPayment(state.paymentData) },
                    onDismiss = onDismiss
                )
            }

            is UpiScanUiState.Threat -> {
                ThreatWarningCard(
                    paymentData = state.paymentData,
                    verdict = state.verdict,
                    onDismiss = onDismiss
                )
            }

            is UpiScanUiState.Error -> {
                ErrorCard(
                    message = state.message,
                    paymentData = state.paymentData,
                    onRetry = { state.paymentData?.let { onRetry(it) } },
                    onDismiss = onDismiss
                )
            }
        }
    }
}

@Composable
private fun ScanningCard(paymentData: UpiPaymentData) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(28.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(36.dp),
                    strokeWidth = 3.dp,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "🛡 AI-Shield Threat Inspection",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Text(
                text = "Verifying UPI payment destination before opening...",
                fontSize = 13.sp,
                color = Color.Gray,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 6.dp, bottom = 20.dp)
            )

            HorizontalDivider()

            Spacer(modifier = Modifier.height(16.dp))

            PaymentDetailRow(label = "Payee", value = paymentData.displayPayee)
            if (!paymentData.pa.isNullOrBlank()) {
                PaymentDetailRow(label = "VPA", value = paymentData.pa)
            }
            PaymentDetailRow(label = "Amount", value = paymentData.displayAmount)
            if (!paymentData.tn.isNullOrBlank()) {
                PaymentDetailRow(label = "Note", value = paymentData.tn)
            }
        }
    }
}

@Composable
private fun SafeVerdictCard(
    paymentData: UpiPaymentData,
    verdict: ScanVerdict,
    onProceed: () -> Unit,
    onDismiss: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF1F8E9)),
        elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(
                shape = CircleShape,
                color = Color(0xFF2E7D32),
                modifier = Modifier.size(60.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(text = "✓", fontSize = 32.sp, color = Color.White, fontWeight = FontWeight.Bold)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Payment Verified Safe",
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF1B5E20)
            )

            val confidencePct = (verdict.confidence * 100).toInt()
            Text(
                text = "AI Confidence: $confidencePct% • Safe to proceed",
                fontSize = 13.sp,
                color = Color(0xFF388E3C),
                modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    PaymentDetailRow(label = "Payee", value = paymentData.displayPayee)
                    if (!paymentData.pa.isNullOrBlank()) {
                        PaymentDetailRow(label = "VPA", value = paymentData.pa)
                    }
                    PaymentDetailRow(label = "Amount", value = paymentData.displayAmount)
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            Button(
                onClick = onProceed,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))
            ) {
                Text(text = "Continue to Payment App", fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(text = "Cancel", color = Color.DarkGray)
            }
        }
    }
}

@Composable
private fun ThreatWarningCard(
    paymentData: UpiPaymentData,
    verdict: ScanVerdict,
    onDismiss: () -> Unit
) {
    val isFraud = verdict.verdict.equals("FRAUD", ignoreCase = true)
    val containerColor = if (isFraud) Color(0xFFFFEBEE) else Color(0xFFFFF3E0)
    val accentColor = if (isFraud) Color(0xFFC62828) else Color(0xFFE65100)
    val titleText = if (isFraud) "🚨 FRAUDULENT UPI LINK DETECTED" else "⚠ SUSPICIOUS UPI PAYMENT DETECTED"

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(
                shape = CircleShape,
                color = accentColor,
                modifier = Modifier.size(64.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(text = "!", fontSize = 36.sp, color = Color.White, fontWeight = FontWeight.Black)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = titleText,
                fontSize = 18.sp,
                fontWeight = FontWeight.ExtraBold,
                color = accentColor,
                textAlign = TextAlign.Center
            )

            val confidencePct = (verdict.confidence * 100).toInt()
            Text(
                text = "Handoff blocked by AI-Shield ($confidencePct% Risk Score)",
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = accentColor.copy(alpha = 0.85f),
                modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "TARGET PAYMENT DETAILS",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.Gray
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    PaymentDetailRow(label = "Payee Name", value = paymentData.displayPayee)
                    if (!paymentData.pa.isNullOrBlank()) {
                        PaymentDetailRow(label = "Payee VPA", value = paymentData.pa)
                    }
                    PaymentDetailRow(label = "Amount", value = paymentData.displayAmount)
                    if (!paymentData.tn.isNullOrBlank()) {
                        PaymentDetailRow(label = "Note", value = paymentData.tn)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "THREAT REASONS",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = accentColor
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    val reasons = if (verdict.reasons.isNotEmpty()) verdict.reasons else listOf("High-risk payment link detected by AI scanner")
                    for (reason in reasons) {
                        Text(
                            text = "• $reason",
                            fontSize = 13.sp,
                            lineHeight = 18.sp,
                            color = Color(0xFF37474F),
                            modifier = Modifier.padding(vertical = 2.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onDismiss,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = accentColor)
            ) {
                Text(
                    text = "🛡 Block & Return to Safety",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    color = Color.White
                )
            }
        }
    }
}

@Composable
private fun ErrorCard(
    message: String,
    paymentData: UpiPaymentData?,
    onRetry: () -> Unit,
    onDismiss: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "⚠ Interception Notice",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.error
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = message,
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(20.dp))

            if (paymentData != null) {
                Button(
                    onClick = onRetry,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text(text = "Retry Scan")
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(text = "Close")
            }
        }
    }
}

@Composable
private fun PaymentDetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            fontSize = 13.sp,
            color = Color.Gray,
            fontWeight = FontWeight.Medium
        )
        Text(
            text = value,
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
            color = Color(0xFF263238),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}
