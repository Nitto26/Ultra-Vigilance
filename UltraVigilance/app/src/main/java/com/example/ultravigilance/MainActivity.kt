package com.example.ultravigilance

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager
import android.widget.Toast
import com.example.ultravigilance.data.network.ScanApiClient
import androidx.activity.ComponentActivity

import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.example.ultravigilance.data.model.ScanVerdict
import com.example.ultravigilance.receiver.SmsScanReceiver
import com.example.ultravigilance.service.ThreatShieldAccessibilityService
import com.example.ultravigilance.ui.UpiInterceptActivity
import com.example.ultravigilance.ui.theme.UltraVigilanceTheme
import com.example.ultravigilance.util.DetectedLink
import com.example.ultravigilance.util.ShieldOverlayManager
import com.example.ultravigilance.util.UpiParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    companion object {
        private const val REQUEST_CODE_PERMISSIONS = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request SMS & Notification permissions on startup
        val permissionsToRequest = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.RECEIVE_SMS)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.READ_SMS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            permissionsToRequest.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        if (permissionsToRequest.isNotEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                permissionsToRequest.toTypedArray(),
                REQUEST_CODE_PERMISSIONS
            )
        }

        enableEdgeToEdge()
        setContent {
            UltraVigilanceTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    DashboardScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

fun isNotificationListenerEnabled(context: Context): Boolean {
    val enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(context)
    return enabledPackages.contains(context.packageName)
}

fun isAccessibilityServiceEnabled(context: Context): Boolean {
    val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
    val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
    val myServiceName = ThreatShieldAccessibilityService::class.java.name
    return enabledServices.any { it.resolveInfo.serviceInfo.name == myServiceName || it.id.contains(context.packageName) }
}

fun isOverlayPermissionEnabled(context: Context): Boolean {
    return ShieldOverlayManager.hasOverlayPermission(context)
}

fun scanLatestInboxSms(context: Context): Pair<String, String>? {
    return try {
        val cursor = context.contentResolver.query(
            Telephony.Sms.Inbox.CONTENT_URI,
            arrayOf(Telephony.Sms.Inbox.ADDRESS, Telephony.Sms.Inbox.BODY),
            null,
            null,
            "${Telephony.Sms.Inbox.DATE} DESC"
        )
        cursor?.use {
            if (it.moveToFirst()) {
                val address = it.getString(it.getColumnIndexOrThrow(Telephony.Sms.Inbox.ADDRESS)) ?: "Unknown Number"
                val body = it.getString(it.getColumnIndexOrThrow(Telephony.Sms.Inbox.BODY)) ?: ""
                Pair(address, body)
            } else null
        }
    } catch (e: Exception) {
        null
    }
}

@Composable
fun DashboardScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var isListenerEnabled by remember { mutableStateOf(isNotificationListenerEnabled(context)) }
    var isAccessibilityEnabled by remember { mutableStateOf(isAccessibilityServiceEnabled(context)) }
    var isOverlayEnabled by remember { mutableStateOf(isOverlayPermissionEnabled(context)) }
    var isScanning by remember { mutableStateOf(false) }

    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    androidx.compose.runtime.DisposableEffect(lifecycleOwner) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
                isListenerEnabled = isNotificationListenerEnabled(context)
                isAccessibilityEnabled = isAccessibilityServiceEnabled(context)
                isOverlayEnabled = isOverlayPermissionEnabled(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LaunchedEffect(Unit) {
        isListenerEnabled = isNotificationListenerEnabled(context)
        isAccessibilityEnabled = isAccessibilityServiceEnabled(context)
        isOverlayEnabled = isOverlayPermissionEnabled(context)
    }

    val hasMandatoryPermissions = isAccessibilityEnabled && isOverlayEnabled

    if (!hasMandatoryPermissions) {
        MandatoryPermissionsLockScreen(
            modifier = modifier,
            isAccessibilityEnabled = isAccessibilityEnabled,
            isOverlayEnabled = isOverlayEnabled,
            onRefresh = {
                isListenerEnabled = isNotificationListenerEnabled(context)
                isAccessibilityEnabled = isAccessibilityServiceEnabled(context)
                isOverlayEnabled = isOverlayPermissionEnabled(context)
            }
        )
        return
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = "🛡 UltraVigilance",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary
        )

        Text(
            text = "Real-Time AI Threat Protection & Interceptor",
            fontSize = 13.sp,
            color = Color.Gray,
            modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
        )

        // Protection Overview Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Text(
                    text = "SHIELD PROTECTION LAYERS",
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(10.dp))

                StatusRow(
                    label = "1. SMS & RCS Notification Scanner",
                    isActive = isListenerEnabled
                )
                StatusRow(
                    label = "2. Universal Screen Tap Shield (UPI)",
                    isActive = isAccessibilityEnabled
                )
                StatusRow(
                    label = "3. Universal Web Link Interceptor",
                    isActive = isAccessibilityEnabled
                )
                StatusRow(
                    label = "4. Floating Security Overlay",
                    isActive = isOverlayEnabled
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Action Buttons for Permissions
        if (!isAccessibilityEnabled) {
            Button(
                onClick = {
                    try {
                        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    } catch (e: Exception) {
                        Toast.makeText(context, "Open Settings -> Accessibility -> UltraVigilance", Toast.LENGTH_LONG).show()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC62828))
            ) {
                Text(
                    text = "⚡ Enable Accessibility Tap Interceptor",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
        }

        if (!isOverlayEnabled) {
            Button(
                onClick = {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        try {
                            val intent = Intent(
                                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                Uri.parse("package:${context.packageName}")
                            ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                            context.startActivity(intent)
                        } catch (e: Exception) {
                            try {
                                val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                context.startActivity(intent)
                            } catch (ex: Exception) {
                                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")).apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                context.startActivity(intent)
                            }
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100))
            ) {
                Text(
                    text = "🪟 Allow Display Over Other Apps",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
        }

        // Direct shortcut to unlock Android 13/14/15/16 Restricted Settings
        OutlinedButton(
            onClick = {
                try {
                    val intent = Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:${context.packageName}")
                    ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                    context.startActivity(intent)
                } catch (e: Exception) {
                    Toast.makeText(context, "Open Settings -> Apps -> UltraVigilance", Toast.LENGTH_SHORT).show()
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = "⚙ Unlock Restricted Settings (App Info)",
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
        Spacer(modifier = Modifier.height(10.dp))

        if (!isListenerEnabled) {
            Button(
                onClick = {
                    val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(intent)
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0))
            ) {
                Text(
                    text = "🔔 Enable RCS Message Access",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
        }


        Spacer(modifier = Modifier.height(6.dp))
        HorizontalDivider()
        Spacer(modifier = Modifier.height(14.dp))

        Text(
            text = "LIVE BACKEND & THREAT SIMULATORS",
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            color = Color.Gray,
            modifier = Modifier.align(Alignment.Start)
        )

        Spacer(modifier = Modifier.height(10.dp))

        // 0. Live Backend Health Test
        Button(
            onClick = {
                coroutineScope.launch {
                    try {
                        val req = com.example.ultravigilance.data.model.ScanPaymentRequest(

                            upiId = "fraud_test@okaxis",
                            gatewayUrl = "upi://pay?pa=fraud_test@okaxis&am=500"
                        )
                        val res = ScanApiClient.api.scanPayment(req)
                        if (res.isSuccessful && res.body() != null) {
                            val body = res.body()!!
                            Toast.makeText(context, "✅ Live Backend Hit: ${body.verdict} (Risk: ${body.confidence})\n${body.detail ?: "Verified"}", Toast.LENGTH_LONG).show()
                        } else {
                            Toast.makeText(context, "❌ HTTP Error ${res.code()}", Toast.LENGTH_LONG).show()
                        }
                    } catch (e: Exception) {
                        Toast.makeText(context, "❌ Connection failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))
        ) {
            Text(
                text = "🌐 Test Live Backend API Hit",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }
        Spacer(modifier = Modifier.height(10.dp))

        // 1. Test UPI Interception

        Button(
            onClick = {
                val demoUpiUri = "upi://pay?pa=fake_lottery_claim@okaxis&pn=Prize%20Claim%20Support&am=2500.00&cu=INR&tn=Processing%20Fee"
                val parsed = UpiParser.parse(demoUpiUri)

                if (ShieldOverlayManager.hasOverlayPermission(context)) {
                    val verdict = ScanVerdict(
                        verdict = "FRAUD",
                        confidence = 0.96,
                        reasons = listOf(
                            "High-risk UPI handle detected: Known phishing pattern",
                            "Unverified payee identity mismatching banking records",
                            "Payment address reported in multiple fraud complaints"
                        )
                    )
                    ShieldOverlayManager.showUpiThreatOverlay(context, parsed, verdict)
                } else {
                    val intent = Intent(context, UpiInterceptActivity::class.java).apply {
                        data = Uri.parse(demoUpiUri)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(intent)
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFD32F2F))
        ) {
            Text(text = "🚨 Simulate UPI Fraud Link Tap", fontSize = 14.sp, fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(8.dp))

        // 2. Test Web Phishing Interception
        Button(
            onClick = {
                val demoWeb = DetectedLink.Web(
                    url = "https://bit.ly/bank-account-kyc-update-alert",
                    host = "bit.ly",
                    isShortener = true,
                    originalText = "https://bit.ly/bank-account-kyc-update-alert"
                )
                val verdict = ScanVerdict(
                    verdict = "FRAUD",
                    confidence = 0.94,
                    reasons = listOf(
                        "Masked shortlink redirects to unverified banking credential harvester",
                        "High urgency phishing pretext detected",
                        "Domain flagged by AI Threat Defense"
                    )
                )
                if (ShieldOverlayManager.hasOverlayPermission(context)) {
                    ShieldOverlayManager.showWebThreatOverlay(context, demoWeb, verdict)
                } else {
                    Toast.makeText(context, "Please allow 'Display Over Other Apps' first", Toast.LENGTH_SHORT).show()
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100))
        ) {
            Text(text = "🌐 Simulate Web Phishing Link Tap", fontSize = 14.sp, fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(8.dp))

        // 3. Scan Inbox SMS
        OutlinedButton(
            onClick = {
                if (isScanning) return@OutlinedButton
                val latest = scanLatestInboxSms(context)
                if (latest != null) {
                    val (sender, body) = latest
                    isScanning = true
                    Toast.makeText(context, "Scanning with AI backend...", Toast.LENGTH_SHORT).show()
                    coroutineScope.launch(Dispatchers.IO) {
                        val verdict = SmsScanReceiver.scanMessage(sender, body)
                        withContext(Dispatchers.Main) {
                            isScanning = false
                            if (verdict.verdict == "FRAUD" || verdict.verdict == "SUSPICIOUS") {
                                SmsScanReceiver.showAlertNotification(context, sender, body, verdict)
                                Toast.makeText(context, "Threat detected (${verdict.verdict})!", Toast.LENGTH_LONG).show()
                            } else {
                                Toast.makeText(context, "Message verified: SAFE", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } else {
                    Toast.makeText(context, "No SMS messages found in inbox", Toast.LENGTH_SHORT).show()
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = if (isScanning) "⏳ Scanning..." else "📥 Scan Most Recent SMS",
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
fun StatusRow(label: String, isActive: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        Text(
            text = if (isActive) "ACTIVE" else "DISABLED",
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = if (isActive) Color(0xFF2E7D32) else Color(0xFFC62828)
        )
    }
}

@Composable
fun MandatoryPermissionsLockScreen(
    modifier: Modifier = Modifier,
    isAccessibilityEnabled: Boolean,
    isOverlayEnabled: Boolean,
    onRefresh: () -> Unit
) {
    val context = LocalContext.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = "🛡🔒",
            fontSize = 48.sp
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "Protection Permissions Required",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = Color(0xFFC62828),
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "UltraVigilance strictly requires the following 2 system permissions to intercept malicious links and block fraud. If these permissions are denied, the app cannot function.",
            fontSize = 13.sp,
            color = Color.Gray,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 8.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Card 1: Display Over Other Apps
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isOverlayEnabled) Color(0xFFE8F5E9) else Color(0xFFFFEBEE)
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "1. Display Over Other Apps",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = Color.Black
                    )
                    Text(
                        text = if (isOverlayEnabled) "✅ GRANTED" else "❌ REQUIRED",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isOverlayEnabled) Color(0xFF2E7D32) else Color(0xFFC62828)
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Required to display instant floating warning overlays over WhatsApp, SMS, and Chrome when a scam is detected.",
                    fontSize = 12.sp,
                    color = Color.DarkGray
                )

                if (!isOverlayEnabled) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                try {
                                    val intent = Intent(
                                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                        Uri.parse("package:${context.packageName}")
                                    ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    try {
                                        val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        }
                                        context.startActivity(intent)
                                    } catch (ex: Exception) {
                                        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")).apply {
                                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        }
                                        context.startActivity(intent)
                                    }
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100))
                    ) {
                        Text("Grant Overlay Permission", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Card 2: Accessibility Service
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isAccessibilityEnabled) Color(0xFFE8F5E9) else Color(0xFFFFEBEE)
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "2. Accessibility Service",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = Color.Black
                    )
                    Text(
                        text = if (isAccessibilityEnabled) "✅ GRANTED" else "❌ REQUIRED",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isAccessibilityEnabled) Color(0xFF2E7D32) else Color(0xFFC62828)
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Required to inspect on-screen taps in WhatsApp and messaging apps to catch malicious UPI transfers and phishing links before execution.",
                    fontSize = 12.sp,
                    color = Color.DarkGray
                )

                if (!isAccessibilityEnabled) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            try {
                                val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                context.startActivity(intent)
                            } catch (e: Exception) {
                                Toast.makeText(context, "Open Settings -> Accessibility -> UltraVigilance", Toast.LENGTH_LONG).show()
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC62828))
                    ) {
                        Text("Enable Accessibility Service", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Android 13/14/15/16 Restricted Settings Helper
        OutlinedButton(
            onClick = {
                try {
                    val intent = Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:${context.packageName}")
                    ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                    context.startActivity(intent)
                } catch (e: Exception) {
                    Toast.makeText(context, "Open Settings -> Apps -> UltraVigilance", Toast.LENGTH_SHORT).show()
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp)
        ) {
            Text("⚙ Can't enable? (Unlock Restricted Settings in App Info)", fontSize = 12.sp)
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Verify & Unlock Button
        Button(
            onClick = {
                onRefresh()
                val granted = isAccessibilityServiceEnabled(context) && isOverlayPermissionEnabled(context)
                if (granted) {
                    Toast.makeText(context, "✅ All required permissions granted! Protection active.", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(
                        context,
                        "⚠ Both permissions must be granted to continue.",
                        Toast.LENGTH_LONG
                    ).show()
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1B5E20))
        ) {
            Text("🔄 Verify & Unlock App", fontSize = 15.sp, fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(10.dp))

        OutlinedButton(
            onClick = {
                (context as? android.app.Activity)?.finishAffinity()
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(46.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Exit App", color = Color.Gray, fontSize = 13.sp)
        }

        Spacer(modifier = Modifier.height(20.dp))
    }
}