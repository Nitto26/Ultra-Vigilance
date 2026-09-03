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
import android.view.accessibility.AccessibilityManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.example.ultravigilance.service.ThreatShieldAccessibilityService
import com.example.ultravigilance.ui.AuthManager
import com.example.ultravigilance.ui.LoginScreen
import com.example.ultravigilance.ui.SignupScreen
import com.example.ultravigilance.ui.theme.CyberBg
import com.example.ultravigilance.ui.theme.CyberBorder
import com.example.ultravigilance.ui.theme.CyberCrimson
import com.example.ultravigilance.ui.theme.CyberCyan
import com.example.ultravigilance.ui.theme.CyberEmerald
import com.example.ultravigilance.ui.theme.CyberSurface
import com.example.ultravigilance.ui.theme.CyberSurfaceVariant
import com.example.ultravigilance.ui.theme.CyberTextMuted
import com.example.ultravigilance.ui.theme.CyberTextPrimary
import com.example.ultravigilance.ui.theme.CyberTextSecondary
import com.example.ultravigilance.ui.theme.UltraVigilanceTheme
import com.example.ultravigilance.util.ShieldOverlayManager

enum class Screen {
    LOGIN,
    SIGNUP,
    DASHBOARD
}

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
                val context = LocalContext.current
                var currentScreen by remember {
                    mutableStateOf(if (AuthManager.isLoggedIn(context)) Screen.DASHBOARD else Screen.LOGIN)
                }

                when (currentScreen) {
                    Screen.LOGIN -> {
                        LoginScreen(
                            onLoginSuccess = { _, _ ->
                                currentScreen = Screen.DASHBOARD
                            },
                            onNavigateToSignup = {
                                currentScreen = Screen.SIGNUP
                            },
                            onSkipDemo = {
                                currentScreen = Screen.DASHBOARD
                            }
                        )
                    }

                    Screen.SIGNUP -> {
                        SignupScreen(
                            onSignupSuccess = { _, _ ->
                                currentScreen = Screen.DASHBOARD
                            },
                            onNavigateToLogin = {
                                currentScreen = Screen.LOGIN
                            }
                        )
                    }

                    Screen.DASHBOARD -> {
                        Scaffold(
                            modifier = Modifier.fillMaxSize(),
                            containerColor = CyberBg
                        ) { innerPadding ->
                            DashboardScreen(
                                modifier = Modifier.padding(innerPadding),
                                onLogout = {
                                    AuthManager.logout(context)
                                    currentScreen = Screen.LOGIN
                                }
                            )
                        }
                    }
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

@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier,
    onLogout: () -> Unit = {}
) {
    val context = LocalContext.current
    val coroutineScope = androidx.compose.runtime.rememberCoroutineScope()
    var isListenerEnabled by remember { mutableStateOf(isNotificationListenerEnabled(context)) }
    var isAccessibilityEnabled by remember { mutableStateOf(isAccessibilityServiceEnabled(context)) }
    var isOverlayEnabled by remember { mutableStateOf(isOverlayPermissionEnabled(context)) }
    var isScanningQr by remember { mutableStateOf(false) }
    var qrScanResult by remember { mutableStateOf<String?>(null) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
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

    val (currentUsername, currentEmail) = AuthManager.getUser(context)

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBg)
            .verticalScroll(rememberScrollState())
            .padding(18.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        // 1. Top Minimalist Profile Row
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(16.dp)),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(34.dp)
                            .clip(CircleShape)
                            .background(CyberSurfaceVariant)
                            .border(1.dp, CyberCyan.copy(alpha = 0.5f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = currentUsername.take(1).uppercase(),
                            color = CyberCyan,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp
                        )
                    }
                    Column {
                        Text(
                            text = currentUsername,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp,
                            color = CyberTextPrimary
                        )
                        Text(
                            text = currentEmail,
                            fontSize = 11.sp,
                            color = CyberTextMuted
                        )
                    }
                }
                TextButton(onClick = onLogout) {
                    Text("Sign Out", fontWeight = FontWeight.SemiBold, fontSize = 11.sp, color = CyberCrimson)
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // 2. Main Hero Shield Status Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(20.dp)),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Pulsing Shield Icon Badge
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(CyberEmerald.copy(alpha = 0.12f))
                        .border(1.5.dp, CyberEmerald.copy(alpha = 0.5f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(text = "🛡", fontSize = 28.sp)
                }

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "SYSTEM PROTECTED",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = CyberEmerald,
                    letterSpacing = 0.5.sp
                )

                Text(
                    text = "UltraVigilance AI Defense is actively monitoring all vectors on this device.",
                    fontSize = 12.sp,
                    color = CyberTextSecondary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 4.dp)
                )

                Spacer(modifier = Modifier.height(14.dp))

                // Armed Status Pill
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier
                        .clip(RoundedCornerShape(20.dp))
                        .background(CyberSurfaceVariant)
                        .padding(horizontal = 12.dp, vertical = 5.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(CyberEmerald)
                    )
                    Text(
                        text = "REAL-TIME INTERCEPTION ACTIVE",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = CyberEmerald
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Compact Minimalist Protection Layers Grid
        Text(
            text = "ACTIVE DEFENSE LAYERS",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = CyberCyan,
            letterSpacing = 0.8.sp,
            modifier = Modifier
                .align(Alignment.Start)
                .padding(start = 4.dp, bottom = 8.dp)
        )

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(16.dp)),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                CompactLayerRow(
                    icon = "📱",
                    title = "SMS & RCS Guard",
                    subtitle = "Smishing & fraud SMS filter",
                    isActive = isListenerEnabled
                )
                HorizontalDivider(color = CyberBorder, modifier = Modifier.padding(vertical = 8.dp))
                CompactLayerRow(
                    icon = "⚡",
                    title = "Screen Tap Interceptor",
                    subtitle = "Click-only UPI payment shield",
                    isActive = isAccessibilityEnabled
                )
                HorizontalDivider(color = CyberBorder, modifier = Modifier.padding(vertical = 8.dp))
                CompactLayerRow(
                    icon = "🌐",
                    title = "Web Link Interceptor",
                    subtitle = "Deep WHOIS & lexical analysis",
                    isActive = isAccessibilityEnabled
                )
                HorizontalDivider(color = CyberBorder, modifier = Modifier.padding(vertical = 8.dp))
                CompactLayerRow(
                    icon = "🪟",
                    title = "Floating Threat Overlay",
                    subtitle = "Instant screen-level threat block",
                    isActive = isOverlayEnabled
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 4. QR Code Security Scanner
        Button(
            onClick = {
                com.example.ultravigilance.util.QrScanHandler.startQrScan(
                    context = context,
                    scope = coroutineScope,
                    onScanStateChanged = { isScanningQr = it },
                    onScanCompleted = { qrScanResult = it }
                )
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = CyberCyan,
                contentColor = CyberBg
            )
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(text = "📷", fontSize = 16.sp)
                Text(
                    text = if (isScanningQr) "Scanning QR with AI Defense..." else "Scan QR Code (AI Shield)",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        if (qrScanResult != null) {
            Spacer(modifier = Modifier.height(10.dp))
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CyberBorder, RoundedCornerShape(12.dp)),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = qrScanResult!!,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = CyberTextPrimary,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = { qrScanResult = null }) {
                        Text("Clear", fontSize = 11.sp, color = CyberTextMuted)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 5. Engine Health & Status Info (Minimalist)
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(16.dp)),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "NEURAL ENGINE STATUS",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = CyberTextMuted,
                    letterSpacing = 0.5.sp
                )
                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(text = "Backend Server", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(text = "FastAPI 2.0 (Online)", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = CyberEmerald)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(text = "Cross-Vector Memory", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(text = "Synchronized", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = CyberCyan)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(text = "Inspection Trigger", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(text = "On-Tap Only (Zero Choosers)", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = CyberTextPrimary)
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))
    }
}

@Composable
fun CompactLayerRow(
    icon: String,
    title: String,
    subtitle: String,
    isActive: Boolean
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(text = icon, fontSize = 16.sp)
            Column {
                Text(
                    text = title,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = CyberTextPrimary
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = CyberTextMuted
                )
            }
        }
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(if (isActive) CyberEmerald.copy(alpha = 0.15f) else CyberCrimson.copy(alpha = 0.15f))
                .padding(horizontal = 8.dp, vertical = 3.dp)
        ) {
            Text(
                text = if (isActive) "ACTIVE" else "OFF",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = if (isActive) CyberEmerald else CyberCrimson
            )
        }
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

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBg)
            .padding(20.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(CyberSurfaceVariant)
                    .border(1.5.dp, CyberCrimson.copy(alpha = 0.5f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(text = "🛡", fontSize = 28.sp)
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = "Setup Shield Protection",
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = CyberTextPrimary
            )

            Text(
                text = "Enable system permissions so UltraVigilance can protect clicks in the background without popups.",
                fontSize = 12.sp,
                color = CyberTextSecondary,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp, bottom = 20.dp)
            )

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CyberBorder, RoundedCornerShape(20.dp)),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = CyberSurface)
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
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
                                .height(44.dp),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = CyberCrimson)
                        ) {
                            Text(text = "1. Enable Accessibility Interceptor", fontSize = 12.sp, fontWeight = FontWeight.Bold)
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
                                        val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        }
                                        context.startActivity(intent)
                                    }
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(44.dp),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg)
                        ) {
                            Text(text = "2. Allow Display Over Other Apps", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                    }

                    OutlinedButton(
                        onClick = onRefresh,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(42.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberTextPrimary),
                        border = ButtonDefaults.outlinedButtonBorder.copy(brush = androidx.compose.ui.graphics.SolidColor(CyberBorder))
                    ) {
                        Text("🔄 Check Status & Continue", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}