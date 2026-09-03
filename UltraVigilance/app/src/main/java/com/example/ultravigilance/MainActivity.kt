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
import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.example.ultravigilance.data.SecurityStatsManager
import com.example.ultravigilance.data.SuspiciousLinkItem
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
import com.example.ultravigilance.ui.theme.GoogleBlue
import com.example.ultravigilance.ui.theme.GoogleGreen
import com.example.ultravigilance.ui.theme.GoogleRed
import com.example.ultravigilance.ui.theme.GoogleYellow
import com.example.ultravigilance.ui.theme.UltraVigilanceTheme
import com.example.ultravigilance.util.ShieldOverlayManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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

private fun isNotificationListenerEnabled(context: Context): Boolean {
    return NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)
}

private fun isAccessibilityServiceEnabled(context: Context): Boolean {
    val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
    val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
    val myServiceClass = ThreatShieldAccessibilityService::class.java.name
    return enabledServices.any {
        it.resolveInfo.serviceInfo.packageName == context.packageName &&
                it.resolveInfo.serviceInfo.name == myServiceClass
    }
}

private fun isOverlayPermissionEnabled(context: Context): Boolean {
    return ShieldOverlayManager.hasOverlayPermission(context)
}

@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier,
    onLogout: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var isListenerEnabled by remember { mutableStateOf(isNotificationListenerEnabled(context)) }
    var isAccessibilityEnabled by remember { mutableStateOf(isAccessibilityServiceEnabled(context)) }
    var isOverlayEnabled by remember { mutableStateOf(isOverlayPermissionEnabled(context)) }

    var isScanningQr by remember { mutableStateOf(false) }
    var qrScanResult by remember { mutableStateOf<String?>(null) }
    var activeFilter by remember { mutableStateOf("ALL") } // "ALL" | "THREATS" | "NORMAL"

    // Real-time Reactive Local Stats State (connected to SecurityStatsManager StateFlow)
    val updateNotifierTick by SecurityStatsManager.updateNotifier.collectAsState()

    var linksCount by remember { mutableIntStateOf(SecurityStatsManager.getTotalLinksScanned(context)) }
    var messagesCount by remember { mutableIntStateOf(SecurityStatsManager.getTotalMessagesScanned(context)) }
    var threatsCount by remember { mutableIntStateOf(SecurityStatsManager.getTotalThreatsFound(context)) }
    var suspiciousLinks by remember { mutableStateOf(SecurityStatsManager.getSuspiciousLinks(context)) }

    fun refreshLocalStats() {
        linksCount = SecurityStatsManager.getTotalLinksScanned(context)
        messagesCount = SecurityStatsManager.getTotalMessagesScanned(context)
        threatsCount = SecurityStatsManager.getTotalThreatsFound(context)
        suspiciousLinks = SecurityStatsManager.getSuspiciousLinks(context)
    }

    LaunchedEffect(updateNotifierTick) {
        refreshLocalStats()
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                isListenerEnabled = isNotificationListenerEnabled(context)
                isAccessibilityEnabled = isAccessibilityServiceEnabled(context)
                isOverlayEnabled = isOverlayPermissionEnabled(context)
                refreshLocalStats()
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
        refreshLocalStats()
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
                refreshLocalStats()
            }
        )
        return
    }

    val (currentUsername, currentEmail) = AuthManager.getUser(context)

    // Filter list based on user selection
    val displayedLinks = when (activeFilter) {
        "THREATS" -> suspiciousLinks.filter { it.userClaim != "CLAIMED_SAFE" }
        "NORMAL" -> suspiciousLinks.filter { it.userClaim == "CLAIMED_SAFE" }
        else -> suspiciousLinks
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBg)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        // 1. Google Workspace Profile & Header Row
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(20.dp)),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CircleShape)
                            .background(GoogleBlue.copy(alpha = 0.2f))
                            .border(1.5.dp, GoogleBlue, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = currentUsername.take(1).uppercase(),
                            color = GoogleBlue,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
                        )
                    }
                    Column {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = currentUsername,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp,
                                color = CyberTextPrimary
                            )
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(GoogleGreen.copy(alpha = 0.18f))
                                    .padding(horizontal = 5.dp, vertical = 1.dp)
                            ) {
                                Text(
                                    text = "Workspace Protected",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = GoogleGreen
                                )
                            }
                        }
                        Text(
                            text = currentEmail,
                            fontSize = 11.sp,
                            color = CyberTextMuted
                        )
                    }
                }
                TextButton(onClick = onLogout) {
                    Text("Sign Out", fontWeight = FontWeight.Bold, fontSize = 11.sp, color = GoogleRed)
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 2. Google Workspace 3-Metric Security Tiles (Real-Time Live Updates + Click to filter)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // Metric 1: Links Scanned
            MetricStatCard(
                modifier = Modifier
                    .weight(1f)
                    .clickable { activeFilter = "ALL" },
                icon = "🔗",
                count = linksCount,
                label = "Links Scanned",
                accentColor = GoogleBlue,
                isSelected = activeFilter == "ALL"
            )

            // Metric 2: Messages Scanned
            MetricStatCard(
                modifier = Modifier
                    .weight(1f)
                    .clickable { activeFilter = "ALL" },
                icon = "💬",
                count = messagesCount,
                label = "SMS Scanned",
                accentColor = GoogleYellow,
                isSelected = false
            )

            // Metric 3: Threats Found (Click to view flagged threat links)
            MetricStatCard(
                modifier = Modifier
                    .weight(1f)
                    .clickable {
                        activeFilter = if (activeFilter == "THREATS") "ALL" else "THREATS"
                    },
                icon = "🚨",
                count = threatsCount,
                label = "Threats Found",
                accentColor = GoogleRed,
                isSelected = activeFilter == "THREATS"
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Camera QR Scanner Button (Positioned just above Suspicious & Flagged Links)
        Button(
            onClick = {
                com.example.ultravigilance.util.QrScanHandler.startQrScan(
                    context = context,
                    scope = coroutineScope,
                    onScanStateChanged = { isScanningQr = it },
                    onScanCompleted = {
                        qrScanResult = it
                        refreshLocalStats()
                    }
                )
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = GoogleBlue,
                contentColor = Color(0xFF041E49)
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
                    .border(1.dp, CyberBorder, RoundedCornerShape(14.dp)),
                shape = RoundedCornerShape(14.dp),
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

        // 4. Suspicious & Flagged Links Hub (With User Choice: Make Normal / Safe vs Confirm Threat)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = if (activeFilter == "THREATS") "🚨 DETECTED THREAT LINKS" else "SUSPICIOUS & FLAGGED LINKS",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (activeFilter == "THREATS") GoogleRed else GoogleYellow,
                    letterSpacing = 0.8.sp,
                    modifier = Modifier.padding(start = 4.dp)
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (activeFilter != "ALL") {
                    Text(
                        text = "Show All",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = GoogleBlue,
                        modifier = Modifier
                            .clickable { activeFilter = "ALL" }
                            .padding(horizontal = 4.dp, vertical = 2.dp)
                    )
                }
                Text(
                    text = "${displayedLinks.size} Listed",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = CyberTextMuted,
                    modifier = Modifier.padding(vertical = 2.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(
                    width = if (activeFilter == "THREATS") 1.5.dp else 1.dp,
                    color = if (activeFilter == "THREATS") GoogleRed.copy(alpha = 0.6f) else CyberBorder,
                    shape = RoundedCornerShape(18.dp)
                ),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                if (displayedLinks.isEmpty()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(CircleShape)
                                .background(GoogleGreen.copy(alpha = 0.12f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(text = "🛡️", fontSize = 20.sp)
                        }
                        Column {
                            Text(
                                text = if (activeFilter == "THREATS") "No Active Threats Found" else "Zero Active Threats Detected",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = CyberTextPrimary
                            )
                            Text(
                                text = if (activeFilter == "THREATS") "All links scanned on this device are currently verified safe or whitelisted." else "All scanned links, QR codes, and SMS messages are verified safe.",
                                fontSize = 11.sp,
                                color = CyberTextSecondary
                            )
                        }
                    }
                } else {
                    displayedLinks.forEachIndexed { index, item ->
                        SuspiciousLinkRow(
                            item = item,
                            onClaimSafe = {
                                SecurityStatsManager.updateUserClaim(context, item.id, "CLAIMED_SAFE")
                                refreshLocalStats()
                                Toast.makeText(context, "Link marked as Normal (Safe)", Toast.LENGTH_SHORT).show()
                            },
                            onConfirmThreat = {
                                SecurityStatsManager.updateUserClaim(context, item.id, "CONFIRMED_THREAT")
                                refreshLocalStats()
                                Toast.makeText(context, "Confirmed as Threat", Toast.LENGTH_SHORT).show()
                            },
                            onReset = {
                                SecurityStatsManager.updateUserClaim(context, item.id, "UNREVIEWED")
                                refreshLocalStats()
                            }
                        )
                        if (index < displayedLinks.size - 1) {
                            HorizontalDivider(color = CyberBorder, modifier = Modifier.padding(vertical = 10.dp))
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 5. Main Hero Shield Status Card
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
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(GoogleGreen.copy(alpha = 0.15f))
                        .border(1.5.dp, GoogleGreen.copy(alpha = 0.5f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(text = "🛡", fontSize = 26.sp)
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "WORKSPACE SYSTEM PROTECTED",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = GoogleGreen,
                    letterSpacing = 0.5.sp
                )

                Text(
                    text = "UltraVigilance AI Defense is actively monitoring all vectors on this device.",
                    fontSize = 11.sp,
                    color = CyberTextSecondary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 4.dp)
                )

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier
                        .clip(RoundedCornerShape(20.dp))
                        .background(CyberSurfaceVariant)
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(GoogleGreen)
                    )
                    Text(
                        text = "REAL-TIME INTERCEPTION ARMED",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = GoogleGreen
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 6. Active Defense Layers Grid
        Text(
            text = "ACTIVE DEFENSE LAYERS",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = GoogleBlue,
            letterSpacing = 0.8.sp,
            modifier = Modifier
                .align(Alignment.Start)
                .padding(start = 4.dp, bottom = 8.dp)
        )

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(18.dp)),
            shape = RoundedCornerShape(18.dp),
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

        // 7. Engine Health & Status Info
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CyberBorder, RoundedCornerShape(18.dp)),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "GOOGLE WORKSPACE DEFENSE ENGINE",
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
                    Text(text = "Backend Service", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(text = "FastAPI 2.0 (Online)", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = GoogleGreen)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(text = "Cross-Vector Memory", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(text = "Synchronized", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = GoogleBlue)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(text = "Local Storage Database", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(text = "SharedPreferences Encrypted", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = CyberTextPrimary)
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))
    }
}

@Composable
fun MetricStatCard(
    modifier: Modifier = Modifier,
    icon: String,
    count: Int,
    label: String,
    accentColor: Color,
    isSelected: Boolean = false
) {
    Card(
        modifier = modifier
            .border(
                width = if (isSelected) 1.5.dp else 1.dp,
                color = if (isSelected) accentColor else CyberBorder,
                shape = RoundedCornerShape(16.dp)
            ),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) accentColor.copy(alpha = 0.10f) else CyberSurface
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.Start
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(text = icon, fontSize = 18.sp)
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(accentColor)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = count.toString(),
                fontSize = 20.sp,
                fontWeight = FontWeight.ExtraBold,
                color = accentColor
            )
            Text(
                text = label,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (isSelected) accentColor else CyberTextSecondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun SuspiciousLinkRow(
    item: SuspiciousLinkItem,
    onClaimSafe: () -> Unit,
    onConfirmThreat: () -> Unit,
    onReset: () -> Unit
) {
    val dateFormatted = remember(item.timestamp) {
        SimpleDateFormat("HH:mm, dd MMM", Locale.getDefault()).format(Date(item.timestamp))
    }
    val isFraud = item.verdict.equals("FRAUD", ignoreCase = true)
    val accentColor = if (isFraud) GoogleRed else GoogleYellow

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(accentColor.copy(alpha = 0.18f))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = if (isFraud) "🚨 FRAUD" else "⚠️ SUSPICIOUS",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = accentColor
                    )
                }
                Text(
                    text = "${Math.round(item.confidence * 100)}% Risk",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = CyberTextMuted
                )
            }
            Text(
                text = dateFormatted,
                fontSize = 10.sp,
                color = CyberTextMuted
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = item.url,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = CyberTextPrimary,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )

        if (item.reasons.isNotEmpty()) {
            Spacer(modifier = Modifier.height(3.dp))
            item.reasons.take(2).forEach { reason ->
                Text(
                    text = "• $reason",
                    fontSize = 10.sp,
                    color = CyberTextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // User Choice Next to Link: Make Normal / Safe vs Confirm Threat
        when (item.userClaim) {
            "CLAIMED_SAFE" -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(GoogleGreen.copy(alpha = 0.2f))
                            .padding(horizontal = 8.dp, vertical = 3.dp)
                    ) {
                        Text(
                            text = "✅ Marked Normal (Safe by You)",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = GoogleGreen
                        )
                    }
                    Text(
                        text = "Undo",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = GoogleBlue,
                        modifier = Modifier
                            .clickable { onReset() }
                            .padding(4.dp)
                    )
                }
            }

            "CONFIRMED_THREAT" -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(GoogleRed.copy(alpha = 0.2f))
                            .padding(horizontal = 8.dp, vertical = 3.dp)
                    ) {
                        Text(
                            text = "🚨 Confirmed Threat",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = GoogleRed
                        )
                    }
                    Text(
                        text = "Undo",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = GoogleBlue,
                        modifier = Modifier
                            .clickable { onReset() }
                            .padding(4.dp)
                    )
                }
            }

            else -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onClaimSafe,
                        modifier = Modifier
                            .weight(1f)
                            .height(34.dp),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = GoogleGreen.copy(alpha = 0.22f),
                            contentColor = GoogleGreen
                        )
                    ) {
                        Text(text = "🛡️ Make Normal (Safe)", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }

                    Button(
                        onClick = onConfirmThreat,
                        modifier = Modifier
                            .weight(1f)
                            .height(34.dp),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = GoogleRed.copy(alpha = 0.22f),
                            contentColor = GoogleRed
                        )
                    ) {
                        Text(text = "🚨 Confirm Threat", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
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
                .background(if (isActive) GoogleGreen.copy(alpha = 0.18f) else GoogleRed.copy(alpha = 0.18f))
                .padding(horizontal = 8.dp, vertical = 3.dp)
        ) {
            Text(
                text = if (isActive) "ACTIVE" else "OFF",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = if (isActive) GoogleGreen else GoogleRed
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
                    .border(1.5.dp, GoogleRed.copy(alpha = 0.5f), CircleShape),
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
                            colors = ButtonDefaults.buttonColors(containerColor = GoogleRed)
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
                            colors = ButtonDefaults.buttonColors(containerColor = GoogleBlue, contentColor = Color(0xFF041E49))
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
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberTextPrimary)
                    ) {
                        Text("🔄 Check Status & Continue", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}