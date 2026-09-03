package com.example.ultravigilance.util

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import android.util.Log

object BrowserLauncher {
    private const val TAG = "BrowserLauncher"

    private val PREFERRED_BROWSERS = listOf(
        "com.android.chrome",
        "com.google.android.apps.chrome",
        "org.mozilla.firefox",
        "com.sec.android.app.sbrowser",
        "com.microsoft.emmx",
        "com.opera.browser",
        "com.brave.browser",
        "com.duckduckgo.mobile.android"
    )

    /**
     * Resolves external web browsers installed on the device, strictly excluding
     * UltraVigilance to prevent loopback interception.
     */
    fun getExternalBrowsers(context: Context, url: String): List<ResolveInfo> {
        val baseIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val packageManager = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PackageManager.MATCH_DEFAULT_ONLY
        } else {
            0
        }

        val allResolvers = packageManager.queryIntentActivities(baseIntent, flags)
        val ownPackage = context.packageName

        return allResolvers.filter { resolveInfo ->
            val pkg = resolveInfo.activityInfo?.packageName
            pkg != null && pkg != ownPackage
        }
    }

    /**
     * Directly launches the genuine external web browser (Chrome, Firefox, Samsung Browser, etc.)
     * without reopening UltraVigilance.
     */
    fun launchGenuineBrowser(context: Context, url: String): Boolean {
        val externalBrowsers = getExternalBrowsers(context, url)
        val appContext = context.applicationContext

        try {
            val target = externalBrowsers.firstOrNull { r ->
                PREFERRED_BROWSERS.contains(r.activityInfo?.packageName)
            } ?: externalBrowsers.firstOrNull()

            if (target != null && target.activityInfo != null) {
                val directIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                    addCategory(Intent.CATEGORY_BROWSABLE)
                    component = ComponentName(target.activityInfo.packageName, target.activityInfo.name)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                appContext.startActivity(directIntent)
                Log.i(TAG, "🚀 Launched external browser: ${target.activityInfo.packageName}")
                return true
            }

            // Fallback: Use setPackage on known browsers if queryIntentActivities was filtered by Android 11+ package visibility
            for (preferredPkg in PREFERRED_BROWSERS) {
                try {
                    val directIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                        addCategory(Intent.CATEGORY_BROWSABLE)
                        setPackage(preferredPkg)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    appContext.startActivity(directIntent)
                    Log.i(TAG, "🚀 Launched preferred browser fallback: $preferredPkg")
                    return true
                } catch (_: Exception) {}
            }

            Log.w(TAG, "No external browser could be directly launched.")
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch genuine external browser: ${e.message}", e)
            return false
        }
    }
}
