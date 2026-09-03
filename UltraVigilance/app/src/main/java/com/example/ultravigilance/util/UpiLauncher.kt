package com.example.ultravigilance.util

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import android.util.Log

object UpiLauncher {
    private const val TAG = "UpiLauncher"

    /**
     * Resolves all installed UPI apps on the device, excluding AI-Shield / UltraVigilance
     * itself to avoid recursive interception loops.
     */
    fun getExternalUpiApps(context: Context, upiUri: String): List<ResolveInfo> {
        val baseIntent = Intent(Intent.ACTION_VIEW, Uri.parse(upiUri))
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
     * Launches the real UPI application directly without triggering OS app suggestion choosers.
     */
    fun launchGenuineUpiApp(context: Context, upiUri: String): Boolean {
        val externalApps = getExternalUpiApps(context, upiUri)

        if (externalApps.isEmpty()) {
            Log.w(TAG, "No external UPI apps installed on this device.")
            return false
        }

        try {
            // Directly launch the primary/default installed UPI app without creating a chooser
            val target = externalApps.first().activityInfo
            val directIntent = Intent(Intent.ACTION_VIEW, Uri.parse(upiUri)).apply {
                component = ComponentName(target.packageName, target.name)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(directIntent)
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch external UPI app", e)
            return false
        }
    }
}
