package dev.sshkeymanager.android

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager

/**
 * Makes every activity's window secure before it is created: no screenshots,
 * no screen recording, and a blank card in Recents. Dialogs and pop-ups
 * Compose opens inherit it from their activity's window.
 */
class SshkmApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        registerActivityLifecycleCallbacks(SecureWindows)
    }

    private object SecureWindows : ActivityLifecycleCallbacks {
        override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
            activity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

        override fun onActivityStarted(activity: Activity) = Unit

        override fun onActivityResumed(activity: Activity) = Unit

        override fun onActivityPaused(activity: Activity) = Unit

        override fun onActivityStopped(activity: Activity) = Unit

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

        override fun onActivityDestroyed(activity: Activity) = Unit
    }
}
