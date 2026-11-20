package dev.sshkeymanager.android

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager
import androidx.annotation.VisibleForTesting

/**
 * Makes every activity's window secure before it is created: no screenshots,
 * no screen recording, and a blank card in Recents. Dialogs and pop-ups
 * Compose opens inherit it from their activity's window.
 *
 * Holds the [AppGraph], and tells the vault when the app comes on screen and
 * leaves it, for locking after a while away.
 */
class SshkmApplication : Application() {
    private var current: AppGraph? = null

    /** Made on first use, so a deadline job that starts the process gets one too. */
    @get:Synchronized @set:VisibleForTesting @set:Synchronized
    var graph: AppGraph
        get() = current ?: AppGraph(this).also { current = it }
        set(value) {
            current = value
        }

    override fun onCreate() {
        super.onCreate()
        registerActivityLifecycleCallbacks(SecureWindows)
        registerActivityLifecycleCallbacks(OnScreen())
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

    /** Counts the app's started activities: the app is on screen while there is one. */
    private inner class OnScreen : ActivityLifecycleCallbacks {
        private var started = 0

        override fun onActivityStarted(activity: Activity) {
            if (started++ == 0) graph.session.appForeground()
        }

        override fun onActivityStopped(activity: Activity) {
            if (--started == 0) graph.session.appBackground()
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

        override fun onActivityResumed(activity: Activity) = Unit

        override fun onActivityPaused(activity: Activity) = Unit

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

        override fun onActivityDestroyed(activity: Activity) = Unit
    }
}
