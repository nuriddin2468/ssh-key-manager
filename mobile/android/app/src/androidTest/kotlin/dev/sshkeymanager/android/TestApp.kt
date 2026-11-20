package dev.sshkeymanager.android

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.rules.ExternalResource

/**
 * Starts each test from a phone without a vault: the app's vault folder and
 * preferences are wiped and a new [AppGraph] made, before the activity starts.
 */
class FreshApp : ExternalResource() {
    val app: SshkmApplication
        get() = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as SshkmApplication

    override fun before() {
        AppGraph.vaultFolder(app).deleteRecursively()
        for (name in listOf("vault", "clipboard")) {
            app.getSharedPreferences(name, 0).edit().clear().commit()
        }
        app.graph = AppGraph(app)
    }
}
