package dev.sshkeymanager.android

import android.os.Bundle
import android.view.View
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.sshkeymanager.android.ui.VaultApp
import dev.sshkeymanager.android.ui.theme.SshkmTheme

class MainActivity : ComponentActivity() {
    private val graph get() = (application as SshkmApplication).graph

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // No autofill service (another password manager) reads or offers to
        // save what is typed in the vault's own fields.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setContent {
            SshkmTheme {
                VaultApp(graph)
            }
        }
    }

    /** Any touch or key in the app counts as using it, for locking after a while without use. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        graph.session.touch()
    }
}
