package dev.sshkeymanager.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.sshkeymanager.android.home.HomeRoute
import dev.sshkeymanager.android.ui.theme.SshkmTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            SshkmTheme {
                HomeRoute()
            }
        }
    }
}
