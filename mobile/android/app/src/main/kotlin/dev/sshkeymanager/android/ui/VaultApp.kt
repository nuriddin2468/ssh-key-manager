package dev.sshkeymanager.android.ui

import android.os.SystemClock
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.sshkeymanager.android.AppGraph
import dev.sshkeymanager.android.DebugTools
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.biometric.SystemPrompter
import dev.sshkeymanager.android.core.coreVersion
import dev.sshkeymanager.android.generator.GeneratorScreen
import dev.sshkeymanager.android.generator.GeneratorViewModel
import dev.sshkeymanager.android.generator.RustPasswordTools
import dev.sshkeymanager.android.logins.DetailScreen
import dev.sshkeymanager.android.logins.DetailViewModel
import dev.sshkeymanager.android.logins.EditScreen
import dev.sshkeymanager.android.logins.EditViewModel
import dev.sshkeymanager.android.logins.LoginsScreen
import dev.sshkeymanager.android.logins.LoginsViewModel
import dev.sshkeymanager.android.settings.SettingsScreen
import dev.sshkeymanager.android.settings.SettingsViewModel
import dev.sshkeymanager.android.setup.NoVaultScreen
import dev.sshkeymanager.android.setup.SetupScreen
import dev.sshkeymanager.android.setup.SetupViewModel
import dev.sshkeymanager.android.ui.components.Heading
import dev.sshkeymanager.android.ui.components.NoKeyboardLearning
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.unlock.UnlockScreen
import dev.sshkeymanager.android.unlock.UnlockViewModel
import dev.sshkeymanager.android.vault.VaultState
import kotlinx.coroutines.launch

/** The app: whichever screen the vault's state calls for. */
@Composable
fun VaultApp(graph: AppGraph) {
    val session = graph.session
    val state by session.vaultState.collectAsStateWithLifecycle()
    val activity = LocalActivity.current
    val prompter: Prompter = remember(activity) { activity?.let(::SystemPrompter) ?: Prompter { _, _ -> error("no activity") } }
    val navigator: Navigator = viewModel()
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) { session.start() }
    // Locking drops every screen of the open vault, and what they held.
    LaunchedEffect(state) { if (state !is VaultState.Unlocked) navigator.reset() }

    NoKeyboardLearning {
        when (val current = state) {
            VaultState.Loading -> Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background))
            VaultState.Missing -> {
                val cache = LocalContext.current.cacheDir
                val testVault = DebugTools.testVault(graph, cache)
                NoVaultScreen(debugTestVault = testVault?.let { load -> { scope.launch { load() } } })
            }
            VaultState.Received -> SetupScreen(viewModel { SetupViewModel(session, RustPasswordTools) })
            is VaultState.Locked -> UnlockScreen(current, viewModel { UnlockViewModel(session) }, prompter)
            VaultState.Unlocked -> UnlockedApp(graph, navigator, prompter)
            is VaultState.Unreadable -> UnreadableScreen(onRetry = { scope.launch { session.load() } })
        }
    }
}

@Composable
private fun UnlockedApp(graph: AppGraph, navigator: Navigator, prompter: Prompter) {
    val session = graph.session
    val entry = navigator.top
    BackHandler(enabled = navigator.entries.size > 1) { navigator.pop() }
    val back: () -> Unit = { navigator.pop() }
    CompositionLocalProvider(LocalViewModelStoreOwner provides entry) {
        key(entry.key) {
            when (val route = entry.route) {
                Route.Logins ->
                    LoginsScreen(
                        viewModel = viewModel { LoginsViewModel(session) },
                        prompter = prompter,
                        onOpen = { navigator.push(Route.Detail(it)) },
                        onAdd = { navigator.push(Route.Edit(null)) },
                        onGenerator = { navigator.push(Route.Generator) },
                        onSettings = { navigator.push(Route.Settings) },
                    )
                is Route.Detail ->
                    DetailScreen(
                        viewModel = viewModel { DetailViewModel(route.id, session, graph.clipboard, SystemClock::elapsedRealtime) },
                        onBack = back,
                        onEdit = { navigator.push(Route.Edit(route.id)) },
                    )
                is Route.Edit ->
                    EditScreen(
                        viewModel = viewModel { EditViewModel(route.id, session) },
                        onBack = back,
                        onSaved = { id ->
                            navigator.pop()
                            // A new entry opens; an edited one is already under the form.
                            if (route.id == null) navigator.push(Route.Detail(id))
                        },
                    )
                Route.Generator ->
                    GeneratorScreen(
                        viewModel = viewModel { GeneratorViewModel(RustPasswordTools, graph.clipboard) },
                        onBack = back,
                    )
                Route.Settings ->
                    SettingsScreen(
                        viewModel = viewModel { SettingsViewModel(session, graph.settings, coreVersion()) },
                        prompter = prompter,
                        onBack = back,
                    )
            }
        }
    }
}

@Composable
private fun UnreadableScreen(onRetry: () -> Unit) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 20) {
            Heading(stringResource(R.string.unreadable_title), stringResource(R.string.unreadable_body))
            SecondaryButton(stringResource(R.string.action_retry), onClick = onRetry)
        }
    }
}
