package dev.sshkeymanager.android.setup

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.ui.components.AppTile
import dev.sshkeymanager.android.ui.components.ErrorText
import dev.sshkeymanager.android.ui.components.Heading
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.ui.components.SecretField
import dev.sshkeymanager.android.ui.components.StrengthMeter
import dev.sshkeymanager.android.ui.components.strengthLabel

/**
 * The first screen of a phone without a vault: the vault comes from one of
 * the user's computers. Pairing goes here in step E of docs/mobile.md; until
 * then the screen says so. Debug builds add a way to load a test vault.
 */
@Composable
fun NoVaultScreen(debugTestVault: (() -> Unit)?) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 20) {
            AppTile()
            Heading(stringResource(R.string.novault_title), stringResource(R.string.novault_body))
            Text(
                text = stringResource(R.string.novault_soon),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (debugTestVault != null) DebugCard(debugTestVault)
        }
    }
}

@Composable
private fun DebugCard(onLoad: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.novault_debug_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Text(
                text = stringResource(R.string.novault_debug_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SecondaryButton(stringResource(R.string.novault_debug_action), onClick = onLoad)
        }
    }
}

/** Setting this phone's master password for the vault it received. */
@Composable
fun SetupScreen(viewModel: SetupViewModel) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 20) {
            AppTile()
            Heading(stringResource(R.string.setup_title), stringResource(R.string.setup_body))
            SecretField(
                state = viewModel.master,
                label = stringResource(R.string.field_master),
                enabled = !state.busy,
                imeAction = ImeAction.Next,
            )
            val text = viewModel.master.text
            val score = remember(text) { viewModel.strength(text) }
            if (text.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    StrengthMeter(score)
                    Text(
                        text =
                            if (score < 3) {
                                stringResource(R.string.setup_weak)
                            } else {
                                stringResource(R.string.generator_strength, stringResource(strengthLabel(score)))
                            },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            SecretField(
                state = viewModel.repeat,
                label = stringResource(R.string.field_master_repeat),
                enabled = !state.busy,
                onImeAction = { viewModel.submit() },
            )
            state.error?.let { ErrorText(stringResource(it)) }
            Button(
                onClick = viewModel::submit,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) {
                if (state.busy) {
                    CircularProgressIndicator(Modifier.padding(4.dp).heightIn(max = 20.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.setup_action))
                }
            }
        }
    }
}
