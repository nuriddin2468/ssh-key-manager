package dev.sshkeymanager.android.unlock

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.ui.components.AppTile
import dev.sshkeymanager.android.ui.components.ErrorText
import dev.sshkeymanager.android.ui.components.Heading
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.ui.components.SecretField
import dev.sshkeymanager.android.vault.FingerprintState
import dev.sshkeymanager.android.vault.LockReason
import dev.sshkeymanager.android.vault.VaultState

/** What the fingerprint prompt says when it opens the vault. */
@Composable
fun unlockPromptText() =
    PromptText(
        title = stringResource(R.string.prompt_unlock_title),
        subtitle = null,
        cancel = stringResource(R.string.prompt_unlock_cancel),
    )

@Composable
fun UnlockScreen(locked: VaultState.Locked, viewModel: UnlockViewModel, prompter: Prompter) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val promptText = unlockPromptText()
    val ready = locked.fingerprint == FingerprintState.READY
    // The prompt comes up by itself, unless the user just locked the vault.
    LaunchedEffect(locked) {
        if (ready && locked.reason != LockReason.MANUAL) viewModel.unlockWithFingerprint(prompter, promptText)
    }
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 20) {
            AppTile()
            Heading(stringResource(R.string.unlock_title), stringResource(R.string.unlock_body))
            when (locked.fingerprint) {
                FingerprintState.AFTER_RESTART -> Note(stringResource(R.string.unlock_after_restart))
                FingerprintState.WEEKLY -> Note(stringResource(R.string.unlock_weekly))
                FingerprintState.CHANGED -> Note(stringResource(R.string.unlock_changed))
                FingerprintState.GONE -> Note(stringResource(R.string.unlock_gone))
                FingerprintState.OFF, FingerprintState.READY -> Unit
            }
            SecretField(
                state = viewModel.password,
                label = stringResource(R.string.field_master),
                enabled = !state.busy,
                onImeAction = { viewModel.unlock() },
            )
            state.error?.let { ErrorText(it.resolve()) }
            Button(
                onClick = viewModel::unlock,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) {
                if (state.busy) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.unlock_action))
                }
            }
            if (ready) {
                SecondaryButton(
                    text = stringResource(R.string.unlock_fingerprint),
                    onClick = { viewModel.unlockWithFingerprint(prompter, promptText) },
                    enabled = !state.busy,
                )
            }
        }
    }
}

/** Why the fingerprint can't open the vault now: a quiet notice, not an error. */
@Composable
private fun Note(text: String) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .background(MaterialTheme.colorScheme.surfaceContainer)
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.medium)
                .padding(16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}
