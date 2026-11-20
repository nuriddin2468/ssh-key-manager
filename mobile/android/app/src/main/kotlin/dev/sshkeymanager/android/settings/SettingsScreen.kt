package dev.sshkeymanager.android.settings

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.logins.enablePromptText
import dev.sshkeymanager.android.ui.NoticeEffect
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.ui.components.VaultTopBar
import dev.sshkeymanager.android.vault.LockAfter

@StringRes
fun lockAfterLabel(value: LockAfter): Int =
    when (value) {
        LockAfter.SECONDS_30 -> R.string.lock_after_30s
        LockAfter.MINUTE_1 -> R.string.lock_after_1m
        LockAfter.MINUTES_5 -> R.string.lock_after_5m
        LockAfter.MINUTES_15 -> R.string.lock_after_15m
    }

@Composable
fun SettingsScreen(viewModel: SettingsViewModel, prompter: Prompter, onBack: () -> Unit) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    NoticeEffect(viewModel.notice, snackbar)
    val enableText = enablePromptText()
    Scaffold(
        topBar = { VaultTopBar(stringResource(R.string.settings_title), onBack = onBack) },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 8) {
            Section(stringResource(R.string.settings_security))
            Text(stringResource(R.string.settings_lock_after), style = MaterialTheme.typography.titleMedium)
            Text(
                stringResource(R.string.settings_lock_after_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Column(Modifier.selectableGroup()) {
                LockAfter.entries.forEach { value ->
                    Row(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .selectable(
                                    selected = state.lockAfter == value,
                                    role = Role.RadioButton,
                                    onClick = { viewModel.setLockAfter(value) },
                                ),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = state.lockAfter == value, onClick = null)
                        Text(
                            stringResource(lockAfterLabel(value)),
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(start = 16.dp),
                        )
                    }
                }
            }
            HorizontalDivider(Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.outlineVariant)

            val available = state.fingerprint == Availability.AVAILABLE
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .toggleable(
                            value = state.fingerprintOn,
                            enabled = (available || state.fingerprintOn) && !state.busy,
                            role = Role.Switch,
                            onValueChange = { viewModel.setFingerprint(it, prompter, enableText) },
                        ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f).padding(end = 16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(stringResource(R.string.settings_fingerprint), style = MaterialTheme.typography.titleMedium)
                    Text(
                        text =
                            stringResource(
                                when (state.fingerprint) {
                                    Availability.AVAILABLE -> R.string.settings_fingerprint_body
                                    Availability.NONE_ENROLLED -> R.string.settings_fingerprint_none
                                    Availability.UNSUPPORTED -> R.string.settings_fingerprint_unsupported
                                },
                            ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = state.fingerprintOn,
                    onCheckedChange = null,
                    enabled = (available || state.fingerprintOn) && !state.busy,
                )
            }
            HorizontalDivider(Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.outlineVariant)
            SecondaryButton(stringResource(R.string.settings_lock_now), onClick = viewModel::lockNow)

            Section(stringResource(R.string.settings_about))
            Text(
                stringResource(R.string.settings_version, viewModel.version),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun Section(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 16.dp).semantics { heading() },
    )
}
