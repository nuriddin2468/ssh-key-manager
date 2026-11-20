package dev.sshkeymanager.android.logins

import android.os.SystemClock
import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.EntryKind
import dev.sshkeymanager.android.core.LoginDetail
import dev.sshkeymanager.android.ui.NoticeEffect
import dev.sshkeymanager.android.ui.components.EmptyState
import dev.sshkeymanager.android.ui.components.ErrorText
import dev.sshkeymanager.android.ui.components.FieldRow
import dev.sshkeymanager.android.ui.components.LocalUse
import dev.sshkeymanager.android.ui.components.countsAsUse
import dev.sshkeymanager.android.ui.components.OtpRow
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.ui.components.SecretRow
import dev.sshkeymanager.android.ui.components.VaultTopBar
import dev.sshkeymanager.android.ui.components.otpPeriod
import java.time.Instant
import kotlinx.coroutines.delay

@Composable
fun DetailScreen(viewModel: DetailViewModel, onBack: () -> Unit, onEdit: () -> Unit) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    NoticeEffect(viewModel.notice, snackbar)
    val detail = state.detail
    val login = detail?.login
    var confirmTrash by remember { mutableStateOf(false) }
    // Every second while up, and at once when back on screen (the phone may
    // have slept): a shown password hides after a while, a 2FA code renews.
    LaunchedEffect(viewModel) { viewModel.follow() }
    LifecycleEventEffect(Lifecycle.Event.ON_START) { viewModel.onScreen() }

    Scaffold(
        topBar = {
            VaultTopBar(
                title = login?.title.orEmpty(),
                onBack = onBack,
                actions = {
                    if (login != null && !login.inTrash) {
                        IconButton(onClick = onEdit) {
                            Icon(Icons.Filled.Edit, contentDescription = stringResource(R.string.detail_edit))
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 4) {
            when {
                state.gone -> EmptyState(null, stringResource(R.string.detail_gone))
                detail != null -> Fields(detail, state, viewModel)
            }
            state.error?.let { ErrorText(stringResource(it)) }
            if (login != null) {
                Column(Modifier.padding(top = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (login.inTrash) {
                        Text(
                            text = stringResource(R.string.detail_in_trash),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        SecondaryButton(stringResource(R.string.detail_restore), onClick = viewModel::restore)
                    } else {
                        SecondaryButton(
                            text = stringResource(R.string.detail_trash),
                            onClick = { confirmTrash = true },
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
    }

    if (confirmTrash && login != null) {
        AlertDialog(
            onDismissRequest = { confirmTrash = false },
            modifier = Modifier.countsAsUse(LocalUse.current),
            title = { Text(stringResource(R.string.trash_confirm_title, login.title)) },
            text = { Text(stringResource(R.string.trash_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmTrash = false
                    viewModel.trash()
                }) { Text(stringResource(R.string.detail_trash)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmTrash = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }
}

@Composable
private fun Fields(detail: LoginDetail, state: DetailState, viewModel: DetailViewModel) {
    val login = detail.login
    loginSubtitle(login)?.takeIf { login.kind != EntryKind.LOGIN }?.let {
        Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    if (login.username.isNotEmpty()) {
        val label = stringResource(R.string.field_username)
        FieldRow(label = label, value = login.username, onCopy = { viewModel.copyUsername(label) })
        Divider()
    }
    val passwordLabel = stringResource(R.string.field_password)
    if (login.hasPassword) {
        SecretRow(
            label = passwordLabel,
            shown = state.shownPassword,
            onToggle = viewModel::togglePassword,
            onCopy = { viewModel.copyPassword(passwordLabel) },
        )
    } else {
        FieldRow(label = passwordLabel, value = stringResource(R.string.password_none), onCopy = null)
    }
    detail.passwordChanged?.let { changed ->
        Text(
            text = stringResource(R.string.detail_password_changed, relativeTime(changed)),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    Divider()
    if (login.hasOtp) {
        OtpField(state, viewModel)
        Divider()
    }
    if (login.url.isNotEmpty()) {
        val label = stringResource(R.string.field_website)
        FieldRow(label = label, value = login.url, onCopy = { viewModel.copyWebsite(label) })
        Divider()
    }
    if (detail.notes.isNotEmpty()) {
        FieldRow(label = stringResource(R.string.field_notes), value = detail.notes, onCopy = null)
    }
}

@Composable
private fun OtpField(state: DetailState, viewModel: DetailViewModel) {
    // The countdown ticks here; the code itself comes from the view model.
    var now by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = SystemClock.elapsedRealtime()
        }
    }
    val otp = state.otp
    val label = stringResource(R.string.field_otp)
    OtpRow(
        label = label,
        code = otp?.code,
        remaining = otp?.remaining(now) ?: 0,
        period = otp?.let { otpPeriod(it.validFor) } ?: 30,
        unreadable = state.otpUnreadable,
        onCopy = { viewModel.copyOtp(label) },
    )
}

@Composable
private fun Divider() = HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

/** "3 days ago", in the user's language. */
private fun relativeTime(rfc3339: String): String =
    runCatching {
        DateUtils
            .getRelativeTimeSpanString(
                Instant.parse(rfc3339).toEpochMilli(),
                System.currentTimeMillis(),
                DateUtils.MINUTE_IN_MILLIS,
            ).toString()
    }.getOrDefault(rfc3339)
