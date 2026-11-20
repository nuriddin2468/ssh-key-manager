package dev.sshkeymanager.android.logins

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.generator.GeneratorPanel
import dev.sshkeymanager.android.generator.GeneratorViewModel
import dev.sshkeymanager.android.ui.components.ErrorText
import dev.sshkeymanager.android.ui.components.PlainField
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.ui.components.ScreenGutter
import dev.sshkeymanager.android.ui.components.SecretField
import dev.sshkeymanager.android.ui.components.VaultTopBar

@Composable
fun EditScreen(viewModel: EditViewModel, onBack: () -> Unit, onSaved: (String) -> Unit) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var generating by remember { mutableStateOf(false) }
    LaunchedEffect(viewModel) { viewModel.saved.collect(onSaved) }

    Scaffold(
        topBar = {
            VaultTopBar(
                title = stringResource(if (viewModel.isNew) R.string.edit_new_title else R.string.edit_title),
                onBack = onBack,
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        ScreenColumn(Modifier.padding(padding), spacing = 12) {
            val busy = state.loading || state.saving
            PlainField(
                state = viewModel.title,
                label = stringResource(R.string.field_title),
                placeholder = stringResource(R.string.edit_title_hint),
                error = state.titleError?.let { stringResource(it) },
                capitalization = KeyboardCapitalization.Sentences,
            )
            PlainField(
                state = viewModel.username,
                label = stringResource(R.string.field_username),
                keyboardType = KeyboardType.Email,
            )
            SecretField(
                state = viewModel.password,
                label = stringResource(if (state.hasPassword) R.string.edit_new_password else R.string.field_password),
                supportingText = if (state.hasPassword) stringResource(R.string.edit_keep_password) else null,
                imeAction = ImeAction.Next,
            )
            SecondaryButton(stringResource(R.string.edit_generate), onClick = { generating = true })
            PlainField(
                state = viewModel.url,
                label = stringResource(R.string.field_website),
                keyboardType = KeyboardType.Uri,
            )
            OtpFields(state, viewModel)
            PlainField(
                state = viewModel.notes,
                label = stringResource(R.string.field_notes),
                singleLine = false,
                capitalization = KeyboardCapitalization.Sentences,
            )
            state.error?.let { ErrorText(stringResource(it)) }
            Button(
                onClick = viewModel::save,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) {
                if (state.saving) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.action_save))
                }
            }
        }
    }

    if (generating) {
        GeneratorSheet(
            onUse = { password ->
                viewModel.usePassword(password)
                generating = false
            },
            onDismiss = { generating = false },
        )
    }
}

@Composable
private fun OtpFields(state: EditState, viewModel: EditViewModel) {
    val label = stringResource(R.string.field_otp_secret)
    val error = state.otpError?.let { stringResource(it) }
    if (!state.hasOtp) {
        SecretField(
            state = viewModel.otp,
            label = label,
            supportingText = stringResource(R.string.edit_otp_hint),
            error = error,
            imeAction = ImeAction.Next,
        )
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(R.string.edit_otp_saved), style = MaterialTheme.typography.bodyLarge)
        val choices =
            listOf(
                OtpChoice.KEEP to R.string.edit_otp_keep,
                OtpChoice.REPLACE to R.string.edit_otp_replace,
                OtpChoice.REMOVE to R.string.edit_otp_remove,
            )
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            choices.forEachIndexed { index, (choice, text) ->
                SegmentedButton(
                    selected = state.otpChoice == choice,
                    onClick = { viewModel.chooseOtp(choice) },
                    shape = SegmentedButtonDefaults.itemShape(index, choices.size),
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text(stringResource(text), maxLines = 2) }
            }
        }
        when (state.otpChoice) {
            OtpChoice.REPLACE ->
                SecretField(
                    state = viewModel.otp,
                    label = label,
                    supportingText = stringResource(R.string.edit_otp_hint),
                    error = error,
                    imeAction = ImeAction.Next,
                )
            OtpChoice.REMOVE ->
                Text(
                    stringResource(R.string.edit_otp_removing),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            OtpChoice.KEEP -> Unit
        }
    }
}

/** The generator in a sheet over the form; its password goes into the form's field. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GeneratorSheet(onUse: (String) -> Unit, onDismiss: () -> Unit) {
    val generator: GeneratorViewModel = viewModel(key = "generator-sheet") { GeneratorViewModel() }
    val state by generator.uiState.collectAsStateWithLifecycle()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberBottomSheetState(SheetValue.Hidden, setOf(SheetValue.Hidden, SheetValue.Expanded)),
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            Modifier
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = ScreenGutter, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.generator_title),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() },
            )
            GeneratorPanel(
                state = state,
                onOptions = generator::setOptions,
                onAgain = generator::generate,
                onUse = onUse,
            )
        }
    }
}
