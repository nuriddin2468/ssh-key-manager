package dev.sshkeymanager.android.generator

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderState
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.PasswordOptions
import dev.sshkeymanager.android.ui.NoticeEffect
import dev.sshkeymanager.android.ui.components.CopyButton
import dev.sshkeymanager.android.ui.components.ErrorText
import dev.sshkeymanager.android.ui.components.ScreenColumn
import dev.sshkeymanager.android.ui.components.SecondaryButton
import dev.sshkeymanager.android.ui.components.StrengthMeter
import dev.sshkeymanager.android.ui.components.VaultTopBar
import dev.sshkeymanager.android.ui.components.strengthLabel
import dev.sshkeymanager.android.ui.theme.SecretTextStyle
import kotlin.math.roundToInt

private const val MIN_LENGTH = 8
private const val MAX_LENGTH = 64

/** The generator on its own, to copy a password. */
@Composable
fun GeneratorScreen(viewModel: GeneratorViewModel, onBack: () -> Unit) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    NoticeEffect(viewModel.notice, snackbar)
    Scaffold(
        topBar = { VaultTopBar(stringResource(R.string.generator_title), onBack = onBack) },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        ScreenColumn(Modifier.padding(padding)) {
            val label = stringResource(R.string.generator_password)
            GeneratorPanel(
                state = state,
                onOptions = viewModel::setOptions,
                onAgain = viewModel::generate,
                onCopy = { viewModel.copy(label) },
            )
        }
    }
}

/**
 * The generated password, its strength and the options. `onUse` adds the
 * button that takes the password into an entry.
 */
@Composable
fun GeneratorPanel(
    state: GeneratorState,
    onOptions: (PasswordOptions) -> Unit,
    onAgain: () -> Unit,
    onCopy: (() -> Unit)? = null,
    onUse: ((String) -> Unit)? = null,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        state.generated?.let { generated ->
            Column(
                modifier = Modifier.semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite },
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = stringResource(R.string.generator_password),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // Not selectable: copying goes through the copy button, which
                // marks the clip sensitive and clears it.
                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .clip(MaterialTheme.shapes.small)
                            .background(MaterialTheme.colorScheme.surfaceContainerLow)
                            .padding(start = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = generated.password,
                        style = SecretTextStyle,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f).padding(vertical = 12.dp),
                    )
                    if (onCopy != null) CopyButton(label = stringResource(R.string.generator_password), onCopy = onCopy)
                }
                StrengthMeter(generated.score)
                Text(
                    text = stringResource(R.string.generator_strength, stringResource(strengthLabel(generated.score))),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        state.error?.let { ErrorText(stringResource(it)) }

        val options = state.options
        Column {
            Text(
                text = stringResource(R.string.generator_length, options.length.toInt()),
                style = MaterialTheme.typography.bodyLarge,
            )
            val slider = remember { SliderState(options.length.toFloat(), 0, MIN_LENGTH.toFloat()..MAX_LENGTH.toFloat()) }
            Slider(
                state = slider,
                onValueChange = { length ->
                    slider.value = length
                    val rounded = length.roundToInt().toUShort()
                    if (rounded != options.length) onOptions(options.copy(length = rounded))
                },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        OptionSwitch(stringResource(R.string.generator_lowercase), options.lowercase) {
            onOptions(options.copy(lowercase = it))
        }
        OptionSwitch(stringResource(R.string.generator_uppercase), options.uppercase) {
            onOptions(options.copy(uppercase = it))
        }
        OptionSwitch(stringResource(R.string.generator_digits), options.digits) {
            onOptions(options.copy(digits = it))
        }
        OptionSwitch(stringResource(R.string.generator_symbols), options.symbols) {
            onOptions(options.copy(symbols = it))
        }
        OptionSwitch(stringResource(R.string.generator_ambiguous), options.avoidAmbiguous) {
            onOptions(options.copy(avoidAmbiguous = it))
        }

        val password = state.generated?.password
        if (onUse != null && password != null) {
            Button(onClick = { onUse(password) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.generator_use))
            }
        }
        SecondaryButton(stringResource(R.string.generator_again), onClick = onAgain)
    }
}

/** A switch with its label, the whole row a 48 dp target. */
@Composable
fun OptionSwitch(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .toggleable(value = checked, role = Role.Switch, onValueChange = onChange),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f).padding(end = 16.dp))
        Switch(checked = checked, onCheckedChange = null)
    }
}
