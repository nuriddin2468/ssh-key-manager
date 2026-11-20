package dev.sshkeymanager.android.ui.components

import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.KeyboardActionHandler
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.editableText
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import dev.sshkeymanager.android.R

/**
 * Keeps the keyboard from learning what is typed anywhere inside: every
 * text field gets `IME_FLAG_NO_PERSONALIZED_LEARNING` (no learned words, no
 * typing history kept by the keyboard), and a password field also gets
 * `TYPE_TEXT_FLAG_NO_SUGGESTIONS`. The whole app is a vault, so this wraps
 * all of it.
 */
@Composable
fun NoKeyboardLearning(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(
        interceptor = { request, nextHandler ->
            nextHandler.startInputMethod(
                object : PlatformTextInputMethodRequest by request {
                    override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
                        val connection = request.createInputConnection(outAttributes)
                        privateEditorInfo(outAttributes)
                        return connection
                    }
                },
            )
        },
        content = content,
    )
}

/** Adds the flags [NoKeyboardLearning] sets to what a text field asked for. */
fun privateEditorInfo(info: EditorInfo) {
    info.imeOptions = info.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
    val variation = info.inputType and InputType.TYPE_MASK_VARIATION
    val password =
        variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
    if (password) {
        info.inputType = (info.inputType or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS) and
            InputType.TYPE_TEXT_FLAG_AUTO_CORRECT.inv()
    }
}

/**
 * A field for a secret: a master password, a password, a 2FA secret. Hidden
 * until the user shows it; a password keyboard, no autocorrect, no
 * suggestions, nothing to copy out of it.
 */
@Composable
fun SecretField(
    state: TextFieldState,
    label: String,
    modifier: Modifier = Modifier,
    supportingText: String? = null,
    error: String? = null,
    enabled: Boolean = true,
    imeAction: ImeAction = ImeAction.Done,
    onImeAction: KeyboardActionHandler? = null,
) {
    var shown by remember { mutableStateOf(false) }
    OutlinedSecureTextField(
        state = state,
        // What accessibility services read: dots, as Android's own password
        // fields report, not the text (Compose would hand it over as is).
        modifier =
            modifier.fillMaxWidth().semantics {
                editableText = AnnotatedString(MASK.repeat(state.text.length))
            },
        enabled = enabled,
        label = { Text(label) },
        supportingText = (error ?: supportingText)?.let { { Text(it) } },
        isError = error != null,
        textObfuscationMode = if (shown) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
        keyboardOptions =
            KeyboardOptions(
                keyboardType = KeyboardType.Password,
                autoCorrectEnabled = false,
                imeAction = imeAction,
            ),
        onKeyboardAction = onImeAction,
        trailingIcon = {
            val description = stringResource(if (shown) R.string.action_hide else R.string.action_show, label)
            val stateText = stringResource(if (shown) R.string.state_shown else R.string.state_hidden)
            IconButton(
                onClick = { shown = !shown },
                modifier = Modifier.semantics { stateDescription = stateText },
            ) {
                Icon(
                    painter = painterResource(if (shown) R.drawable.ic_visibility_off else R.drawable.ic_visibility),
                    contentDescription = description,
                )
            }
        },
    )
}

private const val MASK = "\u2022"

/** A plain field of an entry: title, user name, website, notes. */
@Composable
fun PlainField(
    state: TextFieldState,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    supportingText: String? = null,
    error: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
    capitalization: KeyboardCapitalization = KeyboardCapitalization.None,
    singleLine: Boolean = true,
    imeAction: ImeAction = ImeAction.Next,
) {
    OutlinedTextField(
        state = state,
        modifier = modifier.fillMaxWidth(),
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        supportingText = (error ?: supportingText)?.let { { Text(it) } },
        isError = error != null,
        keyboardOptions =
            KeyboardOptions(
                keyboardType = keyboardType,
                capitalization = capitalization,
                autoCorrectEnabled = keyboardType == KeyboardType.Text && !singleLine,
                imeAction = if (singleLine) imeAction else ImeAction.Default,
            ),
        lineLimits = if (singleLine) TextFieldLineLimits.SingleLine else TextFieldLineLimits.MultiLine(minHeightInLines = 3),
    )
}
