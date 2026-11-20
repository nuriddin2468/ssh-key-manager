package dev.sshkeymanager.android.generator

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.clipboard.Clipboard
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.InternalException
import dev.sshkeymanager.android.core.PasswordOptions
import dev.sshkeymanager.android.ui.Notice
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update

data class Generated(val password: String, val score: Int)

data class GeneratorState(
    val options: PasswordOptions = PasswordOptions(),
    val generated: Generated? = null,
    @param:StringRes val error: Int? = null,
)

/**
 * The password generator: the core's, with the desktop app's defaults. A
 * new password is made at once and whenever an option changes; the core
 * answers in well under a millisecond.
 */
class GeneratorViewModel(
    private val tools: PasswordTools = RustPasswordTools,
    private val clipboard: Clipboard? = null,
) : ViewModel() {
    private val state = MutableStateFlow(GeneratorState())
    val uiState: StateFlow<GeneratorState> = state.asStateFlow()

    private val notices = Channel<Notice>(Channel.BUFFERED)
    val notice = notices.receiveAsFlow()

    init {
        generate()
    }

    fun generate() {
        try {
            val password = tools.generate(state.value.options)
            state.update { it.copy(generated = Generated(password, tools.strength(password)), error = null) }
        } catch (error: CoreException) {
            val invalid = (error as? CoreException.Failed)?.code == ErrorCode.INVALID_INPUT
            state.update { it.copy(error = if (invalid) R.string.error_settings else R.string.error_other) }
        } catch (_: InternalException) {
            // A panic in the core, unwound into an exception by UniFFI.
            state.update { it.copy(error = R.string.error_other) }
        }
    }

    fun setOptions(options: PasswordOptions) {
        state.update { it.copy(options = options) }
        generate()
    }

    fun copy(label: String) {
        val password = state.value.generated?.password ?: return
        val seconds = clipboard?.copy(label, password, secret = true)
        notices.trySend(Notice.Copied(label, seconds))
    }

    override fun onCleared() {
        state.update { it.copy(generated = null) }
    }
}
