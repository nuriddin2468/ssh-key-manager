package dev.sshkeymanager.android.setup

import androidx.annotation.StringRes
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.generator.PasswordTools
import dev.sshkeymanager.android.ui.messageFor
import dev.sshkeymanager.android.vault.VaultSession
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SetupState(
    val busy: Boolean = false,
    @param:StringRes val error: Int? = null,
)

/**
 * Setting this phone's master password for the vault a computer sent. The
 * two fields live here while the screen is up and are wiped once the vault
 * opens or the screen goes.
 */
class SetupViewModel(private val session: VaultSession, private val tools: PasswordTools) : ViewModel() {
    val master = TextFieldState()
    val repeat = TextFieldState()

    private val state = MutableStateFlow(SetupState())
    val uiState: StateFlow<SetupState> = state.asStateFlow()

    /** zxcvbn's score of what is typed, 0 to 4. */
    fun strength(password: CharSequence): Int = if (password.isEmpty()) 0 else tools.strength(password.toString())

    fun submit() {
        if (state.value.busy) return
        val password = master.text.toString()
        val error =
            when {
                password.isEmpty() -> R.string.setup_empty
                password != repeat.text.toString() -> R.string.setup_mismatch
                else -> null
            }
        if (error != null) {
            state.value = SetupState(error = error)
            return
        }
        state.value = SetupState(busy = true)
        viewModelScope.launch {
            try {
                session.setMasterPassword(password)
                wipe()
                state.value = SetupState()
            } catch (failure: Exception) {
                state.value = SetupState(error = messageFor(failure))
            }
        }
    }

    private fun wipe() {
        master.clearText()
        repeat.clearText()
    }

    override fun onCleared() = wipe()
}
