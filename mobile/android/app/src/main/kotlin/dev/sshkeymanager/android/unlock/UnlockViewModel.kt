package dev.sshkeymanager.android.unlock

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.FingerprintException
import dev.sshkeymanager.android.biometric.PromptException
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.ui.UiText
import dev.sshkeymanager.android.ui.messageFor
import dev.sshkeymanager.android.vault.VaultSession
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class UnlockState(
    val busy: Boolean = false,
    val error: UiText? = null,
)

/**
 * The lock screen: the master password, or the fingerprint when fingerprint
 * unlock may open the vault. The typed password lives here only until the
 * vault opens or the screen goes.
 */
class UnlockViewModel(private val session: VaultSession) : ViewModel() {
    val password = TextFieldState()

    private val state = MutableStateFlow(UnlockState())
    val uiState: StateFlow<UnlockState> = state.asStateFlow()

    fun unlock() {
        val typed = password.text.toString()
        if (typed.isEmpty() || state.value.busy) return
        state.value = UnlockState(busy = true)
        viewModelScope.launch {
            try {
                session.unlock(typed)
                password.clearText()
                state.value = UnlockState()
            } catch (failure: Exception) {
                state.value = UnlockState(error = UiText.Res(messageFor(failure)))
            }
        }
    }

    fun unlockWithFingerprint(prompter: Prompter, text: PromptText) {
        if (state.value.busy) return
        state.value = UnlockState(busy = true)
        viewModelScope.launch {
            state.value =
                try {
                    session.unlockWithFingerprint(prompter, text)
                    password.clearText()
                    UnlockState()
                } catch (failure: PromptException) {
                    when (failure.reason) {
                        PromptException.Reason.CANCELLED -> UnlockState()
                        PromptException.Reason.LOCKED_OUT -> UnlockState(error = UiText.Res(R.string.error_fingerprint_lockout))
                        PromptException.Reason.FAILED ->
                            UnlockState(error = failure.message?.let(UiText::Plain) ?: UiText.Res(R.string.error_other))
                    }
                } catch (_: FingerprintException) {
                    // The lock screen says why, from the session's state.
                    UnlockState()
                } catch (failure: Exception) {
                    UnlockState(error = UiText.Res(messageFor(failure)))
                }
        }
    }

    override fun onCleared() = password.clearText()
}
