package dev.sshkeymanager.android.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.PromptException
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.ui.Notice
import dev.sshkeymanager.android.ui.messageFor
import dev.sshkeymanager.android.vault.LockAfter
import dev.sshkeymanager.android.vault.LockSettings
import dev.sshkeymanager.android.vault.VaultSession
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SettingsState(
    val lockAfter: LockAfter,
    val fingerprint: Availability,
    val fingerprintOn: Boolean,
    val busy: Boolean = false,
)

class SettingsViewModel(
    private val session: VaultSession,
    private val settings: LockSettings,
    val version: String,
) : ViewModel() {
    private val state =
        MutableStateFlow(
            session.fingerprintStatus().let { (availability, on) ->
                SettingsState(settings.lockAfter, availability, on)
            },
        )
    val uiState: StateFlow<SettingsState> = state.asStateFlow()

    private val notices = Channel<Notice>(Channel.BUFFERED)
    val notice = notices.receiveAsFlow()

    fun setLockAfter(value: LockAfter) {
        settings.lockAfter = value
        state.update { it.copy(lockAfter = value) }
    }

    fun setFingerprint(on: Boolean, prompter: Prompter, text: PromptText) {
        if (state.value.busy) return
        state.update { it.copy(busy = true) }
        viewModelScope.launch {
            try {
                if (on) session.enableFingerprint(prompter, text) else session.disableFingerprint()
                if (on) notices.send(Notice.Text(R.string.fingerprint_on))
            } catch (failure: PromptException) {
                if (failure.reason != PromptException.Reason.CANCELLED) notices.send(Notice.Text(R.string.error_other))
            } catch (failure: Exception) {
                notices.send(Notice.Text(messageFor(failure)))
            }
            val (availability, enabled) = session.fingerprintStatus()
            state.update { it.copy(fingerprint = availability, fingerprintOn = enabled, busy = false) }
        }
    }

    fun lockNow() = session.lock()
}
