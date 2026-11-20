package dev.sshkeymanager.android.logins

import androidx.annotation.StringRes
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.LoginInput
import dev.sshkeymanager.android.ui.coreCode
import dev.sshkeymanager.android.ui.messageFor
import dev.sshkeymanager.android.vault.VaultSession
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** What happens to an entry's 2FA secret on save. */
enum class OtpChoice { KEEP, REPLACE, REMOVE }

data class EditState(
    val loading: Boolean,
    val saving: Boolean = false,
    /** An existing entry has a password: an empty field keeps it. */
    val hasPassword: Boolean = false,
    /** An existing entry has a 2FA secret. */
    val hasOtp: Boolean = false,
    val otpChoice: OtpChoice = OtpChoice.KEEP,
    @param:StringRes val titleError: Int? = null,
    @param:StringRes val otpError: Int? = null,
    @param:StringRes val error: Int? = null,
)

/**
 * A new entry (`id` null) or an existing one. An existing password is never
 * loaded into the form: the field starts empty and a new password replaces
 * it. Whatever is typed lives here only while the screen is up.
 */
class EditViewModel(private val id: String?, private val session: VaultSession) : ViewModel() {
    val title = TextFieldState()
    val username = TextFieldState()
    val url = TextFieldState()
    val notes = TextFieldState()
    val password = TextFieldState()
    val otp = TextFieldState()

    private val state = MutableStateFlow(EditState(loading = id != null))
    val uiState: StateFlow<EditState> = state.asStateFlow()

    private val saves = Channel<String>(Channel.BUFFERED)

    /** The entry's id once saved. */
    val saved = saves.receiveAsFlow()

    val isNew: Boolean get() = id == null

    init {
        if (id != null) {
            viewModelScope.launch {
                try {
                    val detail = session.read { login(id) }
                    title.setTextAndPlaceCursorAtEnd(detail.login.title)
                    username.setTextAndPlaceCursorAtEnd(detail.login.username)
                    url.setTextAndPlaceCursorAtEnd(detail.login.url)
                    notes.setTextAndPlaceCursorAtEnd(detail.notes)
                    state.update {
                        it.copy(loading = false, hasPassword = detail.login.hasPassword, hasOtp = detail.login.hasOtp)
                    }
                } catch (failure: Exception) {
                    state.update { it.copy(loading = false, error = messageFor(failure)) }
                }
            }
        }
    }

    fun chooseOtp(choice: OtpChoice) {
        if (choice != OtpChoice.REPLACE) otp.clearText()
        state.update { it.copy(otpChoice = choice, otpError = null) }
    }

    /** Takes a password from the generator. */
    fun usePassword(generated: String) = password.setTextAndPlaceCursorAtEnd(generated)

    fun save() {
        val current = state.value
        if (current.saving || current.loading) return
        if (title.text.isBlank()) {
            state.update { it.copy(titleError = R.string.edit_title_required) }
            return
        }
        val input = input(current)
        state.update { it.copy(saving = true, titleError = null, otpError = null, error = null) }
        viewModelScope.launch {
            try {
                val saved =
                    if (id == null) {
                        session.change { addLogin(input) }
                    } else {
                        session.change { updateLogin(id, input) }
                        id
                    }
                wipe()
                saves.send(saved)
            } catch (failure: Exception) {
                val otpRefused = failure.coreCode == ErrorCode.INVALID_INPUT && !input.otp.isNullOrEmpty()
                state.update {
                    it.copy(
                        saving = false,
                        otpError = if (otpRefused) R.string.edit_otp_invalid else null,
                        error = if (otpRefused) null else messageFor(failure),
                    )
                }
            }
        }
    }

    private fun input(current: EditState): LoginInput {
        val typedOtp = otp.text.toString().trim()
        val otpChange =
            when {
                !current.hasOtp -> typedOtp.ifEmpty { null }
                current.otpChoice == OtpChoice.REMOVE -> ""
                current.otpChoice == OtpChoice.REPLACE -> typedOtp.ifEmpty { null }
                else -> null
            }
        return LoginInput(
            title = title.text.toString().trim(),
            username = username.text.toString().trim(),
            url = url.text.toString().trim(),
            notes = notes.text.toString(),
            // An empty field keeps the current password (none for a new entry).
            password = password.text.toString().ifEmpty { null },
            otp = otpChange,
        )
    }

    private fun wipe() {
        password.clearText()
        otp.clearText()
    }

    override fun onCleared() {
        wipe()
        listOf(title, username, url, notes).forEach(TextFieldState::clearText)
    }
}
