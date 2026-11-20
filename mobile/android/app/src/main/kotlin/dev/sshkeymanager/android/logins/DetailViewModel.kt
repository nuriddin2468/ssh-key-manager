package dev.sshkeymanager.android.logins

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.clipboard.Clipboard
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.LoginDetail
import dev.sshkeymanager.android.ui.Notice
import dev.sshkeymanager.android.ui.coreCode
import dev.sshkeymanager.android.ui.messageFor
import dev.sshkeymanager.android.vault.VaultSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** A 2FA code as fetched: valid `validFor` more seconds from `fetchedAt` (elapsed-time clock). */
data class OtpShown(val code: String, val validFor: Int, val fetchedAt: Long) {
    /** Seconds left at `now`. */
    fun remaining(now: Long): Int = (validFor - ((now - fetchedAt).coerceAtLeast(0) / 1000).toInt()).coerceAtLeast(0)
}

data class DetailState(
    val detail: LoginDetail? = null,
    /** The password, only while the user has it shown. */
    val shownPassword: String? = null,
    val otp: OtpShown? = null,
    val otpUnreadable: Boolean = false,
    /** The entry is no longer in the vault. */
    val gone: Boolean = false,
    @param:StringRes val error: Int? = null,
)

/**
 * One entry. Its password is read from the core when the user asks to see
 * it and dropped when it's hidden, when the screen goes and when the vault
 * locks; copying reads it again and holds it nowhere here. The 2FA code is
 * held while it is on screen.
 */
class DetailViewModel(
    private val id: String,
    private val session: VaultSession,
    private val clipboard: Clipboard,
    private val now: () -> Long,
) : ViewModel() {
    private val state = MutableStateFlow(DetailState())
    val uiState: StateFlow<DetailState> = state.asStateFlow()

    private val notices = Channel<Notice>(Channel.BUFFERED)
    val notice = notices.receiveAsFlow()

    init {
        viewModelScope.launch { session.changes.collect { load() } }
    }

    private suspend fun load() {
        try {
            val detail = session.read { login(id) }
            state.update { it.copy(detail = detail, gone = false, error = null) }
        } catch (failure: Exception) {
            if (failure.coreCode == ErrorCode.NOT_FOUND) {
                state.update { DetailState(gone = true) }
            } else {
                state.update { it.copy(error = messageFor(failure)) }
            }
        }
    }

    private var hideLater: Job? = null

    /** Shows the password, or hides it again. Shown, it hides itself after [SHOWN_MILLIS]. */
    fun togglePassword() {
        hideLater?.cancel()
        if (state.value.shownPassword != null) {
            state.update { it.copy(shownPassword = null) }
            return
        }
        hideLater =
            viewModelScope.launch {
                try {
                    val password = session.read { password(id) }
                    state.update { it.copy(shownPassword = password) }
                    delay(SHOWN_MILLIS)
                    state.update { it.copy(shownPassword = null) }
                } catch (failure: CancellationException) {
                    throw failure
                } catch (failure: Exception) {
                    state.update { it.copy(error = messageFor(failure)) }
                }
            }
    }

    fun copyPassword(label: String) {
        viewModelScope.launch {
            try {
                val password = session.read { password(id) }
                notices.send(Notice.Copied(label, clipboard.copy(label, password, secret = true)))
            } catch (failure: Exception) {
                notices.send(Notice.Text(messageFor(failure)))
            }
        }
    }

    fun copyUsername(label: String) = copyPlain(label, state.value.detail?.login?.username)

    fun copyWebsite(label: String) = copyPlain(label, state.value.detail?.login?.url)

    private fun copyPlain(label: String, text: String?) {
        if (text.isNullOrEmpty()) return
        notices.trySend(Notice.Copied(label, clipboard.copy(label, text, secret = false)))
    }

    fun copyOtp(label: String) {
        val code = state.value.otp?.code ?: return
        notices.trySend(Notice.Copied(label, clipboard.copy(label, code, secret = true)))
    }

    /**
     * Keeps the 2FA code current while the screen shows it: fetched now and
     * again just after each one runs out. Runs until cancelled.
     */
    suspend fun followOtp() {
        try {
            while (true) {
                val code =
                    try {
                        session.read { otpCode(id) }
                    } catch (failure: Exception) {
                        state.update { it.copy(otp = null, otpUnreadable = failure.coreCode == ErrorCode.PARSE) }
                        return
                    }
                val validFor = code.validFor.toInt()
                state.update { it.copy(otp = OtpShown(code.code, validFor, now()), otpUnreadable = false) }
                delay(validFor * 1000L + REFRESH_SLACK_MILLIS)
            }
        } finally {
            state.update { it.copy(otp = null) }
        }
    }

    fun trash() {
        val title = state.value.detail?.login?.title ?: return
        viewModelScope.launch {
            try {
                session.change { trashLogin(id) }
                state.update { it.copy(shownPassword = null) }
                notices.send(Notice.Text(R.string.moved_to_trash, title))
            } catch (failure: Exception) {
                notices.send(Notice.Text(messageFor(failure)))
            }
        }
    }

    fun restore() {
        val title = state.value.detail?.login?.title ?: return
        viewModelScope.launch {
            try {
                session.change { restoreLogin(id) }
                notices.send(Notice.Text(R.string.restored, title))
            } catch (failure: Exception) {
                notices.send(Notice.Text(messageFor(failure)))
            }
        }
    }

    override fun onCleared() {
        state.value = DetailState()
    }

    companion object {
        /** After a code runs out, so that the next one is really new. */
        const val REFRESH_SLACK_MILLIS = 600L

        /** A shown password left on screen hides itself after this. */
        const val SHOWN_MILLIS = 30_000L
    }
}
