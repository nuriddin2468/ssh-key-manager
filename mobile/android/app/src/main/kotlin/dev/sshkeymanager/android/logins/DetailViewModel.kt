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
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** A 2FA code as fetched: valid `validFor` more seconds from `fetchedAt` (the clock that counts sleep). */
data class OtpShown(val code: String, val validFor: Int, val fetchedAt: Long) {
    /** Seconds left at `now`. */
    fun remaining(now: Long): Int = (validFor - ((now - fetchedAt).coerceAtLeast(0) / 1000).toInt()).coerceAtLeast(0)

    /** Whether it has run out at `now`, with a little slack so that the next one is really new. */
    fun expired(now: Long): Boolean = now >= fetchedAt + validFor * 1000L + DetailViewModel.REFRESH_SLACK_MILLIS

    override fun toString() = "OtpShown(validFor=$validFor, fetchedAt=$fetchedAt)"
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
) {
    override fun toString() =
        "DetailState(entry=${detail?.login?.id}, passwordShown=${shownPassword != null}, otp=$otp, " +
            "otpUnreadable=$otpUnreadable, gone=$gone, error=$error)"
}

/**
 * One entry. Its password is read from the core when the user asks to see
 * it and dropped when it's hidden, [SHOWN_MILLIS] after it was shown, when
 * the screen goes and when the vault locks; copying reads it again and
 * holds it nowhere here. The 2FA code is held while it is on screen.
 *
 * Times are on `now`, a clock that keeps counting while the phone sleeps
 * (`SystemClock.elapsedRealtime`): coroutine delays don't, so a phone that
 * slept with the screen up would otherwise wake to an old code or a password
 * still shown. The screen calls [refresh] every second and as it comes back.
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

    /** When the password was shown. */
    private var shownAt: Long? = null

    /** Reading the password to show it; a hide before it arrives cancels it. */
    private var showing: Job? = null

    /**
     * The entry's 2FA secret can't make codes: not asked again until the
     * entry changes (an edit may fix it).
     */
    private var otpUnreadable = false

    /** After a failure that may pass (the vault busy or a file unreadable for a moment): when to ask again. */
    private var otpRetryAt: Long? = null

    init {
        viewModelScope.launch { session.changes.collect { load() } }
    }

    /**
     * Reads the entry, at first and after every change saved. When the entry
     * itself changed (an edit may have replaced or fixed its 2FA secret), its
     * code is asked for afresh.
     */
    private suspend fun load() {
        try {
            val detail = session.read { login(id) }
            val changed = detail != state.value.detail
            if (changed) {
                otpUnreadable = false
                otpRetryAt = null
            }
            state.update {
                it.copy(
                    detail = detail,
                    otp = if (changed) null else it.otp,
                    otpUnreadable = otpUnreadable,
                    gone = false,
                    error = null,
                )
            }
        } catch (failure: Exception) {
            if (failure.coreCode == ErrorCode.NOT_FOUND) {
                state.update { DetailState(gone = true) }
            } else {
                state.update { it.copy(error = messageFor(failure)) }
            }
        }
    }

    /**
     * Shows the password, or hides it again. A hide wins over a show still
     * on its way (the core's thread may be busy with a save): the password
     * read for it is dropped.
     */
    fun togglePassword() {
        if (showing?.isActive == true || state.value.shownPassword != null) {
            hidePassword()
            return
        }
        showing =
            viewModelScope.launch {
                try {
                    val password = session.read { password(id) }
                    ensureActive()
                    shownAt = now()
                    state.update { it.copy(shownPassword = password) }
                } catch (failure: CancellationException) {
                    throw failure
                } catch (failure: Exception) {
                    state.update { it.copy(error = messageFor(failure)) }
                }
            }
    }

    private fun hidePassword() {
        showing?.cancel()
        showing = null
        shownAt = null
        state.update { it.copy(shownPassword = null) }
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

    /** Copies the code valid now, fetched afresh: the one on screen may have run out while the phone slept. */
    fun copyOtp(label: String) {
        viewModelScope.launch {
            try {
                val code = fetchOtp()
                notices.send(Notice.Copied(label, clipboard.copy(label, code.code, secret = true)))
            } catch (failure: Exception) {
                notices.send(Notice.Text(messageFor(failure)))
            }
        }
    }

    /**
     * Brings what the screen shows up to date on the clock that counts
     * sleep: hides a password shown [SHOWN_MILLIS] ago, fetches a new 2FA
     * code when the current one ran out.
     */
    suspend fun refresh() {
        shownAt?.let { if (now() - it >= SHOWN_MILLIS) hidePassword() }
        val hasOtp = state.value.detail?.login?.hasOtp == true
        if (!hasOtp || otpUnreadable) return
        if (otpRetryAt?.let { now() < it } == true) return
        val otp = state.value.otp
        if (otp == null || otp.expired(now())) {
            try {
                fetchOtp()
                otpRetryAt = null
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Exception) {
                // An unreadable secret stays so until the entry changes;
                // anything else is asked again a little later.
                otpUnreadable = failure.coreCode == ErrorCode.PARSE
                otpRetryAt = if (otpUnreadable) null else now() + OTP_RETRY_MILLIS
                state.update { it.copy(otp = null, otpUnreadable = otpUnreadable) }
            }
        }
    }

    /** [refresh] at once: the screen came back, maybe after the phone slept. */
    fun onScreen() {
        viewModelScope.launch { refresh() }
    }

    /** [refresh] every second while the screen is up; the 2FA code goes with the screen. */
    suspend fun follow() {
        try {
            while (true) {
                refresh()
                delay(TICK_MILLIS)
            }
        } finally {
            state.update { it.copy(otp = null) }
        }
    }

    private suspend fun fetchOtp(): OtpShown {
        val code = session.read { otpCode(id) }
        val shown = OtpShown(code.code, code.validFor.toInt(), now())
        state.update { it.copy(otp = shown, otpUnreadable = false) }
        return shown
    }

    fun trash() {
        val title = state.value.detail?.login?.title ?: return
        viewModelScope.launch {
            try {
                session.change { trashLogin(id) }
                hidePassword()
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
        showing?.cancel()
        shownAt = null
        state.value = DetailState()
    }

    companion object {
        /** After a code runs out, so that the next one is really new. */
        const val REFRESH_SLACK_MILLIS = 600L

        /** A shown password left on screen hides itself after this. */
        const val SHOWN_MILLIS = 30_000L

        /** How often the screen is brought up to date. */
        const val TICK_MILLIS = 1_000L

        /** How long after a failure that may pass the 2FA code is asked for again. */
        const val OTP_RETRY_MILLIS = 5_000L
    }
}
