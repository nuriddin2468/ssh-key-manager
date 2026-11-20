package dev.sshkeymanager.android.logins

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.PromptException
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.core.Login
import dev.sshkeymanager.android.core.ProjectLabel
import dev.sshkeymanager.android.ui.Notice
import dev.sshkeymanager.android.ui.messageFor
import dev.sshkeymanager.android.vault.FingerprintOffer
import dev.sshkeymanager.android.vault.VaultSession
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Which entries the list shows. */
sealed interface Filter {
    data object All : Filter

    /** Those with a 2FA code. */
    data object Otp : Filter

    data class Project(val id: String) : Filter

    /** A folder of a KeePass file (vaults made by the app have none). */
    data class Group(val path: String) : Filter

    data object Trash : Filter
}

data class LoginsState(
    val loading: Boolean = true,
    val all: List<Login> = emptyList(),
    val projects: List<ProjectLabel> = emptyList(),
    val query: String = "",
    val filter: Filter = Filter.All,
    @param:StringRes val error: Int? = null,
) {
    /** The folders entries outside the recycle bin are in. */
    val groups: List<String> = all.filter { !it.inTrash }.mapNotNull { it.group }.distinct().sorted()

    val hasTrash: Boolean = all.any { it.inTrash }

    val hasOtp: Boolean = all.any { it.hasOtp && !it.inTrash }

    /** What the list shows: the filter's entries that match the search. */
    val shown: List<Login> = all.filter { matches(it) }

    private fun matches(login: Login): Boolean {
        val inFilter =
            when (filter) {
                Filter.All -> !login.inTrash
                Filter.Otp -> !login.inTrash && login.hasOtp
                is Filter.Project -> !login.inTrash && projects.any { it.id == filter.id && login.id in it.logins }
                is Filter.Group -> !login.inTrash && login.group == filter.path
                Filter.Trash -> login.inTrash
            }
        if (!inFilter) return false
        val words = query.trim().lowercase().split(Regex("\\s+")).filter(String::isNotEmpty)
        if (words.isEmpty()) return true
        val text = listOfNotNull(login.title, login.username, login.url, login.host).joinToString(" ").lowercase()
        return words.all(text::contains)
    }
}

/** The list of entries: search, filters, and the fingerprint offer. Holds no secret. */
class LoginsViewModel(private val session: VaultSession) : ViewModel() {
    private val state = MutableStateFlow(LoginsState())
    val uiState: StateFlow<LoginsState> = state.asStateFlow()

    val fingerprintOffer: StateFlow<FingerprintOffer?> = session.fingerprintOffer

    private val notices = Channel<Notice>(Channel.BUFFERED)
    val notice = notices.receiveAsFlow()

    init {
        viewModelScope.launch {
            // Read again after every change saved, from any screen.
            session.changes.collect { load() }
        }
    }

    private suspend fun load() {
        try {
            val (logins, projects) = session.read { logins() to projects() }
            state.update { current ->
                val filter =
                    when (val filter = current.filter) {
                        is Filter.Project -> filter.takeIf { projects.any { it.id == filter.id } }
                        else -> filter
                    } ?: Filter.All
                current.copy(loading = false, all = logins, projects = projects, filter = filter, error = null)
            }
        } catch (failure: Exception) {
            state.update { it.copy(loading = false, error = messageFor(failure)) }
        }
    }

    fun search(query: String) = state.update { it.copy(query = query) }

    fun filter(filter: Filter) = state.update { it.copy(filter = filter) }

    fun lock() = session.lock()

    fun declineFingerprint() = session.declineFingerprint()

    fun enableFingerprint(prompter: Prompter, text: PromptText) {
        viewModelScope.launch {
            try {
                session.enableFingerprint(prompter, text)
                notices.send(Notice.Text(R.string.fingerprint_on))
            } catch (failure: PromptException) {
                if (failure.reason != PromptException.Reason.CANCELLED) {
                    notices.send(Notice.Text(R.string.error_other))
                }
            } catch (failure: Exception) {
                notices.send(Notice.Text(messageFor(failure)))
            }
        }
    }
}
