package dev.sshkeymanager.android.home

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.PasswordOptions
import dev.sshkeymanager.android.core.coreVersion
import dev.sshkeymanager.android.core.generatePassword
import dev.sshkeymanager.android.core.passwordStrength
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** What the home screen asks of the Rust core; tests stand in for it. */
interface Core {
    fun version(): String

    /** A password with the desktop app's default options. */
    fun generatePassword(): String

    /** zxcvbn's score, 0 to 4. */
    fun strength(password: String): Int
}

/** The Rust core, through the bindings UniFFI writes. */
object RustCore : Core {
    override fun version(): String = coreVersion()

    override fun generatePassword(): String = generatePassword(PasswordOptions())

    override fun strength(password: String): Int = passwordStrength(password).score.toInt()
}

data class Generated(val password: String, val score: Int)

data class HomeState(
    val version: String,
    val generated: Generated? = null,
    @param:StringRes val error: Int? = null,
)

/**
 * The home screen: the core's version and the vault's password generator.
 * The core answers in well under a millisecond, so it is called right away.
 */
class HomeViewModel(private val core: Core = RustCore) : ViewModel() {
    private val state = MutableStateFlow(HomeState(version = core.version()))
    val uiState: StateFlow<HomeState> = state.asStateFlow()

    fun generate() {
        try {
            val password = core.generatePassword()
            state.update { it.copy(generated = Generated(password, core.strength(password)), error = null) }
        } catch (error: CoreException) {
            state.update { it.copy(error = errorMessage(error)) }
        }
    }
}

/** The words for a zxcvbn score. */
@StringRes
fun strengthLabel(score: Int): Int =
    when {
        score <= 0 -> R.string.strength_0
        score == 1 -> R.string.strength_1
        score == 2 -> R.string.strength_2
        score == 3 -> R.string.strength_3
        else -> R.string.strength_4
    }

/** What to tell the user when the core can't make a password. */
@StringRes
fun errorMessage(error: CoreException): Int =
    when ((error as? CoreException.Failed)?.code) {
        ErrorCode.INVALID_INPUT -> R.string.error_settings
        else -> R.string.error_other
    }
