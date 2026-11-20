package dev.sshkeymanager.android.vault

import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.FingerprintException
import dev.sshkeymanager.android.biometric.FingerprintUnlock
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.VaultStatus
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Why the vault locked. */
enum class LockReason {
    /** The user locked it. */
    MANUAL,

    /** [LockAfter] passed without use. */
    IDLE,

    /** The core found it locked, or the app restarted. */
    OTHER,
}

/** What fingerprint unlock can do on the lock screen. */
enum class FingerprintState {
    OFF,

    /** The fingerprint may open the vault now. */
    READY,

    /** On, but the master password first: the phone restarted. */
    AFTER_RESTART,

    /** On, but the master password first: once a week. */
    WEEKLY,

    /** Turned off because a fingerprint was added; the master password, then turn it on again. */
    CHANGED,
}

/** Where the vault stands, as the app shows it. */
sealed interface VaultState {
    data object Loading : VaultState

    /** No vault: it comes from a computer. */
    data object Missing : VaultState

    /** A vault came from a computer; the phone's master password is next. */
    data object Received : VaultState

    data class Locked(val reason: LockReason, val fingerprint: FingerprintState) : VaultState

    data object Unlocked : VaultState

    /** The vault's files can't be read (`code` from the core). */
    data class Unreadable(val code: ErrorCode?) : VaultState
}

/** Fingerprint unlock offered after the master password opened the vault. */
enum class FingerprintOffer {
    /** It has never been on. */
    NEW,

    /** It was turned off because a fingerprint was added. */
    AGAIN,
}

/**
 * The vault while the app runs: whether it is open, opening and locking it,
 * and running the app's reads and changes on it off the main thread.
 *
 * It locks itself [LockAfter] after the user last touched the app ([touch]),
 * whether the app stayed on screen (a timer, [appForeground]) or not (a
 * [Deadline] job, [appBackground]). Locking drops the open vault in the core.
 */
class VaultSession(
    private val vault: VaultBridge,
    private val fingerprint: FingerprintUnlock,
    private val policy: PasswordPolicy,
    private val settings: LockSettings,
    private val autoLock: AutoLock,
    private val deadlines: Deadlines,
    private val scope: CoroutineScope,
    private val io: CoroutineDispatcher,
    /** Called whenever the vault locks: clears a copied secret. */
    private val onLock: () -> Unit = {},
) {
    private val state = MutableStateFlow<VaultState>(VaultState.Loading)
    val vaultState: StateFlow<VaultState> = state.asStateFlow()

    private val changeCount = MutableStateFlow(0)

    /** Grows with every change saved, for screens to read the vault again. */
    val changes: StateFlow<Int> = changeCount.asStateFlow()

    private val offered = MutableStateFlow<FingerprintOffer?>(null)
    val fingerprintOffer: StateFlow<FingerprintOffer?> = offered.asStateFlow()

    /** The open vault's id, for fingerprint unlock. */
    @Volatile private var vaultId: String? = null

    private var ticker: Job? = null

    /** Reads where the vault stands. */
    suspend fun load() {
        state.value = withContext(io) { current(LockReason.OTHER) }
    }

    /** Reads where the vault stands the first time a screen asks, not again when the screen is made anew. */
    suspend fun start() {
        if (state.value == VaultState.Loading) load()
    }

    /** Sets this phone's master password for the vault it received, which opens. */
    suspend fun setMasterPassword(master: String) =
        withContext(io) {
            vault.setMasterPassword(master)
            policy.passwordTyped()
            opened(offer = FingerprintOffer.NEW)
        }

    /** Opens the vault with the master password; throws `CoreException`. */
    suspend fun unlock(master: String) =
        withContext(io) {
            val changed = (state.value as? VaultState.Locked)?.fingerprint == FingerprintState.CHANGED
            vault.unlock(master)
            policy.passwordTyped()
            fingerprint.tidy()
            opened(offer = if (changed) FingerprintOffer.AGAIN else FingerprintOffer.NEW)
        }

    /**
     * Opens the vault after a fingerprint; throws `PromptException`,
     * `FingerprintException` (then the lock screen shows why) or
     * `CoreException`.
     */
    suspend fun unlockWithFingerprint(prompter: Prompter, text: PromptText) {
        try {
            fingerprint.unlock(prompter, text)
        } catch (error: FingerprintException) {
            state.update { current ->
                if (current is VaultState.Locked) current.copy(fingerprint = fingerprintState(vaultId)) else current
            }
            throw error
        }
        withContext(io) { opened(offer = null) }
    }

    /** Whether fingerprint unlock is on for the open vault, and possible on this phone. */
    fun fingerprintStatus(): Pair<Availability, Boolean> = fingerprint.availability() to fingerprint.isOn(vaultId)

    /** Turns fingerprint unlock on, after a fingerprint; throws `PromptException` or `CoreException`. */
    suspend fun enableFingerprint(prompter: Prompter, text: PromptText) {
        guard { fingerprint.enable(prompter, text) }
        offered.value = null
    }

    suspend fun disableFingerprint() = guard { fingerprint.disable() }

    fun declineFingerprint() {
        fingerprint.declineOffer()
        offered.value = null
    }

    /** Locks the vault: the core drops it from memory. */
    fun lock(reason: LockReason = LockReason.MANUAL) {
        vault.lock()
        deadlines.cancel(Deadline.LOCK)
        offered.value = null
        onLock()
        if (state.value is VaultState.Unlocked) {
            state.value = VaultState.Locked(reason, fingerprintState(vaultId))
        }
    }

    /** Runs a read of the open vault off the main thread. */
    suspend fun <T> read(work: VaultBridge.() -> T): T = withContext(io) { guard { vault.work() } }

    /** Runs a change of the open vault off the main thread; the core saves it. */
    suspend fun <T> change(work: VaultBridge.() -> T): T = read(work).also { changeCount.update { it + 1 } }

    /** The user did something in the app. */
    fun touch() = autoLock.touch()

    /** The app came on screen: locks if it was away too long, and watches for the next time. */
    fun appForeground() {
        deadlines.cancel(Deadline.LOCK)
        lockIfDue()
        ticker?.cancel()
        ticker =
            scope.launch {
                while (isActive) {
                    delay(TICK_MILLIS)
                    lockIfDue()
                }
            }
    }

    /** The app left the screen: the vault locks in the background when its time comes. */
    fun appBackground() {
        ticker?.cancel()
        ticker = null
        if (vault.isUnlocked()) scheduleLock()
    }

    /** A [Deadline.LOCK] job ran. */
    fun lockDeadline() {
        if (!vault.isUnlocked()) return
        if (autoLock.isDue(settings.lockAfter)) {
            lock(LockReason.IDLE)
        } else {
            scheduleLock()
        }
    }

    /** Locks if [LockAfter] has passed since the last use. */
    fun lockIfDue() {
        if (state.value is VaultState.Unlocked && autoLock.isDue(settings.lockAfter)) lock(LockReason.IDLE)
    }

    /** A job a moment after the vault is due to lock, so that it is due when the job runs. */
    private fun scheduleLock() = deadlines.schedule(Deadline.LOCK, autoLock.remaining(settings.lockAfter) + JOB_SLACK_MILLIS)

    private fun opened(offer: FingerprintOffer?) {
        vaultId = vault.info().vaultId
        autoLock.touch()
        state.value = VaultState.Unlocked
        offered.value = offer?.takeIf { fingerprint.shouldOffer(vaultId) }
    }

    private fun current(reason: LockReason): VaultState {
        val info =
            try {
                vault.info()
            } catch (error: CoreException) {
                return VaultState.Unreadable((error as? CoreException.Failed)?.code)
            }
        vaultId = info.vaultId
        return when (info.status) {
            VaultStatus.MISSING -> VaultState.Missing
            VaultStatus.RECEIVED -> VaultState.Received
            VaultStatus.UNLOCKED -> VaultState.Unlocked
            VaultStatus.LOCKED -> VaultState.Locked(reason, fingerprintState(info.vaultId))
        }
    }

    private fun fingerprintState(vaultId: String?): FingerprintState =
        when {
            fingerprint.isOn(vaultId) && fingerprint.availability() == Availability.AVAILABLE ->
                when (policy.passwordFirst()) {
                    null -> FingerprintState.READY
                    PasswordFirst.PHONE_RESTARTED -> FingerprintState.AFTER_RESTART
                    PasswordFirst.WEEKLY -> FingerprintState.WEEKLY
                }
            fingerprint.wasChanged() -> FingerprintState.CHANGED
            else -> FingerprintState.OFF
        }

    /** Runs `work`; a vault the core found locked locks here too. */
    private inline fun <T> guard(work: () -> T): T =
        try {
            work()
        } catch (error: CoreException.Failed) {
            if (error.code == ErrorCode.VAULT_LOCKED) lock(LockReason.OTHER)
            throw error
        }

    private companion object {
        /** How often the open app checks whether the vault should lock. */
        const val TICK_MILLIS = 5_000L

        /** JobScheduler may start a job a little early. */
        const val JOB_SLACK_MILLIS = 1_000L
    }
}
