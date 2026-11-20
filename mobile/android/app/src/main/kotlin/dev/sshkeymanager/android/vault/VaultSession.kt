package dev.sshkeymanager.android.vault

import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.FingerprintException
import dev.sshkeymanager.android.biometric.FingerprintUnlock
import dev.sshkeymanager.android.biometric.OffReason
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.VaultStatus
import java.util.concurrent.atomic.AtomicBoolean
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

    /** Turned off because its key or slot is gone; the master password, then turn it on again. */
    GONE,
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
    /** It isn't on. */
    NEW,

    /** It was turned off because a fingerprint was added. */
    AGAIN,
}

/**
 * The vault while the app runs: whether it is open, opening and locking it,
 * and running the app's reads and changes on it.
 *
 * Every call into the core's vault runs on `vaultThread`, one at a time and
 * in the order asked, never on the main thread: the core holds its lock for
 * the whole of an unlock or a save (a key derivation, a backup), and the
 * main thread must not wait for it. Whether the vault is open is known here
 * without asking the core.
 *
 * It locks itself [LockAfter] after the user last used the app ([touch]),
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
    /** One call at a time: AppGraph passes `Dispatchers.IO.limitedParallelism(1)`. */
    private val vaultThread: CoroutineDispatcher,
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

    /** Whether the vault is open, as far as the app knows; the core is told on [vaultThread]. */
    private val open = AtomicBoolean(false)

    /** Whether the app is on screen. */
    @Volatile private var onScreen = false

    /** The open vault's id, for fingerprint unlock. */
    @Volatile private var vaultId: String? = null

    private var ticker: Job? = null

    /** Reads where the vault stands. */
    suspend fun load() {
        state.value = withContext(vaultThread) { current(LockReason.OTHER) }
    }

    /** Reads where the vault stands the first time a screen asks, not again when the screen is made anew. */
    suspend fun start() {
        if (state.value == VaultState.Loading) load()
    }

    /** Sets this phone's master password for the vault it received, which opens. */
    suspend fun setMasterPassword(master: String) =
        withContext(vaultThread) {
            vault.setMasterPassword(master)
            policy.passwordTyped()
            opened(offer = FingerprintOffer.NEW)
        }

    /** Opens the vault with the master password; throws `CoreException`. */
    suspend fun unlock(master: String) =
        withContext(vaultThread) {
            val changed = (state.value as? VaultState.Locked)?.fingerprint == FingerprintState.CHANGED
            vault.unlock(master)
            policy.passwordTyped()
            fingerprint.tidy()
            opened(offer = if (changed) FingerprintOffer.AGAIN else FingerprintOffer.NEW)
        }

    /**
     * Opens the vault after a fingerprint, if fingerprint unlock may now.
     * Throws `FingerprintException` (the lock screen then shows why),
     * `PromptException` or `CoreException`.
     */
    suspend fun unlockWithFingerprint(prompter: Prompter, text: PromptText) {
        refreshLocked()
        val allowed = (state.value as? VaultState.Locked)?.fingerprint
        if (allowed != FingerprintState.READY) {
            throw FingerprintException(
                if (allowed == FingerprintState.OFF) FingerprintException.Reason.OFF else FingerprintException.Reason.PASSWORD_FIRST,
            )
        }
        try {
            fingerprint.unlock(prompter, text)
        } catch (error: FingerprintException) {
            refreshLocked()
            throw error
        }
        withContext(vaultThread) { opened(offer = null) }
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

    /**
     * Locks the vault: the app shows it locked at once, and the core drops it
     * from memory on [vaultThread] once what runs there now is done. The
     * returned job finishes then.
     */
    fun lock(reason: LockReason = LockReason.MANUAL): Job {
        open.set(false)
        deadlines.cancel(Deadline.LOCK)
        offered.value = null
        onLock()
        state.update { current ->
            if (current is VaultState.Unlocked) VaultState.Locked(reason, fingerprintState(vaultId)) else current
        }
        return scope.launch(vaultThread) { vault.lock() }
    }

    /** Runs a read of the open vault on [vaultThread]. */
    suspend fun <T> read(work: VaultBridge.() -> T): T = withContext(vaultThread) { guard { vault.work() } }

    /** Runs a change of the open vault on [vaultThread]; the core saves it. */
    suspend fun <T> change(work: VaultBridge.() -> T): T = read(work).also { changeCount.update { it + 1 } }

    /** The user did something in the app: a touch, a key, typing. */
    fun touch() = autoLock.touch()

    /**
     * The app came on screen: locks if it was away too long, says again on
     * the lock screen whether the fingerprint may open the vault (a week may
     * have passed meanwhile), and watches for the next time to lock.
     */
    fun appForeground() {
        onScreen = true
        deadlines.cancel(Deadline.LOCK)
        lockIfDue()
        refreshLocked()
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
        onScreen = false
        ticker?.cancel()
        ticker = null
        if (open.get()) scheduleLock()
    }

    /** A [Deadline.LOCK] job ran; returns the lock under way, if it locked. */
    fun lockDeadline(): Job? {
        if (!open.get()) return null
        if (autoLock.isDue(settings.lockAfter)) return lock(LockReason.IDLE)
        scheduleLock()
        return null
    }

    /** Locks if [LockAfter] has passed since the last use. */
    fun lockIfDue() {
        if (state.value is VaultState.Unlocked && autoLock.isDue(settings.lockAfter)) lock(LockReason.IDLE)
    }

    /** A job a moment after the vault is due to lock, so that it is due when the job runs. */
    private fun scheduleLock() = deadlines.schedule(Deadline.LOCK, autoLock.remaining(settings.lockAfter) + JOB_SLACK_MILLIS)

    /** Says on the lock screen what the fingerprint may do now. */
    private fun refreshLocked() {
        state.update { current ->
            if (current is VaultState.Locked) current.copy(fingerprint = fingerprintState(vaultId)) else current
        }
    }

    /** Called on [vaultThread] once the core opened the vault. */
    private fun opened(offer: FingerprintOffer?) {
        vaultId = vault.info().vaultId
        autoLock.touch()
        open.set(true)
        state.value = VaultState.Unlocked
        offered.value = offer?.takeIf { fingerprint.shouldOffer(vaultId) }
        // Opened while the app was away (a key derivation outlasted the
        // user's patience): the lock job set when it left wasn't.
        if (!onScreen) scheduleLock()
    }

    private fun current(reason: LockReason): VaultState {
        val info =
            try {
                vault.info()
            } catch (error: CoreException) {
                return VaultState.Unreadable((error as? CoreException.Failed)?.code)
            }
        vaultId = info.vaultId
        open.set(info.status == VaultStatus.UNLOCKED)
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
            fingerprint.offReason() == OffReason.CHANGED -> FingerprintState.CHANGED
            fingerprint.offReason() == OffReason.GONE -> FingerprintState.GONE
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
