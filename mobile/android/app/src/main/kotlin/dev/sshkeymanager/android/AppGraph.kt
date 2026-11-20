package dev.sshkeymanager.android

import android.app.Application
import android.os.SystemClock
import android.provider.Settings
import dev.sshkeymanager.android.biometric.FingerprintUnlock
import dev.sshkeymanager.android.biometric.KeystoreDeviceKeys
import dev.sshkeymanager.android.clipboard.Clipboard
import dev.sshkeymanager.android.clipboard.SecretClipboard
import dev.sshkeymanager.android.core.PhoneVault
import dev.sshkeymanager.android.vault.AutoLock
import dev.sshkeymanager.android.vault.Deadline
import dev.sshkeymanager.android.vault.JobDeadlines
import dev.sshkeymanager.android.vault.LockSettings
import dev.sshkeymanager.android.vault.PasswordPolicy
import dev.sshkeymanager.android.vault.Prefs
import dev.sshkeymanager.android.vault.RustVaultBridge
import dev.sshkeymanager.android.vault.VaultBridge
import dev.sshkeymanager.android.vault.VaultSession
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob

/**
 * The app's long-lived parts, made once per process: the vault in the core
 * and what opens, locks and copies from it.
 */
class AppGraph(private val app: Application) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** The core's vault object, kept for the debug build's test vault. */
    val phoneVault = PhoneVault(vaultFolder(app).path)
    val vault: VaultBridge = RustVaultBridge(phoneVault)
    private val prefs = Prefs(app)
    val settings: LockSettings = prefs
    private val deadlines = JobDeadlines(app)
    val clipboard: Clipboard = SecretClipboard(app, deadlines, scope)

    /** Every call into the core's vault, and Keystore around it: one at a time, in order, off the main thread. */
    private val vaultThread = Dispatchers.IO.limitedParallelism(1)

    val session =
        VaultSession(
            vault = vault,
            fingerprint = FingerprintUnlock(vault, KeystoreDeviceKeys(app), prefs, vaultThread),
            policy = PasswordPolicy(prefs, bootCount = ::bootCount, wallClock = System::currentTimeMillis),
            settings = prefs,
            autoLock = AutoLock(SystemClock::elapsedRealtime),
            deadlines = deadlines,
            scope = scope,
            vaultThread = vaultThread,
            onLock = clipboard::clearSecret,
        )

    /** A job came due, maybe in a process started just for it; returns work still under way. */
    fun onDeadline(deadline: Deadline): Job? =
        when (deadline) {
            Deadline.LOCK -> session.lockDeadline()
            Deadline.CLEAR_CLIPBOARD -> {
                clipboard.clearSecret()
                null
            }
        }

    /** How many times the phone has started: another number means it restarted. */
    private fun bootCount(): Int = Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT, -1)

    companion object {
        /**
         * The vault's folder: `vault.kdbx`, `vault.keys` and `backups/`, in
         * the app's storage that Android never backs up.
         */
        fun vaultFolder(app: Application) = File(app.noBackupFilesDir, "vault")
    }
}
