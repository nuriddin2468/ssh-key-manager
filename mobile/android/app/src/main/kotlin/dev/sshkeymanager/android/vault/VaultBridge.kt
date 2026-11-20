package dev.sshkeymanager.android.vault

import dev.sshkeymanager.android.core.DeviceUnlockKey
import dev.sshkeymanager.android.core.Login
import dev.sshkeymanager.android.core.LoginDetail
import dev.sshkeymanager.android.core.LoginInput
import dev.sshkeymanager.android.core.OtpCode
import dev.sshkeymanager.android.core.PhoneVault
import dev.sshkeymanager.android.core.ProjectLabel
import dev.sshkeymanager.android.core.VaultInfo

/**
 * What the app asks of the vault in the Rust core (`PhoneVault` in
 * `crates/sshkm-mobile`); tests stand in for it. Every call may throw
 * `CoreException`, and the slow ones (unlocking, saving) run off the main
 * thread ([VaultSession]).
 *
 * Secrets cross one at a time: [password] when the user asks to see or copy
 * it, [otpCode] for the code on screen, the fingerprint slot's key once when
 * it is made ([enableDeviceUnlock]) and when it opens the vault.
 */
interface VaultBridge {
    fun info(): VaultInfo

    fun setMasterPassword(master: String)

    fun unlock(master: String)

    fun unlockWithDevice(slotId: String, key: ByteArray)

    fun lock()

    fun isUnlocked(): Boolean

    fun enableDeviceUnlock(): DeviceUnlockKey

    fun disableDeviceUnlock(slotId: String)

    fun logins(): List<Login>

    fun login(id: String): LoginDetail

    fun projects(): List<ProjectLabel>

    fun password(id: String): String

    fun otpCode(id: String): OtpCode

    fun addLogin(input: LoginInput): String

    fun updateLogin(id: String, input: LoginInput)

    fun trashLogin(id: String)

    fun restoreLogin(id: String)
}

/** The Rust core's vault, through the bindings UniFFI writes. */
class RustVaultBridge(private val vault: PhoneVault) : VaultBridge {
    override fun info() = vault.info()

    override fun setMasterPassword(master: String) = vault.setMasterPassword(master)

    override fun unlock(master: String) = vault.unlock(master)

    override fun unlockWithDevice(slotId: String, key: ByteArray) = vault.unlockWithDevice(slotId, key)

    override fun lock() = vault.lock()

    override fun isUnlocked() = vault.isUnlocked()

    override fun enableDeviceUnlock() = vault.enableDeviceUnlock()

    override fun disableDeviceUnlock(slotId: String) = vault.disableDeviceUnlock(slotId)

    override fun logins() = vault.logins()

    override fun login(id: String) = vault.login(id)

    override fun projects() = vault.projects()

    override fun password(id: String) = vault.password(id)

    override fun otpCode(id: String) = vault.otpCode(id)

    override fun addLogin(input: LoginInput) = vault.addLogin(input)

    override fun updateLogin(id: String, input: LoginInput) = vault.updateLogin(id, input)

    override fun trashLogin(id: String) = vault.trashLogin(id)

    override fun restoreLogin(id: String) = vault.restoreLogin(id)
}
