package dev.sshkeymanager.android

import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.DeviceKeys
import dev.sshkeymanager.android.biometric.DeviceLink
import dev.sshkeymanager.android.biometric.DeviceLinks
import dev.sshkeymanager.android.biometric.FingerprintUnlock
import dev.sshkeymanager.android.biometric.PromptException
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.clipboard.Clipboard
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.DeviceUnlockKey
import dev.sshkeymanager.android.core.EntryKind
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.Login
import dev.sshkeymanager.android.core.LoginDetail
import dev.sshkeymanager.android.core.LoginInput
import dev.sshkeymanager.android.core.OtpCode
import dev.sshkeymanager.android.core.ProjectColor
import dev.sshkeymanager.android.core.ProjectLabel
import dev.sshkeymanager.android.core.VaultInfo
import dev.sshkeymanager.android.core.VaultStatus
import dev.sshkeymanager.android.vault.AutoLock
import dev.sshkeymanager.android.vault.Deadline
import dev.sshkeymanager.android.vault.Deadlines
import dev.sshkeymanager.android.vault.LockAfter
import dev.sshkeymanager.android.vault.LockSettings
import dev.sshkeymanager.android.vault.PasswordPolicy
import dev.sshkeymanager.android.vault.PasswordUse
import dev.sshkeymanager.android.vault.PasswordUses
import dev.sshkeymanager.android.vault.VaultBridge
import dev.sshkeymanager.android.vault.VaultSession
import dev.sshkeymanager.android.biometric.KeyGoneException
import dev.sshkeymanager.android.biometric.KeyInvalidatedException
import dev.sshkeymanager.android.biometric.OffReason
import java.security.GeneralSecurityException
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope

fun failed(code: ErrorCode) = CoreException.Failed(code, "test")

/** The core's vault, in memory: one master password, slots, logins. */
class FakeVault(var status: VaultStatus = VaultStatus.LOCKED) : VaultBridge {
    var master = "master"
    val slots = mutableMapOf<String, ByteArray>()
    val logins = linkedMapOf<String, Login>()
    val notes = mutableMapOf<String, String>()
    val passwords = mutableMapOf<String, String>()
    val otps = mutableMapOf<String, String>()
    var projects = listOf<ProjectLabel>()
    var lockCalls = 0
    var otpCalls = 0
    var unlockedWithKey: ByteArray? = null
    /** Set to make unlocking with a device key fail this way, e.g. an unreadable key slots file. */
    var deviceFailure: ErrorCode? = null

    /** Set to make 2FA codes fail this way for now, e.g. a file read failing. */
    var otpFailure: ErrorCode? = null
    private var revision = 0

    private fun open() {
        if (status != VaultStatus.UNLOCKED) throw failed(ErrorCode.VAULT_LOCKED)
    }

    override fun info() = VaultInfo(status, if (status == VaultStatus.MISSING || status == VaultStatus.RECEIVED) null else "vault-1", slots.keys.toList())

    override fun setMasterPassword(master: String) {
        if (status != VaultStatus.RECEIVED) throw failed(ErrorCode.NOT_FOUND)
        if (master.isEmpty()) throw failed(ErrorCode.INVALID_INPUT)
        this.master = master
        status = VaultStatus.UNLOCKED
    }

    override fun unlock(master: String) {
        if (master != this.master) throw failed(ErrorCode.WRONG_PASSPHRASE)
        status = VaultStatus.UNLOCKED
    }

    override fun unlockWithDevice(slotId: String, key: ByteArray) {
        deviceFailure?.let { throw failed(it) }
        val expected = slots[slotId] ?: throw failed(ErrorCode.NOT_FOUND)
        if (!expected.contentEquals(key)) throw failed(ErrorCode.WRONG_PASSPHRASE)
        unlockedWithKey = key.copyOf()
        status = VaultStatus.UNLOCKED
    }

    override fun lock() {
        lockCalls++
        if (status == VaultStatus.UNLOCKED) status = VaultStatus.LOCKED
    }

    override fun isUnlocked() = status == VaultStatus.UNLOCKED

    override fun enableDeviceUnlock(): DeviceUnlockKey {
        open()
        val key = ByteArray(32) { (it * 7 + 1).toByte() }
        val slot = "slot-${slots.size + 1}"
        slots[slot] = key.copyOf()
        return DeviceUnlockKey(slot, key)
    }

    override fun disableDeviceUnlock(slotId: String) {
        open()
        slots.remove(slotId)
    }

    override fun logins(): List<Login> {
        open()
        return logins.values.sortedBy { it.title.lowercase() }
    }

    override fun login(id: String): LoginDetail {
        open()
        val login = logins[id] ?: throw failed(ErrorCode.NOT_FOUND)
        return LoginDetail(login = login, notes = notes[id].orEmpty(), passwordChanged = null, created = null)
    }

    override fun projects(): List<ProjectLabel> {
        open()
        return projects
    }

    override fun password(id: String): String {
        open()
        if (id !in logins) throw failed(ErrorCode.NOT_FOUND)
        return passwords[id].orEmpty()
    }

    override fun otpCode(id: String): OtpCode {
        open()
        val secret = otps[id] ?: throw failed(ErrorCode.NOT_FOUND)
        if (secret == "unreadable") throw failed(ErrorCode.PARSE)
        otpFailure?.let { throw failed(it) }
        otpCalls++
        // A new code for each call, so a test can tell a fetch from none.
        return OtpCode("%06d".format(otpCalls), 20u)
    }

    override fun addLogin(input: LoginInput): String {
        open()
        val id = UUID.randomUUID().toString()
        apply(id, input, null)
        return id
    }

    override fun updateLogin(id: String, input: LoginInput) {
        open()
        apply(id, input, logins[id] ?: throw failed(ErrorCode.NOT_FOUND))
    }

    private fun apply(id: String, input: LoginInput, current: Login?) {
        if (input.title.isBlank()) throw failed(ErrorCode.INVALID_INPUT)
        if (input.otp != null && input.otp!!.isNotEmpty() && input.otp != "JBSWY3DPEHPK3PXP") throw failed(ErrorCode.INVALID_INPUT)
        input.password?.let { passwords[id] = it }
        when {
            input.otp == "" -> otps.remove(id)
            input.otp != null -> otps[id] = input.otp!!
        }
        notes[id] = input.notes
        logins[id] =
            login(id, input.title, input.username, input.url).copy(
                kind = current?.kind ?: EntryKind.LOGIN,
                hasPassword = !passwords[id].isNullOrEmpty(),
                hasOtp = id in otps,
                inTrash = current?.inTrash ?: false,
                // As the core's last-modified time: an edit changes the entry.
                modified = "revision ${++revision}",
            )
    }

    override fun trashLogin(id: String) {
        open()
        logins[id] = (logins[id] ?: throw failed(ErrorCode.NOT_FOUND)).copy(inTrash = true)
    }

    override fun restoreLogin(id: String) {
        open()
        logins[id] = (logins[id] ?: throw failed(ErrorCode.NOT_FOUND)).copy(inTrash = false)
    }

    fun put(login: Login, password: String = "", otp: String? = null) {
        logins[login.id] = login.copy(hasPassword = password.isNotEmpty(), hasOtp = otp != null)
        if (password.isNotEmpty()) passwords[login.id] = password
        if (otp != null) otps[login.id] = otp
    }

    companion object {
        fun login(
            id: String,
            title: String,
            username: String = "",
            url: String = "",
        ) = Login(
            id = id,
            title = title,
            username = username,
            url = url,
            kind = EntryKind.LOGIN,
            host = null,
            keyFingerprint = null,
            hasPassword = false,
            hasOtp = false,
            group = null,
            inTrash = false,
            modified = null,
        )

        fun project(id: String, name: String, vararg logins: String) = ProjectLabel(id, name, ProjectColor.TEAL, logins.toList())
    }
}

/** Keystore in software: AES-GCM keys that "a new fingerprint" can invalidate. */
class FakeDeviceKeys(var availability: Availability = Availability.AVAILABLE) : DeviceKeys {
    val keys = mutableMapOf<String, SecretKey>()
    val invalidated = mutableSetOf<String>()

    /** Set to make unwrapping fail as a busy Keystore would. */
    var failure: GeneralSecurityException? = null

    override fun availability() = availability

    override fun newWrapCipher(alias: String): Cipher {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        keys[alias] = key
        invalidated.remove(alias)
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    override fun unwrapCipher(alias: String, iv: ByteArray): Cipher {
        failure?.let { throw it }
        if (alias in invalidated) throw KeyInvalidatedException(null)
        val key = keys[alias] ?: throw KeyGoneException(alias)
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
    }

    override fun delete(alias: String) {
        keys.remove(alias)
    }
}

class FakeLinks : DeviceLinks {
    var stored: DeviceLink? = null

    override fun link() = stored

    override fun saveLink(link: DeviceLink) {
        stored = link
    }

    override fun clearLink() {
        stored = null
    }

    override var staleSlot: String? = null
    override var offReason: OffReason? = null
    override var offer: Boolean = true
}

/** The fingerprint prompt: says yes, or throws `failure` when set. */
class FakePrompter(var failure: PromptException? = null) : Prompter {
    var shown = 0

    override suspend fun authenticate(cipher: Cipher, text: PromptText): Cipher {
        shown++
        failure?.let { throw it }
        return cipher
    }
}

val promptText = PromptText("title", null, "cancel")

class FakeDeadlines : Deadlines {
    val scheduled = mutableMapOf<Deadline, Long>()

    override fun schedule(deadline: Deadline, delayMillis: Long) {
        scheduled[deadline] = delayMillis
    }

    override fun cancel(deadline: Deadline) {
        scheduled.remove(deadline)
    }
}

class FakeClipboard : Clipboard {
    data class Clip(val label: String, val text: String, val secret: Boolean)

    val clips = mutableListOf<Clip>()
    var cleared = 0

    override fun copy(label: String, text: String, secret: Boolean): Int? {
        clips += Clip(label, text, secret)
        return if (secret) Clipboard.CLEAR_SECONDS else null
    }

    override fun clearSecret() {
        cleared++
    }
}

class FakeSettings(override var lockAfter: LockAfter = LockAfter.MINUTE_1) : LockSettings

class FakeUses : PasswordUses {
    var last: PasswordUse? = null

    override fun lastPasswordUse() = last

    override fun savePasswordUse(use: PasswordUse) {
        last = use
    }
}

/** A clock for the auto-lock and the password policy. */
class FakeClock(var now: Long = 1_000_000L, var bootCount: Int = 5)

/** A session over the fakes, as AppGraph builds the real one. */
class SessionFixture(
    dispatcher: CoroutineDispatcher,
    scope: CoroutineScope,
    status: VaultStatus = VaultStatus.LOCKED,
) {
    val vault = FakeVault(status)
    val keys = FakeDeviceKeys()
    val links = FakeLinks()
    val deadlines = FakeDeadlines()
    val clipboard = FakeClipboard()
    val settings = FakeSettings()
    val clock = FakeClock()
    val uses = FakeUses()
    val fingerprint = FingerprintUnlock(vault, keys, links, dispatcher)
    val session =
        VaultSession(
            vault = vault,
            fingerprint = fingerprint,
            policy = PasswordPolicy(uses, bootCount = { clock.bootCount }, wallClock = { clock.now }),
            settings = settings,
            autoLock = AutoLock { clock.now },
            deadlines = deadlines,
            scope = scope,
            vaultThread = dispatcher,
            onLock = clipboard::clearSecret,
        )
}
