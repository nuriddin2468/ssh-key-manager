package dev.sshkeymanager.android.vault

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.core.content.edit
import dev.sshkeymanager.android.biometric.DeviceLink
import dev.sshkeymanager.android.biometric.DeviceLinks
import dev.sshkeymanager.android.biometric.OffReason

/** The vault's preferences. */
interface LockSettings {
    var lockAfter: LockAfter
}

/**
 * What the app remembers outside the vault, in its private storage (never
 * backed up): the lock setting, when the master password was last typed,
 * and fingerprint unlock's slot with its key as Keystore wrapped it, which
 * nothing but Keystore after a fingerprint can unwrap. Nothing here is a
 * secret on its own.
 */
class Prefs(context: Context) : LockSettings, PasswordUses, DeviceLinks {
    private val prefs: SharedPreferences = context.getSharedPreferences("vault", Context.MODE_PRIVATE)

    override var lockAfter: LockAfter
        get() = LockAfter.named(prefs.getString(LOCK_AFTER, null))
        set(value) = prefs.edit { putString(LOCK_AFTER, value.name) }

    override fun lastPasswordUse(): PasswordUse? {
        if (!prefs.contains(PASSWORD_AT)) return null
        return PasswordUse(prefs.getInt(PASSWORD_BOOT, -1), prefs.getLong(PASSWORD_AT, 0))
    }

    override fun savePasswordUse(use: PasswordUse) =
        prefs.edit {
            putInt(PASSWORD_BOOT, use.bootCount)
            putLong(PASSWORD_AT, use.wallClockMillis)
        }

    override fun link(): DeviceLink? {
        val vaultId = prefs.getString(LINK_VAULT, null) ?: return null
        val slotId = prefs.getString(LINK_SLOT, null) ?: return null
        val iv = prefs.getString(LINK_IV, null)?.let(::decode) ?: return null
        val wrapped = prefs.getString(LINK_KEY, null)?.let(::decode) ?: return null
        return DeviceLink(vaultId, slotId, iv, wrapped)
    }

    override fun saveLink(link: DeviceLink) =
        prefs.edit(commit = true) {
            putString(LINK_VAULT, link.vaultId)
            putString(LINK_SLOT, link.slotId)
            putString(LINK_IV, encode(link.iv))
            putString(LINK_KEY, encode(link.wrapped))
        }

    override fun clearLink() =
        prefs.edit(commit = true) {
            remove(LINK_VAULT)
            remove(LINK_SLOT)
            remove(LINK_IV)
            remove(LINK_KEY)
        }

    override var staleSlot: String?
        get() = prefs.getString(STALE_SLOT, null)
        set(value) = prefs.edit { if (value == null) remove(STALE_SLOT) else putString(STALE_SLOT, value) }

    override var offReason: OffReason?
        get() = prefs.getString(OFF_REASON, null)?.let { name -> OffReason.entries.firstOrNull { it.name == name } }
        set(value) = prefs.edit { if (value == null) remove(OFF_REASON) else putString(OFF_REASON, value.name) }

    override var offer: Boolean
        get() = prefs.getBoolean(OFFER, true)
        set(value) = prefs.edit { putBoolean(OFFER, value) }

    private companion object {
        const val LOCK_AFTER = "lock_after"
        const val PASSWORD_BOOT = "password_boot_count"
        const val PASSWORD_AT = "password_at"
        const val LINK_VAULT = "device_vault"
        const val LINK_SLOT = "device_slot"
        const val LINK_IV = "device_iv"
        const val LINK_KEY = "device_wrapped_key"
        const val STALE_SLOT = "device_stale_slot"
        const val OFFER = "device_offer"
        const val OFF_REASON = "device_off_reason"

        fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

        fun decode(text: String): ByteArray? = runCatching { Base64.decode(text, Base64.NO_WRAP) }.getOrNull()
    }
}
