package dev.sshkeymanager.android.biometric

import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.vault.VaultBridge
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext

/**
 * This phone's fingerprint slot in the vault: its id and its key as Keystore
 * wrapped it (AES-GCM, with `iv`).
 */
class DeviceLink(val vaultId: String, val slotId: String, val iv: ByteArray, val wrapped: ByteArray) {
    override fun toString() = "DeviceLink(slot=$slotId)"
}

/** Why fingerprint unlock turned itself off. */
enum class OffReason {
    /** A fingerprint was added (or all were removed): Keystore dropped the key. */
    CHANGED,

    /** Its Keystore key or its slot in the vault is gone. */
    GONE,
}

/** Where the app keeps its [DeviceLink], outside the vault. */
interface DeviceLinks {
    fun link(): DeviceLink?

    fun saveLink(link: DeviceLink)

    fun clearLink()

    /** A slot that nothing opens any more: removed from the vault the next time it is open. */
    var staleSlot: String?

    /** Why fingerprint unlock turned itself off, until the master password opens the vault. */
    var offReason: OffReason?

    /** Whether to offer fingerprint unlock after the master password opens the vault. */
    var offer: Boolean
}

/** Fingerprint unlock can't open the vault now; the app words why and falls back to the master password. */
class FingerprintException(val reason: Reason) : Exception(reason.name) {
    enum class Reason {
        /** Fingerprint unlock is off. */
        OFF,

        /** A fingerprint was added (or all were removed): it turned off until turned on again. */
        CHANGED,

        /** Its key or slot is gone: it turned off until turned on again. */
        GONE,

        /** The master password comes first: after a restart, or weekly. */
        PASSWORD_FIRST,
    }
}

/**
 * Fingerprint unlock as a device key slot of the vault, the way Touch ID
 * opens it on a Mac. Turning it on adds a slot whose random key the core
 * makes; the key is wrapped at once by a Keystore key that a fingerprint
 * releases for one use, and the phone's copy is wiped. Unlocking unwraps it
 * after a fingerprint and hands it to the core, which opens the slot.
 *
 * It turns itself off only when what opens the slot is gone for good: the
 * Keystore key invalidated or missing, or the slot no longer in the vault.
 * Any other failure (Keystore busy, the vault's files unreadable) is an
 * error, and fingerprint unlock stays on.
 *
 * Called on the main thread, where the prompt shows; Keystore and the core
 * are called on `io`.
 */
class FingerprintUnlock(
    private val vault: VaultBridge,
    private val keys: DeviceKeys,
    private val links: DeviceLinks,
    private val io: CoroutineDispatcher,
) {
    fun availability(): Availability = keys.availability()

    /** Whether it is on for the vault `vaultId`. */
    fun isOn(vaultId: String?): Boolean = vaultId != null && links.link()?.vaultId == vaultId

    /** Why it turned itself off, if it did, until the master password opened the vault. */
    fun offReason(): OffReason? = links.offReason

    /** Whether to offer it after the master password opened the vault. */
    fun shouldOffer(vaultId: String?): Boolean = links.offer && !isOn(vaultId) && availability() == Availability.AVAILABLE

    fun declineOffer() {
        links.offer = false
    }

    /** Turns it on for the open vault, after a fingerprint; replaces an older slot of this phone. */
    suspend fun enable(prompter: Prompter, text: PromptText) {
        val (vaultId, cipher) =
            withContext(io) {
                val vaultId = vault.info().vaultId ?: throw FingerprintException(FingerprintException.Reason.OFF)
                vaultId to keys.newWrapCipher(alias(vaultId))
            }
        val authenticated = prompter.authenticate(cipher, text)
        withContext(io) {
            val old = links.link()
            val device = vault.enableDeviceUnlock()
            try {
                val wrapped = authenticated.doFinal(device.key)
                links.saveLink(DeviceLink(vaultId, device.slotId, authenticated.iv, wrapped))
            } catch (error: GeneralSecurityException) {
                removeSlot(device.slotId)
                throw error
            } finally {
                device.key.fill(0)
            }
            links.offer = false
            links.offReason = null
            val stale = links.staleSlot
            links.staleSlot = null
            stale?.let(::removeSlot)
            old?.slotId?.takeIf { it != device.slotId }?.let(::removeSlot)
        }
    }

    /** Opens the vault after a fingerprint. */
    suspend fun unlock(prompter: Prompter, text: PromptText) {
        val link = links.link() ?: throw FingerprintException(FingerprintException.Reason.OFF)
        val cipher =
            withContext(io) {
                try {
                    keys.unwrapCipher(alias(link.vaultId), link.iv)
                } catch (_: KeyInvalidatedException) {
                    throw turnOff(link, OffReason.CHANGED)
                } catch (_: KeyGoneException) {
                    throw turnOff(link, OffReason.GONE)
                }
            }
        val authenticated =
            try {
                prompter.authenticate(cipher, text)
            } catch (error: PromptException) {
                // All fingerprints removed while the prompt was up.
                if (error.reason == PromptException.Reason.FAILED && withContext(io) { invalidated(link) }) {
                    throw turnOff(link, OffReason.CHANGED)
                }
                throw error
            }
        withContext(io) {
            val key =
                try {
                    authenticated.doFinal(link.wrapped)
                } catch (_: AEADBadTagException) {
                    // What the app kept doesn't belong to this key: nothing opens it.
                    throw turnOff(link, OffReason.GONE)
                }
            try {
                vault.unlockWithDevice(link.slotId, key)
            } catch (error: CoreException) {
                if (slotGone(link, error)) throw turnOff(link, OffReason.GONE)
                throw error
            } finally {
                key.fill(0)
            }
        }
    }

    /** Turns it off: the slot leaves the open vault and the Keystore key is deleted. */
    suspend fun disable() =
        withContext(io) {
            val link = links.link() ?: return@withContext
            vault.disableDeviceUnlock(link.slotId)
            keys.delete(alias(link.vaultId))
            links.clearLink()
        }

    /**
     * After the master password opened the vault: removes a slot nothing
     * opens any more. Blocking; called on `io`.
     */
    fun tidy() {
        links.offReason = null
        val stale = links.staleSlot ?: return
        links.staleSlot = null
        removeSlot(stale)
    }

    /** The slot doesn't open with the key the app kept, or is no longer in the vault's key slots. */
    private fun slotGone(link: DeviceLink, error: CoreException): Boolean =
        when ((error as? CoreException.Failed)?.code) {
            ErrorCode.WRONG_PASSPHRASE -> true
            ErrorCode.NOT_FOUND -> {
                // Also what a missing key slots file says: then it's the vault's
                // trouble, not the fingerprint's.
                val info = runCatching { vault.info() }.getOrNull()
                info?.vaultId != null && link.slotId !in info.deviceSlots
            }
            else -> false
        }

    private fun invalidated(link: DeviceLink): Boolean =
        try {
            keys.unwrapCipher(alias(link.vaultId), link.iv)
            false
        } catch (_: KeyInvalidatedException) {
            true
        } catch (_: GeneralSecurityException) {
            false
        }

    private fun turnOff(link: DeviceLink, reason: OffReason): FingerprintException {
        keys.delete(alias(link.vaultId))
        links.clearLink()
        links.staleSlot = link.slotId
        links.offReason = reason
        links.offer = true
        return FingerprintException(
            if (reason == OffReason.CHANGED) FingerprintException.Reason.CHANGED else FingerprintException.Reason.GONE,
        )
    }

    private fun removeSlot(slotId: String) {
        try {
            vault.disableDeviceUnlock(slotId)
        } catch (_: CoreException) {
            // Locked or already gone: tried again after the next unlock.
            links.staleSlot = slotId
        }
    }

    companion object {
        fun alias(vaultId: String) = "vault-unlock-$vaultId"
    }
}
