package dev.sshkeymanager.android.biometric

import android.security.keystore.KeyPermanentlyInvalidatedException
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.vault.VaultBridge
import java.security.GeneralSecurityException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext

/**
 * This phone's fingerprint slot in the vault: its id and its key as Keystore
 * wrapped it (AES-GCM, with `iv`).
 */
class DeviceLink(val vaultId: String, val slotId: String, val iv: ByteArray, val wrapped: ByteArray)

/** Where the app keeps its [DeviceLink], outside the vault. */
interface DeviceLinks {
    fun link(): DeviceLink?

    fun saveLink(link: DeviceLink)

    fun clearLink()

    /**
     * A slot whose Keystore key is gone (a new fingerprint was enrolled):
     * removed from the vault the next time it is open.
     */
    var staleSlot: String?

    /** Whether to offer fingerprint unlock after the master password opens the vault. */
    var offer: Boolean
}

/** Fingerprint unlock can't go on; the app words why and falls back to the master password. */
class FingerprintException(val reason: Reason) : Exception(reason.name) {
    enum class Reason {
        /** Fingerprint unlock is off. */
        OFF,

        /**
         * A fingerprint was added (or all were removed) since it was turned
         * on: Keystore dropped the key, and fingerprint unlock is off until
         * the user turns it on again.
         */
        CHANGED,
    }
}

/**
 * Fingerprint unlock as a device key slot of the vault, the way Touch ID
 * opens it on a Mac. Turning it on adds a slot whose random key the core
 * makes; the key is wrapped at once by a Keystore key that a fingerprint
 * releases for one use, and the phone's copy is wiped. Unlocking unwraps it
 * after a fingerprint and hands it to the core, which opens the slot.
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

    /** Whether fingerprint unlock was turned off because the fingerprints changed. */
    fun wasChanged(): Boolean = links.staleSlot != null

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
                } catch (_: KeyPermanentlyInvalidatedException) {
                    throw changed(link)
                } catch (_: GeneralSecurityException) {
                    // The key is gone (app data partly cleared): it can't come back.
                    throw changed(link)
                }
            }
        val authenticated =
            try {
                prompter.authenticate(cipher, text)
            } catch (error: PromptException) {
                if (error.reason == PromptException.Reason.FAILED && withContext(io) { keyInvalidated(link) }) {
                    throw changed(link)
                }
                throw error
            }
        withContext(io) {
            val key =
                try {
                    authenticated.doFinal(link.wrapped)
                } catch (_: GeneralSecurityException) {
                    throw changed(link)
                }
            try {
                vault.unlockWithDevice(link.slotId, key)
            } catch (error: CoreException) {
                // The slot is gone from the key slots file: nothing opens it.
                if ((error as? CoreException.Failed)?.code in listOf(ErrorCode.NOT_FOUND, ErrorCode.WRONG_PASSPHRASE)) {
                    throw changed(link)
                }
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
     * After the master password opened the vault: removes a slot left from a
     * changed fingerprint. Blocking; called on `io`.
     */
    fun tidy() {
        val stale = links.staleSlot ?: return
        links.staleSlot = null
        removeSlot(stale)
    }

    private fun keyInvalidated(link: DeviceLink): Boolean =
        try {
            keys.unwrapCipher(alias(link.vaultId), link.iv)
            false
        } catch (_: GeneralSecurityException) {
            true
        }

    private fun changed(link: DeviceLink): FingerprintException {
        keys.delete(alias(link.vaultId))
        links.clearLink()
        links.staleSlot = link.slotId
        links.offer = true
        return FingerprintException(FingerprintException.Reason.CHANGED)
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
