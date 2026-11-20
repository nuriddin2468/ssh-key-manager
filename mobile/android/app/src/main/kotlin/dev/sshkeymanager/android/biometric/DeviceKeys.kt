package dev.sshkeymanager.android.biometric

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Whether the phone can do fingerprint unlock now. */
enum class Availability {
    AVAILABLE,

    /** The phone can, but no fingerprint (or other strong biometric) is set up. */
    NONE_ENROLLED,

    /** The phone has no strong biometric sensor. */
    UNSUPPORTED,
}

/**
 * The Keystore key that wraps fingerprint unlock's slot key; tests stand in
 * for it. Ciphers come back initialised and still locked: Keystore lets them
 * work only once a fingerprint prompt has authenticated them.
 */
interface DeviceKeys {
    fun availability(): Availability

    /** Makes a new key under `alias` (dropping one there) and a cipher to wrap with it. */
    fun newWrapCipher(alias: String): Cipher

    /**
     * A cipher to unwrap with the key under `alias`. Throws
     * [android.security.keystore.KeyPermanentlyInvalidatedException] when a
     * fingerprint was added or all were removed since the key was made, and
     * [java.security.GeneralSecurityException] when the key is gone.
     */
    fun unwrapCipher(alias: String, iv: ByteArray): Cipher

    fun delete(alias: String)
}

/**
 * Android Keystore: an AES-256-GCM key that never leaves the secure hardware
 * (StrongBox when the phone has it), works for one operation per strong
 * biometric authentication, only while the phone is unlocked, and is
 * invalidated by Keystore itself when a new fingerprint is enrolled. The
 * phone's screen lock PIN doesn't release it: the master password is the
 * other way in.
 */
class KeystoreDeviceKeys(private val context: Context) : DeviceKeys {
    private val keyStore: KeyStore by lazy { KeyStore.getInstance(KEYSTORE).apply { load(null) } }

    override fun availability(): Availability {
        val manager = context.getSystemService(BiometricManager::class.java) ?: return Availability.UNSUPPORTED
        val result =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                manager.canAuthenticate()
            }
        return when (result) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NONE_ENROLLED
            else -> Availability.UNSUPPORTED
        }
    }

    override fun newWrapCipher(alias: String): Cipher {
        delete(alias)
        val key = generate(alias, strongBox = hasStrongBox())
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    override fun unwrapCipher(alias: String, iv: ByteArray): Cipher {
        val key = keyStore.getKey(alias, null) as? SecretKey ?: throw java.security.KeyException("no key $alias")
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv)) }
    }

    override fun delete(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun hasStrongBox(): Boolean = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun generate(alias: String, strongBox: Boolean): SecretKey {
        val spec =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_BITS)
                .setUserAuthenticationRequired(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        // Every use, with a strong biometric only.
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                    }
                }.setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        return try {
            generator.init(spec)
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            // The feature is there but this key doesn't fit it: the phone's
            // trusted environment instead.
            generate(alias, strongBox = false)
        }
    }

    companion object {
        const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        private const val TAG_BITS = 128
    }
}
