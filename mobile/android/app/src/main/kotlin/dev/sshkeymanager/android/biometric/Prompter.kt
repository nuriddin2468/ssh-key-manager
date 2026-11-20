package dev.sshkeymanager.android.biometric

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import javax.crypto.Cipher
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** What the fingerprint prompt says, in the user's language. */
data class PromptText(val title: String, val subtitle: String?, val cancel: String)

/** The prompt didn't authenticate: why, for the app to word it. */
class PromptException(val reason: Reason, message: String? = null) : Exception(message) {
    enum class Reason {
        /** The user closed the prompt or chose the master password. */
        CANCELLED,

        /** Too many tries: the sensor is locked for a while, or until the phone is unlocked with its PIN. */
        LOCKED_OUT,

        /** No fingerprint any more, or the sensor failed; [message] is the system's own words. */
        FAILED,
    }
}

/** Shows the system's fingerprint prompt for a Keystore cipher; tests stand in for it. */
fun interface Prompter {
    /** The cipher, now usable once; throws [PromptException]. */
    suspend fun authenticate(cipher: Cipher, text: PromptText): Cipher
}

/** The platform's BiometricPrompt, strong biometrics only, over `activity`. */
class SystemPrompter(private val activity: Activity) : Prompter {
    override suspend fun authenticate(cipher: Cipher, text: PromptText): Cipher =
        suspendCancellableCoroutine { continuation ->
            val executor = activity.mainExecutor
            val cancel = CancellationSignal()
            continuation.invokeOnCancellation { cancel.cancel() }
            fun fail(error: PromptException) {
                if (continuation.isActive) continuation.resumeWithException(error)
            }
            val prompt =
                BiometricPrompt
                    .Builder(activity)
                    .setTitle(text.title)
                    .apply { text.subtitle?.let(::setSubtitle) }
                    .setNegativeButton(text.cancel, executor) { _, _ ->
                        fail(PromptException(PromptException.Reason.CANCELLED))
                    }.setConfirmationRequired(false)
                    .apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        }
                    }.build()
            prompt.authenticate(
                BiometricPrompt.CryptoObject(cipher),
                cancel,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authenticated = result.cryptoObject?.cipher
                        if (authenticated == null) {
                            fail(PromptException(PromptException.Reason.FAILED))
                        } else if (continuation.isActive) {
                            continuation.resume(authenticated)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        val reason =
                            when (errorCode) {
                                BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
                                BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                                -> PromptException.Reason.CANCELLED
                                BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT,
                                BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT,
                                -> PromptException.Reason.LOCKED_OUT
                                else -> PromptException.Reason.FAILED
                            }
                        fail(PromptException(reason, errString?.toString()))
                    }
                },
            )
        }
}
