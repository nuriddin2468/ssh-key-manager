package dev.sshkeymanager.android.ui

import androidx.annotation.StringRes
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode

/** The core's error code, if `error` came from the core. */
val Throwable.coreCode: ErrorCode?
    get() = (this as? CoreException.Failed)?.code

/**
 * What to tell the user when the vault refused or failed. The core's
 * `detail` is English for developers and never shown.
 */
@StringRes
fun messageFor(error: Throwable): Int =
    when (error.coreCode) {
        ErrorCode.WRONG_PASSPHRASE -> R.string.error_wrong_master
        ErrorCode.TOO_MANY_ATTEMPTS -> R.string.error_too_many
        ErrorCode.CONFLICT -> R.string.error_conflict
        ErrorCode.IO, ErrorCode.PERMISSION_DENIED -> R.string.error_storage
        else -> R.string.error_other
    }
