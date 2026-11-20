package dev.sshkeymanager.android.vault

import java.util.concurrent.TimeUnit

/** Why the master password is asked for although fingerprint unlock is on. */
enum class PasswordFirst {
    /** The phone restarted since the master password was last typed. */
    PHONE_RESTARTED,

    /** A week has passed since the master password was last typed. */
    WEEKLY,
}

/** When the master password was last typed, to open the vault. */
data class PasswordUse(val bootCount: Int, val wallClockMillis: Long)

interface PasswordUses {
    fun lastPasswordUse(): PasswordUse?

    fun savePasswordUse(use: PasswordUse)
}

/**
 * When fingerprint unlock is not enough and the master password must be
 * typed: after the phone restarts, and once a week. A phone found switched
 * off then needs more than a fingerprint taken from a sleeping owner, and the
 * user keeps knowing the password that the fingerprint stands in for (losing
 * it means the recovery key).
 */
class PasswordPolicy(
    private val uses: PasswordUses,
    private val bootCount: () -> Int,
    private val wallClock: () -> Long,
) {
    fun passwordTyped() {
        uses.savePasswordUse(PasswordUse(bootCount(), wallClock()))
    }

    /** `null` when the fingerprint may open the vault. */
    fun passwordFirst(): PasswordFirst? {
        val last = uses.lastPasswordUse() ?: return PasswordFirst.PHONE_RESTARTED
        if (last.bootCount != bootCount()) return PasswordFirst.PHONE_RESTARTED
        val elapsed = wallClock() - last.wallClockMillis
        // A clock set back counts as a week gone.
        return if (elapsed in 0 until WEEK) null else PasswordFirst.WEEKLY
    }

    companion object {
        val WEEK = TimeUnit.DAYS.toMillis(7)
    }
}
