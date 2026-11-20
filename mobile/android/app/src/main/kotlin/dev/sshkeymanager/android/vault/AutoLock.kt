package dev.sshkeymanager.android.vault

/**
 * How long the open vault stays open without being used. One setting covers
 * both the app left open and the app left for another: what counts is the
 * time since the user last touched the app.
 */
enum class LockAfter(val millis: Long) {
    SECONDS_30(30_000),
    MINUTE_1(60_000),
    MINUTES_5(5 * 60_000),
    MINUTES_15(15 * 60_000),
    ;

    companion object {
        /**
         * A phone is lost or picked up by someone else more often than a
         * computer, and the fingerprint makes opening it again cheap; a minute
         * still covers copying a password into another app and coming back
         * for the code.
         */
        val DEFAULT = MINUTE_1

        fun named(name: String?): LockAfter = entries.firstOrNull { it.name == name } ?: DEFAULT
    }
}

/**
 * When the open vault locks by itself: [LockAfter] after the user last
 * touched the app, whether the app stayed on screen or not. Times come from
 * a clock that keeps counting while the phone sleeps
 * (`SystemClock.elapsedRealtime`).
 */
class AutoLock(private val now: () -> Long) {
    private var lastUse = now()

    /** The user did something in the app. */
    fun touch() {
        lastUse = now()
    }

    /** When the vault should be locked, on the same clock. */
    fun deadline(after: LockAfter): Long = lastUse + after.millis

    fun isDue(after: LockAfter): Boolean = now() >= deadline(after)

    /** Milliseconds until the vault should be locked; 0 or less when it is due. */
    fun remaining(after: LockAfter): Long = deadline(after) - now()
}
