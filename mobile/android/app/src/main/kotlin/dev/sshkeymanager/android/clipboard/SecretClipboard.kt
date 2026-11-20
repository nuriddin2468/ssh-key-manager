package dev.sshkeymanager.android.clipboard

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.PersistableBundle
import androidx.core.content.edit
import dev.sshkeymanager.android.vault.Deadline
import dev.sshkeymanager.android.vault.Deadlines
import kotlin.random.Random
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Copies text for the user; tests stand in for it. */
interface Clipboard {
    /**
     * Copies `text`. A secret is marked sensitive (keyboards and the
     * system's preview don't show or keep it) and cleared after
     * [CLEAR_SECONDS]; returns the seconds until then, or `null`.
     */
    fun copy(label: String, text: String, secret: Boolean): Int?

    /** Clears the clipboard if it still holds a secret copied here. */
    fun clearSecret()

    companion object {
        /** As on computers. */
        const val CLEAR_SECONDS = 30
    }
}

/**
 * The system clipboard. A copied secret is marked sensitive
 * ([ClipDescription.EXTRA_IS_SENSITIVE]) and carries a random mark, so that
 * clearing it later leaves alone whatever the user copied since — when the
 * app can still read the clipboard. In the background it can't (Android 10
 * and newer), and then clears it regardless: a password left there is worse
 * than a lost clip.
 */
class SecretClipboard(
    context: Context,
    private val deadlines: Deadlines,
    private val scope: CoroutineScope,
) : Clipboard {
    private val manager: ClipboardManager? = context.getSystemService(ClipboardManager::class.java)
    private val prefs: SharedPreferences = context.getSharedPreferences("clipboard", Context.MODE_PRIVATE)
    private var timer: Job? = null

    override fun copy(label: String, text: String, secret: Boolean): Int? {
        val manager = manager ?: return null
        val clip = ClipData.newPlainText(label, text)
        if (!secret) {
            manager.setPrimaryClip(clip)
            return null
        }
        val mark = Random.nextLong().let { if (it == NO_MARK) 1 else it }
        clip.description.extras =
            PersistableBundle().apply {
                putBoolean(IS_SENSITIVE, true)
                putLong(MARK, mark)
            }
        // The mark survives the app being stopped, for the job that clears it.
        prefs.edit(commit = true) { putLong(MARK, mark) }
        manager.setPrimaryClip(clip)
        timer?.cancel()
        timer =
            scope.launch {
                delay(Clipboard.CLEAR_SECONDS * 1000L)
                clearSecret()
            }
        deadlines.schedule(Deadline.CLEAR_CLIPBOARD, Clipboard.CLEAR_SECONDS * 1000L)
        return Clipboard.CLEAR_SECONDS
    }

    override fun clearSecret() {
        val mark = prefs.getLong(MARK, NO_MARK)
        if (mark == NO_MARK) return
        prefs.edit(commit = true) { remove(MARK) }
        timer?.cancel()
        timer = null
        deadlines.cancel(Deadline.CLEAR_CLIPBOARD)
        val manager = manager ?: return
        // Null when it is empty, or when the app may not read it now.
        val description = manager.primaryClipDescription
        val ours = description == null || description.extras?.getLong(MARK, NO_MARK) == mark
        if (ours) manager.clearPrimaryClip()
    }

    private companion object {
        const val MARK = "dev.sshkeymanager.android.clip"
        const val NO_MARK = 0L

        /** [ClipDescription.EXTRA_IS_SENSITIVE], which older Androids' keyboards read too. */
        val IS_SENSITIVE: String =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ClipDescription.EXTRA_IS_SENSITIVE
            } else {
                "android.content.extra.IS_SENSITIVE"
            }
    }
}
