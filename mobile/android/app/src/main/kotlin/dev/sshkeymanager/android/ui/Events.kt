package dev.sshkeymanager.android.ui

import androidx.annotation.StringRes
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalResources
import dev.sshkeymanager.android.R
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch

/** Something a screen tells the user once, in a snackbar. */
sealed interface Notice {
    /** `what` was copied; a secret's clipboard clears in `seconds`. */
    data class Copied(val what: String, val seconds: Int?) : Notice

    data class Text(@param:StringRes val id: Int, val arg: String? = null) : Notice
}

/** Shows each [Notice] from `notices` in `snackbar`, the newest replacing the one shown. */
@Composable
fun NoticeEffect(notices: Flow<Notice>, snackbar: SnackbarHostState) {
    val resources = LocalResources.current
    LaunchedEffect(notices) {
        notices.collect { notice ->
            val text =
                when (notice) {
                    is Notice.Copied ->
                        notice.seconds?.let { resources.getQuantityString(R.plurals.clipboard_clears, it, notice.what, it) }
                            ?: resources.getString(R.string.copied, notice.what)
                    is Notice.Text ->
                        if (notice.arg == null) resources.getString(notice.id) else resources.getString(notice.id, notice.arg)
                }
            snackbar.currentSnackbarData?.dismiss()
            launch { snackbar.showSnackbar(text) }
        }
    }
}
