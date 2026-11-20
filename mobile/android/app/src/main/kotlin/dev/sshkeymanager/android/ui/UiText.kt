package dev.sshkeymanager.android.ui

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource

/** Text for the user: one of the app's strings, or words the system gave. */
sealed interface UiText {
    data class Res(@param:StringRes val id: Int) : UiText

    data class Plain(val text: String) : UiText

    @Composable
    fun resolve(): String =
        when (this) {
            is Res -> stringResource(id)
            is Plain -> text
        }
}
