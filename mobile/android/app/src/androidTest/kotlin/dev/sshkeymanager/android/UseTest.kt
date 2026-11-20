package dev.sshkeymanager.android

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.activity.ComponentActivity
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.sshkeymanager.android.ui.components.NoKeyboardLearning
import dev.sshkeymanager.android.ui.components.countsAsUse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What counts as using the app, for locking after a while without use,
 * beyond the touches the activity sees: typing, and touches in windows of
 * their own (dialogs, sheets, menus).
 */
@RunWith(AndroidJUnit4::class)
class UseTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun typingWithTheKeyboardCountsAsUse() {
        var uses = 0
        compose.setContent {
            NoKeyboardLearning(onInput = { uses++ }) {
                BasicTextField(TextFieldState(), Modifier.testTag("field"))
            }
        }
        compose.onNodeWithTag("field").performClick()
        compose.waitForIdle()
        var connection: InputConnection? = null
        compose.runOnUiThread {
            connection = compose.activity.window.decorView.findFocus()?.onCreateInputConnection(EditorInfo())
        }
        assertNotNull("no text input", connection)
        val before = uses
        compose.runOnUiThread {
            connection!!.commitText("a", 1)
            connection!!.setComposingText("b", 1)
            connection!!.deleteSurroundingText(1, 0)
        }
        assertTrue("$uses uses", uses >= before + 3)
    }

    @Test
    fun whatTheKeyboardTypesReachesTheField() {
        val state = TextFieldState()
        compose.setContent {
            NoKeyboardLearning(onInput = {}) {
                BasicTextField(state, Modifier.testTag("field"))
            }
        }
        compose.onNodeWithTag("field").performClick()
        compose.waitForIdle()
        var connection: InputConnection? = null
        compose.runOnUiThread {
            connection = compose.activity.window.decorView.findFocus()?.onCreateInputConnection(EditorInfo())
        }
        assertNotNull("no text input", connection)
        fun type(edit: InputConnection.() -> Unit): String {
            compose.runOnUiThread { connection!!.edit() }
            compose.waitForIdle()
            return state.text.toString()
        }
        assertEquals("hunter", type { commitText("hunter", 1) })
        assertEquals(
            "hunter2",
            type {
                setComposingText("2", 1)
                finishComposingText()
            },
        )
        assertEquals("hunter", type { deleteSurroundingText(1, 0) })
    }

    @Test
    fun touchesInADialogCountAsUse() {
        var uses = 0
        compose.setContent {
            AlertDialog(
                onDismissRequest = {},
                confirmButton = { TextButton(onClick = {}) { Text("OK") } },
                text = { Text("A dialog") },
                modifier = Modifier.countsAsUse { uses++ },
            )
        }
        compose.onNodeWithText("OK").performClick()
        compose.waitForIdle()
        assertTrue("$uses uses", uses > 0)
    }
}
