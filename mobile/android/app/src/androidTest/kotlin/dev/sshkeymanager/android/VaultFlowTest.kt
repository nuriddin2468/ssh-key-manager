package dev.sshkeymanager.android

import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

/** The app end to end on the device: the test vault, unlock and lock, and an entry's round trip. */
@RunWith(AndroidJUnit4::class)
class VaultFlowTest {
    private val fresh = FreshApp()
    private val compose = createAndroidComposeRule<MainActivity>()

    @get:Rule val rules: RuleChain = RuleChain.outerRule(fresh).around(compose)

    private fun string(id: Int, vararg args: Any) = fresh.app.getString(id, *args)

    private fun waitFor(text: String) =
        compose.waitUntil(30_000) { compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }

    /** Waits for the entry's own screen, which has the Edit button. */
    private fun waitForDetail() =
        compose.waitUntil(30_000) {
            compose.onAllNodesWithContentDescription(string(R.string.detail_edit)).fetchSemanticsNodes().isNotEmpty()
        }

    private fun openWithTestVault() {
        compose.onNodeWithText(string(R.string.novault_debug_action)).performClick()
        waitFor(string(R.string.setup_title))
        val fields = compose.onAllNodes(hasSetTextAction())
        fields[0].performTextInput(MASTER)
        fields[1].performTextInput(MASTER)
        compose.onNodeWithText(string(R.string.setup_action)).performClick()
        waitFor("GitHub")
    }

    @Test
    fun unlockAndLock() {
        openWithTestVault()
        compose.onNodeWithContentDescription(string(R.string.action_lock)).performClick()
        waitFor(string(R.string.unlock_title))
        // The core drops the vault on its own thread, a moment later.
        compose.waitUntil(5_000) { !fresh.app.graph.vault.isUnlocked() }

        val field = compose.onAllNodes(hasSetTextAction())[0]
        field.performTextInput("wrong")
        compose.onNodeWithText(string(R.string.unlock_action)).performClick()
        waitFor(string(R.string.error_wrong_master))

        field.performTextReplacement(MASTER)
        compose.onNodeWithText(string(R.string.unlock_action)).performClick()
        waitFor("GitHub")
        assertTrue(fresh.app.graph.vault.isUnlocked())
    }

    @Test
    fun anEntrysPasswordIsShownOnlyWhenAsked() {
        openWithTestVault()
        compose.onNodeWithText("GitHub").performClick()
        val password = string(R.string.field_password)
        compose.onNodeWithContentDescription(string(R.string.action_show, password)).performClick()
        compose.onNodeWithContentDescription(string(R.string.action_hide, password)).assertExists()
        compose.onNodeWithContentDescription(string(R.string.action_hide, password)).performClick()
        compose.onNodeWithText("••••••••••••").assertExists()
    }

    @Test
    fun anEntryRoundTrip() {
        openWithTestVault()
        compose.onNodeWithText(string(R.string.logins_add), useUnmergedTree = true).performClick()
        val fields = compose.onAllNodes(hasSetTextAction())
        fields[0].performTextInput("Bank")
        fields[1].performTextInput("me@example.com")
        fields[2].performTextInput("s3cret!")
        compose.onNodeWithText(string(R.string.action_save)).performScrollTo().performClick()
        waitForDetail()
        compose.onNodeWithText("me@example.com").assertExists()

        // Edit: a new title, the password kept.
        compose.onNodeWithContentDescription(string(R.string.detail_edit)).performClick()
        compose.onAllNodes(hasSetTextAction())[0].performTextReplacement("Bank (old)")
        compose.onNodeWithText(string(R.string.action_save)).performScrollTo().performClick()
        waitForDetail()
        val id = fresh.app.graph.vault.logins().single { it.title == "Bank (old)" }.id
        assertTrue(fresh.app.graph.vault.password(id) == "s3cret!")

        // To the recycle bin, and back.
        compose.onNodeWithText(string(R.string.detail_trash)).performScrollTo().performClick()
        compose.onAllNodesWithText(string(R.string.detail_trash))[1].performClick()
        waitFor(string(R.string.detail_restore))
        assertTrue(fresh.app.graph.vault.login(id).login.inTrash)
        compose.onNodeWithText(string(R.string.detail_restore)).performScrollTo().performClick()
        waitFor(string(R.string.detail_trash))
        assertFalse(fresh.app.graph.vault.login(id).login.inTrash)
    }

    private companion object {
        const val MASTER = "phone master password"
    }
}
