package dev.sshkeymanager.android

import android.app.KeyguardManager
import android.app.job.JobScheduler
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.KeystoreDeviceKeys
import dev.sshkeymanager.android.vault.Deadline
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

/** What keeps secrets in: the keyboard, accessibility, autofill, the clipboard, Keystore, the lock job. */
@RunWith(AndroidJUnit4::class)
class SecurityTest {
    private val fresh = FreshApp()
    private val compose = createAndroidComposeRule<MainActivity>()

    @get:Rule val rules: RuleChain = RuleChain.outerRule(fresh).around(compose)

    private val app get() = fresh.app

    private fun string(id: Int) = app.getString(id)

    /** Loads the test vault and waits for the master password screen. */
    private fun toSetup() {
        compose.onNodeWithText(string(R.string.novault_debug_action)).performClick()
        compose.waitUntil(30_000) {
            compose.onAllNodesWithText(string(R.string.setup_title)).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun onEmulator() = Build.HARDWARE in listOf("ranchu", "goldfish")

    private fun focusedEditorInfo(): EditorInfo {
        val info = EditorInfo()
        compose.runOnUiThread {
            val view: View = compose.activity.window.decorView.findFocus() ?: error("nothing focused")
            assertNotNull("no text input", view.onCreateInputConnection(info))
        }
        return info
    }

    @Test
    fun secretFieldsTurnOffTheKeyboardsLearningAndSuggestions() {
        toSetup()
        compose.onAllNodes(hasSetTextAction()).onFirst().performClick()
        compose.waitForIdle()
        val info = focusedEditorInfo()
        assertTrue(info.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
        assertEquals(InputType.TYPE_TEXT_VARIATION_PASSWORD, info.inputType and InputType.TYPE_MASK_VARIATION)
        assertTrue(info.inputType and InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS != 0)
        assertTrue(info.inputType and InputType.TYPE_TEXT_FLAG_AUTO_CORRECT == 0)
    }

    @Test
    fun accessibilityReadsDotsFromASecretField() {
        toSetup()
        val field = compose.onAllNodes(hasSetTextAction()).onFirst()
        field.performTextInput("hunter2")
        val text = field.fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text
        assertEquals("•".repeat(7), text)
    }

    @Test
    fun noAutofillServiceSeesTheVaultsFields() {
        compose.activityRule.scenario.onActivity { activity ->
            assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, activity.window.decorView.importantForAutofill)
        }
    }

    @Test
    fun aCopiedSecretIsSensitiveAndCleared() {
        val clipboard = app.getSystemService(ClipboardManager::class.java)
        val jobs = app.getSystemService(JobScheduler::class.java)
        compose.runOnUiThread { app.graph.clipboard.copy("Password", "hunter2", secret = true) }
        val description = clipboard.primaryClipDescription!!
        val sensitive =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
        assertTrue(description.extras!!.getBoolean(sensitive))
        assertNotNull("a job clears it if the app is away by then", jobs.getPendingJob(Deadline.CLEAR_CLIPBOARD.jobId))

        compose.runOnUiThread { app.graph.clipboard.clearSecret() }
        assertNull(clipboard.primaryClip?.getItemAt(0)?.text?.takeIf { it == "hunter2" })
        assertNull(jobs.getPendingJob(Deadline.CLEAR_CLIPBOARD.jobId))
    }

    @Test
    fun somethingCopiedSinceIsLeftAlone() {
        val clipboard = app.getSystemService(ClipboardManager::class.java)
        compose.runOnUiThread { app.graph.clipboard.copy("Password", "hunter2", secret = true) }
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("note", "the user's own"))
        compose.runOnUiThread { app.graph.clipboard.clearSecret() }
        assertEquals("the user's own", clipboard.primaryClip?.getItemAt(0)?.text)
    }

    @Test
    fun leavingTheAppSchedulesTheLockAndComingBackCancelsIt() {
        val jobs = app.getSystemService(JobScheduler::class.java)
        toSetup()
        val fields = compose.onAllNodes(hasSetTextAction())
        fields[0].performTextInput("phone master")
        fields[1].performTextInput("phone master")
        compose.onNodeWithText(string(R.string.setup_action)).performClick()
        compose.waitUntil(30_000) { app.graph.vault.isUnlocked() }

        compose.runOnUiThread { app.graph.session.appBackground() }
        assertNotNull(jobs.getPendingJob(Deadline.LOCK.jobId))
        compose.runOnUiThread { app.graph.session.appForeground() }
        assertNull(jobs.getPendingJob(Deadline.LOCK.jobId))
    }

    @Test
    fun theFingerprintKeyNeedsAStrongBiometricForEveryUse() {
        val keyguard = app.getSystemService(KeyguardManager::class.java)
        val keys = KeystoreDeviceKeys(app)
        assumeTrue("needs a screen lock and a fingerprint", keyguard.isDeviceSecure && keys.availability() == Availability.AVAILABLE)
        val alias = "vault-unlock-test"
        try {
            val cipher = keys.newWrapCipher(alias)
            val store = KeyStore.getInstance(KeystoreDeviceKeys.KEYSTORE).apply { load(null) }
            val key = store.getKey(alias, null) as SecretKey
            val info = SecretKeyFactory.getInstance(key.algorithm, KeystoreDeviceKeys.KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
            assertTrue(info.isUserAuthenticationRequired)
            assertTrue(info.isInvalidatedByBiometricEnrollment)
            // An emulator's Keystore is software; a phone's is its secure hardware.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !onEmulator()) {
                assertTrue(info.securityLevel in listOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProperties.SECURITY_LEVEL_STRONGBOX))
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                assertEquals(0, info.userAuthenticationValidityDurationSeconds)
                assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
            }
            try {
                cipher.doFinal(ByteArray(32))
                fail("the key worked without a fingerprint")
            } catch (_: GeneralSecurityException) {
            }
        } finally {
            keys.delete(alias)
        }
    }
}
