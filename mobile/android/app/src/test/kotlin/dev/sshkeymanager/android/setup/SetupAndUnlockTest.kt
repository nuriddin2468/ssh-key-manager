package dev.sshkeymanager.android.setup

import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import dev.sshkeymanager.android.FakePrompter
import dev.sshkeymanager.android.MainDispatcherRule
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.SessionFixture
import dev.sshkeymanager.android.biometric.PromptException
import dev.sshkeymanager.android.core.VaultStatus
import dev.sshkeymanager.android.generator.PasswordTools
import dev.sshkeymanager.android.core.PasswordOptions
import dev.sshkeymanager.android.promptText
import dev.sshkeymanager.android.ui.UiText
import dev.sshkeymanager.android.unlock.UnlockViewModel
import dev.sshkeymanager.android.vault.VaultState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SetupAndUnlockTest {
    @get:Rule val main = MainDispatcherRule()

    private object Tools : PasswordTools {
        override fun generate(options: PasswordOptions) = ""

        override fun strength(password: String) = password.length.coerceAtMost(4)
    }

    private fun fixture(status: VaultStatus) = SessionFixture(main.dispatcher, CoroutineScope(SupervisorJob()), status)

    @Test
    fun `the master password must be typed twice the same`() =
        runTest(main.dispatcher) {
            val f = fixture(VaultStatus.RECEIVED)
            f.session.load()
            val model = SetupViewModel(f.session, Tools)
            model.submit()
            assertEquals(R.string.setup_empty, model.uiState.value.error)
            model.master.setTextAndPlaceCursorAtEnd("one")
            model.repeat.setTextAndPlaceCursorAtEnd("two")
            model.submit()
            assertEquals(R.string.setup_mismatch, model.uiState.value.error)
            assertEquals(VaultState.Received, f.session.vaultState.value)

            model.repeat.setTextAndPlaceCursorAtEnd("one")
            model.submit()
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
            assertEquals("", model.master.text.toString())
            assertEquals("", model.repeat.text.toString())
            assertEquals(0, model.strength(""))
        }

    @Test
    fun `a wrong master password says so and keeps what was typed`() =
        runTest(main.dispatcher) {
            val f = fixture(VaultStatus.LOCKED)
            f.session.load()
            val model = UnlockViewModel(f.session)
            model.password.setTextAndPlaceCursorAtEnd("wrong")
            model.unlock()
            assertEquals(UiText.Res(R.string.error_wrong_master), model.uiState.value.error)
            assertEquals("wrong", model.password.text.toString())

            model.password.setTextAndPlaceCursorAtEnd("master")
            model.unlock()
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
            assertEquals("", model.password.text.toString())
            assertNull(model.uiState.value.error)
        }

    @Test
    fun `a cancelled prompt is no error, a locked-out sensor points to the master password`() =
        runTest(main.dispatcher) {
            val f = fixture(VaultStatus.LOCKED)
            f.session.load()
            f.session.unlock("master")
            f.session.enableFingerprint(FakePrompter(), promptText)
            f.session.lock()
            val model = UnlockViewModel(f.session)
            model.unlockWithFingerprint(FakePrompter(PromptException(PromptException.Reason.CANCELLED)), promptText)
            assertNull(model.uiState.value.error)
            model.unlockWithFingerprint(FakePrompter(PromptException(PromptException.Reason.LOCKED_OUT)), promptText)
            assertEquals(UiText.Res(R.string.error_fingerprint_lockout), model.uiState.value.error)
            model.unlockWithFingerprint(FakePrompter(), promptText)
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
        }
}
