package dev.sshkeymanager.android.logins

import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import dev.sshkeymanager.android.FakeVault
import dev.sshkeymanager.android.MainDispatcherRule
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.SessionFixture
import dev.sshkeymanager.android.core.VaultStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class EditViewModelTest {
    @get:Rule val main = MainDispatcherRule()

    private val fixture = SessionFixture(main.dispatcher, CoroutineScope(SupervisorJob()), VaultStatus.UNLOCKED)
    private val vault = fixture.vault

    @Test
    fun `a new entry needs a title`() {
        val model = EditViewModel(null, fixture.session)
        model.save()
        assertEquals(R.string.edit_title_required, model.uiState.value.titleError)
        assertTrue(vault.logins.isEmpty())
    }

    @Test
    fun `a new entry is saved with what was typed, and the form's secrets are wiped`() =
        runTest(main.dispatcher) {
            val model = EditViewModel(null, fixture.session)
            model.title.setTextAndPlaceCursorAtEnd("  Bank ")
            model.username.setTextAndPlaceCursorAtEnd("me")
            model.usePassword("generated!")
            model.otp.setTextAndPlaceCursorAtEnd("JBSWY3DPEHPK3PXP")
            model.save()
            val id = model.saved.first()
            assertEquals("Bank", vault.logins[id]!!.title)
            assertEquals("generated!", vault.passwords[id])
            assertTrue(id in vault.otps)
            assertEquals("", model.password.text.toString())
            assertEquals("", model.otp.text.toString())
        }

    @Test
    fun `an edit loads no password, and an empty field keeps it`() =
        runTest(main.dispatcher) {
            vault.put(FakeVault.login("1", "GitHub", "octo"), password = "hunter2")
            vault.notes["1"] = "a note"
            val model = EditViewModel("1", fixture.session)
            assertEquals("GitHub", model.title.text.toString())
            assertEquals("a note", model.notes.text.toString())
            assertEquals("", model.password.text.toString())
            assertTrue(model.uiState.value.hasPassword)
            model.title.setTextAndPlaceCursorAtEnd("GitHub (work)")
            model.save()
            assertEquals("1", model.saved.first())
            assertEquals("GitHub (work)", vault.logins["1"]!!.title)
            assertEquals("hunter2", vault.passwords["1"])
        }

    @Test
    fun `an existing 2FA secret is kept, replaced or removed as chosen`() =
        runTest(main.dispatcher) {
            vault.put(FakeVault.login("1", "GitHub"), otp = "old")
            var model = EditViewModel("1", fixture.session)
            assertTrue(model.uiState.value.hasOtp)
            model.save()
            model.saved.first()
            assertEquals("old", vault.otps["1"])

            model = EditViewModel("1", fixture.session)
            model.chooseOtp(OtpChoice.REPLACE)
            model.otp.setTextAndPlaceCursorAtEnd("JBSWY3DPEHPK3PXP")
            model.save()
            model.saved.first()
            assertEquals("JBSWY3DPEHPK3PXP", vault.otps["1"])

            model = EditViewModel("1", fixture.session)
            model.chooseOtp(OtpChoice.REMOVE)
            model.save()
            model.saved.first()
            assertFalse("1" in vault.otps)
        }

    @Test
    fun `a 2FA secret the core refuses is pointed out at its field`() {
        val model = EditViewModel(null, fixture.session)
        model.title.setTextAndPlaceCursorAtEnd("Bank")
        model.otp.setTextAndPlaceCursorAtEnd("not a key")
        model.save()
        assertEquals(R.string.edit_otp_invalid, model.uiState.value.otpError)
        assertNull(model.uiState.value.error)
        assertFalse(model.uiState.value.saving)
    }
}
