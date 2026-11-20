package dev.sshkeymanager.android.logins

import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import dev.sshkeymanager.android.FakeClipboard
import dev.sshkeymanager.android.FakeVault
import dev.sshkeymanager.android.MainDispatcherRule
import dev.sshkeymanager.android.SessionFixture
import dev.sshkeymanager.android.clipboard.Clipboard
import dev.sshkeymanager.android.core.VaultStatus
import dev.sshkeymanager.android.ui.Notice
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class DetailViewModelTest {
    @get:Rule val main = MainDispatcherRule()

    private val fixture = SessionFixture(main.dispatcher, CoroutineScope(SupervisorJob()), VaultStatus.UNLOCKED)
    private var now = 0L

    init {
        fixture.vault.put(FakeVault.login("1", "GitHub", "octo"), password = "hunter2", otp = "JBSWY3DPEHPK3PXP")
    }

    private fun model() = DetailViewModel("1", fixture.session, fixture.clipboard, { now })

    @Test
    fun `the password is read only when shown, and dropped when hidden`() {
        val model = model()
        assertEquals("GitHub", model.uiState.value.detail?.login?.title)
        assertNull(model.uiState.value.shownPassword)
        model.togglePassword()
        assertEquals("hunter2", model.uiState.value.shownPassword)
        model.togglePassword()
        assertNull(model.uiState.value.shownPassword)
    }

    @Test
    fun `a shown password hides itself after a while`() =
        runTest(main.dispatcher) {
            val model = model()
            model.togglePassword()
            assertEquals("hunter2", model.uiState.value.shownPassword)
            advanceTimeBy(DetailViewModel.SHOWN_MILLIS - 1)
            assertEquals("hunter2", model.uiState.value.shownPassword)
            advanceTimeBy(2)
            assertNull(model.uiState.value.shownPassword)
        }

    @Test
    fun `leaving the screen drops what it showed`() {
        val store = ViewModelStore()
        val model =
            ViewModelProvider.create(store, viewModelFactory { initializer { model() } })[DetailViewModel::class.java]
        model.togglePassword()
        store.clear()
        assertNull(model.uiState.value.shownPassword)
        assertNull(model.uiState.value.detail)
    }

    @Test
    fun `copying a password marks it secret, a user name isn't`() =
        runTest(main.dispatcher) {
            val model = model()
            model.copyPassword("Password")
            assertEquals(FakeClipboard.Clip("Password", "hunter2", secret = true), fixture.clipboard.clips.last())
            assertEquals(Notice.Copied("Password", Clipboard.CLEAR_SECONDS), model.notice.first())
            model.copyUsername("User name")
            assertEquals(FakeClipboard.Clip("User name", "octo", secret = false), fixture.clipboard.clips.last())
            // Copying held nothing on screen.
            assertNull(model.uiState.value.shownPassword)
        }

    @Test
    fun `the code is followed while shown and refreshed when it runs out`() =
        runTest(main.dispatcher) {
            val model = model()
            val follow = launch { model.followOtp() }
            val otp = model.uiState.value.otp!!
            assertEquals("123456", otp.code)
            assertEquals(20, otp.remaining(now))
            assertEquals(8, otp.remaining(now + 12_000))
            model.copyOtp("2FA code")
            assertEquals(FakeClipboard.Clip("2FA code", "123456", secret = true), fixture.clipboard.clips.last())
            advanceTimeBy(20_601)
            assertEquals("123456", model.uiState.value.otp?.code)
            follow.cancel()
            follow.join()
            assertNull(model.uiState.value.otp)
        }

    @Test
    fun `a code the phone can't make says so`() =
        runTest(main.dispatcher) {
            fixture.vault.otps["1"] = "unreadable"
            val model = model()
            model.followOtp()
            assertTrue(model.uiState.value.otpUnreadable)
        }

    @Test
    fun `moving to the recycle bin and back`() =
        runTest(main.dispatcher) {
            val model = model()
            model.togglePassword()
            model.trash()
            assertTrue(model.uiState.value.detail!!.login.inTrash)
            assertNull(model.uiState.value.shownPassword)
            model.restore()
            assertTrue(!model.uiState.value.detail!!.login.inTrash)
        }

    @Test
    fun `an entry that went away says so`() {
        fixture.vault.logins.clear()
        assertTrue(model().uiState.value.gone)
    }
}
