package dev.sshkeymanager.android.logins

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import dev.sshkeymanager.android.FakeClipboard
import dev.sshkeymanager.android.FakeVault
import dev.sshkeymanager.android.MainDispatcherRule
import dev.sshkeymanager.android.SessionFixture
import dev.sshkeymanager.android.clipboard.Clipboard
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.LoginInput
import dev.sshkeymanager.android.core.VaultStatus
import dev.sshkeymanager.android.ui.Notice
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    fun `a shown password hides itself after a while, sleep included`() =
        runTest(main.dispatcher) {
            val model = model()
            model.togglePassword()
            assertEquals("hunter2", model.uiState.value.shownPassword)
            now += DetailViewModel.SHOWN_MILLIS - 1
            model.refresh()
            assertEquals("hunter2", model.uiState.value.shownPassword)
            // The phone slept through the rest.
            now += 1
            model.onScreen()
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
    fun `the code renews on the clock that counts sleep`() =
        runTest(main.dispatcher) {
            val model = model()
            val follow = launch { model.follow() }
            assertEquals("000001", model.uiState.value.otp?.code)
            assertEquals(20, model.uiState.value.otp!!.remaining(now))
            // Ticks before it runs out fetch nothing.
            advanceTimeBy(5_000)
            assertEquals(1, fixture.vault.otpCalls)
            // The phone slept: its clock moved on, coroutine time didn't.
            now += 21_000
            model.onScreen()
            assertEquals("000002", model.uiState.value.otp?.code)
            assertEquals(2, fixture.vault.otpCalls)
            follow.cancel()
            follow.join()
            assertNull(model.uiState.value.otp)
        }

    @Test
    fun `copying a code copies the one valid now`() =
        runTest(main.dispatcher) {
            val model = model()
            model.copyOtp("2FA code")
            assertEquals(FakeClipboard.Clip("2FA code", "000001", secret = true), fixture.clipboard.clips.last())
            now += 60_000
            model.copyOtp("2FA code")
            assertEquals("000002", fixture.clipboard.clips.last().text)
        }

    @Test
    fun `a code the phone can't make says so, and isn't asked for again`() =
        runTest(main.dispatcher) {
            fixture.vault.otps["1"] = "unreadable"
            val model = model()
            model.refresh()
            assertTrue(model.uiState.value.otpUnreadable)
            fixture.vault.otps["1"] = "JBSWY3DPEHPK3PXP"
            model.refresh()
            assertEquals(0, fixture.vault.otpCalls)
        }

    @Test
    fun `a 2FA secret fixed in an edit is asked for again`() =
        runTest(main.dispatcher) {
            fixture.vault.otps["1"] = "unreadable"
            val model = model()
            model.refresh()
            assertTrue(model.uiState.value.otpUnreadable)

            fixture.session.change { updateLogin("1", LoginInput(title = "GitHub", username = "octo", otp = "JBSWY3DPEHPK3PXP")) }
            assertFalse(model.uiState.value.otpUnreadable)
            model.refresh()
            assertEquals("000001", model.uiState.value.otp?.code)
        }

    @Test
    fun `a failure that may pass is asked again a little later`() =
        runTest(main.dispatcher) {
            fixture.vault.otpFailure = ErrorCode.IO
            val model = model()
            model.refresh()
            assertNull(model.uiState.value.otp)
            assertFalse("not unreadable", model.uiState.value.otpUnreadable)

            fixture.vault.otpFailure = null
            now += DetailViewModel.OTP_RETRY_MILLIS - 1
            model.refresh()
            assertEquals("not yet", 0, fixture.vault.otpCalls)
            now += 1
            model.refresh()
            assertEquals("000001", model.uiState.value.otp?.code)
        }

    @Test
    fun `a hide wins over a show still on its way`() =
        runTest(main.dispatcher) {
            // The core's thread is busy (a save): calls wait until it runs.
            val busy = StandardTestDispatcher(testScheduler)
            val slow = SessionFixture(busy, CoroutineScope(SupervisorJob()), VaultStatus.UNLOCKED)
            slow.vault.put(FakeVault.login("1", "GitHub", "octo"), password = "hunter2")
            val model = DetailViewModel("1", slow.session, slow.clipboard, { now })
            runCurrent()
            model.togglePassword()
            model.togglePassword()
            advanceUntilIdle()
            assertNull(model.uiState.value.shownPassword)

            // And a show that arrives does show.
            model.togglePassword()
            advanceUntilIdle()
            assertEquals("hunter2", model.uiState.value.shownPassword)
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
