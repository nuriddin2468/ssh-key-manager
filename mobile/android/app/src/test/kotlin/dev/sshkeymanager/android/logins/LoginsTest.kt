package dev.sshkeymanager.android.logins

import dev.sshkeymanager.android.FakeVault
import dev.sshkeymanager.android.MainDispatcherRule
import dev.sshkeymanager.android.SessionFixture
import dev.sshkeymanager.android.core.VaultStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class LoginsTest {
    @get:Rule val main = MainDispatcherRule()

    private val github = FakeVault.login("1", "GitHub", "octo@example.com", "https://github.com")
    private val mail = FakeVault.login("2", "Mail", "me@example.com", "https://mail.example.com")
    private val router = FakeVault.login("3", "Home router", "admin", "http://192.168.1.1").copy(group = "Home")
    private val old = FakeVault.login("4", "Old forum", "octo").copy(inTrash = true)

    private fun state() =
        LoginsState(
            loading = false,
            all = listOf(github.copy(hasOtp = true), mail, router, old),
            projects = listOf(FakeVault.project("p", "Work", "1")),
        )

    @Test
    fun `all shows what isn't in the recycle bin`() {
        assertEquals(listOf("1", "2", "3"), state().shown.map { it.id })
    }

    @Test
    fun `search matches every word in title, user name or website, in any case`() {
        assertEquals(listOf("1"), state().copy(query = "OCTO git").shown.map { it.id })
        assertEquals(listOf("3"), state().copy(query = "192.168").shown.map { it.id })
        assertTrue(state().copy(query = "nothing").shown.isEmpty())
        // The recycle bin's entries don't turn up in a search of all.
        assertEquals(listOf("1"), state().copy(query = "octo").shown.map { it.id })
    }

    @Test
    fun `filters by 2FA, project, folder and the recycle bin`() {
        assertEquals(listOf("1"), state().copy(filter = Filter.Otp).shown.map { it.id })
        assertEquals(listOf("1"), state().copy(filter = Filter.Project("p")).shown.map { it.id })
        assertEquals(listOf("3"), state().copy(filter = Filter.Group("Home")).shown.map { it.id })
        assertEquals(listOf("4"), state().copy(filter = Filter.Trash).shown.map { it.id })
        assertEquals(listOf("Home"), state().groups)
        assertTrue(state().hasTrash && state().hasOtp)
    }

    @Test
    fun `the list reads the vault and again after each change`() =
        runTest(main.dispatcher) {
            val f = SessionFixture(main.dispatcher, CoroutineScope(SupervisorJob()), VaultStatus.UNLOCKED)
            f.vault.put(github, password = "secret")
            f.vault.projects = listOf(FakeVault.project("p", "Work", "1"))
            val model = LoginsViewModel(f.session)
            assertEquals(listOf("GitHub"), model.uiState.value.shown.map { it.title })
            model.filter(Filter.Project("p"))

            f.session.change { addLogin(dev.sshkeymanager.android.core.LoginInput(title = "Bank")) }
            assertEquals(2, model.uiState.value.all.size)
            // A project that went away falls back to all.
            f.vault.projects = emptyList()
            f.session.change { trashLogin("1") }
            assertEquals(Filter.All, model.uiState.value.filter)
            assertEquals(listOf("Bank"), model.uiState.value.shown.map { it.title })
        }
}
