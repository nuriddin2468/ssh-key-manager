package dev.sshkeymanager.android.home

import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.InternalException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HomeViewModelTest {
    private class FakeCore(private val generate: () -> String) : Core {
        override fun version() = "9.9.9"

        override fun generatePassword() = generate()

        override fun strength(password: String) = if (password.length >= 20) 4 else 1
    }

    @Test
    fun `the version comes from the core and nothing is generated before asking`() {
        val state = HomeViewModel(FakeCore { "x" }).uiState.value
        assertEquals("9.9.9", state.version)
        assertNull(state.generated)
        assertNull(state.error)
    }

    @Test
    fun `generating shows the password and its strength`() {
        val model = HomeViewModel(FakeCore { "a".repeat(20) })
        model.generate()
        assertEquals(Generated("a".repeat(20), 4), model.uiState.value.generated)
    }

    @Test
    fun `invalid settings say so and keep the last password`() {
        var fail = false
        val model =
            HomeViewModel(
                FakeCore {
                    if (fail) throw CoreException.Failed(ErrorCode.INVALID_INPUT, "length must be 8 to 128")
                    "b".repeat(20)
                },
            )
        model.generate()
        fail = true
        model.generate()
        assertEquals(R.string.error_settings, model.uiState.value.error)
        assertEquals("b".repeat(20), model.uiState.value.generated?.password)
    }

    @Test
    fun `any other failure asks to try again, and a success clears it`() {
        var fail = true
        val model =
            HomeViewModel(
                FakeCore {
                    if (fail) throw CoreException.Failed(ErrorCode.IO, "disk")
                    "c".repeat(20)
                },
            )
        model.generate()
        assertEquals(R.string.error_other, model.uiState.value.error)
        fail = false
        model.generate()
        assertNull(model.uiState.value.error)
    }

    @Test
    fun `a panic in the core asks to try again instead of closing the app`() {
        val model = HomeViewModel(FakeCore { throw InternalException("Rust panic") })
        model.generate()
        assertEquals(R.string.error_other, model.uiState.value.error)
    }

    @Test
    fun `every score has its words`() {
        assertEquals(R.string.strength_0, strengthLabel(0))
        assertEquals(R.string.strength_1, strengthLabel(1))
        assertEquals(R.string.strength_2, strengthLabel(2))
        assertEquals(R.string.strength_3, strengthLabel(3))
        assertEquals(R.string.strength_4, strengthLabel(4))
    }
}
