package dev.sshkeymanager.android.generator

import dev.sshkeymanager.android.FakeClipboard
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.InternalException
import dev.sshkeymanager.android.core.PasswordOptions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GeneratorViewModelTest {
    private class FakeTools(private val generate: (PasswordOptions) -> String) : PasswordTools {
        override fun generate(options: PasswordOptions) = generate.invoke(options)

        override fun strength(password: String) = if (password.length >= 20) 4 else 1
    }

    @Test
    fun `a password is made at once, with the desktop's defaults`() {
        var asked: PasswordOptions? = null
        val model = GeneratorViewModel(FakeTools { asked = it; "a".repeat(20) })
        assertEquals(Generated("a".repeat(20), 4), model.uiState.value.generated)
        assertEquals(PasswordOptions(), asked)
    }

    @Test
    fun `changing an option makes a new one with it`() {
        val model = GeneratorViewModel(FakeTools { "x".repeat(it.length.toInt()) })
        model.setOptions(PasswordOptions(length = 12u))
        assertEquals("x".repeat(12), model.uiState.value.generated?.password)
    }

    @Test
    fun `settings that make nothing say so and keep the last password`() {
        var fail = false
        val model =
            GeneratorViewModel(
                FakeTools {
                    if (fail) throw CoreException.Failed(ErrorCode.INVALID_INPUT, "no characters")
                    "b".repeat(20)
                },
            )
        fail = true
        model.setOptions(PasswordOptions(lowercase = false, uppercase = false, digits = false, symbols = false))
        assertEquals(R.string.error_settings, model.uiState.value.error)
        assertEquals("b".repeat(20), model.uiState.value.generated?.password)
    }

    @Test
    fun `a panic in the core asks to try again instead of closing the app`() {
        val model = GeneratorViewModel(FakeTools { throw InternalException("Rust panic") })
        assertEquals(R.string.error_other, model.uiState.value.error)
        assertNull(model.uiState.value.generated)
    }

    @Test
    fun `copying marks the password secret`() {
        val clipboard = FakeClipboard()
        val model = GeneratorViewModel(FakeTools { "c".repeat(20) }, clipboard)
        model.copy("Generated password")
        assertTrue(clipboard.clips.single().secret)
    }
}
