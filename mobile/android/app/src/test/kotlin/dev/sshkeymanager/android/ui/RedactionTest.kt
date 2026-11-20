package dev.sshkeymanager.android.ui

import dev.sshkeymanager.android.FakeVault
import dev.sshkeymanager.android.biometric.DeviceLink
import dev.sshkeymanager.android.core.LoginDetail
import dev.sshkeymanager.android.generator.Generated
import dev.sshkeymanager.android.generator.GeneratorState
import dev.sshkeymanager.android.logins.DetailState
import dev.sshkeymanager.android.logins.OtpShown
import org.junit.Assert.assertFalse
import org.junit.Test

/** What holds a secret never prints it: a log line or a crash report would carry it. */
class RedactionTest {
    private fun assertHides(value: Any, vararg secrets: String) {
        val text = value.toString()
        for (secret in secrets) assertFalse("$text shows $secret", text.contains(secret))
    }

    @Test
    fun `secrets stay out of toString`() {
        val otp = OtpShown("492039", 30, 0)
        assertHides(otp, "492039")
        val login = FakeVault.login("1", "GitHub")
        assertHides(
            DetailState(detail = LoginDetail(login, "notes", null, null), shownPassword = "hunter2", otp = otp),
            "hunter2",
            "492039",
        )
        assertHides(Generated("t9#Vq2@Lm!8xKp4", 4), "t9#Vq2@Lm!8xKp4")
        assertHides(GeneratorState(generated = Generated("t9#Vq2@Lm!8xKp4", 4)), "t9#Vq2@Lm!8xKp4")
        assertHides(DeviceLink("vault", "slot", byteArrayOf(1, 2), byteArrayOf(42, 43)), "[42", "42, 43")
    }
}
