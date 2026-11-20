package dev.sshkeymanager.android.ui

import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.core.InternalException
import dev.sshkeymanager.android.failed
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.ui.components.formatOtp
import dev.sshkeymanager.android.ui.components.otpPeriod
import org.junit.Assert.assertEquals
import org.junit.Test

class ErrorsAndOtpTest {
    @Test
    fun `every failure gets words, never the core's detail`() {
        assertEquals(R.string.error_wrong_master, messageFor(failed(ErrorCode.WRONG_PASSPHRASE)))
        assertEquals(R.string.error_too_many, messageFor(failed(ErrorCode.TOO_MANY_ATTEMPTS)))
        assertEquals(R.string.error_conflict, messageFor(failed(ErrorCode.CONFLICT)))
        assertEquals(R.string.error_storage, messageFor(failed(ErrorCode.IO)))
        assertEquals(R.string.error_other, messageFor(failed(ErrorCode.PARSE)))
        assertEquals(R.string.error_other, messageFor(InternalException("panic")))
    }

    @Test
    fun `codes read in halves, and their period follows from what is left`() {
        assertEquals("492 039", formatOtp("492039"))
        assertEquals("1234 5678", formatOtp("12345678"))
        assertEquals("12345", formatOtp("12345"))
        assertEquals(30, otpPeriod(30))
        assertEquals(60, otpPeriod(45))
    }
}
