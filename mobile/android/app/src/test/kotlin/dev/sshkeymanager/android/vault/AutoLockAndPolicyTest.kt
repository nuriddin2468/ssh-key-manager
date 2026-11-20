package dev.sshkeymanager.android.vault

import dev.sshkeymanager.android.FakeClock
import dev.sshkeymanager.android.FakeUses
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoLockAndPolicyTest {
    private val clock = FakeClock()

    @Test
    fun `the vault is due to lock the set time after the last use`() {
        val autoLock = AutoLock { clock.now }
        clock.now += 59_999
        assertFalse(autoLock.isDue(LockAfter.MINUTE_1))
        assertEquals(1, autoLock.remaining(LockAfter.MINUTE_1))
        clock.now += 1
        assertTrue(autoLock.isDue(LockAfter.MINUTE_1))
        autoLock.touch()
        assertFalse(autoLock.isDue(LockAfter.MINUTE_1))
        assertTrue(autoLock.isDue(LockAfter.SECONDS_30).not())
    }

    @Test
    fun `an unknown setting falls back to the default of a minute`() {
        assertEquals(LockAfter.MINUTE_1, LockAfter.named("SOMETHING_ELSE"))
        assertEquals(LockAfter.MINUTES_15, LockAfter.named("MINUTES_15"))
        assertEquals(LockAfter.MINUTE_1, LockAfter.DEFAULT)
    }

    @Test
    fun `the master password comes first until typed, after a restart, and after a week`() {
        val uses = FakeUses()
        val policy = PasswordPolicy(uses, bootCount = { clock.bootCount }, wallClock = { clock.now })
        assertEquals(PasswordFirst.PHONE_RESTARTED, policy.passwordFirst())

        policy.passwordTyped()
        assertNull(policy.passwordFirst())

        clock.now += PasswordPolicy.WEEK - 1
        assertNull(policy.passwordFirst())
        clock.now += 1
        assertEquals(PasswordFirst.WEEKLY, policy.passwordFirst())

        policy.passwordTyped()
        clock.bootCount++
        assertEquals(PasswordFirst.PHONE_RESTARTED, policy.passwordFirst())
    }

    @Test
    fun `a clock set back counts as a week gone`() {
        val uses = FakeUses()
        val policy = PasswordPolicy(uses, bootCount = { clock.bootCount }, wallClock = { clock.now })
        policy.passwordTyped()
        clock.now -= 1
        assertEquals(PasswordFirst.WEEKLY, policy.passwordFirst())
    }
}
