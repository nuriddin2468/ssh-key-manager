package dev.sshkeymanager.android.vault

import dev.sshkeymanager.android.SessionFixture
import dev.sshkeymanager.android.biometric.Availability
import dev.sshkeymanager.android.biometric.FingerprintException
import dev.sshkeymanager.android.biometric.FingerprintUnlock
import dev.sshkeymanager.android.biometric.PromptException
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.VaultStatus
import dev.sshkeymanager.android.promptText
import dev.sshkeymanager.android.FakePrompter
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VaultSessionTest {
    private val dispatcher = StandardTestDispatcher()
    private val scope = TestScope(dispatcher)

    private fun fixture(status: VaultStatus = VaultStatus.LOCKED) = SessionFixture(dispatcher, scope.backgroundScope, status)

    private suspend fun expectCode(code: ErrorCode, block: suspend () -> Unit) {
        try {
            block()
            fail("no $code")
        } catch (error: CoreException.Failed) {
            assertEquals(code, error.code)
        }
    }

    @Test
    fun `the state follows the core`() =
        scope.runTest {
            for ((status, expected) in listOf(
                VaultStatus.MISSING to VaultState.Missing,
                VaultStatus.RECEIVED to VaultState.Received,
                VaultStatus.UNLOCKED to VaultState.Unlocked,
            )) {
                val f = fixture(status)
                f.session.load()
                assertEquals(expected, f.session.vaultState.value)
            }
            val f = fixture()
            f.session.load()
            assertEquals(VaultState.Locked(LockReason.OTHER, FingerprintState.OFF), f.session.vaultState.value)
        }

    @Test
    fun `setting the phone's master password opens the vault and offers the fingerprint`() =
        scope.runTest {
            val f = fixture(VaultStatus.RECEIVED)
            f.session.load()
            f.session.setMasterPassword("new master")
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
            assertEquals(FingerprintOffer.NEW, f.session.fingerprintOffer.value)
            assertNotNull("the password counts as typed", f.uses.last)
        }

    @Test
    fun `no offer on a phone without a fingerprint, nor once declined`() =
        scope.runTest {
            val f = fixture()
            f.keys.availability = Availability.NONE_ENROLLED
            f.session.load()
            f.session.unlock("master")
            assertNull(f.session.fingerprintOffer.value)

            f.keys.availability = Availability.AVAILABLE
            f.session.lock()
            f.session.unlock("master")
            assertEquals(FingerprintOffer.NEW, f.session.fingerprintOffer.value)
            f.session.declineFingerprint()
            f.session.lock()
            f.session.unlock("master")
            assertNull(f.session.fingerprintOffer.value)
        }

    @Test
    fun `a screen made anew doesn't read the state again`() =
        scope.runTest {
            val f = fixture()
            f.session.start()
            f.session.unlock("master")
            f.session.lock()
            f.session.start()
            assertEquals(LockReason.MANUAL, (f.session.vaultState.value as VaultState.Locked).reason)
        }

    @Test
    fun `a wrong master password leaves it locked`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            expectCode(ErrorCode.WRONG_PASSPHRASE) { f.session.unlock("wrong") }
            assertTrue(f.session.vaultState.value is VaultState.Locked)
        }

    @Test
    fun `locking drops the vault in the core, clears a copied secret and the lock job`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.session.appBackground()
            assertTrue(Deadline.LOCK in f.deadlines.scheduled)
            f.session.lock()
            assertEquals(1, f.vault.lockCalls)
            assertFalse(f.vault.isUnlocked())
            assertEquals(1, f.clipboard.cleared)
            assertFalse(Deadline.LOCK in f.deadlines.scheduled)
            assertEquals(VaultState.Locked(LockReason.MANUAL, FingerprintState.OFF), f.session.vaultState.value)
        }

    @Test
    fun `it locks after the set time without use, not before`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.clock.now += 50_000
            f.session.touch()
            f.clock.now += 50_000
            f.session.lockIfDue()
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
            f.clock.now += 10_000
            f.session.lockIfDue()
            assertEquals(LockReason.IDLE, (f.session.vaultState.value as VaultState.Locked).reason)
        }

    @Test
    fun `in the background a job locks it when its time comes`() =
        scope.runTest {
            val f = fixture()
            f.settings.lockAfter = LockAfter.SECONDS_30
            f.session.load()
            f.session.unlock("master")
            f.clock.now += 10_000
            f.session.appBackground()
            // 20 seconds left, and a second so that it's due when the job runs.
            assertEquals(21_000L, f.deadlines.scheduled[Deadline.LOCK])

            // Started a little early: it runs again later.
            f.clock.now += 19_000
            f.session.lockDeadline()
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
            assertEquals(2_000L, f.deadlines.scheduled[Deadline.LOCK])

            f.clock.now += 2_000
            f.session.lockDeadline()
            assertEquals(LockReason.IDLE, (f.session.vaultState.value as VaultState.Locked).reason)
        }

    @Test
    fun `coming back after too long locks at once`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.session.appBackground()
            f.clock.now += 61_000
            f.session.appForeground()
            assertEquals(LockReason.IDLE, (f.session.vaultState.value as VaultState.Locked).reason)
            assertFalse(Deadline.LOCK in f.deadlines.scheduled)
        }

    @Test
    fun `a vault the core found locked locks the app too`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.vault.status = VaultStatus.LOCKED
            expectCode(ErrorCode.VAULT_LOCKED) { f.session.read { logins() } }
            assertEquals(LockReason.OTHER, (f.session.vaultState.value as VaultState.Locked).reason)
        }

    @Test
    fun `changes are counted for the screens to read again`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            val before = f.session.changes.value
            f.session.change { addLogin(dev.sshkeymanager.android.core.LoginInput(title = "A")) }
            assertEquals(before + 1, f.session.changes.value)
        }

    @Test
    fun `fingerprint unlock wraps the slot key and unwraps it after the prompt`() =
        scope.runTest {
            val f = fixture()
            val prompter = FakePrompter()
            f.session.load()
            f.session.unlock("master")
            f.session.enableFingerprint(prompter, promptText)
            assertEquals(1, prompter.shown)
            val link = f.links.stored!!
            assertEquals("vault-1", link.vaultId)
            assertTrue(link.slotId in f.vault.slots)
            assertFalse("the key is stored wrapped", link.wrapped.contentEquals(f.vault.slots[link.slotId]))
            assertTrue(f.keys.keys.containsKey(FingerprintUnlock.alias("vault-1")))
            assertEquals(Availability.AVAILABLE to true, f.session.fingerprintStatus())

            f.session.lock()
            assertEquals(FingerprintState.READY, (f.session.vaultState.value as VaultState.Locked).fingerprint)
            f.session.unlockWithFingerprint(prompter, promptText)
            assertEquals(VaultState.Unlocked, f.session.vaultState.value)
            assertArrayEquals(f.vault.slots[link.slotId], f.vault.unlockedWithKey)
        }

    @Test
    fun `turning it on again replaces the phone's old slot, and turning it off removes it`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.session.enableFingerprint(FakePrompter(), promptText)
            val first = f.links.stored!!.slotId
            f.session.enableFingerprint(FakePrompter(), promptText)
            assertEquals(listOf(f.links.stored!!.slotId), f.vault.slots.keys.toList())
            assertFalse(first in f.vault.slots)

            f.session.disableFingerprint()
            assertTrue(f.vault.slots.isEmpty())
            assertNull(f.links.stored)
            assertTrue(f.keys.keys.isEmpty())
        }

    @Test
    fun `a cancelled prompt turns nothing on`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            try {
                f.session.enableFingerprint(FakePrompter(PromptException(PromptException.Reason.CANCELLED)), promptText)
                fail("turned on")
            } catch (_: PromptException) {
            }
            assertTrue(f.vault.slots.isEmpty())
            assertNull(f.links.stored)
        }

    @Test
    fun `the master password comes first after a restart and once a week`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.session.enableFingerprint(FakePrompter(), promptText)

            f.clock.bootCount++
            f.session.lock()
            assertEquals(FingerprintState.AFTER_RESTART, (f.session.vaultState.value as VaultState.Locked).fingerprint)
            f.session.unlock("master")

            f.clock.now += PasswordPolicy.WEEK
            f.session.lock()
            assertEquals(FingerprintState.WEEKLY, (f.session.vaultState.value as VaultState.Locked).fingerprint)
            f.session.unlock("master")
            f.session.lock()
            assertEquals(FingerprintState.READY, (f.session.vaultState.value as VaultState.Locked).fingerprint)
        }

    @Test
    fun `a new fingerprint turns it off until the master password and a new yes`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.session.enableFingerprint(FakePrompter(), promptText)
            val slot = f.links.stored!!.slotId
            f.session.lock()

            // Keystore invalidated the key when a fingerprint was enrolled.
            f.keys.invalidated += FingerprintUnlock.alias("vault-1")
            try {
                f.session.unlockWithFingerprint(FakePrompter(), promptText)
                fail("opened")
            } catch (error: FingerprintException) {
                assertEquals(FingerprintException.Reason.CHANGED, error.reason)
            }
            assertEquals(FingerprintState.CHANGED, (f.session.vaultState.value as VaultState.Locked).fingerprint)
            assertNull(f.links.stored)
            assertTrue("the slot waits for the vault to be open", slot in f.vault.slots)

            f.session.unlock("master")
            assertFalse("removed once the vault opened", slot in f.vault.slots)
            assertEquals(FingerprintOffer.AGAIN, f.session.fingerprintOffer.value)
        }

    @Test
    fun `a slot gone from the vault turns fingerprint unlock off`() =
        scope.runTest {
            val f = fixture()
            f.session.load()
            f.session.unlock("master")
            f.session.enableFingerprint(FakePrompter(), promptText)
            f.vault.slots.clear()
            f.session.lock()
            try {
                f.session.unlockWithFingerprint(FakePrompter(), promptText)
                fail("opened")
            } catch (error: FingerprintException) {
                assertEquals(FingerprintException.Reason.CHANGED, error.reason)
            }
            assertNull(f.links.stored)
        }
}
