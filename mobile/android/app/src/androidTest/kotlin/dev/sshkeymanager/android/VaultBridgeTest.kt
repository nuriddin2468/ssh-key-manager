package dev.sshkeymanager.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.LoginInput
import dev.sshkeymanager.android.core.PhoneVault
import dev.sshkeymanager.android.core.VaultStatus
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The phone's vault in the Rust core, on the device: the test vault, unlock, lock and a login round trip. */
@RunWith(AndroidJUnit4::class)
class VaultBridgeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var folder: File
    private lateinit var vault: PhoneVault

    @Before
    fun setUp() {
        folder = File(context.cacheDir, "vault-test-${System.nanoTime()}")
        vault = PhoneVault(folder.path)
        vault.receiveTestVault(context.cacheDir.path)
        vault.setMasterPassword(MASTER)
    }

    @After
    fun tearDown() {
        vault.lock()
        vault.close()
        folder.deleteRecursively()
    }

    private fun expect(code: ErrorCode, block: () -> Unit) {
        try {
            block()
            fail("no $code")
        } catch (error: CoreException.Failed) {
            assertEquals(code, error.code)
        }
    }

    @Test
    fun theTestVaultIsWrittenToTheFolderAndOpen() {
        assertEquals(VaultStatus.UNLOCKED, vault.info().status)
        assertTrue(File(folder, "vault.kdbx").isFile)
        assertTrue(File(folder, "vault.keys").isFile)
        val logins = vault.logins()
        assertTrue(logins.any { it.title == "GitHub" && it.hasOtp })
        assertEquals(1, logins.count { it.inTrash })
        assertEquals(listOf("Personal", "Work"), vault.projects().map { it.name }.sorted())
    }

    @Test
    fun lockingDropsTheVaultAndOnlyThisPhonesPasswordOpensIt() {
        vault.lock()
        assertFalse(vault.isUnlocked())
        assertEquals(VaultStatus.LOCKED, vault.info().status)
        expect(ErrorCode.VAULT_LOCKED) { vault.logins() }
        expect(ErrorCode.WRONG_PASSPHRASE) { vault.unlock("wrong") }
        vault.unlock(MASTER)
        assertTrue(vault.isUnlocked())
    }

    @Test
    fun aLoginRoundTrip() {
        val id = vault.addLogin(LoginInput(title = "Bank", username = "me", password = "s3cret!", otp = "JBSWY3DPEHPK3PXP"))
        assertEquals("s3cret!", vault.password(id))
        val code = vault.otpCode(id)
        assertEquals(6, code.code.length)
        assertTrue(code.validFor in 1u..30u)

        vault.updateLogin(id, LoginInput(title = "Bank (old)", username = "me"))
        assertEquals("Bank (old)", vault.login(id).login.title)
        assertEquals("s3cret!", vault.password(id))

        vault.trashLogin(id)
        assertTrue(vault.login(id).login.inTrash)
        vault.restoreLogin(id)

        // Saved to the file, with backups of what was there before.
        vault.lock()
        vault.unlock(MASTER)
        assertEquals("Bank (old)", vault.login(id).login.title)
        assertTrue(File(folder, "backups").listFiles().orEmpty().size >= 4)
    }

    @Test
    fun theFingerprintSlotsKeyOpensTheVault() {
        val device = vault.enableDeviceUnlock()
        assertEquals(32, device.key.size)
        vault.lock()
        vault.unlockWithDevice(device.slotId, device.key)
        assertTrue(vault.isUnlocked())
        vault.disableDeviceUnlock(device.slotId)
        vault.lock()
        try {
            vault.unlockWithDevice(device.slotId, device.key)
            fail("a removed slot opened the vault")
        } catch (_: CoreException) {
        }
    }

    private companion object {
        const val MASTER = "phone master password"
    }
}
