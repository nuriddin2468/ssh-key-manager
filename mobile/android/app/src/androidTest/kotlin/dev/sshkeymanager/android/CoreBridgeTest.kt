package dev.sshkeymanager.android

import android.view.WindowManager
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.sshkeymanager.android.core.CoreException
import dev.sshkeymanager.android.core.ErrorCode
import dev.sshkeymanager.android.core.PasswordOptions
import dev.sshkeymanager.android.core.coreVersion
import dev.sshkeymanager.android.core.generatePassword
import dev.sshkeymanager.android.core.passwordStrength
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** The Rust core, called on the device through the UniFFI bindings. */
@RunWith(AndroidJUnit4::class)
class CoreBridgeTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun theCoreAnswersWithItsVersion() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val app = context.packageManager.getPackageInfo(context.packageName, 0)
        assertEquals(app.versionName, coreVersion())
    }

    @Test
    fun theVaultsGeneratorMakesAStrongPassword() {
        val password = generatePassword(PasswordOptions())
        assertEquals(20, password.length)
        assertEquals(4, passwordStrength(password).score.toInt())
    }

    @Test
    fun theCoresErrorsArriveWithTheirCode() {
        try {
            generatePassword(PasswordOptions(length = 7u))
            fail("a 7-character password was made")
        } catch (error: CoreException.Failed) {
            assertEquals(ErrorCode.INVALID_INPUT, error.code)
        }
    }

    @Test
    fun theWindowIsSecure() {
        compose.activityRule.scenario.onActivity { activity ->
            val flags = activity.window.attributes.flags
            assertTrue(flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
        }
    }

    @Test
    fun theScreenGeneratesAPassword() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        compose.onNodeWithText(context.getString(R.string.generator_generate)).performClick()
        compose.onNodeWithText(context.getString(R.string.generator_again)).assertExists()
        val strong = context.getString(R.string.generator_strength, context.getString(R.string.strength_4))
        compose.onNodeWithText(strong).assertExists()
    }
}
