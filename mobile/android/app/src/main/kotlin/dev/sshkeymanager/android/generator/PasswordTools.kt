package dev.sshkeymanager.android.generator

import dev.sshkeymanager.android.core.PasswordOptions
import dev.sshkeymanager.android.core.generatePassword
import dev.sshkeymanager.android.core.passwordStrength

/** The core's password generator and strength estimate; tests stand in for it. */
interface PasswordTools {
    fun generate(options: PasswordOptions): String

    /** zxcvbn's score, 0 to 4. */
    fun strength(password: String): Int
}

object RustPasswordTools : PasswordTools {
    override fun generate(options: PasswordOptions): String = generatePassword(options)

    override fun strength(password: String): Int = passwordStrength(password).score.toInt()
}
