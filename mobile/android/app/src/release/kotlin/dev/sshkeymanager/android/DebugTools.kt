package dev.sshkeymanager.android

import java.io.File

/**
 * The release build's half of DebugTools: no test vault. Its Rust library is
 * built without the `test-vault` feature, so the function doesn't exist
 * there either.
 */
object DebugTools {
    @Suppress("UNUSED_PARAMETER")
    fun testVault(graph: AppGraph, cache: File): (suspend () -> Unit)? = null
}
