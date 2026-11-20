package dev.sshkeymanager.android

import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Debug builds only (a release build has its own DebugTools, with nothing).
 * Until a computer can send the vault (step E of docs/mobile.md), the first
 * screen offers a made-up one: the Rust core makes it with the `test-vault`
 * feature, which only debug builds turn on, and receives it the way it will
 * receive one from a computer. Setting the phone's master password and
 * everything after it are the real thing.
 */
object DebugTools {
    fun testVault(graph: AppGraph, cache: File): (suspend () -> Unit)? =
        {
            runCatching { withContext(Dispatchers.IO) { graph.phoneVault.receiveTestVault(cache.path) } }
            graph.session.load()
        }
}
