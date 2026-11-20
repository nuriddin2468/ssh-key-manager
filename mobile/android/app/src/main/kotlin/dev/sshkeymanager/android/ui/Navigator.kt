package dev.sshkeymanager.android.ui

import androidx.compose.runtime.mutableStateListOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner

/** A screen of the open vault. */
sealed interface Route {
    data object Logins : Route

    data class Detail(val id: String) : Route

    /** A new entry when `id` is null. */
    data class Edit(val id: String?) : Route

    data object Generator : Route

    data object Settings : Route
}

/** A screen on the back stack, with its own view models. */
class Entry(val key: Long, val route: Route) : ViewModelStoreOwner {
    override val viewModelStore = ViewModelStore()
}

/**
 * The open vault's back stack. Each screen's view models live in its
 * [Entry] and are cleared when it leaves the stack, and all of them when the
 * vault locks ([reset]): whatever secret a screen held goes with it.
 */
class Navigator : ViewModel() {
    private var next = 0L
    val entries = mutableStateListOf(entry(Route.Logins))

    val top: Entry get() = entries.last()

    fun push(route: Route) {
        entries.add(entry(route))
    }

    /** Goes back one screen; false when on the first. */
    fun pop(): Boolean {
        if (entries.size <= 1) return false
        entries.removeAt(entries.lastIndex).viewModelStore.clear()
        return true
    }

    /** Goes back to the screen under every `route` on top, e.g. after a save. */
    fun popTo(predicate: (Route) -> Boolean) {
        while (entries.size > 1 && !predicate(top.route)) pop()
    }

    /** Back to the list, with every screen's view models cleared. */
    fun reset() {
        while (entries.size > 1) pop()
        top.viewModelStore.clear()
        entries[0] = entry(Route.Logins)
    }

    override fun onCleared() {
        entries.forEach { it.viewModelStore.clear() }
    }

    private fun entry(route: Route) = Entry(next++, route)
}
