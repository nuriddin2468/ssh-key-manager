//! Being told when the user's session or screen is locked.
//!
//! - **macOS**: the distributed notification `com.apple.screenIsLocked`.
//!   macOS delivers it through the **main thread's run loop**, whichever
//!   thread called [`watch`]; the app's `NSApplication` runs that loop, but a
//!   command-line program must run it itself (see the `watch_lock` example).
//!   The callback then runs on a private serial queue, not the main thread.
//! - **Windows**: `WM_WTSSESSION_CHANGE` / `WTS_SESSION_LOCK`, received by a
//!   hidden message-only window on a thread of this crate, so no window handle
//!   from the app is needed. Switching to another user also locks the session.
//! - **Linux**: systemd-logind (or elogind) on the system bus: the current
//!   session's `Lock` signal and its `LockedHint` property turning true, which
//!   GNOME, KDE, Cinnamon, MATE, Xfce and light-locker report. Without logind,
//!   the session bus `ActiveChanged(true)` signal of `org.freedesktop.ScreenSaver`
//!   or `org.gnome.ScreenSaver` is used instead. Lockers that report neither
//!   (such as swaylock or i3lock) are not noticed.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as sys;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as sys;

#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
use win as sys;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
use unsupported as sys;

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::Result;

/// Calls `on_lock` every time the user's session or screen gets locked, until
/// the returned [`Watcher`] is dropped.
///
/// `on_lock` runs on a thread of this crate or of the OS, never the caller's;
/// keep it short (emit an event, lock the vault). It may occasionally run
/// twice for one lock, so make it idempotent. A panic in it is caught and
/// ignored where panics unwind (the workspace's release profile aborts).
///
/// Returns [`Error::Unsupported`](crate::Error::Unsupported) when the platform
/// or desktop cannot report screen locks, and
/// [`Error::Failed`](crate::Error::Failed) when setting up the watch failed.
pub fn watch(on_lock: impl Fn() + Send + Sync + 'static) -> Result<Watcher> {
    let shared = Arc::new(Shared {
        on_lock: Box::new(on_lock),
        active: AtomicBool::new(true),
    });
    let inner = sys::watch(Arc::clone(&shared))?;
    Ok(Watcher {
        shared,
        _inner: inner,
    })
}

/// Watches for screen locks until dropped.
///
/// After the drop the callback is never called again; the OS resources are
/// released shortly after (best effort).
#[must_use = "watching stops when the Watcher is dropped"]
pub struct Watcher {
    shared: Arc<Shared>,
    /// Releases the OS resources when dropped, which happens after
    /// [`Drop::drop`] below has switched the callback off.
    _inner: sys::Watcher,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.shared.active.store(false, Ordering::Release);
    }
}

impl fmt::Debug for Watcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watcher").finish_non_exhaustive()
    }
}

/// The callback plus the switch that turns it off, shared with the platform
/// code.
struct Shared {
    on_lock: Box<dyn Fn() + Send + Sync>,
    active: AtomicBool,
}

impl Shared {
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Calls the callback unless the watcher was dropped. A panic must not
    /// unwind into the OS frames that called us.
    fn notify(&self) {
        if self.is_active() {
            let _ = catch_unwind(AssertUnwindSafe(|| (self.on_lock)()));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    fn counting() -> (Arc<AtomicUsize>, Shared) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let shared = Shared {
            on_lock: Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
            active: AtomicBool::new(true),
        };
        (calls, shared)
    }

    #[test]
    fn notify_calls_until_deactivated() {
        let (calls, shared) = counting();
        shared.notify();
        shared.notify();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        shared.active.store(false, Ordering::Release);
        shared.notify();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_panicking_callback_is_contained() {
        let shared = Shared {
            on_lock: Box::new(|| panic!("boom")),
            active: AtomicBool::new(true),
        };
        shared.notify();
        shared.notify();
    }

    #[test]
    fn watcher_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Watcher>();
    }

    /// Prints a line for every lock. Run it with
    /// `cargo test -p sshkm-os -- --ignored real_watch --nocapture` and lock
    /// the screen within 30 seconds. On macOS use the `watch_lock` example
    /// instead: the test harness does not run the main run loop.
    #[test]
    #[ignore = "needs a person to lock the screen"]
    fn real_watch() {
        let watcher = watch(|| println!("locked")).expect("watching is supported here");
        std::thread::sleep(std::time::Duration::from_secs(30));
        drop(watcher);
    }
}
