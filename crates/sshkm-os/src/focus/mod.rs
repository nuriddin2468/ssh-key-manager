//! Giving the focus back to the app the user was in.
//!
//! A window the user calls up from anywhere (the quick search) takes the
//! focus from whatever app was in front. When the user is done with it, the
//! focus should go back there, so that a password copied in it can be
//! pasted right away.
//!
//! - **macOS**: closing the window leaves this app active, with its main
//!   window (if any) in front, so [`Previous::restore`] activates the app
//!   that was frontmost when [`Previous::frontmost`] was called.
//! - **Windows, Linux**: the system gives the focus to the window that had it
//!   before, so there is nothing to remember.

#[cfg(target_os = "macos")]
mod macos;

/// The app that was in front, if it was another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Previous {
    #[cfg(target_os = "macos")]
    pid: i32,
}

impl Previous {
    /// The app in front now, unless it is this one (or the system doesn't
    /// need to be told).
    pub fn frontmost() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            macos::frontmost_other().map(|pid| Self { pid })
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Brings that app to the front again, if it is still running.
    #[cfg_attr(not(target_os = "macos"), allow(clippy::unused_self))]
    pub fn restore(self) {
        #[cfg(target_os = "macos")]
        macos::activate(self.pid);
    }
}
