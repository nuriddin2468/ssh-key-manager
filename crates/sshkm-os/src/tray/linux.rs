//! Loading the `AppIndicator` library the way `libappindicator-sys` does.

#![allow(unsafe_code)]

/// The names `libappindicator-sys` tries, in its order; the last two only
/// with its `backcompat` feature, which `libappindicator` turns on by
/// default, as Tauri leaves it.
const LIBRARIES: [&str; 4] = [
    "libayatana-appindicator3.so.1",
    "libappindicator3.so.1",
    "libayatana-appindicator3.so",
    "libappindicator3.so",
];

pub fn appindicator_loads() -> bool {
    LIBRARIES.iter().any(|name| {
        // SAFETY: loading a library runs its initialisers. These are the
        // libraries the tray code loads anyway, in the same process, as soon
        // as the app makes its icon; nothing is called from them here, and
        // dropping the handle only lowers the loader's count.
        unsafe { libloading::Library::new(name) }.is_ok()
    })
}
