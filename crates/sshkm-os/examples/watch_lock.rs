//! Prints a line every time the session or screen is locked.
//!
//! ```sh
//! cargo run -p sshkm-os --example watch_lock
//! ```
//!
//! Then lock the screen (Ctrl+Cmd+Q on macOS, Win+L on Windows, Super+L on
//! most Linux desktops), unlock, and look at the output. Stop with Ctrl+C.

use std::{
    process::ExitCode,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

fn main() -> ExitCode {
    static LOCKS: AtomicUsize = AtomicUsize::new(0);

    // Started from another thread on purpose: the app may call `watch` from
    // any thread.
    let watcher = thread::spawn(|| {
        sshkm_os::screen_lock::watch(|| {
            let n = LOCKS.fetch_add(1, Ordering::SeqCst) + 1;
            println!("screen locked (#{n})");
        })
    })
    .join()
    .expect("the setup thread panicked");
    let _watcher = match watcher {
        Ok(watcher) => watcher,
        Err(err) => {
            eprintln!("cannot watch screen locks: {err} ({})", err.code());
            return ExitCode::FAILURE;
        }
    };
    println!("Watching for screen locks; press Ctrl+C to stop.");

    // macOS delivers the notification through the main thread's run loop,
    // which an app's NSApplication runs and this program must run itself.
    #[cfg(target_os = "macos")]
    loop {
        objc2_foundation::NSRunLoop::mainRunLoop().run();
        // `run` returns at once if the loop has no sources yet.
        thread::sleep(std::time::Duration::from_millis(100));
    }
    #[cfg(not(target_os = "macos"))]
    loop {
        thread::park();
    }
}
