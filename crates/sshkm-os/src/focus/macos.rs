//! `NSWorkspace.frontmostApplication` and `NSRunningApplication.activate`.
//! Both are documented as usable from any thread.

use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication, NSWorkspace};

/// The frontmost app's process id, unless it is this process.
pub(super) fn frontmost_other() -> Option<i32> {
    let app = NSWorkspace::sharedWorkspace().frontmostApplication()?;
    let pid = app.processIdentifier();
    (pid > 0 && pid != NSRunningApplication::currentApplication().processIdentifier())
        .then_some(pid)
}

pub(super) fn activate(pid: i32) {
    if let Some(app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid) {
        app.activateWithOptions(NSApplicationActivationOptions::empty());
    }
}
