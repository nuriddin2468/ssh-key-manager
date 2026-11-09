//! `SMAppService.statusForLegacyURL:` and
//! `SMAppService.openSystemSettingsLoginItems`, both from macOS 13.

#![allow(unsafe_code)]

use std::path::Path;

use objc2::available;
use objc2_foundation::{NSString, NSURL};
use objc2_service_management::{SMAppService, SMAppServiceStatus};

pub(super) fn turned_off(plist: &Path) -> bool {
    if !available!(macos = 13.0) {
        return false;
    }
    let Some(path) = plist.to_str() else {
        return false;
    };
    let url = NSURL::fileURLWithPath(&NSString::from_str(path));
    // SAFETY: the class exists from macOS 13, checked above, and the method
    // takes any file URL; it only reads the system's records.
    let status = unsafe { SMAppService::statusForLegacyURL(&url) };
    // `NotRegistered` / `NotFound`: the system hasn't seen the file yet (it
    // was just written), which doesn't mean it won't run.
    status == SMAppServiceStatus::RequiresApproval
}

pub(super) fn open_settings() -> bool {
    if !available!(macos = 13.0) {
        return false;
    }
    // SAFETY: the class exists from macOS 13, checked above; the method takes
    // nothing and only opens System Settings.
    unsafe { SMAppService::openSystemSettingsLoginItems() };
    true
}
