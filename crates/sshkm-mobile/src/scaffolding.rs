//! UniFFI's per-crate scaffolding, and what the app asks about the core
//! itself.

uniffi::setup_scaffolding!("sshkm_mobile");

/// The core's version: the app's version, the same on every device.
#[uniffi::export]
pub fn core_version() -> String {
    sshkm_core::VERSION.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_workspace_one() {
        assert_eq!(core_version(), env!("CARGO_PKG_VERSION"));
    }
}
