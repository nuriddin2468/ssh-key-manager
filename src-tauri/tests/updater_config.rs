//! The updater settings the app ships with, read by the updater plugin's own
//! parser from `tauri.conf.json`.

use tauri_plugin_updater::Config;

fn updater() -> Config {
    let conf: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json");
    serde_json::from_value(conf["plugins"]["updater"].clone()).expect("plugins.updater")
}

/// A release is installed only if its signature names the version the
/// release list announces, so an older release can't be offered as a newer one.
#[test]
fn an_update_must_be_signed_for_the_version_it_is_offered_as() {
    assert!(updater().require_signed_version);
}

#[test]
fn only_a_newer_version_is_offered() {
    assert!(!updater().allow_downgrades);
}

#[test]
fn updates_come_over_https_with_checked_certificates() {
    let config = updater();
    assert_eq!(config.endpoints.len(), 1);
    assert_eq!(config.endpoints[0].scheme(), "https");
    assert!(!config.dangerous_insecure_transport_protocol);
    assert!(!config.dangerous_accept_invalid_certs);
    assert!(!config.dangerous_accept_invalid_hostnames);
}
