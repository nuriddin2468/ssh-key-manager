//! Registers the app as a native messaging host with the browsers.
//!
//! Each browser looks for `dev.sshkeymanager.autofill.json` in a folder of
//! its own (on Windows, under a registry key naming the file), which names
//! the program to start and the extensions allowed to start it. Only browsers
//! whose profile folder exists are registered, and only for this user.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::json;

use super::{CHROMIUM_EXTENSION_IDS, FIREFOX_EXTENSION_ID, HOST_NAME, MANIFEST_FILE};

/// A browser this app can register with, and whether it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct BrowserInstall {
    pub name: String,
    /// The manifest is in place and names this copy of the app.
    pub registered: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
}

struct Target {
    name: &'static str,
    family: Family,
    /// The browser's own folder: present means installed.
    profile: PathBuf,
    /// Where its manifest goes.
    manifest: PathBuf,
    /// The registry key that points at the manifest.
    #[cfg(windows)]
    key: &'static str,
}

#[cfg(target_os = "macos")]
fn targets() -> Vec<Target> {
    let Some(support) = dirs::data_dir() else {
        return Vec::new();
    };
    let chromium = |name, folder: &str| Target {
        name,
        family: Family::Chromium,
        profile: support.join(folder),
        manifest: support
            .join(folder)
            .join("NativeMessagingHosts")
            .join(MANIFEST_FILE),
    };
    vec![
        chromium("Google Chrome", "Google/Chrome"),
        chromium("Microsoft Edge", "Microsoft Edge"),
        chromium("Brave", "BraveSoftware/Brave-Browser"),
        chromium("Vivaldi", "Vivaldi"),
        chromium("Chromium", "Chromium"),
        Target {
            name: "Firefox",
            family: Family::Firefox,
            profile: support.join("Firefox"),
            manifest: support
                .join("Mozilla/NativeMessagingHosts")
                .join(MANIFEST_FILE),
        },
    ]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn targets() -> Vec<Target> {
    let (Some(config), Some(home)) = (dirs::config_dir(), dirs::home_dir()) else {
        return Vec::new();
    };
    let chromium = |name, folder: &str| Target {
        name,
        family: Family::Chromium,
        profile: config.join(folder),
        manifest: config
            .join(folder)
            .join("NativeMessagingHosts")
            .join(MANIFEST_FILE),
    };
    vec![
        chromium("Google Chrome", "google-chrome"),
        chromium("Microsoft Edge", "microsoft-edge"),
        chromium("Brave", "BraveSoftware/Brave-Browser"),
        chromium("Vivaldi", "vivaldi"),
        chromium("Chromium", "chromium"),
        Target {
            name: "Firefox",
            family: Family::Firefox,
            profile: home.join(".mozilla/firefox"),
            manifest: home
                .join(".mozilla/native-messaging-hosts")
                .join(MANIFEST_FILE),
        },
    ]
}

#[cfg(windows)]
fn targets() -> Vec<Target> {
    let (Some(local), Some(roaming), Ok(ours)) =
        (dirs::data_local_dir(), dirs::data_dir(), super::data_dir())
    else {
        return Vec::new();
    };
    // One manifest per family in the app's folder; the keys point at them.
    let chromium = ours.join("native-messaging/chromium").join(MANIFEST_FILE);
    let firefox = ours.join("native-messaging/firefox").join(MANIFEST_FILE);
    let target = |name, folder: &str, key| Target {
        name,
        family: Family::Chromium,
        profile: local.join(folder),
        manifest: chromium.clone(),
        key,
    };
    vec![
        target(
            "Google Chrome",
            r"Google\Chrome\User Data",
            r"HKCU\Software\Google\Chrome\NativeMessagingHosts\dev.sshkeymanager.autofill",
        ),
        target(
            "Microsoft Edge",
            r"Microsoft\Edge\User Data",
            r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\dev.sshkeymanager.autofill",
        ),
        target(
            "Brave",
            r"BraveSoftware\Brave-Browser\User Data",
            r"HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\dev.sshkeymanager.autofill",
        ),
        target(
            "Chromium",
            r"Chromium\User Data",
            r"HKCU\Software\Chromium\NativeMessagingHosts\dev.sshkeymanager.autofill",
        ),
        Target {
            name: "Firefox",
            family: Family::Firefox,
            profile: roaming.join(r"Mozilla\Firefox"),
            manifest: firefox,
            key: r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.sshkeymanager.autofill",
        },
    ]
}

/// The manifest for a browser family, naming `program`.
fn manifest(family: Family, program: &Path) -> String {
    let mut manifest = json!({
        "name": HOST_NAME,
        "description": "SSH Key Manager: fills logins from the password vault",
        "path": program,
        "type": "stdio",
    });
    match family {
        Family::Chromium => {
            let origins: Vec<String> = CHROMIUM_EXTENSION_IDS
                .iter()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect();
            manifest["allowed_origins"] = json!(origins);
        }
        Family::Firefox => manifest["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]),
    }
    let mut text = serde_json::to_string_pretty(&manifest).unwrap_or_default();
    text.push('\n');
    text
}

/// The installed browsers and whether each is registered for `program`
/// (none is, without one).
pub fn status(program: Option<&Path>) -> Vec<BrowserInstall> {
    targets()
        .into_iter()
        .filter(|target| target.profile.is_dir())
        .map(|target| BrowserInstall {
            name: target.name.to_owned(),
            registered: program.is_some_and(|program| registered(&target, program)),
        })
        .collect()
}

fn registered(target: &Target, program: &Path) -> bool {
    std::fs::read_to_string(&target.manifest).is_ok_and(|text| {
        text.trim() == manifest(target.family, program).trim() && registry_points_at(target)
    })
}

/// Registers `program` with every installed browser. Returns the names of
/// browsers that failed, with why.
pub fn install(program: &Path) -> Vec<(String, io::Error)> {
    let mut failed = Vec::new();
    for target in targets()
        .into_iter()
        .filter(|target| target.profile.is_dir())
    {
        if let Err(error) = install_one(&target, program) {
            log::warn!("browser: cannot register with {}: {error}", target.name);
            failed.push((target.name.to_owned(), error));
        }
    }
    failed
}

fn install_one(target: &Target, program: &Path) -> io::Result<()> {
    if let Some(dir) = target.manifest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    sshkm_core::fsutil::atomic_write(
        &target.manifest,
        manifest(target.family, program).as_bytes(),
        0o644,
    )
    .map_err(|e| io::Error::other(e.to_string()))?;
    set_registry(target)
}

/// Removes the registration from every browser.
pub fn remove() {
    for target in targets() {
        remove_one(&target);
    }
}

/// Removes the registrations that name a program in a temporary folder
/// ([`super::HostProgram::Temporary`]), such as an `AppImage`'s mount, which
/// earlier versions registered.
pub fn remove_temporary() {
    for target in targets() {
        if registered_program(&target).is_some_and(|program| super::is_temporary(&program)) {
            remove_one(&target);
        }
    }
}

/// The program a browser's manifest names, if it has one.
fn registered_program(target: &Target) -> Option<PathBuf> {
    let text = std::fs::read_to_string(&target.manifest).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&text).ok()?;
    manifest["path"].as_str().map(PathBuf::from)
}

fn remove_one(target: &Target) {
    match std::fs::remove_file(&target.manifest) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => log::warn!("browser: cannot unregister from {}: {e}", target.name),
    }
    clear_registry(target);
}

#[cfg(windows)]
fn set_registry(target: &Target) -> io::Result<()> {
    let manifest = target.manifest.to_string_lossy();
    let output = crate::process::run(
        "reg",
        &[
            "add",
            target.key,
            "/ve",
            "/t",
            "REG_SZ",
            "/d",
            manifest.as_ref(),
            "/f",
        ],
        std::time::Duration::from_secs(10),
    )?;
    if output.success {
        Ok(())
    } else {
        Err(io::Error::other(output.stderr.trim().to_owned()))
    }
}

#[cfg(windows)]
fn clear_registry(target: &Target) {
    let _ = crate::process::run(
        "reg",
        &["delete", target.key, "/f"],
        std::time::Duration::from_secs(10),
    );
}

#[cfg(windows)]
fn registry_points_at(target: &Target) -> bool {
    crate::process::run(
        "reg",
        &["query", target.key, "/ve"],
        std::time::Duration::from_secs(10),
    )
    .is_ok_and(|out| out.success && out.stdout.contains(&*target.manifest.to_string_lossy()))
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps, reason = "fails on Windows")]
fn set_registry(_target: &Target) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn clear_registry(_target: &Target) {}

#[cfg(not(windows))]
fn registry_points_at(_target: &Target) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_name_the_program_and_our_extensions_only() {
        let program = Path::new("/Applications/SSH Key Manager.app/Contents/MacOS/sshkm-app");
        let chromium: serde_json::Value =
            serde_json::from_str(&manifest(Family::Chromium, program)).unwrap();
        assert_eq!(chromium["name"], HOST_NAME);
        assert_eq!(chromium["type"], "stdio");
        assert_eq!(chromium["path"], program.to_str().unwrap());
        assert_eq!(
            chromium["allowed_origins"][0],
            format!("chrome-extension://{}/", CHROMIUM_EXTENSION_IDS[0])
        );
        assert!(chromium.get("allowed_extensions").is_none());

        let firefox: serde_json::Value =
            serde_json::from_str(&manifest(Family::Firefox, program)).unwrap();
        assert_eq!(firefox["allowed_extensions"][0], FIREFOX_EXTENSION_ID);
        assert!(firefox.get("allowed_origins").is_none());
    }

    #[test]
    fn reads_back_the_registered_program() {
        let dir = tempfile::tempdir().unwrap();
        let target = Target {
            name: "Test",
            family: Family::Chromium,
            profile: dir.path().to_path_buf(),
            manifest: dir.path().join(MANIFEST_FILE),
            #[cfg(windows)]
            key: r"HKCU\Software\sshkm-test",
        };
        assert_eq!(registered_program(&target), None);
        let program = Path::new("/tmp/.mount_SSH KeAbC123/usr/bin/sshkm-app");
        std::fs::write(&target.manifest, manifest(Family::Chromium, program)).unwrap();
        assert_eq!(registered_program(&target).as_deref(), Some(program));
        assert!(super::super::is_temporary(program));
    }

    #[test]
    fn host_name_is_one_chrome_accepts() {
        assert!(
            HOST_NAME
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
        );
        assert_eq!(MANIFEST_FILE, format!("{HOST_NAME}.json"));
        for target in targets() {
            assert_eq!(target.manifest.file_name().unwrap(), MANIFEST_FILE);
        }
    }
}
