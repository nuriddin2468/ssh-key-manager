//! Finding the browsers' profiles on this computer.
//!
//! The folders are the browsers' own, under the user's home; profile names
//! come from the browser's `Local State` (Chromium) or `profiles.ini`
//! (Firefox). A profile is listed when it has saved logins. Its folder never
//! leaves this side: the UI gets an id, which [`browser_profiles`] maps back.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::chromium::{LOGIN_FILES, SafeStorage};
use crate::fsutil;

/// Largest `Local State` / `profiles.ini` read.
const MAX_INDEX_SIZE: u64 = 16 * 1024 * 1024;
/// Most profiles listed per browser.
const MAX_PROFILES: usize = 64;

/// The kind of browser a profile belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum BrowserFamily {
    Chromium,
    Firefox,
}

/// A browser profile with saved logins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct BrowserProfile {
    /// What names the profile in the import commands, e.g. `chrome:Default`.
    pub id: String,
    /// The browser, as the app's browser detection names it ("Google
    /// Chrome", "Firefox").
    pub browser: String,
    /// The profile's name in the browser ("Person 1", "default-release").
    pub name: String,
    pub family: BrowserFamily,
    /// The profile's folder.
    #[serde(skip)]
    #[cfg_attr(feature = "ts", ts(skip))]
    pub(super) dir: PathBuf,
    /// Chromium: the browser's data folder, with `Local State`.
    #[serde(skip)]
    #[cfg_attr(feature = "ts", ts(skip))]
    pub(super) user_data: PathBuf,
    #[serde(skip)]
    #[cfg_attr(feature = "ts", ts(skip))]
    pub(super) storage: Option<SafeStorage>,
}

/// A Chromium browser: its name, id prefix, data folder on each system, and
/// where its key is kept.
pub(super) struct Chromium {
    name: &'static str,
    key: &'static str,
    mac: &'static str,
    linux: &'static str,
    windows: &'static str,
    storage: SafeStorage,
}

const fn storage(
    service: &'static str,
    account: &'static str,
    application: &'static str,
) -> SafeStorage {
    SafeStorage {
        service,
        account,
        application,
    }
}

pub(super) const CHROMIUM: &[Chromium] = &[
    Chromium {
        name: "Google Chrome",
        key: "chrome",
        mac: "Google/Chrome",
        linux: "google-chrome",
        windows: "Google/Chrome/User Data",
        storage: storage("Chrome Safe Storage", "Chrome", "chrome"),
    },
    Chromium {
        name: "Microsoft Edge",
        key: "edge",
        mac: "Microsoft Edge",
        linux: "microsoft-edge",
        windows: "Microsoft/Edge/User Data",
        storage: storage(
            "Microsoft Edge Safe Storage",
            "Microsoft Edge",
            "microsoft-edge",
        ),
    },
    Chromium {
        name: "Brave",
        key: "brave",
        mac: "BraveSoftware/Brave-Browser",
        linux: "BraveSoftware/Brave-Browser",
        windows: "BraveSoftware/Brave-Browser/User Data",
        storage: storage("Brave Safe Storage", "Brave", "brave"),
    },
    Chromium {
        name: "Vivaldi",
        key: "vivaldi",
        mac: "Vivaldi",
        linux: "vivaldi",
        windows: "Vivaldi/User Data",
        storage: storage("Vivaldi Safe Storage", "Vivaldi", "vivaldi"),
    },
    Chromium {
        name: "Chromium",
        key: "chromium",
        mac: "Chromium",
        linux: "chromium",
        windows: "Chromium/User Data",
        storage: storage("Chromium Safe Storage", "Chromium", "chromium"),
    },
];

/// The profiles with saved logins of the browsers on this computer:
/// Chromium browsers first, then Firefox; each browser's default profile
/// first.
pub fn browser_profiles() -> Vec<BrowserProfile> {
    let mut profiles = Vec::new();
    if let Some(base) = chromium_base() {
        for browser in CHROMIUM {
            let folder = if cfg!(target_os = "macos") {
                browser.mac
            } else if cfg!(windows) {
                browser.windows
            } else {
                browser.linux
            };
            profiles.extend(chromium_profiles(browser, &base.join(folder)));
        }
    }
    for (n, root) in firefox_roots().iter().enumerate() {
        profiles.extend(firefox_profiles(n, root));
    }
    profiles
}

fn chromium_base() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        dirs::data_dir()
    } else if cfg!(windows) {
        dirs::data_local_dir()
    } else {
        dirs::config_dir()
    }
}

/// The folders Firefox keeps `profiles.ini` in.
fn firefox_roots() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        dirs::data_dir()
            .map(|d| vec![d.join("Firefox")])
            .unwrap_or_default()
    } else if cfg!(windows) {
        dirs::data_dir()
            .map(|d| vec![d.join("Mozilla/Firefox")])
            .unwrap_or_default()
    } else {
        let mut roots = Vec::new();
        if let Some(home) = dirs::home_dir() {
            roots.push(home.join(".mozilla/firefox"));
            roots.push(home.join("snap/firefox/common/.mozilla/firefox"));
            roots.push(home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"));
        }
        // Firefox 147 and later, on a new install.
        if let Some(config) = dirs::config_dir() {
            roots.push(config.join("mozilla/firefox"));
        }
        roots
    }
}

pub(super) fn chromium_profiles(browser: &Chromium, user_data: &Path) -> Vec<BrowserProfile> {
    if !user_data.is_dir() {
        return Vec::new();
    }
    // Profile folders and names from `Local State`; any other folder with
    // logins in it after them, by its own name.
    let mut found: Vec<(String, String)> = local_state_profiles(user_data);
    if let Ok(entries) = fs::read_dir(user_data) {
        let mut others: Vec<String> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|name| name == "Default" || name.starts_with("Profile "))
            .filter(|name| !found.iter().any(|(dir, _)| dir == name))
            .collect();
        others.sort();
        found.extend(others.into_iter().map(|dir| (dir.clone(), dir)));
    }
    found.sort_by_key(|(dir, _)| dir != "Default");
    found
        .into_iter()
        .filter(|(dir, _)| is_plain_name(dir))
        .map(|(dir, name)| (user_data.join(&dir), dir, name))
        .filter(|(path, _, _)| LOGIN_FILES.iter().any(|f| path.join(f).is_file()))
        .take(MAX_PROFILES)
        .map(|(path, dir, name)| BrowserProfile {
            id: format!("{}:{dir}", browser.key),
            browser: browser.name.to_owned(),
            name,
            family: BrowserFamily::Chromium,
            dir: path,
            user_data: user_data.to_owned(),
            storage: Some(browser.storage),
        })
        .collect()
}

/// `(folder, name)` of each profile `Local State` lists.
fn local_state_profiles(user_data: &Path) -> Vec<(String, String)> {
    let Ok(bytes) = fsutil::read_limited(&user_data.join("Local State"), MAX_INDEX_SIZE) else {
        return Vec::new();
    };
    let Ok(state) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let Some(cache) = state["profile"]["info_cache"].as_object() else {
        return Vec::new();
    };
    cache
        .iter()
        .map(|(dir, info)| {
            let name = info["name"]
                .as_str()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or(dir);
            (dir.clone(), name.trim().to_owned())
        })
        .collect()
}

pub(super) fn firefox_profiles(root_index: usize, root: &Path) -> Vec<BrowserProfile> {
    let Ok(bytes) = fsutil::read_limited(&root.join("profiles.ini"), MAX_INDEX_SIZE) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut profiles: Vec<(bool, BrowserProfile)> = parse_profiles_ini(&text)
        .into_iter()
        .filter_map(|section| {
            let path = section.path?;
            let dir = if section.relative {
                if !Path::new(&path)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
                {
                    return None;
                }
                root.join(&path)
            } else {
                PathBuf::from(&path)
            };
            if !dir.join("logins.json").is_file() {
                return None;
            }
            let name = section
                .name
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| path.clone());
            Some((
                section.default,
                BrowserProfile {
                    id: format!("firefox:{root_index}:{path}"),
                    browser: "Firefox".to_owned(),
                    name,
                    family: BrowserFamily::Firefox,
                    dir,
                    user_data: root.to_owned(),
                    storage: None,
                },
            ))
        })
        .take(MAX_PROFILES)
        .collect();
    profiles.sort_by_key(|(default, _)| !default);
    profiles.into_iter().map(|(_, profile)| profile).collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct IniProfile {
    pub(super) name: Option<String>,
    pub(super) path: Option<String>,
    pub(super) relative: bool,
    pub(super) default: bool,
}

/// The `[Profile…]` sections of `profiles.ini`.
pub(super) fn parse_profiles_ini(text: &str) -> Vec<IniProfile> {
    let mut profiles = Vec::new();
    let mut current: Option<IniProfile> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            profiles.extend(current.take());
            if section.starts_with("Profile") {
                current = Some(IniProfile {
                    relative: true,
                    ..IniProfile::default()
                });
            }
            continue;
        }
        let (Some(profile), Some((key, value))) = (current.as_mut(), line.split_once('=')) else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Name" => profile.name = Some(value.to_owned()),
            "Path" => profile.path = Some(value.to_owned()),
            "IsRelative" => profile.relative = value != "0",
            "Default" => profile.default = value == "1",
            _ => {}
        }
    }
    profiles.extend(current);
    profiles
}

/// A single folder name: no separators, not `.` or `..`.
fn is_plain_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !name.contains(['/', '\\'])
}
