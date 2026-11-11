//! Folders a cloud service copies to its servers: a `.env` file there
//! leaves the computer in plain text.
//!
//! Found by where the services keep their folders: iCloud Drive
//! (`~/Library/Mobile Documents`, and Desktop and Documents when they are
//! in iCloud), the File Provider folders of macOS (`~/Library/CloudStorage`:
//! Dropbox, `OneDrive`, Google Drive and others), `~/Dropbox` and the
//! folders Dropbox's own `info.json` names, `~/OneDrive` and the folders
//! Windows names in `OneDrive*` variables, `~/iCloudDrive` on Windows, and
//! Google Drive's `My Drive`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

/// A cloud service that copies a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum CloudService {
    ICloudDrive,
    Dropbox,
    OneDrive,
    GoogleDrive,
    /// Another service of macOS's `~/Library/CloudStorage`.
    Other,
}

/// The cloud folders of this computer.
#[derive(Debug, Clone, Default)]
pub struct CloudRoots(Vec<(PathBuf, CloudService)>);

impl CloudRoots {
    pub fn new(roots: Vec<(PathBuf, CloudService)>) -> Self {
        Self(roots)
    }

    /// The cloud folders found under `home` and in the environment.
    pub fn detect(home: Option<&Path>) -> Self {
        let mut roots = Vec::new();
        if let Some(home) = home {
            let library = home.join("Library");
            let mobile = library.join("Mobile Documents");
            roots.push((mobile.clone(), CloudService::ICloudDrive));
            // Desktop and Documents in iCloud have their twins there.
            let drive = mobile.join("com~apple~CloudDocs");
            for name in ["Desktop", "Documents"] {
                if drive.join(name).is_dir() {
                    roots.push((home.join(name), CloudService::ICloudDrive));
                }
            }
            for (name, _) in folders(&library.join("CloudStorage")) {
                let service = service_named(&name).unwrap_or(CloudService::Other);
                roots.push((library.join("CloudStorage").join(name), service));
            }
            for (name, path) in folders(home) {
                if let Some(service) = service_named(&name) {
                    roots.push((path, service));
                } else if name == "iCloudDrive" {
                    roots.push((path, CloudService::ICloudDrive));
                }
            }
            roots.extend(
                dropbox_info(&home.join(".dropbox").join("info.json"))
                    .into_iter()
                    .map(|path| (path, CloudService::Dropbox)),
            );
        }
        for variable in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            if let Some(path) = std::env::var_os(variable).map(PathBuf::from)
                && path.is_absolute()
            {
                roots.push((path, CloudService::OneDrive));
            }
        }
        Self(roots)
    }

    /// The service that copies `path`, if one does.
    pub fn service(&self, path: &Path) -> Option<CloudService> {
        if let Some((_, service)) = self
            .0
            .iter()
            .filter(|(root, _)| starts_with(path, root))
            .max_by_key(|(root, _)| root.components().count())
        {
            return Some(*service);
        }
        // Google Drive for desktop: a drive whose top folder is `My Drive`
        // or `Shared drives` (`G:\My Drive`), or `~/Google Drive`.
        let mut normal = path.components().filter_map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        });
        let first = normal.next();
        let drive_root = matches!(first, Some("My Drive" | "Shared drives"))
            && path
                .components()
                .next()
                .is_some_and(|part| matches!(part, Component::Prefix(_)));
        drive_root.then_some(CloudService::GoogleDrive)
    }
}

/// Whether `path` is `root` or in it, comparing names without case where
/// the file system usually ignores it.
fn starts_with(path: &Path, root: &Path) -> bool {
    if cfg!(any(target_os = "macos", windows)) {
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(path).starts_with(lower(root))
    } else {
        path.starts_with(root)
    }
}

/// The service a folder's name says: `Dropbox`, `Dropbox (Company)`,
/// `OneDrive - Company`, `GoogleDrive-me@example.com`, `Google Drive`.
fn service_named(name: &str) -> Option<CloudService> {
    if name == "Dropbox" || name.starts_with("Dropbox (") || name.starts_with("Dropbox-") {
        Some(CloudService::Dropbox)
    } else if name == "OneDrive" || name.starts_with("OneDrive - ") || name.starts_with("OneDrive-")
    {
        Some(CloudService::OneDrive)
    } else if name == "Google Drive" || name == "My Drive" || name.starts_with("GoogleDrive") {
        Some(CloudService::GoogleDrive)
    } else if name.starts_with("iCloud") {
        Some(CloudService::ICloudDrive)
    } else {
        None
    }
}

/// The folders in `dir`, by name; none if it can't be read.
fn folders(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    read.filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| Some((entry.file_name().to_str()?.to_owned(), entry.path())))
        .collect()
}

/// The folders Dropbox's `info.json` names: `{"personal": {"path": …}}`.
fn dropbox_info(path: &Path) -> Vec<PathBuf> {
    let Ok(bytes) = crate::fsutil::read_limited(path, 64 * 1024) else {
        return Vec::new();
    };
    let Ok(serde_json::Value::Object(accounts)) = serde_json::from_slice(&bytes) else {
        return Vec::new();
    };
    accounts
        .values()
        .filter_map(|account| account.get("path")?.as_str().map(PathBuf::from))
        .filter(|path| path.is_absolute())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_of_cloud_services_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for folder in [
            "Library/Mobile Documents/com~apple~CloudDocs/Documents",
            "Library/CloudStorage/OneDrive-Personal",
            "Library/CloudStorage/Box-Box",
            "Dropbox (Acme)",
            "code",
        ] {
            fs::create_dir_all(home.join(folder)).unwrap();
        }
        let elsewhere = home.join("elsewhere");
        fs::create_dir_all(home.join(".dropbox")).unwrap();
        fs::write(
            home.join(".dropbox").join("info.json"),
            serde_json::json!({ "business": { "path": elsewhere } }).to_string(),
        )
        .unwrap();
        let roots = CloudRoots::detect(Some(home));
        let service = |parts: &[&str]| {
            let mut path = home.to_path_buf();
            path.extend(parts);
            roots.service(&path)
        };
        assert_eq!(service(&["code", "shop", ".env"]), None);
        assert_eq!(
            service(&["Documents", "shop", ".env"]),
            Some(CloudService::ICloudDrive)
        );
        assert_eq!(
            service(&["Library", "CloudStorage", "OneDrive-Personal", "a", ".env"]),
            Some(CloudService::OneDrive)
        );
        assert_eq!(
            service(&["Library", "CloudStorage", "Box-Box", ".env"]),
            Some(CloudService::Other)
        );
        assert_eq!(
            service(&["Dropbox (Acme)", "app", ".env"]),
            Some(CloudService::Dropbox)
        );
        assert_eq!(service(&["elsewhere", ".env"]), Some(CloudService::Dropbox));
        assert_eq!(service(&["Desktop", ".env"]), None);
    }

    #[cfg(windows)]
    #[test]
    fn google_drive_is_a_drive_of_its_own() {
        let roots = CloudRoots::default();
        assert_eq!(
            roots.service(Path::new(r"G:\My Drive\shop\.env")),
            Some(CloudService::GoogleDrive)
        );
        assert_eq!(roots.service(Path::new(r"C:\code\My Drive\.env")), None);
    }
}
