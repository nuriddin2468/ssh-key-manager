//! Locations of the OpenSSH files and helpers for `~` paths.

use std::path::{Component, MAIN_SEPARATOR, Path, PathBuf};

use serde::{Serialize, Serializer};

use crate::{Error, Result};

/// The OpenSSH files the application works with.
///
/// Every other function in the crate takes explicit paths, so tests and
/// alternative locations never touch the real `~/.ssh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct SshPaths {
    /// Home directory used for `~` and `%d` expansion.
    #[serde(serialize_with = "serialize_path")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub home: PathBuf,
    /// The `.ssh` directory (`~/.ssh`, `%USERPROFILE%\.ssh` on Windows).
    #[serde(serialize_with = "serialize_path")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub dir: PathBuf,
    /// The user's client configuration (`<dir>/config`).
    #[serde(serialize_with = "serialize_path")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub config: PathBuf,
    /// The user's known hosts file (`<dir>/known_hosts`).
    #[serde(serialize_with = "serialize_path")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub known_hosts: PathBuf,
}

impl SshPaths {
    /// Paths for the current user, from the home directory reported by the OS
    /// (`$HOME` on Unix, the profile folder on Windows — the same one OpenSSH
    /// for Windows uses).
    pub fn detect() -> Result<Self> {
        let home = home_dir().ok_or_else(|| Error::NotFound("home directory".into()))?;
        Ok(Self::with_home(home.clone(), home.join(".ssh")))
    }

    /// Paths for an explicit `.ssh` directory. The home directory is taken to
    /// be its parent.
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let home = dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| dir.clone(), Path::to_path_buf);
        Self::with_home(home, dir)
    }

    /// Paths for an explicit home and `.ssh` directory.
    pub fn with_home(home: impl Into<PathBuf>, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            home: home.into(),
            config: dir.join("config"),
            known_hosts: dir.join("known_hosts"),
            dir,
        }
    }
}

/// The current user's home directory, if the OS knows it.
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir().filter(|p| !p.as_os_str().is_empty())
}

/// Expands a leading `~` (`~`, `~/…`, and `~\…` on Windows) against the current
/// user's home directory. Other inputs, including `~user/…`, are returned as is.
pub fn expand_tilde(input: &str) -> PathBuf {
    match home_dir() {
        Some(home) => expand_tilde_in(input, &home),
        None => PathBuf::from(input),
    }
}

/// Like [`expand_tilde`] with an explicit home directory.
pub fn expand_tilde_in(input: &str, home: &Path) -> PathBuf {
    if input == "~" {
        return home.to_path_buf();
    }
    let rest = input
        .strip_prefix("~/")
        .or_else(|| cfg!(windows).then(|| input.strip_prefix("~\\")).flatten());
    match rest {
        Some(rest) => home.join(native_separators(rest)),
        None => PathBuf::from(input),
    }
}

/// Formats a path for display, abbreviating the current user's home as `~`.
pub fn display_path(path: &Path) -> String {
    match home_dir() {
        Some(home) => display_path_in(path, &home),
        None => path_string(path),
    }
}

/// Like [`display_path`] with an explicit home directory.
pub fn display_path_in(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) if !rest.components().any(|c| matches!(c, Component::ParentDir)) => {
            format!("~{MAIN_SEPARATOR}{}", rest.to_string_lossy())
        }
        _ => path_string(path),
    }
}

/// A path as a `String` for the UI (lossy only for non-UTF-8 paths, which the
/// key scanner reports instead of returning).
pub(crate) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Rewrites `/` to the platform separator on Windows (no-op elsewhere), so paths
/// built from `ssh_config` values compare equal to paths found by scanning.
pub(crate) fn native_separators(s: &str) -> String {
    if cfg!(windows) {
        s.replace('/', "\\")
    } else {
        s.to_owned()
    }
}

#[allow(clippy::ptr_arg)] // signature required by serde's `serialize_with`
pub(crate) fn serialize_path<S: Serializer>(path: &PathBuf, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_dir_derives_files() {
        let p = SshPaths::from_dir("/home/u/.ssh");
        assert_eq!(p.home, PathBuf::from("/home/u"));
        assert_eq!(p.config, PathBuf::from("/home/u/.ssh/config"));
        assert_eq!(p.known_hosts, PathBuf::from("/home/u/.ssh/known_hosts"));
    }

    #[test]
    fn tilde_expansion() {
        let home = Path::new("/home/u");
        assert_eq!(expand_tilde_in("~", home), PathBuf::from("/home/u"));
        assert_eq!(
            expand_tilde_in("~/.ssh/id", home),
            home.join(native_separators(".ssh/id"))
        );
        assert_eq!(expand_tilde_in("~bob/x", home), PathBuf::from("~bob/x"));
        assert_eq!(expand_tilde_in("/abs", home), PathBuf::from("/abs"));
    }

    #[cfg(unix)]
    #[test]
    fn display_abbreviates_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            display_path_in(Path::new("/home/u/.ssh/id"), home),
            "~/.ssh/id"
        );
        assert_eq!(display_path_in(Path::new("/home/u"), home), "~");
        assert_eq!(
            display_path_in(Path::new("/home/user2/x"), home),
            "/home/user2/x"
        );
        assert_eq!(display_path_in(Path::new("/etc/ssh"), home), "/etc/ssh");
    }

    #[test]
    fn serializes_paths_as_strings() {
        let p = SshPaths::from_dir("/h/.ssh");
        let v = serde_json::to_value(&p).unwrap();
        assert!(v["knownHosts"].is_string());
        assert_eq!(v["dir"], "/h/.ssh");
    }
}
