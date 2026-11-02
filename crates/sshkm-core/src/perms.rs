//! File permission checks and fixes, mirroring what OpenSSH enforces.
//!
//! - Unix: private keys must not be accessible by group or others
//!   (`mode & 0o077 == 0`, OpenSSH refuses them otherwise); public keys and
//!   `config` must not be writable by group or others; `~/.ssh` should be 0700.
//! - Windows: OpenSSH for Windows accepts a file only if the access list grants
//!   rights to nobody except the current user, `SYSTEM` (`S-1-5-18`) and
//!   `Administrators` (`S-1-5-32-544`). ACLs are read with one PowerShell call
//!   per batch of paths and compared by SID, which is independent of the
//!   display language. Fixes use `icacls`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// What a path is, which decides the rule applied to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PermKind {
    /// A private key: owner-only (0600).
    PrivateKey,
    /// A public key: not writable by others (0644).
    PublicKey,
    /// `ssh_config` or `known_hosts`: not writable by others (fixed to 0600).
    Config,
    /// The `.ssh` directory: owner-only (0700).
    SshDir,
}

impl PermKind {
    /// The mode [`fix`] applies on Unix.
    pub const fn recommended_mode(self) -> u32 {
        match self {
            Self::PrivateKey | Self::Config => 0o600,
            Self::PublicKey => 0o644,
            Self::SshDir => 0o700,
        }
    }
}

/// Why a path's permissions are not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PermissionProblem {
    /// Group or others can read (or otherwise access) a file that must be
    /// owner-only (Unix).
    GroupOrOtherAccess,
    /// Group or others can write the file (Unix).
    WritableByOthers,
    /// Users other than the owner, `SYSTEM` and `Administrators` have access, or
    /// the owner is someone else (Windows).
    OtherPrincipals,
    /// The path does not exist.
    NotFound,
    /// The permissions could not be determined.
    CheckFailed,
}

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PermissionReport {
    /// True if the permissions are acceptable.
    pub ok: bool,
    /// Octal permission bits, e.g. `"600"` (Unix only).
    pub mode: Option<String>,
    /// The problem when `ok` is false.
    pub problem: Option<PermissionProblem>,
}

impl PermissionReport {
    fn good(mode: Option<u32>) -> Self {
        Self {
            ok: true,
            mode: mode.map(format_mode),
            problem: None,
        }
    }

    fn bad(mode: Option<u32>, problem: PermissionProblem) -> Self {
        Self {
            ok: false,
            mode: mode.map(format_mode),
            problem: Some(problem),
        }
    }

    /// True if the report describes an actual permission problem (as opposed
    /// to a missing file or a failed check).
    pub fn is_problem(&self) -> bool {
        matches!(
            self.problem,
            Some(
                PermissionProblem::GroupOrOtherAccess
                    | PermissionProblem::WritableByOthers
                    | PermissionProblem::OtherPrincipals
            )
        )
    }
}

fn format_mode(mode: u32) -> String {
    format!("{:03o}", mode & 0o777)
}

/// Applies the Unix rule for `kind` to permission bits. Pure; exposed so the
/// rules are testable on every platform.
pub fn evaluate_mode(mode: u32, kind: PermKind) -> PermissionReport {
    let mode = mode & 0o777;
    match kind {
        PermKind::PrivateKey | PermKind::SshDir => {
            if mode & 0o022 != 0 {
                PermissionReport::bad(Some(mode), PermissionProblem::WritableByOthers)
            } else if mode & 0o077 != 0 {
                PermissionReport::bad(Some(mode), PermissionProblem::GroupOrOtherAccess)
            } else {
                PermissionReport::good(Some(mode))
            }
        }
        PermKind::PublicKey | PermKind::Config => {
            if mode & 0o022 != 0 {
                PermissionReport::bad(Some(mode), PermissionProblem::WritableByOthers)
            } else {
                PermissionReport::good(Some(mode))
            }
        }
    }
}

/// Checks one path.
pub fn check(path: &Path, kind: PermKind) -> PermissionReport {
    check_many(&[(path.to_path_buf(), kind)])
        .pop()
        .unwrap_or_else(|| PermissionReport::bad(None, PermissionProblem::CheckFailed))
}

/// Checks many paths at once; the result has the same order as `items`. On
/// Windows this spawns PowerShell once per batch instead of once per path.
pub fn check_many(items: &[(PathBuf, PermKind)]) -> Vec<PermissionReport> {
    imp::check_many(items)
}

/// Restricts `path` to the permissions recommended for `kind`
/// ([`PermKind::recommended_mode`] on Unix; owner, `SYSTEM` and
/// `Administrators` on Windows).
pub fn fix(path: &Path, kind: PermKind) -> Result<()> {
    if std::fs::symlink_metadata(path).is_err() {
        return Err(Error::NotFound(path.display().to_string()));
    }
    imp::fix(path, kind)
}

#[cfg(unix)]
mod imp {
    use std::{fs, io, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::{PermKind, PermissionProblem, PermissionReport, evaluate_mode};
    use crate::{Result, fsutil};

    pub(super) fn check_many(items: &[(PathBuf, PermKind)]) -> Vec<PermissionReport> {
        items
            .iter()
            .map(|(path, kind)| match fs::metadata(path) {
                Ok(meta) => evaluate_mode(meta.permissions().mode(), *kind),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    PermissionReport::bad(None, PermissionProblem::NotFound)
                }
                Err(_) => PermissionReport::bad(None, PermissionProblem::CheckFailed),
            })
            .collect()
    }

    pub(super) fn fix(path: &std::path::Path, kind: PermKind) -> Result<()> {
        fsutil::set_mode(path, kind.recommended_mode())
    }
}

#[cfg(windows)]
mod imp {
    use std::{
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::OnceLock,
    };

    use base64ct::{Base64, Encoding};

    use super::{PermKind, PermissionProblem, PermissionReport, windows_acl};
    use crate::{Error, Result};

    /// `CREATE_NO_WINDOW`: do not flash a console window from the GUI app.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// Paths per PowerShell invocation (keeps the command line well below the
    /// 32 767 character limit).
    const BATCH: usize = 40;

    pub(super) fn check_many(items: &[(PathBuf, PermKind)]) -> Vec<PermissionReport> {
        let Some(user) = current_user_sid() else {
            return items
                .iter()
                .map(|_| PermissionReport::bad(None, PermissionProblem::CheckFailed))
                .collect();
        };
        let mut out = Vec::with_capacity(items.len());
        for chunk in items.chunks(BATCH) {
            let paths: Vec<&Path> = chunk.iter().map(|(p, _)| p.as_path()).collect();
            let acls = query_acls(&paths);
            for ((path, _kind), acl) in chunk.iter().zip(acls) {
                out.push(match acl {
                    Some(acl) => windows_acl::evaluate(&acl, user),
                    None if !path.exists() => {
                        PermissionReport::bad(None, PermissionProblem::NotFound)
                    }
                    None => PermissionReport::bad(None, PermissionProblem::CheckFailed),
                });
            }
        }
        out
    }

    pub(super) fn fix(path: &Path, kind: PermKind) -> Result<()> {
        let user = current_user_sid()
            .ok_or_else(|| Error::Unsupported("cannot determine the current user's SID".into()))?;
        let rights = if kind == PermKind::SshDir {
            "(OI)(CI)F"
        } else {
            "F"
        };
        let mut cmd = Command::new("icacls");
        cmd.arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("*{user}:{rights}"))
            .arg(format!("*{}:{rights}", windows_acl::SYSTEM))
            .arg(format!("*{}:{rights}", windows_acl::ADMINISTRATORS));
        run_quiet(&mut cmd, path)?;

        // `/grant:r` leaves explicit entries of other principals in place;
        // remove them as well.
        if let Some(Some(acl)) = query_acls(&[path]).pop() {
            let extra = windows_acl::extra_principals(&acl, user);
            if !extra.is_empty() {
                let mut cmd = Command::new("icacls");
                cmd.arg(path).arg("/remove:g");
                for sid in extra {
                    cmd.arg(format!("*{sid}"));
                }
                run_quiet(&mut cmd, path)?;
            }
        }
        Ok(())
    }

    fn run_quiet(cmd: &mut Command, path: &Path) -> Result<()> {
        let output = cmd
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| Error::io(e, path))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::PermissionDenied(format!(
                "icacls failed for {}",
                path.display()
            )))
        }
    }

    /// The current user's SID from `whoami /user /fo csv /nh`, cached.
    fn current_user_sid() -> Option<&'static str> {
        static SID: OnceLock<Option<String>> = OnceLock::new();
        SID.get_or_init(|| {
            let output = Command::new("whoami")
                .args(["/user", "/fo", "csv", "/nh"])
                .stdin(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            windows_acl::parse_whoami_csv(&String::from_utf8_lossy(&output.stdout))
        })
        .as_deref()
    }

    /// Reads owner and allow-ACE SIDs of each path with one PowerShell call.
    fn query_acls(paths: &[&Path]) -> Vec<Option<windows_acl::Acl>> {
        let script = windows_acl::script(paths);
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = Base64::encode_string(&utf16);
        let output = Command::new("powershell.exe")
            // Started from a PowerShell 7 session (directly or through other
            // processes), `PSModulePath` lists PowerShell 7's modules first, and
            // Windows PowerShell then fails to load `Get-Acl` and `Sort-Object`.
            // Without it, Windows PowerShell uses its own default module path.
            .env_remove("PSModulePath")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                &encoded,
            ])
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        match output {
            Ok(out) => {
                windows_acl::parse_output(&String::from_utf8_lossy(&out.stdout), paths.len())
            }
            Err(_) => vec![None; paths.len()],
        }
    }
}

/// Platform-independent pieces of the Windows ACL check (unit-tested everywhere).
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_acl {
    use std::path::Path;

    use super::{PermissionProblem, PermissionReport};

    pub(super) const SYSTEM: &str = "S-1-5-18";
    pub(super) const ADMINISTRATORS: &str = "S-1-5-32-544";

    /// Owner and the SIDs of all `Allow` entries of one file.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Acl {
        pub(super) owner: String,
        pub(super) allowed: Vec<String>,
    }

    fn is_trusted(sid: &str, user: &str) -> bool {
        sid == user || sid == SYSTEM || sid == ADMINISTRATORS
    }

    pub(super) fn evaluate(acl: &Acl, user: &str) -> PermissionReport {
        if !is_trusted(&acl.owner, user) || !extra_principals(acl, user).is_empty() {
            PermissionReport::bad(None, PermissionProblem::OtherPrincipals)
        } else {
            PermissionReport::good(None)
        }
    }

    pub(super) fn extra_principals<'a>(acl: &'a Acl, user: &str) -> Vec<&'a str> {
        acl.allowed
            .iter()
            .map(String::as_str)
            .filter(|sid| !is_trusted(sid, user))
            .collect()
    }

    /// Quotes a string as a PowerShell single-quoted literal. PowerShell also
    /// treats the typographic quotes U+2018..U+201B as single quotes.
    fn ps_quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('\'');
        for c in s.chars() {
            if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
                out.push(c);
            }
            out.push(c);
        }
        out.push('\'');
        out
    }

    /// Script printing one line per path: `<index>\tOK\t<owner>\t<sid,sid,…>`
    /// or `<index>\tERR`. Paths are never echoed, so the console code page does
    /// not matter.
    pub(super) fn script(paths: &[&Path]) -> String {
        let list = paths
            .iter()
            .map(|p| ps_quote(&p.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"$ErrorActionPreference = 'Stop'
$sidType = [System.Security.Principal.SecurityIdentifier]
$paths = @({list})
for ($i = 0; $i -lt $paths.Count; $i++) {{
  try {{
    $acl = Get-Acl -LiteralPath $paths[$i]
    $owner = try {{ $acl.GetOwner($sidType).Value }} catch {{ '?' }}
    $sids = @(foreach ($ace in $acl.Access) {{
      if ($ace.AccessControlType -ne 'Allow') {{ continue }}
      try {{ $ace.IdentityReference.Translate($sidType).Value }} catch {{ '?' }}
    }})
    [Console]::Out.WriteLine("$i`tOK`t$owner`t" + (($sids | Sort-Object -Unique) -join ','))
  }} catch {{
    [Console]::Out.WriteLine("$i`tERR")
  }}
}}
"#
        )
    }

    pub(super) fn parse_output(stdout: &str, count: usize) -> Vec<Option<Acl>> {
        let mut out = vec![None; count];
        for line in stdout.lines() {
            let mut fields = line.trim_end_matches('\r').split('\t');
            let Some(Ok(index)) = fields.next().map(str::parse::<usize>) else {
                continue;
            };
            if index >= count || fields.next() != Some("OK") {
                continue;
            }
            let owner = fields.next().unwrap_or("?").trim().to_owned();
            let allowed = fields
                .next()
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            out[index] = Some(Acl { owner, allowed });
        }
        out
    }

    /// Extracts the SID from `"domain\user","S-1-5-21-…"`.
    pub(super) fn parse_whoami_csv(stdout: &str) -> Option<String> {
        let line = stdout.lines().find(|l| !l.trim().is_empty())?;
        let sid = line.rsplit(',').next()?.trim().trim_matches('"');
        sid.starts_with("S-1-").then(|| sid.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_rules() {
        assert!(evaluate_mode(0o600, PermKind::PrivateKey).ok);
        assert!(evaluate_mode(0o400, PermKind::PrivateKey).ok);
        let r = evaluate_mode(0o644, PermKind::PrivateKey);
        assert_eq!(r.problem, Some(PermissionProblem::GroupOrOtherAccess));
        assert_eq!(r.mode.as_deref(), Some("644"));
        let r = evaluate_mode(0o666, PermKind::PrivateKey);
        assert_eq!(r.problem, Some(PermissionProblem::WritableByOthers));
        assert!(evaluate_mode(0o644, PermKind::PublicKey).ok);
        assert!(!evaluate_mode(0o664, PermKind::PublicKey).ok);
        assert!(evaluate_mode(0o644, PermKind::Config).ok);
        assert_eq!(
            evaluate_mode(0o646, PermKind::Config).problem,
            Some(PermissionProblem::WritableByOthers)
        );
        assert!(evaluate_mode(0o700, PermKind::SshDir).ok);
        assert_eq!(
            evaluate_mode(0o755, PermKind::SshDir).problem,
            Some(PermissionProblem::GroupOrOtherAccess)
        );
        assert_eq!(
            evaluate_mode(0o100_600, PermKind::PrivateKey)
                .mode
                .as_deref(),
            Some("600")
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_and_fix_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id");
        std::fs::write(&key, "x").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let missing = dir.path().join("missing");
        let reports = check_many(&[
            (key.clone(), PermKind::PrivateKey),
            (key.clone(), PermKind::PublicKey),
            (missing.clone(), PermKind::PrivateKey),
        ]);
        assert!(!reports[0].ok);
        assert!(reports[0].is_problem());
        assert!(reports[1].ok);
        assert_eq!(reports[2].problem, Some(PermissionProblem::NotFound));
        assert!(!reports[2].is_problem());
        fix(&key, PermKind::PrivateKey).unwrap();
        assert!(check(&key, PermKind::PrivateKey).ok);
        fix(dir.path(), PermKind::SshDir).unwrap();
        assert!(check(dir.path(), PermKind::SshDir).ok);
        assert_eq!(
            fix(&missing, PermKind::PrivateKey).unwrap_err().code(),
            crate::ErrorCode::NotFound
        );
    }

    #[cfg(windows)]
    #[test]
    fn check_and_fix_acl_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id");
        std::fs::write(&key, "x").unwrap();
        // Let the local Users group read the key.
        let granted = std::process::Command::new("icacls")
            .arg(&key)
            .args(["/grant", "*S-1-5-32-545:R"])
            .output()
            .unwrap();
        assert!(granted.status.success(), "{granted:?}");
        let missing = dir.path().join("missing");
        let reports = check_many(&[
            (key.clone(), PermKind::PrivateKey),
            (missing.clone(), PermKind::PrivateKey),
        ]);
        assert_eq!(
            reports[0].problem,
            Some(PermissionProblem::OtherPrincipals),
            "{reports:?}"
        );
        assert!(reports[0].is_problem());
        assert_eq!(reports[1].problem, Some(PermissionProblem::NotFound));
        fix(&key, PermKind::PrivateKey).unwrap();
        let report = check(&key, PermKind::PrivateKey);
        assert!(report.ok, "{report:?}");
        fix(dir.path(), PermKind::SshDir).unwrap();
        let report = check(dir.path(), PermKind::SshDir);
        assert!(report.ok, "{report:?}");
        assert_eq!(
            fix(&missing, PermKind::PrivateKey).unwrap_err().code(),
            crate::ErrorCode::NotFound
        );
    }

    #[test]
    fn windows_acl_evaluation() {
        use windows_acl::*;
        let user = "S-1-5-21-1-2-3-1001";
        let good = Acl {
            owner: user.into(),
            allowed: vec![user.into(), SYSTEM.into(), ADMINISTRATORS.into()],
        };
        assert!(evaluate(&good, user).ok);
        let users_group = Acl {
            owner: user.into(),
            allowed: vec![user.into(), "S-1-5-32-545".into()],
        };
        let r = evaluate(&users_group, user);
        assert_eq!(r.problem, Some(PermissionProblem::OtherPrincipals));
        assert_eq!(extra_principals(&users_group, user), vec!["S-1-5-32-545"]);
        let foreign_owner = Acl {
            owner: "S-1-5-21-9-9-9-500".into(),
            allowed: vec![user.into()],
        };
        assert!(!evaluate(&foreign_owner, user).ok);
    }

    #[test]
    fn windows_output_parsing() {
        use windows_acl::*;
        let out = "0\tOK\tS-1-5-18\tS-1-5-18,S-1-5-32-544\r\n1\tERR\r\n7\tOK\tx\ty\r\ngarbage\n";
        let parsed = parse_output(out, 2);
        assert_eq!(
            parsed[0],
            Some(Acl {
                owner: "S-1-5-18".into(),
                allowed: vec!["S-1-5-18".into(), "S-1-5-32-544".into()],
            })
        );
        assert_eq!(parsed[1], None);
        assert_eq!(
            parse_whoami_csv("\"desktop-1\\ivan\",\"S-1-5-21-111-222-333-1001\"\r\n").as_deref(),
            Some("S-1-5-21-111-222-333-1001")
        );
        assert_eq!(parse_whoami_csv("nonsense"), None);
    }

    #[test]
    fn windows_script_quotes_paths() {
        let p = Path::new("C:\\Users\\O'Brien\\.ssh\\id");
        let s = windows_acl::script(&[p]);
        assert!(s.contains("'C:\\Users\\O''Brien\\.ssh\\id'"));
    }

    #[test]
    fn serialization() {
        let r = evaluate_mode(0o644, PermKind::PrivateKey);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["problem"], "groupOrOtherAccess");
        assert_eq!(v["mode"], "644");
        assert_eq!(serde_json::to_value(PermKind::SshDir).unwrap(), "sshDir");
    }
}
