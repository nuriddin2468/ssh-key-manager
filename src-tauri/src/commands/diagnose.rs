//! Why a connection failed (see [`sshkm_core::diagnose`]), and two checks
//! that help fix it: a quick probe of the server's port, and the audit's
//! permission fix for a file `ssh` refused.

use std::path::Path;
use std::time::Duration;

use sshkm_core::ErrorCode;
use sshkm_core::audit::{self, FixAction};
use sshkm_core::diagnose::{self, Context, Diagnosis, PortProbe};
use sshkm_core::perms;
use tauri::State;

use super::remote::check_alias;
use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::process;
use crate::state::AppState;
use crate::terminal::text::Resolved;

/// The option that makes a check's `ssh` say what it tries: the keys it
/// offers and the methods the server takes. Its debug lines never hold an
/// answer (those go through askpass), and [`diagnose::readable`] keeps them
/// out of what the user reads; they can hold the values of environment
/// variables `ssh` sends, so only lines about the failure are kept.
pub const VERBOSE: &str = "-v";

/// How long the probe waits for each address.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Why the run of `alias` that printed `output` failed, with what `ssh -G`
/// says about the host.
pub fn diagnosis(alias: &str, output: &str, timed_out: bool) -> Diagnosis {
    let resolved = ssh_g(alias).ok();
    let context = Context {
        host_name: resolved.as_ref().and_then(|r| r.resolved.host_name.clone()),
        proxy_jump: resolved.and_then(|r| r.resolved.proxy_jump),
        timed_out,
    };
    diagnose::diagnose(output, &context)
}

/// Connects to the port of `alias`, or of its first jump host (the one this
/// computer connects to), and closes the connection at once, to tell a
/// server that is off or behind a firewall from one that turns `ssh` down.
///
/// Fails with `unsupported` for a host behind a `ProxyCommand`, whose way
/// there is the command's.
#[tauri::command]
pub async fn diagnose_probe(state: State<'_, Shared>, alias: String) -> AppResult<PortProbe> {
    blocking(&state, move |_| probe(&alias)).await
}

fn probe(alias: &str) -> AppResult<PortProbe> {
    check_alias(alias)?;
    let target = ssh_g(alias)?;
    let (host, port) = if let Some(jump) = target.resolved.proxy_jump.as_deref() {
        let (first, port) = diagnose::first_jump(jump)
            .ok_or_else(|| AppError::invalid("the ProxyJump names no host"))?;
        // `ssh -G` puts the jump host's name into commands as it does an
        // alias's.
        check_alias(&first)?;
        let hop = ssh_g(&first)?;
        (
            hop.resolved.host_name.unwrap_or(first),
            port.unwrap_or(hop.port),
        )
    } else if target.resolved.proxy_command.is_some() {
        return Err(AppError::new(
            ErrorCode::Unsupported,
            "the host is reached through a ProxyCommand",
        ));
    } else {
        (
            target
                .resolved
                .host_name
                .unwrap_or_else(|| alias.to_owned()),
            target.port,
        )
    };
    Ok(diagnose::probe(&host, port, PROBE_TIMEOUT))
}

/// Fixes the permissions of a file `ssh` refused (`path` as it printed it)
/// if the audit offers that fix, so only files in `~/.ssh`. Returns whether
/// it fixed one.
#[tauri::command]
pub async fn diagnose_fix_permissions(state: State<'_, Shared>, path: String) -> AppResult<bool> {
    blocking(&state, move |state| fix_permissions(state, &path)).await
}

fn fix_permissions(state: &AppState, printed: &str) -> AppResult<bool> {
    let report = audit::run_for_paths(&state.paths, &state.hosts_file, &[])?;
    // Compared as paths: Windows' `ssh` mixes and doubles separators.
    let wanted = Path::new(printed);
    let offered = report
        .findings
        .into_iter()
        .find_map(|finding| match finding.fix {
            Some(FixAction::FixPermissions { path, target }) if Path::new(&path) == wanted => {
                Some((path, target))
            }
            _ => None,
        });
    let Some((path, kind)) = offered else {
        return Ok(false);
    };
    perms::fix_inside(&state.paths.dir, Path::new(&path), kind)?;
    Ok(true)
}

/// What `ssh -G` says, with the port.
struct SshG {
    resolved: Resolved,
    port: u16,
}

fn ssh_g(alias: &str) -> AppResult<SshG> {
    let output = process::run("ssh", &["-G", "--", alias], Duration::from_secs(10))?;
    if !output.success {
        return Err(AppError::invalid(format!(
            "ssh cannot read its configuration for {alias}: {}",
            output.stderr.trim()
        )));
    }
    let port = output
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("port "))
        .and_then(|port| port.trim().parse().ok())
        .unwrap_or(22);
    Ok(SshG {
        resolved: Resolved::parse(&output.stdout),
        port,
    })
}

#[cfg(test)]
mod tests {
    use sshkm_core::paths::SshPaths;

    use super::*;

    #[test]
    fn probes_refuse_aliases_with_shell_syntax() {
        for alias in ["x';id;'.internal", "-oProxyCommand=id", "*"] {
            let error = probe(alias).expect_err(alias);
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }

    /// Only what the audit offers is fixed.
    #[cfg(unix)]
    #[test]
    fn fixes_only_files_the_audit_names() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = AppState::new(
            SshPaths::with_home(home.path(), dir.clone()),
            home.path().join("hosts"),
            home.path().join("backups"),
            home.path().join("data"),
        );
        let key = dir.join("id_ed25519");
        std::fs::write(
            &key,
            include_str!("../../../crates/sshkm-core/src/keys/testdata/openssh_ed25519"),
        )
        .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let outside = home.path().join("elsewhere");
        std::fs::write(&outside, "x").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o666)).unwrap();

        assert!(!fix_permissions(&state, &outside.to_string_lossy()).unwrap());
        assert_eq!(mode(&outside), 0o666);
        assert!(fix_permissions(&state, &key.to_string_lossy()).unwrap());
        assert_eq!(mode(&key), 0o600);
        assert!(!fix_permissions(&state, &key.to_string_lossy()).unwrap());
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }
}
