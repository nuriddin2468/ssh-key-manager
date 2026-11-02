use std::time::Duration;

use ssh_key::{HashAlg, PublicKey};
use sshkm_core::known_hosts::{HostMarker, KnownHosts};
use tauri::State;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::process;
use crate::state::AppState;
use crate::types::{HostKeyCheck, HostKeyStatus, KnownHostsFile, OfferedKey};

#[tauri::command]
pub async fn read_known_hosts(state: State<'_, Shared>) -> AppResult<KnownHostsFile> {
    blocking(&state, known_hosts_file).await
}

/// Lines whose host patterns match `host` (including hashed entries, which the
/// UI cannot match itself).
#[tauri::command]
pub async fn find_known_hosts(
    state: State<'_, Shared>,
    host: String,
    port: Option<u16>,
) -> AppResult<Vec<u32>> {
    blocking(&state, move |state| {
        let known = KnownHosts::load(&state.paths.known_hosts)?;
        Ok(known
            .matches(host.trim(), port.unwrap_or(22))
            .into_iter()
            .map(|entry| entry.line)
            .collect())
    })
    .await
}

#[tauri::command]
pub async fn remove_known_hosts(
    state: State<'_, Shared>,
    lines: Vec<u32>,
) -> AppResult<KnownHostsFile> {
    blocking(&state, move |state| {
        let mut known = KnownHosts::load(&state.paths.known_hosts)?;
        if known.remove_lines(&lines) > 0 {
            known.save(&state.paths.known_hosts, &state.backup_dir)?;
        }
        known_hosts_file(state)
    })
    .await
}

/// Fetches the keys a server offers now (`ssh-keyscan`) and compares them with
/// the saved ones — the safe way to handle "REMOTE HOST IDENTIFICATION HAS
/// CHANGED".
#[tauri::command]
pub async fn check_host_key(
    state: State<'_, Shared>,
    host: String,
    port: Option<u16>,
) -> AppResult<HostKeyCheck> {
    blocking(&state, move |state| {
        let host = host.trim().to_owned();
        if host.is_empty() || host.starts_with('-') || host.chars().any(char::is_whitespace) {
            return Err(AppError::invalid("not a host name"));
        }
        let port = port.unwrap_or(22);
        let saved: Vec<_> = KnownHosts::load(&state.paths.known_hosts)?
            .matches(&host, port)
            .into_iter()
            .filter(|entry| entry.marker == HostMarker::None)
            .collect();

        let port_arg = port.to_string();
        let output = process::run(
            "ssh-keyscan",
            &["-T", "6", "-p", &port_arg, "--", &host],
            Duration::from_secs(15),
        )?;
        let offered: Vec<OfferedKey> = output
            .stdout
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let mut fields = line.split_whitespace().skip(1);
                let (key_type, blob) = (fields.next()?, fields.next()?);
                let key = PublicKey::from_openssh(&format!("{key_type} {blob}")).ok()?;
                Some(OfferedKey {
                    key_type: key_type.to_owned(),
                    fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                })
            })
            .collect();

        let status = if offered.is_empty() {
            HostKeyStatus::Failed
        } else if saved.is_empty() {
            HostKeyStatus::Unknown
        } else if offered
            .iter()
            .any(|o| saved.iter().any(|s| s.fingerprint == o.fingerprint))
        {
            HostKeyStatus::Match
        } else {
            HostKeyStatus::Changed
        };
        let error = (status == HostKeyStatus::Failed).then(|| {
            let text = output.stderr.trim();
            if output.timed_out || text.is_empty() {
                "no answer".to_owned()
            } else {
                text.to_owned()
            }
        });

        Ok(HostKeyCheck {
            status,
            offered,
            saved,
            error,
        })
    })
    .await
}

fn known_hosts_file(state: &AppState) -> AppResult<KnownHostsFile> {
    let known = KnownHosts::load(&state.paths.known_hosts)?;
    Ok(KnownHostsFile {
        path: state.paths.known_hosts.to_string_lossy().into_owned(),
        exists: state.paths.known_hosts.exists(),
        view: known.view(),
    })
}
