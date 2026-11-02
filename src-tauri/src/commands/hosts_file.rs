use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use sshkm_core::hosts_file::{self, HostsFile};
use tauri::State;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::types::{HostsFileInfo, NameLookup};

/// How long a lookup may take before the UI is told there was no answer.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

#[tauri::command]
pub async fn read_hosts_file(state: State<'_, Shared>) -> AppResult<HostsFileInfo> {
    blocking(&state, hosts_file_info).await
}

/// Asks the system resolver (the hosts file, then DNS) for a name's
/// addresses, as `ssh` would. DNS goes over the network, so the UI calls this
/// only when the user asks.
#[tauri::command]
pub async fn lookup_host(state: State<'_, Shared>, name: String) -> AppResult<NameLookup> {
    blocking(&state, move |_| {
        let name = name.trim().to_owned();
        if !hosts_file::is_valid_name(&name) {
            return Err(AppError::invalid("not a host name"));
        }
        // The resolver has no timeout of its own; a stuck lookup is left to
        // finish on its thread.
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let result = (name.as_str(), 0)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|addr| addr.ip().to_string()).collect::<Vec<_>>());
            let _ = send.send(result);
        });
        Ok(match receive.recv_timeout(LOOKUP_TIMEOUT) {
            Ok(Ok(found)) => {
                let mut addresses: Vec<String> = Vec::new();
                for address in found {
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                NameLookup {
                    addresses,
                    error: None,
                }
            }
            Ok(Err(error)) => NameLookup {
                addresses: Vec::new(),
                error: Some(error.to_string()),
            },
            Err(_) => NameLookup {
                addresses: Vec::new(),
                error: Some("no answer".to_owned()),
            },
        })
    })
    .await
}

fn hosts_file_info(state: &AppState) -> AppResult<HostsFileInfo> {
    let file = HostsFile::load(&state.hosts_file)?;
    Ok(HostsFileInfo {
        path: state.hosts_file.to_string_lossy().into_owned(),
        exists: state.hosts_file.exists(),
        view: file.view(),
    })
}
