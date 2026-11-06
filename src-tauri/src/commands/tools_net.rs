//! The Tools page: secrets made for one job, and network checks.
//!
//! A generated secret goes to the UI, which shows it, like
//! [`super::vault::vault_generate`]'s; copying it goes back through Rust to
//! the clipboard the way a vault password does. The network checks run only
//! when the user asks, on the blocking pool, each with its timeout.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sshkm_core::net::dns::{self, DnsReport};
use sshkm_core::net::tls::{self, TlsReport};
use sshkm_core::net::{self, PortCheck, SshPing};
use sshkm_core::vault::{self, SecretPreset};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::State;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::types::CopyResult;

/// How long a connection, a banner or a handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long each DNS server has to answer.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// The longest text the generator's copy takes: a connection string or a
/// JSON line around a secret.
const MAX_COPY: usize = 8 * 1024;

/// A secret from [`tools_generate_secret`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct GeneratedSecret {
    pub value: String,
    /// The random bits it holds, rounded down.
    pub bits: u16,
}

/// A secret for one job. Works while the vault is locked.
#[tauri::command]
pub async fn tools_generate_secret(preset: SecretPreset) -> AppResult<GeneratedSecret> {
    let generated = vault::generate_preset(&preset)?;
    Ok(GeneratedSecret {
        value: generated.value.expose_secret().to_owned(),
        bits: generated.bits,
    })
}

/// Copies what the generator made (the secret, or a line around it) like a
/// vault password: kept out of clipboard history and cloud clipboards, and
/// cleared after the vault's clipboard time. Works while the vault is locked.
#[tauri::command]
pub async fn tools_copy_secret(
    state: State<'_, Shared>,
    text: SecretString,
) -> AppResult<CopyResult> {
    blocking(&state, move |state| {
        let length = text.expose_secret().len();
        if length == 0 || length > MAX_COPY {
            return Err(AppError::invalid("nothing to copy"));
        }
        let clears_in_secs = Arc::clone(&state.vault).copy(&text, true)?;
        Ok(CopyResult { clears_in_secs })
    })
    .await
}

/// Times `samples` TCP connections to `host:port` and reads the SSH
/// server's identification line.
#[tauri::command]
pub async fn tools_ssh_ping(
    state: State<'_, Shared>,
    host: String,
    port: u16,
    samples: u8,
) -> AppResult<SshPing> {
    blocking(&state, move |_| {
        Ok(net::ssh_ping(&host, port, samples, CONNECT_TIMEOUT)?)
    })
    .await
}

/// Whether `host:port` takes TCP connections, waiting `timeout_ms` at most.
#[tauri::command]
pub async fn tools_port_check(
    state: State<'_, Shared>,
    host: String,
    port: u16,
    timeout_ms: u32,
) -> AppResult<PortCheck> {
    let timeout = Duration::from_millis(timeout_ms.into());
    blocking(&state, move |_| Ok(net::port_check(&host, port, timeout)?)).await
}

/// A name's A, AAAA, CNAME, MX and TXT records from the computer's DNS
/// servers.
#[tauri::command]
pub async fn tools_dns_lookup(state: State<'_, Shared>, name: String) -> AppResult<DnsReport> {
    blocking(&state, move |_| Ok(dns::lookup(&name, DNS_TIMEOUT)?)).await
}

/// The TLS certificate `host:port` presents, and whether the system trusts
/// it.
#[tauri::command]
pub async fn tools_tls_check(
    state: State<'_, Shared>,
    host: String,
    port: u16,
) -> AppResult<TlsReport> {
    blocking(&state, move |_| {
        Ok(tls::tls_check(&host, port, CONNECT_TIMEOUT)?)
    })
    .await
}
