use sshkm_core::SecretString;
use sshkm_core::agent::{self, AgentClient};
use sshkm_core::keys;
use tauri::State;
use time::format_description::well_known::Rfc3339;

use super::keys::{agent_comment, find_key, private_path};
use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::types::{AgentIdentityView, AgentView};

/// Makes the agent client check who serves a Windows agent pipe before it
/// sends anything (a key) over it: this user or the system, never another
/// user ([`agent::set_pipe_check`]). Call once at startup, before any
/// `AgentClient` is used; until then every Windows agent pipe is refused.
/// Does nothing elsewhere.
pub fn check_agent_pipes() {
    #[cfg(windows)]
    agent::set_pipe_check(|pipe| {
        use std::os::windows::io::AsHandle;
        sshkm_os::pipe::check_server(pipe.as_handle(), sshkm_os::pipe::Trusted::UserOrSystem)
            .map_err(std::io::Error::other)
    });
}

#[tauri::command]
pub async fn agent_view(state: State<'_, Shared>) -> AppResult<AgentView> {
    blocking(&state, |state| {
        let status = agent::status();
        let identities = if status.available {
            AgentClient::from_env()
                .and_then(|a| a.list())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let scanned = keys::scan(&state.paths.dir)
            .map(|s| s.keys)
            .unwrap_or_default();
        let identities = identities
            .into_iter()
            .map(|identity| {
                let key_id = scanned
                    .iter()
                    .find(|k| k.fingerprint.as_deref() == Some(identity.fingerprint.as_str()))
                    .map(|k| k.id.clone());
                let expires_at = state
                    .expires_at(&identity.fingerprint)
                    .and_then(|t| t.format(&Rfc3339).ok());
                AgentIdentityView {
                    identity,
                    key_id,
                    expires_at,
                }
            })
            .collect();
        Ok(AgentView { status, identities })
    })
    .await
}

#[tauri::command]
pub async fn agent_add(
    state: State<'_, Shared>,
    key_id: String,
    passphrase: Option<SecretString>,
    lifetime_secs: Option<u32>,
) -> AppResult<()> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let unlocked = keys::load_private(&private_path(&info)?, passphrase.as_ref())?;
        AgentClient::from_env()?.add(&unlocked, &agent_comment(&info), lifetime_secs, false)?;
        state.record_lifetime(&unlocked.fingerprint(), lifetime_secs);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn agent_remove(state: State<'_, Shared>, fingerprint: String) -> AppResult<()> {
    blocking(&state, move |state| {
        let agent = AgentClient::from_env()?;
        let identity = agent
            .list()?
            .into_iter()
            .find(|id| id.fingerprint == fingerprint)
            .ok_or_else(|| AppError::not_found(format!("{fingerprint} in ssh-agent")))?;
        agent.remove(&identity.public_key)?;
        state.forget_lifetime(&fingerprint);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn agent_remove_all(state: State<'_, Shared>) -> AppResult<()> {
    blocking(&state, |state| {
        AgentClient::from_env()?.remove_all()?;
        state.forget_all_lifetimes();
        Ok(())
    })
    .await
}
