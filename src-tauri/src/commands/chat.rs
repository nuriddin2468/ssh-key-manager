//! Chats with paired computers and the user's own devices, on the Nearby
//! page (see [`crate::nearby::chat`]). Secret values reach the page only
//! through [`chat_reveal`], one at a time, when the user asks.

use std::sync::Arc;

use sshkm_core::{ErrorCode, ExposeSecret, SecretString};
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::nearby::chat::{ChatEntry, ChatList, VarReview, VarTarget};
use crate::nearby::items::SendRequest;
use crate::nearby::{Nearby, SharedNearby};
use crate::types::CopyResult;

async fn on_chats<T, F>(nearby: &SharedNearby, work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Arc<Nearby>) -> AppResult<T> + Send + 'static,
{
    let nearby = Arc::clone(nearby);
    tauri::async_runtime::spawn_blocking(move || work(&nearby))
        .await
        .map_err(|e| AppError::new(ErrorCode::Io, format!("background task failed: {e}")))?
}

/// Nearby is open (or not): while it is, and the vault is unlocked, this
/// computer is online for chats.
#[tauri::command]
pub async fn chat_set_open(nearby: State<'_, SharedNearby>, open: bool) -> AppResult<()> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_set_open(open);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn chat_list(nearby: State<'_, SharedNearby>) -> AppResult<ChatList> {
    on_chats(&nearby, |nearby| nearby.chat_list()).await
}

#[tauri::command]
pub async fn chat_history(
    nearby: State<'_, SharedNearby>,
    key: String,
) -> AppResult<Vec<ChatEntry>> {
    on_chats(&nearby, move |nearby| nearby.chat_history(&key)).await
}

#[tauri::command]
pub async fn chat_mark_read(nearby: State<'_, SharedNearby>, key: String) -> AppResult<()> {
    on_chats(&nearby, move |nearby| nearby.chat_mark_read(&key)).await
}

#[tauri::command]
pub async fn chat_send_text(
    nearby: State<'_, SharedNearby>,
    key: String,
    text: String,
) -> AppResult<()> {
    on_chats(&nearby, move |nearby| nearby.chat_send_text(&key, &text)).await
}

/// Sends a secret the user typed, gone after `ttl` seconds (an hour, a day
/// or a week).
#[tauri::command]
pub async fn chat_send_secret(
    nearby: State<'_, SharedNearby>,
    key: String,
    label: String,
    value: SecretString,
    ttl: u64,
) -> AppResult<()> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_send_secret(&key, &label, &value, ttl)
    })
    .await
}

/// Sends variables of an environment, read from the vault.
#[tauri::command]
pub async fn chat_send_variables(
    nearby: State<'_, SharedNearby>,
    key: String,
    env_id: String,
    names: Vec<String>,
    ttl: u64,
) -> AppResult<()> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_send_variables(&key, &env_id, &names, ttl)
    })
    .await
}

/// Offers what `request` names, as Nearby sends it.
#[tauri::command]
pub async fn chat_send_item(
    nearby: State<'_, SharedNearby>,
    key: String,
    request: SendRequest,
) -> AppResult<()> {
    on_chats(&nearby, move |nearby| nearby.chat_send_item(&key, &request)).await
}

/// Accepts or turns down an item offered.
#[tauri::command]
pub async fn chat_answer(
    nearby: State<'_, SharedNearby>,
    key: String,
    id: String,
    accept: bool,
) -> AppResult<()> {
    on_chats(&nearby, move |nearby| nearby.chat_answer(&key, &id, accept)).await
}

/// A secret's value, or a variable's (`name`), for the page to show.
#[tauri::command]
pub async fn chat_reveal(
    nearby: State<'_, SharedNearby>,
    key: String,
    id: String,
    name: Option<String>,
) -> AppResult<String> {
    on_chats(&nearby, move |nearby| {
        nearby
            .chat_reveal(&key, &id, name.as_deref())
            .map(|value| value.expose_secret().to_owned())
    })
    .await
}

/// Copies a secret's value, or a variable's, without it passing through the
/// page.
#[tauri::command]
pub async fn chat_copy(
    nearby: State<'_, SharedNearby>,
    key: String,
    id: String,
    name: Option<String>,
) -> AppResult<CopyResult> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_copy(&key, &id, name.as_deref())
    })
    .await
}

/// Wipes a secret or variables this user sent: with `everywhere`, on the
/// other computer too, which must be online; else only here.
#[tauri::command]
pub async fn chat_revoke(
    nearby: State<'_, SharedNearby>,
    key: String,
    id: String,
    everywhere: bool,
) -> AppResult<()> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_revoke(&key, &id, everywhere)
    })
    .await
}

/// Sends a message that didn't arrive again.
#[tauri::command]
pub async fn chat_retry(nearby: State<'_, SharedNearby>, key: String, id: String) -> AppResult<()> {
    on_chats(&nearby, move |nearby| nearby.chat_retry(&key, &id)).await
}

/// What adding received variables to an environment would do.
#[tauri::command]
pub async fn chat_review_variables(
    nearby: State<'_, SharedNearby>,
    key: String,
    id: String,
    env_id: Option<String>,
) -> AppResult<Vec<VarReview>> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_review_variables(&key, &id, env_id.as_deref())
    })
    .await
}

/// Adds the received variables the user picked to an environment.
#[tauri::command]
pub async fn chat_add_variables(
    nearby: State<'_, SharedNearby>,
    key: String,
    id: String,
    target: VarTarget,
    names: Vec<String>,
) -> AppResult<String> {
    on_chats(&nearby, move |nearby| {
        nearby.chat_add_variables(&key, &id, &target, &names)
    })
    .await
}

/// Deletes the conversation from this computer.
#[tauri::command]
pub async fn chat_delete(nearby: State<'_, SharedNearby>, key: String) -> AppResult<()> {
    on_chats(&nearby, move |nearby| nearby.chat_delete(&key)).await
}
