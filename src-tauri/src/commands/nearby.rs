//! The Nearby page: this device on the local network, the others found
//! there, pairing with them, the contacts pairing made, and the user's own
//! devices and syncing with them (see [`crate::nearby`]).

use std::sync::Arc;

use sshkm_core::vault::Contact;
use sshkm_core::vault::envs::files::CloudService;
use sshkm_core::{ErrorCode, ExposeSecret, SecretString};
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::nearby::items::{ReceivedGroup, SendRequest};
use crate::nearby::sync::SyncDecisions;
use crate::nearby::{MyDevice, Nearby, NearbyStatus, SharedNearby};

async fn on_nearby<T, F>(nearby: &SharedNearby, work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Arc<Nearby>) -> AppResult<T> + Send + 'static,
{
    let nearby = Arc::clone(nearby);
    tauri::async_runtime::spawn_blocking(move || work(&nearby))
        .await
        .map_err(|e| AppError::new(ErrorCode::Io, format!("background task failed: {e}")))?
}

#[tauri::command]
pub async fn nearby_status(nearby: State<'_, SharedNearby>) -> AppResult<NearbyStatus> {
    Ok(nearby.status())
}

/// Renames this device, as others see it.
#[tauri::command]
pub async fn nearby_set_name(
    nearby: State<'_, SharedNearby>,
    name: String,
) -> AppResult<NearbyStatus> {
    on_nearby(&nearby, move |nearby| nearby.set_name(&name)).await
}

/// Makes this device visible on the local network for ten minutes, or hides
/// it. Needs the vault unlocked: a pairing saves a contact there.
#[tauri::command]
pub async fn nearby_set_visible(
    nearby: State<'_, SharedNearby>,
    visible: bool,
) -> AppResult<NearbyStatus> {
    on_nearby(&nearby, move |nearby| nearby.set_visible(visible)).await
}

/// Starts or stops looking for other devices.
#[tauri::command]
pub async fn nearby_set_looking(
    nearby: State<'_, SharedNearby>,
    looking: bool,
) -> AppResult<NearbyStatus> {
    on_nearby(&nearby, move |nearby| nearby.set_looking(looking)).await
}

/// Starts pairing with a device found nearby (its id) or at an address
/// (`host:port`). Returns the pairing's id; the rest comes as events.
#[tauri::command]
pub async fn nearby_pair(nearby: State<'_, SharedNearby>, target: String) -> AppResult<u32> {
    on_nearby(&nearby, move |nearby| nearby.pair(&target)).await
}

/// Sends what `item` names to a device found nearby (its id) or at an
/// address, pairing first if the two don't know each other. Returns the
/// pairing's id; the rest comes as events.
#[tauri::command]
pub async fn nearby_send(
    nearby: State<'_, SharedNearby>,
    target: String,
    item: SendRequest,
) -> AppResult<u32> {
    on_nearby(&nearby, move |nearby| nearby.send(&target, &item)).await
}

/// Whether the codes on both screens match, or whether to accept an item.
#[tauri::command]
pub async fn nearby_answer(
    nearby: State<'_, SharedNearby>,
    id: u32,
    matched: bool,
) -> AppResult<()> {
    nearby.answer(id, matched)
}

/// Makes this computer, which has no vault, visible for ten minutes to be
/// given one by another of the user's computers; or hides it.
#[tauri::command]
pub async fn nearby_join(nearby: State<'_, SharedNearby>, on: bool) -> AppResult<NearbyStatus> {
    on_nearby(&nearby, move |nearby| nearby.join(on)).await
}

/// Makes a device found nearby (its id) or at an address one of the user's
/// devices, giving it the vault if it has none. Returns the conversation's
/// id; the rest comes as events.
#[tauri::command]
pub async fn nearby_add_device(nearby: State<'_, SharedNearby>, target: String) -> AppResult<u32> {
    on_nearby(&nearby, move |nearby| nearby.add_device(&target)).await
}

/// The user's yes to adding a device: with the master password, or with
/// Touch ID / Windows Hello when there is none.
#[tauri::command]
pub async fn nearby_authorize(
    nearby: State<'_, SharedNearby>,
    id: u32,
    master: Option<SecretString>,
) -> AppResult<()> {
    on_nearby(&nearby, move |nearby| nearby.authorize(id, master.as_ref())).await
}

/// Sets up the vault another computer gave, with this computer's own
/// master password, and unlocks it.
#[tauri::command]
pub async fn nearby_finish_join(
    nearby: State<'_, SharedNearby>,
    id: u32,
    master: SecretString,
) -> AppResult<()> {
    on_nearby(&nearby, move |nearby| nearby.finish_join(id, &master)).await
}

/// The user's devices, this computer among them.
#[tauri::command]
pub async fn nearby_devices(nearby: State<'_, SharedNearby>) -> AppResult<Vec<MyDevice>> {
    on_nearby(&nearby, |nearby| nearby.my_devices()).await
}

/// Removes one of the user's devices.
#[tauri::command]
pub async fn nearby_remove_device(
    nearby: State<'_, SharedNearby>,
    key: String,
    delete_chat: Option<bool>,
) -> AppResult<()> {
    on_nearby(&nearby, move |nearby| {
        nearby.remove_device(&key)?;
        nearby.chat_forget(&key, delete_chat.unwrap_or(false));
        Ok(())
    })
    .await
}

/// Whether this computer is announced to the user's devices while the
/// vault is unlocked.
#[tauri::command]
pub async fn nearby_set_reachable(
    nearby: State<'_, SharedNearby>,
    reachable: bool,
) -> AppResult<NearbyStatus> {
    on_nearby(&nearby, move |nearby| nearby.set_reachable(reachable)).await
}

/// Syncs with one of the user's devices (its key), or with every one
/// reachable when there is none. The results come as events.
#[tauri::command]
pub async fn nearby_sync(nearby: State<'_, SharedNearby>, key: Option<String>) -> AppResult<()> {
    on_nearby(&nearby, move |nearby| nearby.sync(key.as_deref())).await
}

/// The user's decisions on what a sync brings.
#[tauri::command]
pub async fn nearby_decide(
    nearby: State<'_, SharedNearby>,
    id: u32,
    decisions: SyncDecisions,
) -> AppResult<()> {
    nearby.decide(id, decisions)
}

/// One text field of a conflict in the sync `id` under review, as this
/// computer (`theirs` false) or the other one has it, for the user to see.
/// A 2FA secret is never shown.
#[tauri::command]
pub async fn nearby_sync_value(
    nearby: State<'_, SharedNearby>,
    id: u32,
    item: String,
    field: String,
    theirs: bool,
) -> AppResult<String> {
    on_nearby(&nearby, move |nearby| {
        Ok(nearby
            .sync_value(id, &item, &field, theirs)?
            .expose_secret()
            .to_owned())
    })
    .await
}

/// The cloud service whose folder holds the vault, if one does: the user's
/// devices then don't sync its entries, the service does.
#[tauri::command]
pub async fn nearby_vault_cloud(
    nearby: State<'_, SharedNearby>,
) -> AppResult<Option<CloudService>> {
    on_nearby(&nearby, |nearby| nearby.vault_cloud()).await
}

/// Cancels a pairing, or forgets one that is over.
#[tauri::command]
pub async fn nearby_close(nearby: State<'_, SharedNearby>, id: u32) -> AppResult<()> {
    nearby.close(id);
    Ok(())
}

/// The hosts file group that came with pairing `id`, for the Hosts file page
/// to show as a change; `None` once another one came.
#[tauri::command]
pub async fn nearby_received_group(
    nearby: State<'_, SharedNearby>,
    id: u32,
) -> AppResult<Option<ReceivedGroup>> {
    Ok(nearby.received_group(id))
}

#[tauri::command]
pub async fn nearby_contacts(app: AppHandle, state: State<'_, Shared>) -> AppResult<Vec<Contact>> {
    blocking(&state, move |state| {
        state.vault.with_quietly(&app, |vault| Ok(vault.contacts()))
    })
    .await
}

/// Forgets a contact. To send it anything again, the two devices pair again.
#[tauri::command]
pub async fn nearby_remove_contact(
    app: AppHandle,
    state: State<'_, Shared>,
    nearby: State<'_, SharedNearby>,
    key: String,
    delete_chat: Option<bool>,
) -> AppResult<()> {
    let nearby = Arc::clone(&nearby);
    blocking(&state, move |state| {
        let removed = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.remove_contact(&key))
        })?;
        if removed {
            // Its chat link closes now, and the chat goes if the user said so.
            nearby.chat_forget(&key, delete_chat.unwrap_or(false));
            Ok(())
        } else {
            Err(AppError::not_found("that device is not a contact"))
        }
    })
    .await
}
