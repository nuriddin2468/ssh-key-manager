//! The Nearby page: this device on the local network, the others found
//! there, pairing with them, and the contacts pairing made (see
//! [`crate::nearby`]).

use std::sync::Arc;

use sshkm_core::ErrorCode;
use sshkm_core::vault::Contact;
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::nearby::items::{ReceivedGroup, SendRequest};
use crate::nearby::{Nearby, NearbyStatus, SharedNearby};

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
    key: String,
) -> AppResult<()> {
    blocking(&state, move |state| {
        let removed = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.remove_contact(&key))
        })?;
        if removed {
            Ok(())
        } else {
            Err(AppError::not_found("that device is not a contact"))
        }
    })
    .await
}
