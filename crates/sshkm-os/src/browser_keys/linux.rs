use std::collections::HashMap;

use secrecy::zeroize::Zeroizing;
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use zbus::blocking::{Connection, Proxy};

use crate::{Error, Result};

/// The name this app gives `KWallet` when it asks to open the wallet.
const APP_ID: &str = "SSH Key Manager";

pub(super) fn safe_storage(
    service: &str,
    account: &str,
    application: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match from_secret_service(service, application) {
        Ok(Some(secret)) => return Ok(Some(secret)),
        Err(Error::Cancelled) => return Err(Error::Cancelled),
        Ok(None) | Err(_) => {}
    }
    from_kwallet(&format!("{account} Keys"), service)
}

/// The Secret Service item with the browser's `application` attribute,
/// preferring the one labelled with `service` ("Chrome Safe Storage").
fn from_secret_service(service: &str, application: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let store = SecretService::connect(EncryptionType::Dh).map_err(store_error)?;
    let found = store
        .search_items(HashMap::from([("application", application)]))
        .map_err(store_error)?;
    let items: Vec<_> = found.unlocked.iter().chain(found.locked.iter()).collect();
    let item = items
        .iter()
        .find(|item| item.get_label().is_ok_and(|label| label == service))
        .or_else(|| items.first());
    let Some(item) = item else {
        return Ok(None);
    };
    if item.is_locked().map_err(store_error)? {
        item.unlock().map_err(store_error)?;
    }
    let secret = Zeroizing::new(item.get_secret().map_err(store_error)?);
    Ok(Some(secret))
}

fn store_error(error: secret_service::Error) -> Error {
    match error {
        secret_service::Error::Prompt => Error::Cancelled,
        secret_service::Error::Unavailable => {
            Error::Unavailable("no Secret Service is running".into())
        }
        other => Error::Store(format!("Secret Service: {other}")),
    }
}

/// The entry `key` in `folder` of the network wallet, from `kwalletd6` or
/// `kwalletd5`.
fn from_kwallet(folder: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let connection = Connection::session().map_err(|e| kwallet_error(&e))?;
    for version in ["6", "5"] {
        let proxy = Proxy::new(
            &connection,
            format!("org.kde.kwalletd{version}"),
            format!("/modules/kwalletd{version}"),
            "org.kde.KWallet",
        )
        .map_err(|e| kwallet_error(&e))?;
        let Ok(wallet) = proxy.call::<_, _, String>("networkWallet", &()) else {
            continue;
        };
        // May ask the user to unlock the wallet, or to let this app in.
        let handle: i32 = proxy
            .call("open", &(wallet.as_str(), 0i64, APP_ID))
            .map_err(|e| kwallet_error(&e))?;
        if handle < 0 {
            return Err(Error::Cancelled);
        }
        let read = || -> Result<Option<Zeroizing<Vec<u8>>>> {
            let has: bool = proxy
                .call("hasEntry", &(handle, folder, key, APP_ID))
                .map_err(|e| kwallet_error(&e))?;
            if !has {
                return Ok(None);
            }
            let password: String = proxy
                .call("readPassword", &(handle, folder, key, APP_ID))
                .map_err(|e| kwallet_error(&e))?;
            Ok(Some(Zeroizing::new(
                Zeroizing::new(password).as_bytes().to_vec(),
            )))
        };
        let result = read();
        let _ = proxy.call::<_, _, i32>("close", &(handle, false, APP_ID));
        return result;
    }
    Ok(None)
}

fn kwallet_error(error: &zbus::Error) -> Error {
    Error::Store(format!("KWallet: {error}"))
}
