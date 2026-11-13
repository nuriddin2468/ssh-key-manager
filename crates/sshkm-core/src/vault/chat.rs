//! The key a computer's chat history is sealed with ([`crate::chat`]).
//!
//! It is kept in the database's custom data as `sshkm.chat.<device key>`:
//! one per computer, named after its device key, so the history is readable
//! only while the vault is unlocked, and only on the computer whose files
//! they are. The history itself never goes into the database. A sync between
//! the user's devices leaves custom data of this kind on each computer, and
//! versions before chats keep it as they found it.

use std::path::Path;

use keepass::db::{CustomDataItem, CustomDataValue, Times};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::Vault;
use crate::Result;
use crate::p2p::PeerKey;

const CHAT_PREFIX: &str = "sshkm.chat.";
const KEY_LEN: usize = 32;

impl Vault {
    /// The key the chat history of the computer with this device key is
    /// sealed with, if it has one yet.
    pub fn chat_key(&self, device: &PeerKey) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let item = self
            .db
            .meta
            .custom_data
            .get(&format!("{CHAT_PREFIX}{device}"))?;
        let Some(CustomDataValue::Binary(bytes)) = &item.value else {
            return None;
        };
        let bytes: &[u8; KEY_LEN] = bytes.as_slice().try_into().ok()?;
        Some(Zeroizing::new(*bytes))
    }

    /// Makes the key for this computer's chat history and saves the vault,
    /// unless there is one; returns whether it made one. A key that isn't
    /// saved is not kept.
    pub fn make_chat_key(&mut self, device: &PeerKey, backup_dir: &Path) -> Result<bool> {
        if self.chat_key(device).is_some() {
            return Ok(false);
        }
        let name = format!("{CHAT_PREFIX}{device}");
        let mut key = Zeroizing::new([0; KEY_LEN]);
        OsRng.fill_bytes(key.as_mut());
        self.db.meta.custom_data.insert(
            name.clone(),
            CustomDataItem {
                value: Some(CustomDataValue::Binary(key.to_vec())),
                last_modification_time: Some(Times::now()),
            },
        );
        if let Err(error) = self.save(backup_dir) {
            self.db.meta.custom_data.remove(&name);
            return Err(error);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::Identity;
    use crate::vault::VaultPaths;

    #[test]
    fn each_computer_gets_a_chat_key_that_stays_with_the_vault_and_out_of_its_entries() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let master = secrecy::SecretString::from("master");
        let mut vault = Vault::create(&paths, &master).unwrap().0;
        let backups = dir.path().join("backups");
        let (laptop, desktop) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        let entries = vault.entries().len();
        assert!(vault.chat_key(&laptop).is_none());
        assert!(vault.make_chat_key(&laptop, &backups).unwrap());
        assert!(!vault.make_chat_key(&laptop, &backups).unwrap());
        let key = vault.chat_key(&laptop).unwrap();
        assert!(vault.chat_key(&desktop).is_none(), "per computer");
        assert!(vault.make_chat_key(&desktop, &backups).unwrap());
        assert_ne!(*vault.chat_key(&desktop).unwrap(), *key);
        // Nothing a version before chats would list.
        assert_eq!(vault.entries().len(), entries);
        assert_eq!(vault.contacts().len(), 0);
        assert_eq!(vault.own_devices().len(), 0);

        drop(vault);
        let vault = Vault::unlock(&paths, &master).unwrap();
        assert_eq!(*vault.chat_key(&laptop).unwrap(), *key);
    }
}
