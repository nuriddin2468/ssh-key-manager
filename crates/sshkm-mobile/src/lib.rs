//! The phone app's bridge to the core of SSH Key Manager.
//!
//! The Android app (`mobile/android`) is Kotlin; whatever it does with the
//! vault, sync and SSH goes through this crate to `sshkm-core`, built without
//! the features only computers use. [UniFFI] writes the Kotlin side from what
//! is exported here: records, enums, errors and functions. The API grows with
//! the steps of `docs/mobile.md`: the core's version, the vault's password
//! generator, the vault on the phone ([`PhoneVault`]) and SSH ([`ssh`]).
//!
//! Secrets cross the bridge one at a time, when the user asks for them, and
//! are never logged.
//!
//! [UniFFI]: https://mozilla.github.io/uniffi-rs/

// Everything here is under the workspace's `forbid(unsafe_code)`: the
// `unsafe` in what UniFFI's macros generate is theirs, and rustc doesn't
// report the lint inside another crate's macro output. Hand-written `unsafe`
// fails to build.
mod error;
mod generator;
mod scaffolding;
pub mod ssh;
mod vault;

pub use error::CoreError;
pub use generator::{PasswordOptions, PasswordStrength, generate_password, password_strength};
pub use scaffolding::core_version;
// The tag UniFFI's generated code names as `crate::UniFfiTag`.
pub use scaffolding::UniFfiTag;
pub use vault::{
    DeviceUnlockKey, Login, LoginDetail, LoginInput, OtpCode, PhoneVault, ProjectLabel, VaultInfo,
    VaultStatus,
};
