# sshkm-mobile

The phone app's bridge to `sshkm-core`, through
[UniFFI](https://mozilla.github.io/uniffi-rs/) (proc-macro style, no UDL). The
Android app in `mobile/android` loads it as `libsshkm_mobile.so` and calls it
through the Kotlin bindings UniFFI writes from the built library
(package `dev.sshkeymanager.android.core`, see `uniffi.toml`).

The core is built with `default-features = false`: none of what only
computers use (see the core's README). The API grows with the steps of
`docs/mobile.md`; today it is:

| Kotlin | What it does |
|---|---|
| `coreVersion()` | The core's version, the app's version. |
| `generatePassword(PasswordOptions())` | A random password from the vault's generator; the defaults are the desktop app's (20 characters, every kind). |
| `passwordStrength(password)` | zxcvbn's score and guesses. |
| `CoreException.Failed(code, detail)` | Every error: `code` is the core's stable `ErrorCode`, for the app to word; `detail` is English for developers. |

### The vault on the phone (`PhoneVault`, step C)

One object for the vault in a folder of the app's private storage
(`vault.kdbx`, `vault.keys`, `backups/`). The phone never makes a vault: it
gets the one its computers share (step E) and sets its own master password,
as a new computer does (`Vault::join`). Until it is unlocked nothing but
`info()` reads the files.

| Kotlin | What it does |
|---|---|
| `PhoneVault(folder)` | The vault in `folder`; reads nothing yet. |
| `info()` | `VaultInfo(status, vaultId, deviceSlots)`: `MISSING`, `RECEIVED` (waiting for the master password), `LOCKED`, `UNLOCKED`. |
| `setMasterPassword(master)` | Writes the received vault with this phone's master password and opens it. |
| `unlock(master)` | Opens it; wrong passwords in a row wait (`TOO_MANY_ATTEMPTS`), as on computers. |
| `unlockWithDevice(slotId, key)` | Opens it with the fingerprint slot's 32-byte key, which the app unwrapped with Keystore. The key is wiped on the Rust side. |
| `lock()`, `isUnlocked()` | Drops the open vault (database and secret) from memory. |
| `verifyMasterPassword(master)` | Checks it without changing anything. |
| `enableDeviceUnlock()` | Adds the phone's fingerprint slot; its random key comes back once (`DeviceUnlockKey`) for the app to wrap. |
| `disableDeviceUnlock(slotId)` | Removes a fingerprint slot. |
| `logins()`, `login(id)` | `Login` / `LoginDetail`: no secrets. Every entry, the recycle bin's included. |
| `projects()` | `ProjectLabel(id, name, color, logins)`, to filter by. |
| `password(id)` | One password, when the user asks to see or copy it. |
| `otpCode(id)` | The current 2FA code and the seconds it stays valid; the 2FA secret never crosses. |
| `addLogin(input)`, `updateLogin(id, input)` | Saved at once with a backup of the previous file. `LoginInput.password = null` keeps the password; `otp = ""` removes the 2FA secret. An edit keeps the entry's kind, host and key. |
| `trashLogin(id)`, `restoreLogin(id)` | To the recycle bin and back, as on computers. |
| `receiveTestVault(scratch)` | **Debug builds only** (the `test-vault` feature): a made-up vault, received as if a computer had sent it. |

A change that fails, in the core or when saving, leaves the vault in memory
as it is on disk. Records holding a secret (`LoginInput`, `OtpCode`,
`DeviceUnlockKey`) leave it out of their `Debug` output.

## Unsafe code

The crate takes the workspace's lints, `forbid(unsafe_code)` included. The
scaffolding UniFFI generates around every export is `unsafe` (`extern "C"`,
raw buffers), but it comes from UniFFI's macros, and rustc doesn't report
`unsafe_code` inside another crate's macro output. Any `unsafe` written here
fails to build.

## Building

`mobile/android` does it all from Gradle. By hand:

```sh
cargo ndk -t arm64-v8a -P 29 -o out/jniLibs build -p sshkm-mobile
cargo run -p sshkm-mobile --features bindgen --bin uniffi-bindgen -- \
  generate --library out/jniLibs/arm64-v8a/libsshkm_mobile.so \
  --language kotlin --out-dir out/kotlin
```

`cargo test -p sshkm-mobile --all-features` tests the API on the computer,
the test vault included.
