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

### SSH (`ssh.rs`)

A shell on one of the user's servers by its name, through `sshkm-ssh` (see its
README for the rules). The app passes the host blocks and `known_hosts` it
carries as text; the client runs on a tokio runtime of the bridge's own.

| Kotlin | What it does |
|---|---|
| `sshOpenShell(SshConnectRequest(...), callbacks)` | `suspend`: connects (jump hosts included), signs in and opens a shell (`xterm-256color`, `cols` × `rows`). Returns `SshShell`. |
| `SshCallbacks` | The app's side, implemented in Kotlin: `suspend sign(SshSignRequest)` returns Keystore's DER `SHA256withECDSA` signature; `suspend unknownHost(SshUnknownHost)` returns the user's yes or no; `hostKeyTrusted(line)` hands over the `known_hosts` line to store after a yes (on the connection's thread: return at once, never block); `suspend answer(SshAuthPrompt)` returns one answer per prompt (`kind`: password, one-time code, other; `attempt` counts repeats, at most 3) or `null` to cancel. Every method may throw: `SshCallbackException.Cancelled` or a `CancellationException` cancels the connection, anything else fails it (`SshException.App`). |
| `SshShell.nextEvent()` | `suspend`: `Output(data)`, or `Closed(exitStatus, exitSignal, connectionLost)`. Keep one coroutine asking while the shell is open, even off screen: while nobody asks, the whole connection waits, keepalives included. |
| `SshShell.write(data)`, `resize(cols, rows)` | Return at once; go out in the order of the calls. Typed bytes are wiped after they go. |
| `SshShell.keepalive()`, `disconnect()` | `suspend`. `disconnect` ends the shell and the connection; `close()` (`AutoCloseable`) frees the object, as for every UniFFI object. |
| `sshRoute(hostsConfig, destination)` | The machines on the way, without connecting; `SshException.NotAvailable` for a host the phone can't connect to. |
| `sshPublicKeyFromSpki(der, comment)` | The phone's OpenSSH public key line from Keystore's `PublicKey.getEncoded()`. |
| `sshKeyFingerprint(publicKey)` | Its `SHA256:…` fingerprint. |
| `SshException` | Typed: `NotAvailable` (`RunsProgram`, `Undecided`, `OddLine`), `NameNotFound`, `Refused`, `TimedOut`, `Unreachable`, `JumpFailed`, `HostKeyChanged` (both fingerprints), `HostKeyRevoked`, `UnknownHostDeclined`, `AuthFailed`, `Signer`, `Cancelled`, `App`, `ShellRefused`, `Disconnected`, … each naming the machine (`alias`). |

Cancelling the coroutine of a call stops the work behind it.

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
