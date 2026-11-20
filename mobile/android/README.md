# SSH Key Manager for Android

The phone app: Kotlin, Jetpack Compose and Material 3 over the Rust core
(`crates/sshkm-core`), reached through UniFFI (`crates/sshkm-mobile`). The plan
and its steps are in [docs/mobile.md](../../docs/mobile.md).

Application id `dev.sshkeymanager.android`, Android 10 (API 29) and newer,
UI in English, Russian and Uzbek. No third-party SDKs: AndroidX, Kotlin, and
JNA, which UniFFI's Kotlin bindings call the Rust library through.

## What you need

- Android Studio, or the Android SDK with `platforms;android-37.2`, and the
  NDK `30.0.16248370` (Gradle installs what is missing when the licences are
  accepted).
- A JDK 17 or newer to run Gradle; Android Studio's own JBR works.
- Rust (the toolchain in `rust-toolchain.toml`) with the Android targets, and
  cargo-ndk:

  ```sh
  rustup target add aarch64-linux-android x86_64-linux-android
  cargo install cargo-ndk --locked
  ```

Gradle finds `cargo` on the `PATH`, in `$CARGO`, or in `~/.cargo/bin`; pass
`-Pcargo=/path/to/cargo` otherwise. It uses `$CARGO_TARGET_DIR` when it is set.

## Building and running

From this folder:

```sh
./gradlew assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug         # onto the running emulator or the phone on USB
./gradlew lint test            # what CI runs, with assembleDebug
./gradlew connectedDebugAndroidTest   # the bridge, on a device or emulator
```

Each variant builds the Rust library first (`cargoBuildDebug`, with Cargo's dev
profile; `cargoBuildRelease`, with its release profile) for the ABIs in
`gradle.properties`, `arm64-v8a` for phones and `x86_64` for the emulator on
x86 machines. On an Apple Silicon Mac the emulator is `arm64-v8a`, so
`-PrustAbis=arm64-v8a` builds half as much. Then UniFFI's generator writes the
Kotlin bindings from the built library (`uniffi-bindgen` from this
workspace, so its version is always the runtime's). Both are generated
sources under `app/build/rust/`; nothing generated is committed.

The release build unwinds on a Rust panic instead of aborting (the desktop's
release profile aborts): UniFFI turns a panic inside a call into an
`InternalException`, and the app shows an error instead of closing. Release
builds also strip only debug info, since a full strip removes the metadata
UniFFI writes the bindings from; packaging strips the library again.

Android Studio opens this folder as a project. Set its Gradle JDK to 17 or
newer.

## Security from the start

- Every window is `FLAG_SECURE` (`SshkmApplication`): no screenshots, screen
  recording or Recents preview. Compose dialogs and pop-ups inherit it. To take
  screenshots for a pull request, use the emulator's own screenshot button or
  `adb emu screenrecord screenshot <folder>`; `adb shell screencap` and
  screenshots on a phone come out black, as they should.
- No backup of app data: `allowBackup="false"`, and data extraction rules
  that exclude every domain from cloud backup and device-to-device transfer.
  The vault lives in `noBackupFilesDir` besides.
- One permission: `USE_BIOMETRIC`, for fingerprint unlock (granted at
  install). The merged manifest also has androidx.core's signature-level
  `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`, which only the app holds, and
  a job service only the system may bind (`BIND_JOB_SERVICE`).
- No autofill service sees the app's own fields
  (`IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS`).

## The vault on the phone

The vault is `vault.kdbx`, `vault.keys` and `backups/` in
`noBackupFilesDir/vault`, opened by the Rust core (`PhoneVault`, see
`crates/sshkm-mobile`). The phone never makes a vault of its own: it gets the
one its computers share (pairing, step E) and the user sets a master
password for the phone. Until step E the first screen says so; **debug
builds** add "Load a test vault", which makes a vault in the core (the
`test-vault` Cargo feature, which only the debug variant turns on) and
receives it as if a computer had sent it. Release builds have neither the
button (`src/release/.../DebugTools.kt`) nor the function.

- **Fingerprint unlock** is a device key slot of the vault, as Touch ID on a
  Mac. The slot's random key is wrapped by an AES-256-GCM key in Android
  Keystore (StrongBox when the phone has it) that works once per strong
  biometric authentication, only while the phone is unlocked, and that
  Keystore invalidates when a fingerprint is added. The phone's PIN doesn't
  release it: the master password is the other way in. When it is
  invalidated, the app says so, removes the slot once the master password
  opened the vault, and offers to turn it on again.
- **The master password stays required** after the phone restarts and once
  a week, even with fingerprint unlock on.
- **Locking**: after one setting's time without use (30 s, 1 min by
  default, 5 or 15 min), counted whether the app is on screen or not, and on
  demand. In the background a JobScheduler job does it, since Android freezes
  the app's own timers. Locking drops the open vault in the core.
- **Copying** a password or a code marks the clip sensitive
  (`EXTRA_IS_SENSITIVE`) and clears it after 30 seconds, unless something
  else was copied meanwhile (while the app can still tell).
- **The keyboard** learns nothing anywhere in the app
  (`IME_FLAG_NO_PERSONALIZED_LEARNING`); secret fields also get a password
  keyboard without suggestions or autocorrect, and accessibility services
  read dots from them, as from Android's own password fields.
- **Secrets cross the bridge one at a time**: a password when the user shows
  or copies it, a 2FA code while it is on screen. View models hold them only
  while shown; a shown password hides itself after 30 seconds, and every
  screen of the open vault, with its view models, goes when the vault locks.

## Testing

`./gradlew test` runs the view models and the session over fakes of the
core, Keystore and the fingerprint prompt. `connectedDebugAndroidTest` runs
the real core on the device (the test vault, unlock, lock, a login's round
trip), the UI end to end, and the keyboard, accessibility, clipboard and lock
job checks. The Keystore key test runs only on a device with a screen lock
and a fingerprint; on an emulator set them up with
`adb shell locksettings set-pin 1234`, Settings → Security → Fingerprint, and
`adb emu finger touch 1`, which also stands in for the finger in the prompt.

## Layout

```
app/src/main/kotlin/dev/sshkeymanager/android/
  SshkmApplication.kt   FLAG_SECURE on every activity; tells the vault when the app comes and goes
  AppGraph.kt           the long-lived parts: the core's vault, the session, the clipboard
  MainActivity.kt
  vault/                the session (unlock, lock, auto-lock, deadlines), the bridge, preferences
  biometric/            Keystore key, the fingerprint prompt, fingerprint unlock
  clipboard/            copying secrets
  setup/ unlock/ logins/ generator/ settings/   screens and their view models
  ui/                   the app's root and back stack, shared components, theme
app/src/debug/          the test vault (debug builds only)
app/src/release/        the same entry point, empty
app/src/main/res/
  values/ values-ru/ values-uz/   strings
  xml/data_extraction_rules.xml
```
