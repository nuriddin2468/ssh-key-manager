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
- No permissions. The merged manifest has only what AndroidX adds for
  itself: androidx.core's signature-level
  `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`, which the app defines and
  only it holds.
- The generated password is shown, never selectable: copying, with the
  clipboard marked sensitive and cleared after a while, comes with the vault.

## Layout

```
app/src/main/kotlin/dev/sshkeymanager/android/
  SshkmApplication.kt   FLAG_SECURE on every activity
  MainActivity.kt
  home/                 the first screen and its view model
  ui/theme/             the desktop app's tokens as Material 3 colour schemes
app/src/main/res/
  values/ values-ru/ values-uz/   strings
  xml/data_extraction_rules.xml
```
