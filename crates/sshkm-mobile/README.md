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

## Unsafe code

UniFFI's scaffolding around every export is `extern "C"` glue that has to be
`unsafe`, so the crate has `unsafe_code = "deny"` instead of the workspace's
`forbid`, and its modules opt in with `#[allow(unsafe_code)]` where lib.rs
declares them. Nothing written by hand here uses `unsafe`.

## Building

`mobile/android` does it all from Gradle. By hand:

```sh
cargo ndk -t arm64-v8a -P 29 -o out/jniLibs build -p sshkm-mobile
cargo run -p sshkm-mobile --features bindgen --bin uniffi-bindgen -- \
  generate --library out/jniLibs/arm64-v8a/libsshkm_mobile.so \
  --language kotlin --out-dir out/kotlin
```

`cargo test -p sshkm-mobile` tests the API on the computer.
