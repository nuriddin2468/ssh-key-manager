//! UniFFI's bindings generator, built from the workspace so its version is
//! always the runtime's. `mobile/android` runs it on the built library:
//! `uniffi-bindgen generate --library <libsshkm_mobile.so> --language kotlin
//! --out-dir <dir>`.

fn main() {
    uniffi::uniffi_bindgen_main();
}
