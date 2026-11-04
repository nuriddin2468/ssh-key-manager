use std::env;
use std::path::Path;

fn main() {
    let mut windows = tauri_build::WindowsAttributes::new();
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Tauri puts its manifest, which asks for Common Controls v6 (the
        // dialog plugin's `TaskDialogIndirect`), only into the app's
        // executable. A test binary that links the native dialogs then fails
        // to start with STATUS_ENTRYPOINT_NOT_FOUND, so the linker embeds the
        // same manifest into every binary of the crate instead.
        windows = tauri_build::WindowsAttributes::new_without_app_manifest();
        let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("set by cargo"))
            .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run the Tauri build script");
}
