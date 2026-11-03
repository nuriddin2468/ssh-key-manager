//! Points `WebKitGTK` at a GPU it can render with on Linux.

use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const EGL_VENDOR_FILES: &str = "__EGL_VENDOR_LIBRARY_FILENAMES";
const EGL_VENDOR_DIRS: &str = "__EGL_VENDOR_LIBRARY_DIRS";
const MESA_EGL: &str = "/usr/share/glvnd/egl_vendor.d/50_mesa.json";

/// Kernel drivers of the GPUs Mesa renders with.
const MESA_DRIVERS: &[&str] = &["amdgpu", "radeon", "i915", "xe"];

/// With NVIDIA's driver loaded, glvnd gives `WebKitGTK` NVIDIA's EGL, which it
/// cannot start hardware acceleration with on Wayland. It then paints every
/// frame on the CPU and the UI lags on every click and keystroke. When the
/// machine also has an AMD or Intel GPU, restarts the app with EGL pointed at
/// Mesa, which renders with that GPU instead.
///
/// Leaves the environment alone if the user chose an EGL vendor, which also
/// stops the restarted app from restarting again.
pub fn prefer_mesa_egl() {
    if env::var_os(EGL_VENDOR_FILES).is_some() || env::var_os(EGL_VENDOR_DIRS).is_some() {
        return;
    }
    let wants = wants_mesa(
        env::var_os("WAYLAND_DISPLAY").is_some(),
        Path::new("/proc/driver/nvidia/version").exists(),
        Path::new(MESA_EGL).exists(),
        &render_node_drivers(),
    );
    if !wants {
        return;
    }
    let Ok(exe) = env::current_exe() else {
        return;
    };
    // `exec` only returns if it failed; the app then starts as it would have.
    let error = Command::new(exe)
        .args(env::args_os().skip(1))
        .env(EGL_VENDOR_FILES, MESA_EGL)
        .exec();
    eprintln!("not restarting with Mesa EGL: {error}");
}

fn wants_mesa(wayland: bool, nvidia: bool, mesa_egl: bool, drivers: &[String]) -> bool {
    wayland
        && nvidia
        && mesa_egl
        && drivers
            .iter()
            .any(|driver| MESA_DRIVERS.contains(&driver.as_str()))
}

/// Kernel drivers of the GPUs that have a render node, such as `amdgpu`.
fn render_node_drivers() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("renderD"))
        .filter_map(|entry| fs::read_link(entry.path().join("device/driver")).ok())
        .filter_map(|driver| Some(driver.file_name()?.to_string_lossy().into_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drivers(names: &[&str]) -> Vec<String> {
        names.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn switches_to_mesa_only_with_nvidia_beside_a_mesa_gpu_on_wayland() {
        let hybrid = drivers(&["nvidia", "amdgpu"]);
        assert!(wants_mesa(true, true, true, &hybrid));
        assert!(wants_mesa(true, true, true, &drivers(&["i915", "nvidia"])));

        assert!(
            !wants_mesa(true, true, true, &drivers(&["nvidia"])),
            "no other GPU"
        );
        assert!(
            !wants_mesa(true, false, true, &drivers(&["amdgpu"])),
            "no NVIDIA driver"
        );
        assert!(
            !wants_mesa(true, true, false, &hybrid),
            "Mesa EGL not installed"
        );
        assert!(!wants_mesa(false, true, true, &hybrid), "X11 session");
    }
}
