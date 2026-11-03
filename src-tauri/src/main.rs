// Hides the console window on Windows release builds. The askpass helper
// below still reaches `ssh`: Win32-OpenSSH hands it a pipe as stdout through
// STARTF_USESTDHANDLES, which works for GUI-subsystem programs too.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    // `ssh` runs this executable as its askpass program to ask for a password,
    // code or passphrase. Answer and exit before Tauri starts: the
    // single-instance plugin would hand the launch to the running app.
    if let Some(code) = sshkm_app_lib::askpass::run_helper_from_env() {
        return code;
    }
    // A browser runs it as the extension's native messaging host.
    if let Some(code) = sshkm_app_lib::browser::run_host_from_args() {
        return code;
    }
    sshkm_app_lib::run();
    ExitCode::SUCCESS
}
