//! The helper: the app executable started by `ssh` as its askpass program.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

use sshkm_core::{ExposeSecret, SecretString};

use super::{ENDPOINT_VAR, TOKEN_VAR, platform, wire};

/// Runs the helper if this process was started as one, that is if
/// `SSHKM_ASKPASS_ENDPOINT` and `SSHKM_ASKPASS_TOKEN` are set, and returns its
/// exit code: 0 after printing the answer and a newline to stdout, 1 when the
/// server refuses or cannot be reached. Returns `None` for a normal start.
///
/// `main` calls this before anything else. It must return before Tauri
/// starts, or the single-instance plugin would hand the launch to the running
/// app.
pub fn run_helper_from_env() -> Option<ExitCode> {
    let endpoint = std::env::var_os(ENDPOINT_VAR)?;
    let token = std::env::var_os(TOKEN_VAR)?;
    // `ssh` passes the prompt as one argument. Win32-OpenSSH does not quote
    // an argument that starts with `'`, which splits it; join the pieces.
    let prompt = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    // `confirm` for yes/no questions (OpenSSH 8.2+), `none` for notices.
    let hint = std::env::var("SSH_ASKPASS_PROMPT").unwrap_or_default();

    let answer = ask(&endpoint, &token.to_string_lossy(), &hint, &prompt);
    Some(match answer {
        Ok(Some(secret)) if print(&secret).is_ok() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    })
}

/// Sends `prompt` to the askpass server at `endpoint` for the session with
/// `token`. Returns the reply, or `None` if the session refused. Fails if the
/// server is unreachable or does not know the token.
pub fn ask(
    endpoint: &OsStr,
    token: &str,
    hint: &str,
    prompt: &str,
) -> io::Result<Option<SecretString>> {
    let mut stream = platform::connect(endpoint)?;
    stream.write_all(&wire::encode_request(token, hint, prompt)?)?;
    stream.flush()?;
    wire::read_answer(&mut stream)
}

/// Writes the answer and a newline straight to the stdout handle: the buffer
/// of `io::stdout()` would keep a copy of the secret.
///
/// On Windows the release build is a GUI-subsystem program, which gets no
/// console. It still has a stdout: Win32-OpenSSH starts askpass with
/// `STARTF_USESTDHANDLES` and inherited handles, its pipe being stdout. With
/// no valid handle this fails and the helper exits with 1, which `ssh` treats
/// as a cancelled prompt.
fn print(secret: &SecretString) -> io::Result<()> {
    let mut out = stdout_handle()?;
    out.write_all(secret.expose_secret().as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

#[cfg(unix)]
fn stdout_handle() -> io::Result<File> {
    use std::os::fd::AsFd;
    Ok(File::from(io::stdout().as_fd().try_clone_to_owned()?))
}

#[cfg(windows)]
fn stdout_handle() -> io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(File::from(io::stdout().as_handle().try_clone_to_owned()?))
}
