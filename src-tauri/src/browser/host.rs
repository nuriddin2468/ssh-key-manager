//! The native messaging host: the app executable started by the browser for
//! the extension.
//!
//! It reads the browser's messages from stdin (a native-endian `u32` length,
//! then JSON), passes each to the running app over the bridge and writes the
//! app's reply to stdout the same way. It reads nothing but where the bridge
//! is, and never sees a secret in the clear: everything past pairing is
//! sealed between the extension and the app.
//!
//! One message is its own: `{"type":"launch"}` starts the app when it isn't
//! running.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use sshkm_core::browser::protocol::MAX_MESSAGE;

use super::{MANIFEST_FILE, endpoint_file, frame, platform};

/// What the host itself replies when the app can't be reached.
const NOT_RUNNING: &[u8] = br#"{"type":"error","code":"notRunning"}"#;
const LAUNCHED: &[u8] = br#"{"type":"launched"}"#;
const LAUNCH_FAILED: &[u8] = br#"{"type":"error","code":"launchFailed"}"#;

/// Runs the host if the browser started this process as one, and returns its
/// exit code; `None` for a normal start.
///
/// Chromium browsers pass the extension's origin, `chrome-extension://<id>/`
/// (and on Windows `--parent-window=<n>`); Firefox passes the path of the
/// host manifest, then the add-on id.
pub fn run_host_from_args() -> Option<ExitCode> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let caller = caller(&args)?;
    Some(
        match serve(&caller, &mut io::stdin().lock(), &mut io::stdout().lock()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
    )
}

/// The extension that started the host, if the arguments are a browser's.
fn caller(args: &[OsString]) -> Option<String> {
    let first = args.first()?.to_str()?;
    if first.starts_with("chrome-extension://") {
        return Some(first.to_owned());
    }
    let manifest = Path::new(first);
    if manifest.is_absolute() && manifest.file_name()? == MANIFEST_FILE {
        return args.get(1)?.to_str().map(str::to_owned);
    }
    None
}

/// Relays messages until the browser closes stdin.
fn serve(caller: &str, input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    while let Some(message) = read_message(input)? {
        let reply = if is_launch(&message) {
            if launch().is_ok() {
                LAUNCHED.to_vec()
            } else {
                LAUNCH_FAILED.to_vec()
            }
        } else {
            relay(caller, &message).unwrap_or_else(|_| NOT_RUNNING.to_vec())
        };
        write_message(output, &reply)?;
    }
    Ok(())
}

/// Sends one message to the app and returns its reply.
fn relay(caller: &str, message: &[u8]) -> io::Result<Vec<u8>> {
    let endpoint = std::fs::read_to_string(endpoint_file()?)?;
    let mut stream = platform::connect(endpoint.trim().as_ref())?;
    let caller = serde_json::to_string(caller)?;
    let mut envelope = Vec::with_capacity(message.len() + caller.len() + 24);
    envelope.extend_from_slice(b"{\"caller\":");
    envelope.extend_from_slice(caller.as_bytes());
    envelope.extend_from_slice(b",\"message\":");
    envelope.extend_from_slice(message);
    envelope.push(b'}');
    frame::write(&mut stream, &envelope)?;
    frame::read(&mut stream)
}

fn is_launch(message: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Kind {
        #[serde(rename = "type")]
        kind: String,
    }
    serde_json::from_slice::<Kind>(message).is_ok_and(|m| m.kind == "launch")
}

/// Starts the app, detached from the browser so it outlives the host.
fn launch() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "macos")]
    if let Some(bundle) = exe
        .ancestors()
        .find(|p| p.extension() == Some("app".as_ref()))
    {
        return Command::new("/usr/bin/open")
            .arg(bundle)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(drop);
    }
    let mut command = Command::new(exe);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // The browser may end the host's whole process group.
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        command.creation_flags(
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
        );
        if command.spawn().is_ok() {
            return Ok(());
        }
        // The browser's job may not allow breaking away.
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    command.spawn().map(drop)
}

/// A message from the browser, or `None` when it closed stdin.
fn read_message(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    match input.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::try_from(u32::from_ne_bytes(header))
        .ok()
        .filter(|&len| len <= MAX_MESSAGE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message too long"))?;
    let mut message = vec![0; len];
    input.read_exact(&mut message)?;
    Ok(Some(message))
}

fn write_message(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let len = u32::try_from(message.len())
        .ok()
        .filter(|&len| len as usize <= MAX_MESSAGE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reply too long"))?;
    output.write_all(&len.to_ne_bytes())?;
    output.write_all(message)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(messages: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for message in messages {
            bytes.extend_from_slice(&u32::try_from(message.len()).unwrap().to_ne_bytes());
            bytes.extend_from_slice(message);
        }
        bytes
    }

    #[test]
    fn recognises_browser_launches() {
        let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            caller(&args(&["chrome-extension://abc/", "--parent-window=0"])).as_deref(),
            Some("chrome-extension://abc/")
        );
        let manifest = std::env::temp_dir().join(MANIFEST_FILE);
        let manifest = manifest.to_str().unwrap();
        assert_eq!(
            caller(&args(&[manifest, "autofill@sshkeymanager.dev"])).as_deref(),
            Some("autofill@sshkeymanager.dev")
        );
        assert_eq!(caller(&args(&[])), None);
        assert_eq!(caller(&args(&["--some-flag"])), None);
        assert_eq!(caller(&args(&["other.json", "x"])), None);
        assert_eq!(
            caller(&args(&[MANIFEST_FILE, "x"])),
            None,
            "a relative path"
        );
    }

    #[test]
    fn native_messages_round_trip_and_stop_at_eof() {
        let input = framed(&[br#"{"type":"hello"}"#, b"{}"]);
        let mut reader = input.as_slice();
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            br#"{"type":"hello"}"#
        );
        assert_eq!(read_message(&mut reader).unwrap().unwrap(), b"{}");
        assert!(read_message(&mut reader).unwrap().is_none());

        let mut out = Vec::new();
        write_message(&mut out, b"{\"a\":1}").unwrap();
        assert_eq!(out, framed(&[b"{\"a\":1}"]));

        let huge = u32::try_from(MAX_MESSAGE + 1).unwrap().to_ne_bytes();
        assert!(read_message(&mut huge.as_slice()).is_err());
    }

    #[test]
    fn spots_launch_requests() {
        assert!(is_launch(br#"{"type":"launch"}"#));
        assert!(!is_launch(br#"{"type":"hello"}"#));
        assert!(!is_launch(b"not json"));
    }
}
