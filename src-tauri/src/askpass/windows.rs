//! The askpass server on Windows: a named pipe with a random name.
//!
//! The pipe rejects remote clients and is created as the first instance of its
//! name, so no other process can have claimed it. Its default security lets
//! other local users open it for reading only; they cannot send a token, so
//! the server never answers them.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use sshkm_core::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::time::timeout;

use super::{Answer, IO_TIMEOUT, Registry, hex, wire};

/// `SecurityIdentification << 16`: the server may learn who the client is
/// but not act as it.
const SECURITY_IDENTIFICATION: u32 = 1 << 16;
const ERROR_PIPE_BUSY: i32 = 231;

pub struct Listener {
    name: OsString,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Listener {
    pub fn start(registry: Arc<Registry>) -> io::Result<Self> {
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let name = OsString::from(format!(r"\\.\pipe\sshkm-askpass-{}", hex(&random)));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let first = {
            let _context = runtime.enter();
            options().first_pipe_instance(true).create(&name)?
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new().name("askpass".into()).spawn({
            let (name, stop) = (name.clone(), Arc::clone(&stop));
            move || runtime.block_on(accept(first, name, registry, stop))
        })?;
        Ok(Self {
            name,
            stop,
            thread: Some(thread),
        })
    }

    pub fn endpoint(&self) -> &OsStr {
        &self.name
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = connect(&self.name);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn options() -> ServerOptions {
    let mut options = ServerOptions::new();
    options
        .reject_remote_clients(true)
        .access_inbound(true)
        .access_outbound(true)
        .pipe_mode(PipeMode::Byte);
    options
}

async fn accept(
    mut server: NamedPipeServer,
    name: OsString,
    registry: Arc<Registry>,
    stop: Arc<AtomicBool>,
) {
    loop {
        let connected = server.connect().await;
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // The next instance exists before this one is handed off, so the name
        // is never free for another process to take.
        let next = match options().create(&name) {
            Ok(next) => next,
            Err(e) => {
                log::warn!("askpass: cannot create a pipe instance: {e}");
                break;
            }
        };
        let client = std::mem::replace(&mut server, next);
        if connected.is_ok() {
            tokio::spawn(serve(client, Arc::clone(&registry)));
        }
    }
}

async fn serve(mut pipe: NamedPipeServer, registry: Arc<Registry>) {
    let Ok(Ok(request)) = timeout(IO_TIMEOUT, read_request(&mut pipe)).await else {
        return;
    };
    // The responder may block; keep it off the accept loop's thread.
    let Ok(answer) = tokio::task::spawn_blocking(move || registry.answer(&request)).await else {
        return;
    };
    let reply = match answer {
        Answer::Unknown => return,
        Answer::Refuse => None,
        Answer::Text(secret) => Some(secret),
    };
    if !matches!(
        timeout(IO_TIMEOUT, write_answer(&mut pipe, reply.as_ref())).await,
        Ok(Ok(()))
    ) {
        return;
    }
    // Wait for the helper to read the answer and hang up, so closing this end
    // cannot discard it.
    let mut byte = [0; 1];
    let _ = timeout(IO_TIMEOUT, pipe.read(&mut byte)).await;
}

async fn read_request(pipe: &mut NamedPipeServer) -> io::Result<wire::Request> {
    let mut header = [0; 4];
    pipe.read_exact(&mut header).await?;
    let mut payload = vec![0; wire::request_len(header)?];
    pipe.read_exact(&mut payload).await?;
    wire::decode_request(&payload)
}

async fn write_answer(pipe: &mut NamedPipeServer, reply: Option<&SecretString>) -> io::Result<()> {
    let (header, body) = wire::answer_frame(reply)?;
    pipe.write_all(&header).await?;
    pipe.write_all(body).await?;
    pipe.flush().await
}

/// The helper's side: opens the server's pipe, retrying briefly while every
/// instance is busy.
pub fn connect(endpoint: &OsStr) -> io::Result<File> {
    let mut attempts = 0;
    loop {
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(endpoint);
        match opened {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 40 => {
                attempts += 1;
                thread::sleep(Duration::from_millis(50));
            }
            other => return other,
        }
    }
}
