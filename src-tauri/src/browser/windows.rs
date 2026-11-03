//! The bridge on Windows: a named pipe with a random name.
//!
//! As for askpass, the pipe rejects remote clients and is created as the
//! first instance of its name. Its default security lets other local users
//! open it for reading only, so they can't send a request.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::time::timeout;

use super::{Handler, IO_TIMEOUT, frame};

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
    pub fn start(handler: Handler) -> io::Result<Self> {
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let name = OsString::from(format!(r"\\.\pipe\sshkm-browser-{}", super::hex(&random)));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let first = {
            let _context = runtime.enter();
            options().first_pipe_instance(true).create(&name)?
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new().name("browser".into()).spawn({
            let (name, stop) = (name.clone(), Arc::clone(&stop));
            move || runtime.block_on(accept(first, name, handler, stop))
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
    handler: Handler,
    stop: Arc<AtomicBool>,
) {
    loop {
        let connected = server.connect().await;
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let next = match options().create(&name) {
            Ok(next) => next,
            Err(e) => {
                log::warn!("browser: cannot create a pipe instance: {e}");
                break;
            }
        };
        let client = std::mem::replace(&mut server, next);
        if connected.is_ok() {
            tokio::spawn(serve(client, Arc::clone(&handler)));
        }
    }
}

async fn serve(mut pipe: NamedPipeServer, handler: Handler) {
    let Ok(Ok(request)) = timeout(IO_TIMEOUT, read_frame(&mut pipe)).await else {
        return;
    };
    // Pairing waits for the user; keep it off the accept loop's thread.
    let Ok(reply) = tokio::task::spawn_blocking(move || handler(&request)).await else {
        return;
    };
    let mut message = frame::header(reply.len()).to_vec();
    message.extend_from_slice(&reply);
    if !matches!(
        timeout(IO_TIMEOUT, async {
            pipe.write_all(&message).await?;
            pipe.flush().await
        })
        .await,
        Ok(Ok(()))
    ) {
        return;
    }
    // Wait for the host to read the reply and hang up, so closing this end
    // cannot discard it.
    let mut byte = [0; 1];
    let _ = timeout(IO_TIMEOUT, pipe.read(&mut byte)).await;
}

async fn read_frame(pipe: &mut NamedPipeServer) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    pipe.read_exact(&mut header).await?;
    let mut payload = vec![0; frame::length(header)?];
    pipe.read_exact(&mut payload).await?;
    Ok(payload)
}

/// The host's side: opens the app's pipe, retrying briefly while every
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
