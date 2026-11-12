//! Level 3 ([`super::FileLevel::Virtual`]): in place of a `.env` file, a
//! named pipe (FIFO) that the app answers while it runs, on macOS and Linux.
//! Nothing is kept on disk.
//!
//! **Serving.** One thread per pipe ([`PipeServer`]) waits for a reader to
//! open it, and then hands that reader one whole answer: the variables as
//! a `.env` file while the vault is unlocked, or a comment saying why there
//! are none ([`Answer`]). The answer goes into the pipe in one write and the
//! pipe is closed at once, so a reader that opens it and never reads holds
//! up no one; an answer larger than the pipe's buffer (8 KiB on macOS) waits
//! for its reader [`SERVE_TIMEOUT`] at most, and is taken back out if it
//! isn't taken, so no reader ever gets half of one. While an answer waits
//! unread in the pipe, nothing is added to it. Readers that open the pipe at
//! the very same moment share one answer: a pipe is one stream, and the
//! first to read takes it. Readers one after another each get a whole one;
//! one that comes back right after its answer, before it closed the pipe,
//! may get it twice.
//!
//! Writing into a pipe changes its time of change, and tools that watch a
//! `.env` file (Next.js, Vite, editors) would take each answer for an edit
//! and read it again. The time is put back after each answer, so to them
//! the file never changes.
//!
//! **Read-only.** A pipe keeps nothing written into it. A file saved over
//! it, by renaming, is the app's to take like any edit of a file
//! ([`super::Vault::env_files_pull`]); the pipe then comes back.
//!
//! **Going away.** A pipe is removed when its binding goes, when its level
//! changes and when the app quits; readers already waiting get a comment
//! first ([`answer_waiting`]), so none is left hanging. The app keeps a list
//! of its pipes on disk ([`PipeList`], no values) for its guard process and
//! its next start, which remove what a crash leaves the same way.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result, fsutil};

/// How long an answer waits for its reader to take it.
pub const SERVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// How long the pipe rests after an answer, so the reader that took it can
/// close it first: opened again while that reader still has it open, the
/// pipe would give it a second answer after the first. (Whole, and the
/// same, so every parser still reads the same values; a reader slower than
/// this may still get one.)
const REST: std::time::Duration = std::time::Duration::from_millis(25);
/// Most pipes a list keeps.
const MAX_PIPES: usize = 4096;

/// Which pipe: its device and inode, so a pipe put in its place by someone
/// else is told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PipeId {
    dev: u64,
    ino: u64,
}

impl PipeId {
    /// The pipe at `path`, not following a link, if a pipe is there.
    pub fn of(path: &Path) -> Option<Self> {
        Self::of_meta(&fs::symlink_metadata(path).ok()?)
    }

    #[cfg(unix)]
    fn of_meta(meta: &fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        meta.file_type().is_fifo().then(|| Self {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    #[cfg(not(unix))]
    fn of_meta(_: &fs::Metadata) -> Option<Self> {
        None
    }
}

/// Whether this system has pipes in folders: macOS and Linux do, Windows
/// doesn't.
pub const SUPPORTED: bool = cfg!(unix);

/// What a pipe answers.
#[derive(Clone, PartialEq, Eq)]
pub enum Answer {
    /// The variables, as a `.env` file.
    Values(Zeroizing<String>),
    /// The vault is locked.
    Locked,
    /// A shared value the environment uses can't be found.
    Unresolved,
    /// The pipe is going: its binding went or its level changed.
    Stopped,
    /// The app isn't running (it quit, or crashed and its guard answers).
    NotRunning,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the values.
        f.write_str(match self {
            Self::Values(_) => "Values(…)",
            Self::Locked => "Locked",
            Self::Unresolved => "Unresolved",
            Self::Stopped => "Stopped",
            Self::NotRunning => "NotRunning",
        })
    }
}

impl Answer {
    /// The answer as a reader gets it. Without values it is comments only,
    /// so a tool finds no variable rather than an empty one.
    pub fn text(&self) -> Zeroizing<String> {
        Zeroizing::new(match self {
            Self::Values(text) => return text.clone(),
            Self::Locked => {
                "# SSH Key Manager: the vault is locked. Unlock it to read this file.\n".to_owned()
            }
            Self::Unresolved => "# SSH Key Manager: a shared value this environment uses can't \
                                 be found. Open the app to fix it.\n"
                .to_owned(),
            Self::Stopped => {
                "# SSH Key Manager no longer serves this file. Read it again.\n".to_owned()
            }
            Self::NotRunning => "# SSH Key Manager isn't running. Open it and unlock the vault \
                                 to read this file.\n"
                .to_owned(),
        })
    }
}

/// A level-3 file after a round: its pipe and what it is to answer.
#[derive(Clone, PartialEq, Eq)]
pub struct VirtualFile {
    /// The pipe, in its folder with links resolved.
    pub path: PathBuf,
    /// The pipe as the project's folder names it.
    pub display: PathBuf,
    pub id: PipeId,
    pub answer: Answer,
}

impl std::fmt::Debug for VirtualFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualFile")
            .field("path", &self.path)
            .field("id", &self.id)
            .field("answer", &self.answer)
            .finish_non_exhaustive()
    }
}

/// A pipe on the app's list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedPipe {
    pub path: PathBuf,
    pub id: PipeId,
}

/// The pipes the app made and serves, as it keeps them in its data folder
/// for its guard and its next start: where they are and which they are,
/// nothing more.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeList {
    #[serde(default)]
    pipes: Vec<ListedPipe>,
}

impl PipeList {
    pub fn new(pipes: Vec<ListedPipe>) -> Self {
        let mut pipes = pipes;
        pipes.truncate(MAX_PIPES);
        Self { pipes }
    }

    /// The list kept at `path`; empty if there is none or it can't be read.
    pub fn load(path: &Path) -> Self {
        fsutil::read_limited(path, 4 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .map(|list: Self| Self::new(list.pipes))
            .unwrap_or_default()
    }

    /// Keeps the list at `path`, readable by this user only; an empty one
    /// removes the file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.pipes.is_empty() {
            return match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(Error::io(e, path)),
            };
        }
        let json = serde_json::to_vec(self).map_err(|e| Error::Parse(format!("{e}")))?;
        if fs::read(path).is_ok_and(|current| current == json) {
            return Ok(());
        }
        fsutil::atomic_write(path, &json, 0o600)
    }

    pub fn is_empty(&self) -> bool {
        self.pipes.is_empty()
    }

    pub fn pipes(&self) -> &[ListedPipe] {
        &self.pipes
    }

    /// Removes the pipes kept at `path` that are still the pipes listed,
    /// after answering readers waiting on them that the app isn't running,
    /// and the list with them: after a crash, by the guard or the next
    /// start. Returns how many it removed.
    pub fn sweep_at(path: &Path) -> usize {
        let list = Self::load(path);
        if list.is_empty() {
            return 0;
        }
        let removed = list
            .pipes
            .iter()
            .filter(|pipe| remove(&pipe.path, pipe.id, &Answer::NotRunning))
            .count();
        let _ = Self::default().save(path);
        removed
    }
}

/// Makes a pipe at `path`, readable and writable by this user only, where
/// nothing is. Fails if something is there by then.
pub fn make(path: &Path) -> Result<PipeId> {
    imp::mkfifo(path)?;
    fsutil::set_mode(path, 0o600)?;
    PipeId::of(path).ok_or_else(|| Error::invalid(format!("{} isn't a pipe", path.display())))
}

/// Puts a pipe in place of the regular file at `path`, only if it still
/// holds `expected`: the pipe is made next to it and renamed over it, so a
/// reader never finds no file. Returns the pipe, or `None` when the file
/// changed meanwhile and nothing was done.
pub fn make_over(path: &Path, expected: &[u8]) -> Result<Option<PipeId>> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| Error::invalid("not a file in a folder"))?;
    let dir = path
        .parent()
        .ok_or_else(|| Error::invalid("not a file in a folder"))?;
    // Named as the app's own writes are, so a crash's leftover is swept
    // with theirs (`fsutil::sweep_private_temps`).
    let temp = dir.join(format!(
        "{name}{}{}.tmp",
        fsutil::PRIVATE_TEMP.0,
        random_tag()
    ));
    make(&temp)?;
    let same = fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
        && fsutil::read_limited(path, crate::vault::envs::MAX_FILE_SIZE)
            .is_ok_and(|bytes| Zeroizing::new(bytes).as_slice() == expected);
    if !same {
        let _ = fs::remove_file(&temp);
        return Ok(None);
    }
    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(Error::io(e, path));
    }
    Ok(PipeId::of(path))
}

fn random_tag() -> String {
    use rand_core::{OsRng, RngCore};
    const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| char::from(LETTERS[usize::from(*b) % LETTERS.len()]))
        .collect()
}

/// Answers the readers waiting on the pipe `id` at `path` with `answer`,
/// then removes it if it is still that pipe. Returns whether it removed it.
pub fn remove(path: &Path, id: PipeId, answer: &Answer) -> bool {
    if PipeId::of(path) != Some(id) {
        return false;
    }
    answer_waiting(path, id, answer);
    PipeId::of(path) == Some(id) && fs::remove_file(path).is_ok()
}

/// Answers the readers waiting on the pipe `id` at `path` right now, if
/// any, with `answer`, without ever waiting for one: a reader that is
/// blocked opening it would otherwise wait on a pipe no one serves. A
/// handful of rounds at most, briefly.
pub fn answer_waiting(path: &Path, id: PipeId, answer: &Answer) {
    let text = answer.text();
    for _ in 0..4 {
        let Some(pipe) = imp::open_if_read(path, id) else {
            return;
        };
        let served = imp::answer(
            path,
            id,
            &pipe,
            text.as_bytes(),
            None,
            std::time::Duration::from_millis(50),
        );
        if served != imp::Served::Answered {
            return;
        }
    }
}

pub use imp::PipeServer;

#[cfg(unix)]
mod imp {
    //! The system calls: `mkfifo`, `fcntl`, `poll` and `futimens` through
    //! `libc`, each on a descriptor or path the call borrows.
    #![allow(unsafe_code)]

    use std::fs::{File, OpenOptions};
    use std::io::{self, Write as _};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use super::{Answer, PipeId, SERVE_TIMEOUT};
    use crate::{Error, Result};

    pub(super) fn mkfifo(path: &Path) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::invalid("a path with a NUL byte"))?;
        // SAFETY: a valid C string; mkfifo reads it and keeps nothing.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if made == 0 {
            Ok(())
        } else {
            Err(Error::io(io::Error::last_os_error(), path))
        }
    }

    /// The pipe `id` at `path`, opened to write to, if a reader has it
    /// open now; never waits.
    pub(super) fn open_if_read(path: &Path, id: PipeId) -> Option<File> {
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
            .ok()?;
        (id_of(&file) == Some(id)).then_some(file)
    }

    fn id_of(file: &File) -> Option<PipeId> {
        PipeId::of_meta(&file.metadata().ok()?)
    }

    /// What answering a reader came to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Served {
        Answered,
        /// An earlier answer is still in the pipe, unread: a reader holds
        /// the pipe open without reading. It is the next reader's, and
        /// nothing is added to it.
        Pending,
        /// The pipe at the path isn't this one any more.
        Gone,
    }

    /// Answers the readers that opened the pipe `id` at `path`, which
    /// `pipe` has open to write: `bytes` goes into it whole, unless an
    /// earlier answer is still there unread, without waiting longer than
    /// `timeout` for a reader to take it. An answer cut short by that is
    /// taken back out, so a reader never gets half of one (a value cut in
    /// two). Then the pipe's time of change is put back to `mtime`, if
    /// given (its last access becomes now).
    pub(super) fn answer(
        path: &Path,
        id: PipeId,
        pipe: &File,
        bytes: &[u8],
        mtime: Option<libc::timespec>,
        timeout: Duration,
    ) -> Served {
        // A reader of its own, to see what the pipe holds; read from only
        // to take a cut answer back.
        let Some(own) = open_reader(path, id) else {
            return Served::Gone;
        };
        if unread(&own) > 0 {
            return Served::Pending;
        }
        if !write_whole(pipe, bytes, timeout) {
            drain(&own);
        }
        if let Some(mtime) = mtime {
            let times = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_NOW,
                },
                mtime,
            ];
            // SAFETY: `times` is two valid timespecs; the descriptor is
            // borrowed for the call.
            unsafe {
                libc::futimens(pipe.as_raw_fd(), times.as_ptr());
            }
        }
        Served::Answered
    }

    /// The pipe `id` at `path`, opened to read without waiting.
    fn open_reader(path: &Path, id: PipeId) -> Option<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
            .ok()?;
        (id_of(&file) == Some(id)).then_some(file)
    }

    /// How many bytes the pipe holds unread.
    fn unread(reader: &File) -> usize {
        let mut count: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int, here `count`.
        let done = unsafe { libc::ioctl(reader.as_raw_fd(), libc::FIONREAD, &raw mut count) };
        if done == 0 {
            usize::try_from(count).unwrap_or(0)
        } else {
            0
        }
    }

    /// Takes everything the pipe holds now out of it, and forgets it.
    fn drain(reader: &File) {
        use std::io::Read as _;
        let mut sink = zeroize::Zeroizing::new([0u8; 4096]);
        let mut reader = reader;
        while matches!(reader.read(&mut sink[..]), Ok(n) if n > 0) {}
    }

    /// Writes `bytes` to the pipe, without waiting longer than `timeout` for
    /// room. Returns whether it wrote them all.
    fn write_whole(pipe: &File, bytes: &[u8], timeout: Duration) -> bool {
        let fd = pipe.as_raw_fd();
        // SAFETY: plain fcntl calls on a descriptor this function borrows.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            // A reader that goes before the end gives an error, not a
            // signal that ends the app.
            #[cfg(target_os = "macos")]
            libc::fcntl(fd, libc::F_SETNOSIGPIPE, 1);
            // Room for the whole answer, where the pipe can grow.
            #[cfg(target_os = "linux")]
            if bytes.len() > 64 * 1024 {
                let wanted = libc::c_int::try_from(bytes.len().min(1024 * 1024)).unwrap_or(0);
                libc::fcntl(fd, libc::F_SETPIPE_SZ, wanted);
            }
        }
        let deadline = Instant::now() + timeout;
        let mut rest = bytes;
        let mut writer = pipe;
        while !rest.is_empty() {
            match writer.write(rest) {
                Ok(0) => break,
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() || !writable(fd, left) {
                        break;
                    }
                }
                // The reader went.
                Err(_) => break,
            }
        }
        rest.is_empty()
    }

    /// Waits up to `left` for the pipe to take more.
    fn writable(fd: libc::c_int, left: Duration) -> bool {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid pollfd for the length of the call.
        let ready = unsafe { libc::poll(&raw mut poll, 1, ms) };
        ready > 0 && poll.revents & libc::POLLOUT != 0
    }

    /// Serves one pipe from a thread of its own, until stopped.
    pub struct PipeServer {
        shared: Arc<Shared>,
    }

    struct Shared {
        path: PathBuf,
        id: PipeId,
        /// The pipe's time of change when it was made, put back after each
        /// answer.
        mtime: libc::timespec,
        answer: Mutex<Answer>,
        stop: AtomicBool,
        /// The thread is gone; set with `gone_signal`.
        gone: Mutex<bool>,
        gone_signal: Condvar,
    }

    impl PipeServer {
        /// Starts serving the pipe `id` at `path` with `answer`.
        pub fn start(path: &Path, id: PipeId, answer: Answer) -> Result<Self> {
            let meta = std::fs::symlink_metadata(path).map_err(|e| Error::io(e, path))?;
            if PipeId::of_meta(&meta) != Some(id) {
                return Err(Error::invalid(format!("{} isn't the pipe", path.display())));
            }
            let shared = Arc::new(Shared {
                path: path.to_path_buf(),
                id,
                mtime: timespec(meta.mtime(), meta.mtime_nsec()),
                answer: Mutex::new(answer),
                stop: AtomicBool::new(false),
                gone: Mutex::new(false),
                gone_signal: Condvar::new(),
            });
            let serving = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("sshkm-env-pipe".into())
                .spawn(move || {
                    run(&serving);
                    *lock(&serving.gone) = true;
                    serving.gone_signal.notify_all();
                })
                .map_err(|e| Error::io(e, path))?;
            Ok(Self { shared })
        }

        pub fn id(&self) -> PipeId {
            self.shared.id
        }

        pub fn path(&self) -> &Path {
            &self.shared.path
        }

        /// What the next reader gets.
        pub fn set_answer(&self, answer: Answer) {
            *lock(&self.shared.answer) = answer;
        }

        /// The thread still serves: it stops when the pipe at its path is
        /// no longer its pipe.
        pub fn is_serving(&self) -> bool {
            !*lock(&self.shared.gone)
        }

        /// Stops serving: readers waiting get `answer`, and the pipe is
        /// removed if it is still the one served. Returns once that is
        /// done; a thread still waiting on a pipe that was replaced (its
        /// path names something else now, and no reader can reach it) is
        /// left to wait, harmlessly, until the app quits.
        pub fn stop(self, answer: &Answer) -> bool {
            let shared = &self.shared;
            *lock(&shared.answer) = answer.clone();
            shared.stop.store(true, Ordering::SeqCst);
            // Opening the pipe to read lets the thread's wait end; it then
            // answers whoever else waits, and goes. Nothing is read here.
            let wake = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open(&shared.path)
                .ok()
                .filter(|file| id_of(file) == Some(shared.id));
            if wake.is_some() {
                let gone = lock(&shared.gone);
                let _ =
                    shared
                        .gone_signal
                        .wait_timeout_while(gone, Duration::from_secs(1), |gone| !*gone);
            }
            drop(wake);
            super::remove(&shared.path, shared.id, answer)
        }
    }

    /// A time as `futimens` takes it.
    #[allow(clippy::cast_possible_truncation, clippy::unnecessary_cast)]
    fn timespec(secs: i64, nanos: i64) -> libc::timespec {
        libc::timespec {
            tv_sec: secs as libc::time_t,
            tv_nsec: nanos as _,
        }
    }

    fn run(shared: &Shared) {
        // While an answer waits in the pipe unread, the pipe is looked at
        // less and less often, up to once a second.
        let mut pause = Duration::ZERO;
        loop {
            if shared.stop.load(Ordering::SeqCst) {
                return;
            }
            // Waits until a reader opens the pipe; at once while one holds
            // it open.
            let opened = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&shared.path);
            let Ok(pipe) = opened else {
                return;
            };
            // Something else is at the path now (a file saved over it):
            // never written to.
            if id_of(&pipe) != Some(shared.id) {
                return;
            }
            let text = lock(&shared.answer).text();
            let served = answer(
                &shared.path,
                shared.id,
                &pipe,
                text.as_bytes(),
                Some(shared.mtime),
                SERVE_TIMEOUT,
            );
            drop(pipe);
            match served {
                Served::Answered => {
                    pause = Duration::ZERO;
                    std::thread::sleep(super::REST);
                }
                Served::Pending => {
                    pause = (pause * 2).clamp(Duration::from_millis(50), Duration::from_secs(1));
                    std::thread::sleep(pause);
                }
                Served::Gone => return,
            }
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(not(unix))]
mod imp {
    use std::fs::File;
    use std::path::Path;
    use std::time::Duration;

    use super::{Answer, PipeId};
    use crate::{Error, Result};

    fn unsupported() -> Error {
        Error::Unsupported("virtual files work on macOS and Linux".into())
    }

    pub(super) fn mkfifo(_: &Path) -> Result<()> {
        Err(unsupported())
    }

    pub(super) fn open_if_read(_: &Path, _: PipeId) -> Option<File> {
        None
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Served {
        #[allow(dead_code, reason = "the same as on Unix, never made here")]
        Answered,
        Gone,
    }

    pub(super) fn answer(
        _: &Path,
        _: PipeId,
        _: &File,
        _: &[u8],
        _: Option<()>,
        _: Duration,
    ) -> Served {
        Served::Gone
    }

    /// No pipes in folders here.
    pub struct PipeServer;

    impl PipeServer {
        pub fn start(_: &Path, _: PipeId, _: Answer) -> Result<Self> {
            Err(unsupported())
        }

        pub fn id(&self) -> PipeId {
            unreachable!("never started")
        }

        pub fn path(&self) -> &Path {
            unreachable!("never started")
        }

        pub fn set_answer(&self, _: Answer) {}

        pub fn is_serving(&self) -> bool {
            false
        }

        pub fn stop(self, _: &Answer) -> bool {
            false
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Reads the whole file at `path` in a thread, as a tool does; the
    /// receiver gets what it read.
    fn reader(path: &Path) -> mpsc::Receiver<Vec<u8>> {
        let (done, got) = mpsc::channel();
        let path = path.to_path_buf();
        std::thread::spawn(move || {
            let _ = done.send(fs::read(&path).unwrap_or_default());
        });
        got
    }

    fn within(got: &mpsc::Receiver<Vec<u8>>) -> String {
        String::from_utf8(
            got.recv_timeout(Duration::from_secs(10))
                .expect("a reader hung"),
        )
        .unwrap()
    }

    /// Whether `text` is whole answers out of `answers`, one or more: a
    /// reader that comes back before it closed may get one twice.
    fn whole(text: &str, answers: &[&str]) -> bool {
        let mut rest = text;
        while !rest.is_empty() {
            let Some(answer) = answers.iter().find(|answer| rest.starts_with(**answer)) else {
                return false;
            };
            rest = &rest[answer.len()..];
        }
        !text.is_empty()
    }

    fn values(text: &str) -> Answer {
        Answer::Values(Zeroizing::new(text.to_owned()))
    }

    fn pipe(dir: &Path) -> (PathBuf, PipeId) {
        let path = dir.join(".env");
        let id = make(&path).unwrap();
        (path, id)
    }

    #[test]
    fn each_reader_gets_one_whole_answer_and_the_time_stays() {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = pipe(dir.path());
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o600);
        let before = fs::symlink_metadata(&path).unwrap();
        let server = PipeServer::start(&path, id, values("A=1\n")).unwrap();
        for _ in 0..3 {
            let text = within(&reader(&path));
            assert!(whole(&text, &["A=1\n"]), "{text:?}");
        }
        server.set_answer(Answer::Locked);
        let locked = within(&reader(&path));
        assert!(whole(&locked, &[&Answer::Locked.text()]), "{locked:?}");
        // Larger than the pipe's buffer: a reader that reads gets it all.
        let big = format!("B={}\n", "x".repeat(200 * 1024));
        server.set_answer(values(&big));
        assert!(whole(&within(&reader(&path)), &[&big]));
        // Watching tools see no change.
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (after.mtime(), after.mtime_nsec()),
            (before.mtime(), before.mtime_nsec())
        );
        assert!(server.stop(&Answer::Stopped));
        assert!(!path.exists());
    }

    #[test]
    fn a_reader_that_never_reads_holds_up_no_one() {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = pipe(dir.path());
        let server = PipeServer::start(&path, id, values("A=1\n")).unwrap();
        let idle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        // The next reader gets the answer the idle one left, whole, and at
        // most a new one after it if it took that one first: nothing else
        // piles up meanwhile.
        std::thread::sleep(Duration::from_millis(300));
        server.set_answer(values("A=2\n"));
        let text = within(&reader(&path));
        assert!(
            text.starts_with("A=1\n") && whole(&text, &["A=1\n", "A=2\n"]),
            "{text:?}"
        );
        assert!(text.len() < 4 * 4, "{text:?}");
        drop(idle);
        let text = within(&reader(&path));
        assert!(whole(&text, &["A=2\n"]), "{text:?}");
        // An answer larger than the pipe, for a reader that never reads,
        // is taken back after a while: the next reader gets a whole one.
        let big = format!("B={}\n", "y".repeat(256 * 1024));
        server.set_answer(values(&big));
        let idle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        std::thread::sleep(SERVE_TIMEOUT + Duration::from_millis(500));
        let text = within(&reader(&path));
        assert!(
            text.is_empty() || whole(&text, &[&big]),
            "{} bytes",
            text.len()
        );
        drop(idle);
        assert!(whole(&within(&reader(&path)), &[&big]));
        server.stop(&Answer::Stopped);
    }

    #[test]
    fn readers_waiting_when_it_stops_get_an_answer_and_the_pipe_goes() {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = pipe(dir.path());
        // No server yet: the reader waits, as on a pipe left by a crash.
        let waiting = reader(&path);
        std::thread::sleep(Duration::from_millis(100));
        assert!(remove(&path, id, &Answer::NotRunning));
        assert!(within(&waiting).starts_with("# SSH Key Manager isn't running."));
        assert!(!path.exists());

        let (path, id) = pipe(dir.path());
        let server = PipeServer::start(&path, id, values("A=1\n")).unwrap();
        assert!(server.is_serving());
        assert!(server.stop(&Answer::Stopped));
        assert!(!path.exists());
        // A reader after that finds no file, rather than waiting.
        assert!(fs::read(&path).is_err());
    }

    #[test]
    fn a_file_saved_over_the_pipe_is_never_written_to_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = pipe(dir.path());
        let server = PipeServer::start(&path, id, values("SECRET=1\n")).unwrap();
        let saved = dir.path().join(".env.saved");
        fs::write(&saved, "A=2\n").unwrap();
        fs::rename(&saved, &path).unwrap();
        // The thread waits on the pipe no one can reach now; stopping
        // doesn't wait for it, nor touches the file.
        assert!(!server.stop(&Answer::Stopped));
        assert_eq!(fs::read_to_string(&path).unwrap(), "A=2\n");
        // A pipe of someone else's in its place is left too.
        fs::remove_file(&path).unwrap();
        let (path, _) = pipe(dir.path());
        assert!(!remove(&path, id, &Answer::Stopped));
        assert!(PipeId::of(&path).is_some());
    }

    #[test]
    fn a_list_left_by_a_crash_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        let list_path = dir.path().join("pipes.json");
        let one = dir.path().join("a");
        fs::create_dir(&one).unwrap();
        let (a, a_id) = pipe(&one);
        let two = dir.path().join("b");
        fs::create_dir(&two).unwrap();
        let (b, b_id) = pipe(&two);
        PipeList::new(vec![
            ListedPipe {
                path: a.clone(),
                id: a_id,
            },
            ListedPipe {
                path: b.clone(),
                id: b_id,
            },
        ])
        .save(&list_path)
        .unwrap();
        assert_eq!(
            fs::symlink_metadata(&list_path).unwrap().mode() & 0o777,
            0o600
        );
        // `b` was replaced by a file of the user's.
        fs::remove_file(&b).unwrap();
        fs::write(&b, "MINE=1\n").unwrap();
        let waiting = reader(&a);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(PipeList::sweep_at(&list_path), 1);
        assert!(within(&waiting).contains("isn't running"));
        assert!(!a.exists());
        assert_eq!(fs::read_to_string(&b).unwrap(), "MINE=1\n");
        assert!(!list_path.exists());
        assert_eq!(PipeList::sweep_at(&list_path), 0);
    }

    #[test]
    fn a_pipe_takes_a_files_place_only_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, "A=1\n").unwrap();
        assert_eq!(make_over(&path, b"A=2\n").unwrap(), None);
        assert_eq!(fs::read_to_string(&path).unwrap(), "A=1\n");
        let id = make_over(&path, b"A=1\n").unwrap().unwrap();
        assert_eq!(PipeId::of(&path), Some(id));
        // No temporary pipe is left next to it.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(".env")]);
        // Something already there: no pipe is made over it.
        assert!(make(&path).is_err());
    }
}
