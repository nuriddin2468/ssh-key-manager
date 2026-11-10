//! Searching a file in chunks, and overwriting what was found.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::Ordering;

use zeroize::Zeroizing;

use super::{Matcher, ScanControl};

/// Bytes read at a time.
const CHUNK: usize = 1024 * 1024;

/// A match: which pattern, where (in bytes from the start of the file), and
/// on which line it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Hit {
    pub pattern: usize,
    pub start: u64,
    pub end: u64,
    pub line: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Options<'a> {
    /// Stop at a NUL byte in the first chunk: a binary file.
    pub text_only: bool,
    /// Progress and cancelling.
    pub control: Option<&'a ScanControl>,
    /// Bytes read at a time; 0 for [`CHUNK`]. Small in tests.
    pub chunk: usize,
}

/// Why a search stopped early.
#[derive(Debug)]
pub(super) enum Stop {
    Cancelled,
    Io(io::Error),
}

impl From<io::Error> for Stop {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Stop {
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io(error) => error,
            Self::Cancelled => io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
        }
    }
}

/// Calls `on_hit` for every match of `matcher`'s patterns in `reader`,
/// overlapping ones too, in the order they end. Reads a chunk at a time and keeps the end of the previous chunk, as long as the longest
/// pattern, so no match is cut in two or reported twice. Returns `false`
/// for a binary file when `options.text_only` is set.
pub(super) fn search(
    mut reader: impl Read,
    matcher: &Matcher,
    options: Options<'_>,
    mut on_hit: impl FnMut(Hit),
) -> Result<bool, Stop> {
    let Some(automaton) = matcher.automaton() else {
        return Ok(true);
    };
    let keep = matcher.longest().saturating_sub(1);
    let chunk = if options.chunk == 0 {
        CHUNK
    } else {
        options.chunk
    };
    // The file's text passes through here: wiped when done.
    let mut buffer = Zeroizing::new(Vec::with_capacity(chunk + keep));
    // Where `buffer` starts in the file, and the line it starts on.
    let mut base: u64 = 0;
    let mut base_line: u32 = 1;
    // Matches ending here or before were reported already.
    let mut reported_to: u64 = 0;
    let mut first = true;
    loop {
        if options.control.is_some_and(ScanControl::cancelled) {
            return Err(Stop::Cancelled);
        }
        let read = fill(&mut reader, &mut buffer, chunk)?;
        if let Some(control) = options.control {
            control
                .bytes_done
                .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        // Nothing new: what the buffer keeps was searched already.
        if read == 0 {
            return Ok(true);
        }
        if first && options.text_only && buffer[..buffer.len().min(8 * 1024)].contains(&0) {
            return Ok(false);
        }
        first = false;

        // Lines are counted from the buffer's start up to each match.
        let mut counted_to = 0_usize;
        let mut line = base_line;
        for found in automaton.find_overlapping_iter(buffer.as_slice()) {
            let end = base + found.end() as u64;
            if end <= reported_to {
                continue;
            }
            if found.start() < counted_to {
                counted_to = 0;
                line = base_line;
            }
            line += newlines(&buffer[counted_to..found.start()]);
            counted_to = found.start();
            on_hit(Hit {
                pattern: found.pattern().as_usize(),
                start: base + found.start() as u64,
                end,
                line,
            });
        }
        reported_to = base + buffer.len() as u64;
        // `fill` reads less only at the end of the file.
        if read < chunk {
            return Ok(true);
        }

        let drop = buffer.len() - keep.min(buffer.len());
        base_line += newlines(&buffer[..drop]);
        base += drop as u64;
        let left = buffer.len() - drop;
        buffer.copy_within(drop.., 0);
        buffer.truncate(left);
    }
}

/// Appends up to `want` bytes from `reader` to `buffer`: fewer only at the
/// end of the file. Returns how many.
fn fill(reader: &mut impl Read, buffer: &mut Vec<u8>, want: usize) -> io::Result<usize> {
    let start = buffer.len();
    buffer.resize(start + want, 0);
    let mut filled = 0;
    while filled < want {
        match reader.read(&mut buffer[start + filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                buffer.truncate(start);
                return Err(e);
            }
        }
    }
    buffer.truncate(start + filled);
    Ok(filled)
}

#[allow(
    clippy::naive_bytecount,
    reason = "lines are counted only up to a match, which is rare"
)]
fn newlines(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.iter().filter(|b| **b == b'\n').count()).unwrap_or(u32::MAX)
}

/// Writes `marker(len)` over each range of the file at `path`, in place:
/// nothing else of the file changes, and it is never truncated.
pub(super) fn overwrite(
    path: &Path,
    ranges: &[(u64, u64)],
    marker: impl Fn(usize) -> Vec<u8>,
) -> io::Result<()> {
    if ranges.is_empty() {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    if ranges.iter().any(|(_, end)| *end > len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the file got shorter since it was read",
        ));
    }
    for &(start, end) in ranges {
        let size = usize::try_from(end - start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "match too long"))?;
        file.seek(SeekFrom::Start(start))?;
        file.write_all(&marker(size))?;
    }
    file.sync_all()
}
