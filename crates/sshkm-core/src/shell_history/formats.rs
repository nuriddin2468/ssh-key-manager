//! The history files of zsh, bash, fish and PowerShell, read into commands.

/// One command from a history file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    pub text: String,
    /// When it ran, in seconds since 1970, if the file says.
    pub when: Option<i64>,
}

/// `~/.zsh_history`: one command a line, `: <start>:<elapsed>;<command>`
/// with `EXTENDED_HISTORY`. A line that ends in `\` goes on on the next.
/// zsh writes some bytes "metafied", as `0x83` and the byte XOR 32.
pub(super) fn zsh(bytes: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(&unmetafy(bytes)).into_owned();
    let mut entries: Vec<Entry> = Vec::new();
    let mut open = false;
    for line in lines(&text) {
        if open && let Some(last) = entries.last_mut() {
            last.text.pop();
            last.text.push('\n');
            last.text.push_str(line);
        } else {
            entries.push(match extended(line) {
                Some((when, command)) => Entry {
                    text: command.to_owned(),
                    when: Some(when),
                },
                None => Entry {
                    text: line.to_owned(),
                    when: None,
                },
            });
        }
        open = entries.last().is_some_and(|e| e.text.ends_with('\\'));
    }
    entries
}

/// `: 1700000000:0;ssh host` → the time and the command.
fn extended(line: &str) -> Option<(i64, &str)> {
    let rest = line.strip_prefix(": ")?;
    let (stamp, rest) = rest.split_once(':')?;
    let (elapsed, command) = rest.split_once(';')?;
    if !elapsed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((stamp.parse().ok()?, command))
}

fn unmetafy(bytes: &[u8]) -> Vec<u8> {
    const META: u8 = 0x83;
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter();
    while let Some(&byte) = iter.next() {
        if byte == META {
            if let Some(&next) = iter.next() {
                out.push(next ^ 32);
            }
        } else {
            out.push(byte);
        }
    }
    out
}

/// `~/.bash_history`: one line a command; with `HISTTIMEFORMAT` set, a
/// `#<seconds>` line before each says when it ran.
pub(super) fn bash(bytes: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(bytes);
    let mut when = None;
    let mut entries = Vec::new();
    for line in lines(&text) {
        if let Some(stamp) = line.strip_prefix('#')
            && !stamp.is_empty()
            && stamp.bytes().all(|b| b.is_ascii_digit())
        {
            when = stamp.parse().ok();
            continue;
        }
        entries.push(Entry {
            text: line.to_owned(),
            when,
        });
    }
    entries
}

/// fish's `fish_history`, a subset of YAML:
///
/// ```text
/// - cmd: ssh host
///   when: 1700000000
///   paths:
///     - ~/notes
/// ```
///
/// In `cmd`, `\\` is a backslash and `\n` a new line.
pub(super) fn fish(bytes: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(bytes);
    let mut entries: Vec<Entry> = Vec::new();
    for line in lines(&text) {
        if let Some(command) = line.strip_prefix("- cmd: ") {
            entries.push(Entry {
                text: fish_unescape(command),
                when: None,
            });
        } else if let Some(stamp) = line.strip_prefix("  when: ")
            && let Some(last) = entries.last_mut()
        {
            last.when = stamp.trim().parse().ok();
        }
    }
    entries
}

fn fish_unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') | None => out.push('\\'),
            Some('n') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// `PSReadLine`'s `ConsoleHost_history.txt`: one command a line; the lines
/// of a command that spans several end in a backquote, which `PSReadLine`
/// added and takes off again. No times.
pub(super) fn powershell(bytes: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut entries: Vec<Entry> = Vec::new();
    let mut open = false;
    for line in lines(text) {
        let (part, continues) = match line.strip_suffix('`') {
            Some(part) => (part, true),
            None => (line, false),
        };
        if open && let Some(last) = entries.last_mut() {
            last.text.push('\n');
            last.text.push_str(part);
        } else {
            entries.push(Entry {
                text: part.to_owned(),
                when: None,
            });
        }
        open = continues;
    }
    entries
}

/// The lines of `text`, without their `\n` or `\r\n`.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.is_empty())
}
