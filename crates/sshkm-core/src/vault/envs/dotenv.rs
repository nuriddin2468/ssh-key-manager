//! Reading `.env` files the way the common loaders (dotenv, Docker Compose)
//! read them:
//!
//! - `NAME=value`, optionally after `export `, with spaces around `=`;
//! - blank lines and lines starting with `#` are skipped, and in a value
//!   without quotes a `#` after a space starts a comment;
//! - `'…'` and `` `…` `` keep their text as it is, `"…"` reads `\n`, `\r`,
//!   `\t`, `\"` and `\\` (any other backslash stays), and all three may
//!   span lines;
//! - a value without quotes is trimmed and taken as it is.
//!
//! References such as `${HOME}` are kept as written: nothing is expanded,
//! nothing is run. A name that comes again replaces the earlier value, as in
//! the loaders. Lines that can't be read are reported by number, never with
//! their text, which may be a secret.

use std::ops::Range;

use serde::Serialize;
use zeroize::Zeroizing;

use super::{MAX_VARIABLES, is_valid_name};
use crate::vault::MAX_FIELD_LEN;

/// A variable read from the file.
pub struct ParsedVar {
    pub name: String,
    pub value: Zeroizing<String>,
    /// Where it starts, from 1.
    pub line: u32,
}

impl std::fmt::Debug for ParsedVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedVar")
            .field("name", &self.name)
            .field("line", &self.line)
            .finish_non_exhaustive()
    }
}

/// A line of the file that gave no variable, or whose variable doesn't count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ParseProblem {
    /// From 1.
    pub line: u32,
    pub kind: ProblemKind,
    /// The variable's name, for [`ProblemKind::TooLong`] and
    /// [`ProblemKind::Replaced`]: lines that can't be read aren't quoted.
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ProblemKind {
    /// A line with no `=`.
    NoEquals,
    /// The name isn't letters, digits and `_`, starting with a letter or `_`.
    BadName,
    /// A quote that never closes.
    Unterminated,
    /// Something other than a comment after the closing quote.
    TrailingText,
    /// The value is longer than a vault field may be, or holds a NUL.
    TooLong,
    /// A later line sets the same name.
    Replaced,
    /// More variables than an environment may hold; the rest were left out.
    TooMany,
}

/// What a file holds.
#[derive(Debug, Default)]
pub struct ParsedEnv {
    pub vars: Vec<ParsedVar>,
    pub problems: Vec<ParseProblem>,
}

/// Reads the text of a `.env` file.
pub fn parse(text: &str) -> ParsedEnv {
    let scan = scan(text);
    let (effective, cut) = effective(&scan.assignments);
    let mut parsed = ParsedEnv::default();
    // The names set again, with the line they were first set on.
    for (index, assignment) in scan.assignments.iter().enumerate() {
        if cut.is_some_and(|cut| index >= cut) {
            break;
        }
        if !effective.contains(&index) {
            parsed.problems.push(ParseProblem {
                line: assignment.line,
                kind: ProblemKind::Replaced,
                name: Some(assignment.name.clone()),
            });
        }
    }
    let cut_line = cut.map(|cut| scan.assignments[cut].line);
    if let Some(line) = cut_line {
        parsed.problems.push(ParseProblem {
            line,
            kind: ProblemKind::TooMany,
            name: None,
        });
    }
    parsed.problems.extend(
        scan.problems
            .into_iter()
            .filter(|problem| cut_line.is_none_or(|cut| problem.line < cut)),
    );
    parsed.problems.sort_by_key(|problem| problem.line);
    let mut assignments: Vec<Option<Assignment>> = scan.assignments.into_iter().map(Some).collect();
    parsed.vars = effective
        .into_iter()
        .filter_map(|index| assignments[index].take())
        .map(|assignment| ParsedVar {
            name: assignment.name,
            value: assignment.value,
            line: assignment.line,
        })
        .collect();
    parsed
}

/// A line (or lines) of the file that sets a variable, and where it is.
pub(super) struct Assignment {
    pub name: String,
    pub value: Zeroizing<String>,
    /// Where it starts, from 1.
    pub line: u32,
    /// The bytes of the whole assignment in the text: from the start of its
    /// first line to past the line break of its last one.
    pub span: Range<usize>,
    /// The bytes of the value as written, quotes included. For an empty
    /// value without quotes, the empty range right after `=`.
    pub raw: Range<usize>,
    /// The quote the value is in, if any.
    pub quote: Option<char>,
}

/// What [`scan`] finds: every assignment in order, names set again
/// included, and the lines that set nothing.
pub(super) struct Scan {
    pub assignments: Vec<Assignment>,
    pub problems: Vec<ParseProblem>,
    /// Where the line with the first quote that never closes starts: it
    /// takes the rest of the file, so nothing can be added after it.
    pub unterminated_at: Option<usize>,
}

/// Which of `assignments` count, in their order: of a name set twice the
/// later one, as the loaders read it, and no more than [`MAX_VARIABLES`].
/// The second value is the index of the assignment past that limit, where
/// reading stops.
pub(super) fn effective(assignments: &[Assignment]) -> (Vec<usize>, Option<usize>) {
    let mut kept: Vec<usize> = Vec::new();
    for (index, assignment) in assignments.iter().enumerate() {
        if let Some(at) = kept
            .iter()
            .position(|&other| assignments[other].name == assignment.name)
        {
            kept.remove(at);
        }
        if kept.len() == MAX_VARIABLES {
            return (kept, Some(index));
        }
        kept.push(index);
    }
    (kept, None)
}

/// A line of the text without its line break, and where it is.
struct Line<'a> {
    text: &'a str,
    start: usize,
    /// Past its line break.
    end: usize,
}

/// Reads every assignment of the text with where it is, for [`parse`] and
/// for editing the file in place.
pub(super) fn scan(text: &str) -> Scan {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    let base = text.len() - body.len();
    let mut lines = Vec::new();
    let mut start = 0;
    for piece in body.split('\n') {
        let end = start + piece.len();
        let broken = end < body.len();
        lines.push(Line {
            text: piece.strip_suffix('\r').unwrap_or(piece),
            start: base + start,
            end: base + end + usize::from(broken),
        });
        start = end + 1;
    }
    let mut scan = Scan {
        assignments: Vec::new(),
        problems: Vec::new(),
        unterminated_at: None,
    };
    let mut next = 0;
    while next < lines.len() {
        let first = next;
        let line = number(first);
        let current = lines[first].text;
        next += 1;
        let problem = |kind| ParseProblem {
            line,
            kind,
            name: None,
        };
        let trimmed = current.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let rest = strip_export(trimmed);
        let Some(equals) = rest.find('=') else {
            scan.problems.push(problem(ProblemKind::NoEquals));
            continue;
        };
        let name = rest[..equals].trim();
        if !is_valid_name(name) {
            scan.problems.push(problem(ProblemKind::BadName));
            continue;
        }
        let after = &rest[equals + 1..];
        let opening = after
            .trim_start()
            .chars()
            .next()
            .filter(|c| matches!(c, '"' | '\'' | '`'));
        let (value, raw, quote) = if let Some(quote) = opening {
            let open = after.len() - after.trim_start().len();
            match quoted(text, &after[open + 1..], quote, &lines, &mut next) {
                Ok((value, end)) => (value, offset(text, &after[open..])..end, Some(quote)),
                Err(kind) => {
                    if kind == ProblemKind::Unterminated && scan.unterminated_at.is_none() {
                        scan.unterminated_at = Some(lines[first].start);
                    }
                    scan.problems.push(problem(kind));
                    continue;
                }
            }
        } else {
            let value = unquoted(after);
            let at = if value.is_empty() {
                offset(text, after)
            } else {
                offset(text, value)
            };
            (Zeroizing::new(value.to_owned()), at..at + value.len(), None)
        };
        if value.len() > MAX_FIELD_LEN || value.contains('\0') {
            scan.problems.push(ParseProblem {
                line,
                kind: ProblemKind::TooLong,
                name: Some(name.to_owned()),
            });
            continue;
        }
        scan.assignments.push(Assignment {
            name: name.to_owned(),
            value,
            line,
            span: lines[first].start..lines[next - 1].end,
            raw,
            quote,
        });
    }
    scan
}

/// Where `part`, a piece of `text`, starts in it.
fn offset(text: &str, part: &str) -> usize {
    part.as_ptr() as usize - text.as_ptr() as usize
}

fn number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

/// The line without a leading `export ` (a shell's way to write it).
fn strip_export(line: &str) -> &str {
    match line.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
        _ => line,
    }
}

/// A value without quotes: up to a `#` that follows a space, trimmed.
fn unquoted(after: &str) -> &str {
    let mut previous_space = after.is_empty() || after.starts_with([' ', '\t']);
    for (index, c) in after.char_indices() {
        if c == '#' && previous_space {
            return after[..index].trim();
        }
        previous_space = c == ' ' || c == '\t';
    }
    after.trim()
}

/// A quoted value starting right after its opening `quote`, perhaps going
/// on over the following lines (`next` moves past them), and where its
/// closing quote ends in `text`. After the closing quote only spaces and a
/// comment may follow.
fn quoted(
    text: &str,
    first: &str,
    quote: char,
    lines: &[Line<'_>],
    next: &mut usize,
) -> Result<(Zeroizing<String>, usize), ProblemKind> {
    let mut body = Zeroizing::new(String::new());
    let mut current = first;
    let (rest, end) = loop {
        if let Some(close) = closing(current, quote) {
            body.push_str(&current[..close]);
            let past = close + quote.len_utf8();
            break (&current[past..], offset(text, current) + past);
        }
        body.push_str(current);
        let Some(line) = lines.get(*next) else {
            return Err(ProblemKind::Unterminated);
        };
        body.push('\n');
        current = line.text;
        *next += 1;
        if body.len() > MAX_FIELD_LEN {
            return Err(ProblemKind::TooLong);
        }
    };
    let rest = rest.trim_start();
    if !rest.is_empty() && !rest.starts_with('#') {
        return Err(ProblemKind::TrailingText);
    }
    Ok((if quote == '"' { unescape(&body) } else { body }, end))
}

/// Where `quote` closes in `text`; in double quotes, `\"` doesn't close.
fn closing(text: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (index, c) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' && quote == '"' {
            escaped = true;
        } else if c == quote {
            return Some(index);
        }
    }
    None
}

/// The escapes of a double-quoted value. Any other backslash stays, so
/// `\$` keeps a reference from being expanded where the value goes.
fn unescape(body: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(body.len()));
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') | None => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(text: &str) -> Vec<(String, String)> {
        parse(text)
            .vars
            .into_iter()
            .map(|var| (var.name, var.value.to_string()))
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn reads_plain_lines_comments_and_export() {
        let text = "\u{feff}# the app\r\n\
                    PORT=3000\r\n\
                    \r\n\
                    export NODE_ENV = production\n\
                    exported=1\n\
                    \t  # indented comment\n\
                    EMPTY=\n\
                    SPACED=  two words  \n\
                    COMMENTED=value # a comment\n\
                    HASH=abc#def\n\
                    ONLY_COMMENT= # nothing\n\
                    EQUALS=a=b=c\n";
        assert_eq!(
            vars(text),
            pairs(&[
                ("PORT", "3000"),
                ("NODE_ENV", "production"),
                ("exported", "1"),
                ("EMPTY", ""),
                ("SPACED", "two words"),
                ("COMMENTED", "value"),
                ("HASH", "abc#def"),
                ("ONLY_COMMENT", ""),
                ("EQUALS", "a=b=c"),
            ])
        );
        assert_eq!(parse(text).problems, Vec::<ParseProblem>::new());
    }

    #[test]
    fn reads_quotes_and_escapes() {
        let text = r#"SINGLE='it\'s'
DOUBLE="say \"hi\"\n\tand \\ go \$HOME \q"
BACKTICK=`a 'b' "c"`
HASH_IN_QUOTES="a # b" # comment
REF=${HOME}/app
REF_QUOTED="${DB_HOST}:5432"
"#;
        assert_eq!(
            vars(text),
            pairs(&[
                ("DOUBLE", "say \"hi\"\n\tand \\ go \\$HOME \\q"),
                ("BACKTICK", "a 'b' \"c\""),
                ("HASH_IN_QUOTES", "a # b"),
                ("REF", "${HOME}/app"),
                ("REF_QUOTED", "${DB_HOST}:5432"),
            ])
        );
        // Single quotes take no escapes: `'it\'s'` closes after `\`, and
        // `s'` is left over.
        let problems = parse(text).problems;
        assert_eq!(problems.len(), 1);
        assert_eq!(
            (problems[0].line, problems[0].kind),
            (1, ProblemKind::TrailingText)
        );
    }

    #[test]
    fn reads_values_over_several_lines() {
        let text =
            "KEY=\"-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\"\nAFTER=1\nRAW='one\r\ntwo'\n";
        assert_eq!(
            vars(text),
            pairs(&[
                ("KEY", "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"),
                ("AFTER", "1"),
                ("RAW", "one\ntwo"),
            ])
        );
        let parsed = parse(text);
        assert_eq!(
            parsed.vars.iter().map(|v| v.line).collect::<Vec<_>>(),
            [1, 5, 6]
        );
    }

    #[test]
    fn reports_lines_it_cannot_read_without_their_text() {
        let text = "just-a-token\n\
                    1BAD=x\n\
                    bad-name=x\n\
                    GOOD=1\n\
                    OPEN=\"never closed\n\
                    LOST=1\n";
        let parsed = parse(text);
        assert_eq!(
            parsed
                .vars
                .iter()
                .map(|v| v.name.as_str())
                .collect::<Vec<_>>(),
            ["GOOD"]
        );
        let kinds: Vec<(u32, ProblemKind)> =
            parsed.problems.iter().map(|p| (p.line, p.kind)).collect();
        assert_eq!(
            kinds,
            [
                (1, ProblemKind::NoEquals),
                (2, ProblemKind::BadName),
                (3, ProblemKind::BadName),
                (5, ProblemKind::Unterminated),
            ]
        );
        assert!(parsed.problems.iter().all(|p| p.name.is_none()));
    }

    #[test]
    fn a_name_set_again_replaces_the_value() {
        let parsed = parse("A=1\nB=2\nA=3\n");
        assert_eq!(
            parsed
                .vars
                .iter()
                .map(|v| (v.name.as_str(), v.value.as_str()))
                .collect::<Vec<_>>(),
            [("B", "2"), ("A", "3")]
        );
        assert_eq!(
            parsed.problems,
            [ParseProblem {
                line: 1,
                kind: ProblemKind::Replaced,
                name: Some("A".into()),
            }]
        );
    }

    #[test]
    fn refuses_values_a_vault_field_cannot_hold() {
        let long = "x".repeat(MAX_FIELD_LEN + 1);
        let parsed = parse(&format!("LONG={long}\nNUL=\"a\\\0b\"\nOK=1\n"));
        assert_eq!(parsed.vars.len(), 1);
        assert_eq!(
            parsed
                .problems
                .iter()
                .map(|p| (p.kind, p.name.as_deref()))
                .collect::<Vec<_>>(),
            [
                (ProblemKind::TooLong, Some("LONG")),
                (ProblemKind::TooLong, Some("NUL"))
            ]
        );
    }

    #[test]
    fn debug_never_shows_a_value() {
        let parsed = parse("TOKEN=hunter2\n");
        assert!(!format!("{parsed:?}").contains("hunter2"));
    }
}
