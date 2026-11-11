//! Editing a `.env` file in place, the way the `ssh_config` model edits
//! `~/.ssh/config`: a file nobody changed comes out byte for byte as it
//! came in, and a change touches only the lines of the variables it
//! changes. Comments, blank lines, the order of the lines, `export `, the
//! spaces around `=`, the quotes a value is in, a comment after it, line
//! breaks (`\n` or `\r\n`), a missing final line break and a byte order
//! mark all stay as they are.
//!
//! - A changed value is written in its own quotes where they can hold it:
//!   a value in `"…"` stays in double quotes, one in `'…'` or `` `…` ``
//!   in its quotes unless the new value has that quote or a line break it
//!   didn't have; a value without quotes stays without them while it is
//!   only safe characters. A value that spanned several lines keeps doing
//!   so.
//! - A variable the file should no longer have loses its lines, every line
//!   that sets it.
//! - A new variable goes at the end, as `NAME=value`.
//!
//! Lines that set nothing (a word without `=`, a name a shell can't take)
//! are kept as they are. What comes out is read back before it is used:
//! if it doesn't hold exactly the variables asked for, nothing is written.

use std::collections::BTreeMap;
use std::ops::Range;

use zeroize::Zeroizing;

use super::dotenv::{self, ParsedEnv};
use super::format::dotenv_value;
use crate::{Error, Result};

/// The text of a `.env` file, to read and to change in place.
pub struct EnvDocument {
    text: Zeroizing<String>,
}

impl std::fmt::Debug for EnvDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvDocument")
            .field("len", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl EnvDocument {
    /// Takes the text as it is; never fails.
    pub fn new(text: &str) -> Self {
        Self {
            text: Zeroizing::new(text.to_owned()),
        }
    }

    /// The text, as read or as changed.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The variables the loaders read from it ([`dotenv::parse`]).
    pub fn parse(&self) -> ParsedEnv {
        dotenv::parse(&self.text)
    }

    /// Makes the file set exactly `wanted`, each name to its value,
    /// changing only the lines of variables whose value differs, that it
    /// should no longer have, or that it lacks. Returns whether the text
    /// changed. Fails, changing nothing, when the result would not read
    /// back as `wanted`: after a quote that never closes, say.
    pub fn set_variables(&mut self, wanted: &[(&str, &str)]) -> Result<bool> {
        let scan = dotenv::scan(&self.text);
        let (effective, cut) = dotenv::effective(&scan.assignments);
        let eol = line_break(&self.text);
        let wanted_by_name: BTreeMap<&str, &str> = wanted.iter().copied().collect();
        if wanted_by_name.len() != wanted.len() {
            return Err(Error::invalid("a variable is named twice"));
        }
        let managed = &scan.assignments[..cut.unwrap_or(scan.assignments.len())];
        let mut edits: Vec<(Range<usize>, Zeroizing<String>)> = Vec::new();
        for (index, assignment) in managed.iter().enumerate() {
            match wanted_by_name.get(assignment.name.as_str()) {
                None => edits.push((assignment.span.clone(), Zeroizing::new(String::new()))),
                Some(value) if effective.contains(&index) && **value != *assignment.value => {
                    let multiline = self.text[assignment.raw.clone()].contains('\n');
                    edits.push((
                        assignment.raw.clone(),
                        raw_value(value, assignment.quote, multiline, eol),
                    ));
                }
                Some(_) => {}
            }
        }
        let present: Vec<&str> = effective
            .iter()
            .map(|&index| scan.assignments[index].name.as_str())
            .collect();
        let missing: Vec<&(&str, &str)> = wanted
            .iter()
            .filter(|(name, _)| !present.contains(name))
            .collect();
        if edits.is_empty() && missing.is_empty() {
            return Ok(false);
        }
        let mut text = Zeroizing::new(self.text.as_str().to_owned());
        // Where new lines go: the end, or before a quote that never closes
        // and so takes every line after it.
        let mut insert_at = scan.unterminated_at;
        edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
        for (range, replacement) in edits {
            if let Some(at) = insert_at.as_mut()
                && *at >= range.end
            {
                *at = *at + replacement.len() - range.len();
            }
            text.replace_range(range, &replacement);
        }
        if !missing.is_empty() {
            let at = insert_at.unwrap_or(text.len());
            let before = text[..at].trim_start_matches('\u{feff}');
            let mut block = Zeroizing::new(String::new());
            if !before.is_empty() && !before.ends_with('\n') {
                block.push_str(eol);
            }
            for (name, value) in missing {
                block.push_str(name);
                block.push('=');
                dotenv_value(&mut block, value);
                block.push_str(eol);
            }
            text.insert_str(at, &block);
        }
        check_reads_back(&text, &wanted_by_name)?;
        let changed = *text != *self.text;
        self.text = text;
        Ok(changed)
    }
}

/// Fails unless `text` sets exactly `wanted`.
fn check_reads_back(text: &str, wanted: &BTreeMap<&str, &str>) -> Result<()> {
    let parsed = dotenv::parse(text);
    let fine = parsed.vars.len() == wanted.len()
        && parsed.vars.iter().all(|var| {
            wanted
                .get(var.name.as_str())
                .is_some_and(|value| *value == var.value.as_str())
        });
    if fine {
        Ok(())
    } else {
        Err(Error::invalid(
            "the file can't be changed without touching lines that aren't the app's to change",
        ))
    }
}

/// The line break new lines get: that of the first line, else `\n`.
fn line_break(text: &str) -> &'static str {
    match text.find('\n') {
        Some(at) if text[..at].ends_with('\r') => "\r\n",
        _ => "\n",
    }
}

/// `value` as written in place of a value that was in `quote` (none for a
/// bare one) and spanned several lines or not.
fn raw_value(value: &str, quote: Option<char>, multiline: bool, eol: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(value.len() + 2));
    match quote {
        None => dotenv_value(&mut out, value),
        Some('"') => double_quoted(&mut out, value, multiline, eol),
        Some(quote) => {
            let fits = !value.contains(quote)
                && !value.contains('\r')
                && (multiline || !value.contains('\n'));
            if fits {
                out.push(quote);
                for c in value.chars() {
                    if c == '\n' {
                        out.push_str(eol);
                    } else {
                        out.push(c);
                    }
                }
                out.push(quote);
            } else {
                double_quoted(&mut out, value, multiline, eol);
            }
        }
    }
    out
}

/// `"…"`, with `\` and `"` escaped, a carriage return as `\r`, and a line
/// break as is in a value written over several lines, else as `\n`.
fn double_quoted(out: &mut String, value: &str, lines: bool, eol: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\r"),
            '\n' if lines => out.push_str(eol),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str, wanted: &[(&str, &str)]) -> String {
        let mut doc = EnvDocument::new(text);
        doc.set_variables(wanted).unwrap();
        doc.text().to_owned()
    }

    fn vars(text: &str) -> Vec<(String, String)> {
        dotenv::parse(text)
            .vars
            .into_iter()
            .map(|var| (var.name, var.value.to_string()))
            .collect()
    }

    const MESSY: &str = "\u{feff}# The app\r\n\
        \r\n\
        export NODE_ENV = production\r\n\
        PORT=3000 # the API\r\n\
        \t  # indented comment\r\n\
        GREETING='it''s'\r\n\
        KEY=\"-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----\" # pem\r\n\
        RAW=`a 'b' \"c\"`\r\n\
        just-a-token\r\n\
        EMPTY=\r\n\
        HASH=abc#def\r\n\
        A=1\r\n\
        A=2\r\n\
        LAST=x";

    #[test]
    fn an_unchanged_file_comes_out_byte_for_byte() {
        for text in [
            MESSY,
            "",
            "\n",
            "A=1",
            "A=1\n\n\n",
            "# only a comment",
            "OPEN=\"never closed\nB=2\n",
        ] {
            let parsed = vars(text);
            let wanted: Vec<(&str, &str)> = parsed
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let mut doc = EnvDocument::new(text);
            assert!(!doc.set_variables(&wanted).unwrap(), "{text:?}");
            assert_eq!(doc.text(), text);
        }
    }

    #[test]
    fn a_change_touches_only_its_own_lines() {
        let mut wanted: Vec<(String, String)> = vars(MESSY);
        for (name, value) in &mut wanted {
            match name.as_str() {
                "NODE_ENV" => *value = "development".into(),
                "PORT" => *value = "4000".into(),
                "KEY" => *value = "-----BEGIN KEY-----\nxyz\n-----END KEY-----".into(),
                "RAW" => *value = "plain".into(),
                "A" => *value = "3".into(),
                _ => {}
            }
        }
        let wanted: Vec<(&str, &str)> = wanted
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            set(MESSY, &wanted),
            "\u{feff}# The app\r\n\
             \r\n\
             export NODE_ENV = development\r\n\
             PORT=4000 # the API\r\n\
             \t  # indented comment\r\n\
             GREETING='it''s'\r\n\
             KEY=\"-----BEGIN KEY-----\r\nxyz\r\n-----END KEY-----\" # pem\r\n\
             RAW=`plain`\r\n\
             just-a-token\r\n\
             EMPTY=\r\n\
             HASH=abc#def\r\n\
             A=1\r\n\
             A=3\r\n\
             LAST=x"
        );
    }

    #[test]
    fn removed_variables_lose_every_line_and_new_ones_go_last() {
        let text = "# keep me\nA=1\nB=\"two\nlines\"\nA=again\nC=3";
        assert_eq!(
            set(text, &[("C", "3"), ("D", "four words"), ("E", "")]),
            "# keep me\nC=3\nD=\"four words\"\nE=\n"
        );
        // An empty file gets plain lines.
        assert_eq!(set("", &[("A", "1"), ("B", "x y")]), "A=1\nB=\"x y\"\n");
        assert_eq!(set("\u{feff}", &[("A", "1")]), "\u{feff}A=1\n");
        assert_eq!(set("X=1\r\n", &[("X", "1"), ("Y", "2")]), "X=1\r\nY=2\r\n");
        assert_eq!(set("A=1\nB=2\n", &[]), "");
    }

    #[test]
    fn values_keep_their_quotes_where_they_can() {
        let cases = [
            ("V=\"old\"\n", "new value", "V=\"new value\"\n"),
            ("V=\"old\"\n", "say \"hi\"\\", "V=\"say \\\"hi\\\"\\\\\"\n"),
            ("V=\"old\"\n", "a\nb", "V=\"a\\nb\"\n"),
            ("V='old'\n", "a b", "V='a b'\n"),
            ("V='old'\n", "it's", "V=\"it's\"\n"),
            ("V='old'\n", "a\nb", "V=\"a\\nb\"\n"),
            ("V='one\ntwo'\n", "a\nb\nc", "V='a\nb\nc'\n"),
            ("V=`old`\n", "a`b", "V=\"a`b\"\n"),
            ("V=old # note\n", "new", "V=new # note\n"),
            ("V=old # note\n", "a b", "V=\"a b\" # note\n"),
            ("V= # note\n", "x", "V=x # note\n"),
            ("V=old\n", "", "V=\n"),
            ("V=\"old\"\n", "", "V=\"\"\n"),
            ("V=old\n", "a\r\nb", "V=\"a\\r\\nb\"\n"),
            ("V='a\r\nb'\r\n", "c\nd", "V='c\r\nd'\r\n"),
        ];
        for (text, value, expected) in cases {
            let out = set(text, &[("V", value)]);
            assert_eq!(out, expected, "{text:?} ← {value:?}");
            assert_eq!(vars(&out), [("V".to_owned(), value.to_owned())]);
        }
    }

    #[test]
    fn new_lines_never_go_inside_a_quote_that_never_closes() {
        let text = "A=1\nOPEN=\"never closed\nB=2\n";
        let out = set(text, &[("A", "1"), ("C", "3")]);
        assert_eq!(out, "A=1\nC=3\nOPEN=\"never closed\nB=2\n");
        let out = set(text, &[("C", "3")]);
        assert_eq!(out, "C=3\nOPEN=\"never closed\nB=2\n");
    }

    #[test]
    fn nothing_is_written_that_would_read_back_differently() {
        let mut doc = EnvDocument::new("A=1\n");
        assert!(doc.set_variables(&[("A", "1"), ("A", "2")]).is_err());
        assert_eq!(doc.text(), "A=1\n");
    }

    #[test]
    fn debug_never_shows_the_text() {
        let doc = EnvDocument::new("TOKEN=hunter2\n");
        assert!(!format!("{doc:?}").contains("hunter2"));
    }
}
