//! Line-preserving text model shared by the `ssh_config` and `known_hosts`
//! parsers. Splitting and re-joining is byte-for-byte lossless.

use std::fmt;

/// Line terminator of one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Eol {
    /// `\n`
    Lf,
    /// `\r\n`
    CrLf,
    /// Last line of a file without a final newline.
    None,
}

impl Eol {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::CrLf => "\r\n",
            Self::None => "",
        }
    }
}

/// One line of a text file without its terminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    pub(crate) text: String,
    pub(crate) eol: Eol,
}

impl Line {
    pub(crate) fn new(text: impl Into<String>, eol: Eol) -> Self {
        Self {
            text: text.into(),
            eol,
        }
    }

    /// True if the line has only whitespace.
    pub(crate) fn is_blank(&self) -> bool {
        self.text
            .trim_start_matches('\u{feff}')
            .chars()
            .all(char::is_whitespace)
    }
}

/// Splits `input` into lines. `"a\nb"` gives two lines, the second without a
/// terminator; `"a\n"` gives one line; `""` gives none.
pub(crate) fn split_lines(input: &str) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        if let Some(pos) = rest.find('\n') {
            let (head, tail) = rest.split_at(pos);
            rest = &tail[1..];
            match head.strip_suffix('\r') {
                Some(text) => lines.push(Line::new(text, Eol::CrLf)),
                None => lines.push(Line::new(head, Eol::Lf)),
            }
        } else {
            lines.push(Line::new(rest, Eol::None));
            rest = "";
        }
    }
    lines
}

/// The terminator new lines should use: the one of the first terminated line,
/// or `\n` for files without any.
pub(crate) fn dominant_eol(lines: &[Line]) -> Eol {
    lines
        .iter()
        .map(|l| l.eol)
        .find(|e| *e != Eol::None)
        .unwrap_or(Eol::Lf)
}

/// Writes all lines with their original terminators.
pub(crate) fn write_lines(lines: &[Line], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for line in lines {
        f.write_str(&line.text)?;
        f.write_str(line.eol.as_str())?;
    }
    Ok(())
}

/// Removes lines `start..end` while keeping the "file ends with a newline"
/// property of the whole file intact.
pub(crate) fn remove_range(lines: &mut Vec<Line>, start: usize, end: usize) {
    let had_final_eol = lines.last().is_some_and(|l| l.eol != Eol::None);
    let removed_tail = end >= lines.len();
    lines.drain(start..end.min(lines.len()));
    if removed_tail {
        fix_final_eol(lines, had_final_eol);
    }
}

/// Removes the lines at the given indices (out-of-range ones are ignored),
/// keeping the final-newline property. Returns how many were removed.
pub(crate) fn remove_indices(
    lines: &mut Vec<Line>,
    doomed: &std::collections::HashSet<usize>,
) -> usize {
    let had_final_eol = lines.last().is_some_and(|l| l.eol != Eol::None);
    let before = lines.len();
    let mut index = 0;
    lines.retain(|_| {
        let keep = !doomed.contains(&index);
        index += 1;
        keep
    });
    fix_final_eol(lines, had_final_eol);
    before - lines.len()
}

/// Makes the last line end with (or without) a terminator.
pub(crate) fn fix_final_eol(lines: &mut [Line], want_final_eol: bool) {
    let default = dominant_eol(lines);
    if let Some(last) = lines.last_mut() {
        if want_final_eol && last.eol == Eol::None {
            last.eol = default;
        } else if !want_final_eol {
            last.eol = Eol::None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Joined<'a>(&'a [Line]);
    impl fmt::Display for Joined<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_lines(self.0, f)
        }
    }

    #[test]
    fn split_and_join_round_trip() {
        for input in [
            "",
            "\n",
            "a",
            "a\n",
            "a\r\nb\nc",
            "\r\n\r\n",
            "x\ry\n",
            "trailing   \n\tindent\n",
            "ünïcödé\n",
        ] {
            let lines = split_lines(input);
            assert_eq!(Joined(&lines).to_string(), input, "{input:?}");
        }
    }

    #[test]
    fn eol_detection() {
        assert_eq!(dominant_eol(&split_lines("a\r\nb\n")), Eol::CrLf);
        assert_eq!(dominant_eol(&split_lines("a")), Eol::Lf);
    }

    #[test]
    fn remove_tail_keeps_missing_final_newline() {
        let mut lines = split_lines("a\nb\nc");
        remove_range(&mut lines, 2, 3);
        assert_eq!(Joined(&lines).to_string(), "a\nb");
        let mut lines = split_lines("a\nb\nc\n");
        remove_range(&mut lines, 1, 3);
        assert_eq!(Joined(&lines).to_string(), "a\n");
    }
}
