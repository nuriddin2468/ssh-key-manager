//! Line-level lexing of `ssh_config`, following OpenSSH's `readconf.c` and
//! `argv_split()` (quotes, backslash escapes, `#` comments at token starts).

/// Whitespace as OpenSSH sees it inside a line.
pub(crate) fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\x0c')
}

fn is_ws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\x0c')
}

/// How the value of a keyword is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueStyle {
    /// The rest of the line is taken literally (`ProxyCommand`, …): no
    /// unquoting, no inline comments.
    RestOfLine,
    /// A single argument (path, host name, user): shown unquoted, quoted on
    /// write when needed.
    Single,
    /// Everything else: the value text is shown and written as is.
    Raw,
}

pub(crate) fn value_style(key_lower: &str) -> ValueStyle {
    match key_lower {
        "proxycommand" | "localcommand" | "remotecommand" | "knownhostscommand" => {
            ValueStyle::RestOfLine
        }
        "identityfile"
        | "certificatefile"
        | "identityagent"
        | "controlpath"
        | "hostname"
        | "user"
        | "hostkeyalias"
        | "pkcs11provider"
        | "securitykeyprovider"
        | "xauthlocation"
        | "revokedhostkeys"
        | "proxyjump"
        | "port" => ValueStyle::Single,
        _ => ValueStyle::Raw,
    }
}

/// A `Keyword[ =]value` line split into its parts. Concatenating
/// `indent + key + sep + value + tail` gives the original line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Directive<'a> {
    pub(crate) indent: &'a str,
    pub(crate) key: &'a str,
    pub(crate) sep: &'a str,
    /// The value without trailing whitespace and without an inline comment.
    pub(crate) value: &'a str,
    /// Trailing whitespace and inline comment.
    pub(crate) tail: &'a str,
}

impl Directive<'_> {
    pub(crate) fn key_lower(&self) -> String {
        self.key.to_ascii_lowercase()
    }

    /// The value as the read view shows it (see [`ValueStyle`]).
    pub(crate) fn logical_value(&self) -> String {
        match value_style(&self.key_lower()) {
            ValueStyle::Single => split_args(self.value).0.join(" "),
            ValueStyle::RestOfLine | ValueStyle::Raw => self.value.to_owned(),
        }
    }

    /// The line with its value replaced, keeping indentation, keyword
    /// spelling, separator style and any inline comment.
    pub(crate) fn with_value(&self, value: &str) -> String {
        let sep = if self.sep.is_empty() { " " } else { self.sep };
        // A tail of only whitespace is dropped; an inline comment is kept.
        let tail = if self.tail.trim_matches(is_ws).is_empty() {
            ""
        } else {
            self.tail
        };
        format!("{}{}{sep}{value}{tail}", self.indent, self.key)
    }
}

/// Classification of one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineKind<'a> {
    Blank,
    Comment,
    Directive(Directive<'a>),
}

/// Lexes one line (without its terminator). Total.
pub(crate) fn lex(text: &str) -> LineKind<'_> {
    let after_bom = text.strip_prefix('\u{feff}').unwrap_or(text);
    let body = after_bom.trim_start_matches(is_ws);
    if body.trim_end_matches(is_ws).is_empty() {
        return LineKind::Blank;
    }
    if body.starts_with('#') {
        return LineKind::Comment;
    }
    let key_start = text.len() - body.len();
    let key_len = body
        .find(|c: char| is_ws(c) || c == '=')
        .unwrap_or(body.len());
    let after_key = &body[key_len..];
    let r = after_key.trim_start_matches(is_ws);
    let r = r.strip_prefix('=').unwrap_or(r);
    let r = r.trim_start_matches(is_ws);
    let value_start = key_start + key_len + (after_key.len() - r.len());
    let key = &body[..key_len];
    let value_region = &text[value_start..];
    let value_len = if value_style(&key.to_ascii_lowercase()) == ValueStyle::RestOfLine {
        value_region.trim_end_matches(is_ws).len()
    } else {
        value_len_without_comment(value_region)
    };
    LineKind::Directive(Directive {
        indent: &text[..key_start],
        key,
        sep: &text[key_start + key_len..value_start],
        value: &value_region[..value_len],
        tail: &value_region[value_len..],
    })
}

/// Length of `s` up to the end of the last argument before an inline comment
/// (an unquoted `#` at the start of an argument) or trailing whitespace.
fn value_len_without_comment(input: &str) -> usize {
    let bytes = input.as_bytes();
    let (mut pos, mut end) = (0, 0);
    loop {
        while pos < bytes.len() && is_ws_byte(bytes[pos]) {
            pos += 1;
        }
        if pos >= bytes.len() || bytes[pos] == b'#' {
            return end;
        }
        let mut quote = 0u8;
        while pos < bytes.len() {
            let current = bytes[pos];
            if current == b'\\' && pos + 1 < bytes.len() {
                let next = bytes[pos + 1];
                pos += if matches!(next, b'\'' | b'"' | b'\\') || (quote == 0 && next == b' ') {
                    2
                } else {
                    1
                };
                continue;
            }
            if quote == 0 && is_ws_byte(current) {
                break;
            }
            if quote == 0 && (current == b'"' || current == b'\'') {
                quote = current;
            } else if quote != 0 && current == quote {
                quote = 0;
            }
            pos += 1;
        }
        end = pos.min(bytes.len());
    }
}

/// Splits a value into arguments like OpenSSH's `argv_split()`. The flag is
/// true if a quote was left open.
pub(crate) fn split_args(s: &str) -> (Vec<String>, bool) {
    let mut args = Vec::new();
    let mut unterminated = false;
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().copied().is_some_and(is_ws) {
            chars.next();
        }
        match chars.peek() {
            None | Some('#') => break,
            Some(_) => {}
        }
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while let Some(&c) = chars.peek() {
            if c == '\\' {
                chars.next();
                match chars.peek().copied() {
                    Some(n) if matches!(n, '\'' | '"' | '\\') || (quote.is_none() && n == ' ') => {
                        arg.push(n);
                        chars.next();
                    }
                    _ => arg.push('\\'),
                }
                continue;
            }
            if quote.is_none() && is_ws(c) {
                break;
            }
            chars.next();
            match quote {
                None if c == '"' || c == '\'' => quote = Some(c),
                Some(q) if c == q => quote = None,
                _ => arg.push(c),
            }
        }
        unterminated |= quote.is_some();
        args.push(arg);
    }
    (args, unterminated)
}

/// Quotes one argument so that [`split_args`] returns it unchanged.
pub(crate) fn quote_arg(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    let has_escape = chars
        .windows(2)
        .any(|w| w[0] == '\\' && matches!(w[1], '\\' | '"' | '\'' | ' '));
    let special = v.is_empty()
        || v.starts_with('#')
        || has_escape
        || chars.iter().any(|&c| is_ws(c) || c == '"' || c == '\'');
    if !special {
        return v.to_owned();
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' if matches!(chars.get(i + 1), None | Some('\\' | '"' | '\'')) => {
                out.push_str("\\\\");
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Renders a value for writing according to the keyword's [`ValueStyle`].
///
/// A single-argument value that already arrives as one quoted argument (the
/// user typed `"~/my key"`) is written as is instead of being quoted again.
pub(crate) fn render_value(key_lower: &str, value: &str) -> String {
    match value_style(key_lower) {
        ValueStyle::Single if is_one_quoted_arg(value) => value.to_owned(),
        ValueStyle::Single => quote_arg(value),
        ValueStyle::RestOfLine | ValueStyle::Raw => value.to_owned(),
    }
}

fn is_one_quoted_arg(value: &str) -> bool {
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    quoted && matches!(split_args(value), (args, false) if args.len() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(line: &str) -> Directive<'_> {
        match lex(line) {
            LineKind::Directive(d) => d,
            other => panic!("{line:?} lexed as {other:?}"),
        }
    }

    fn rebuild(d: &Directive<'_>) -> String {
        format!("{}{}{}{}{}", d.indent, d.key, d.sep, d.value, d.tail)
    }

    #[test]
    fn lexes_separator_styles() {
        for (line, key, sep, value) in [
            ("HostName example.com", "HostName", " ", "example.com"),
            ("  Port=22", "Port", "=", "22"),
            ("\tUser = bob  ", "User", " = ", "bob"),
            (
                "IdentityFile \"~/my key\"",
                "IdentityFile",
                " ",
                "\"~/my key\"",
            ),
            ("Host", "Host", "", ""),
            ("Host foo # trailing", "Host", " ", "foo"),
            (
                "ProxyCommand ssh -W %h:%p jump # not a comment",
                "ProxyCommand",
                " ",
                "ssh -W %h:%p jump # not a comment",
            ),
            ("SendEnv \"A # B\" C", "SendEnv", " ", "\"A # B\" C"),
            ("\u{feff}Host x", "Host", " ", "x"),
        ] {
            let d = directive(line);
            assert_eq!((d.key, d.sep, d.value), (key, sep, value), "{line:?}");
            assert_eq!(rebuild(&d), line);
        }
        assert_eq!(lex("   "), LineKind::Blank);
        assert_eq!(lex(""), LineKind::Blank);
        assert_eq!(lex("  # c"), LineKind::Comment);
        assert_eq!(lex("#"), LineKind::Comment);
    }

    #[test]
    fn argv_split_semantics() {
        assert_eq!(split_args("a b\tc").0, ["a", "b", "c"]);
        assert_eq!(split_args("\"a b\" 'c d'").0, ["a b", "c d"]);
        assert_eq!(split_args("x\"y z\"w").0, ["xy zw"]);
        assert_eq!(split_args(r"a\ b").0, ["a b"]);
        assert_eq!(split_args(r#""a\"b""#).0, [r#"a"b"#]);
        assert_eq!(
            split_args(r"C:\Users\me\.ssh\id").0,
            [r"C:\Users\me\.ssh\id"]
        );
        assert_eq!(split_args(r"\\server\share").0, [r"\server\share"]);
        assert_eq!(split_args("a #comment").0, ["a"]);
        assert_eq!(split_args("\"\"").0, [""]);
        let (args, open) = split_args("\"unterminated");
        assert_eq!(args, ["unterminated"]);
        assert!(open);
    }

    #[test]
    fn quote_round_trips() {
        for v in [
            "plain",
            "~/.ssh/my key",
            r"C:\Users\John Smith\.ssh\id_ed25519",
            r"C:\dir\",
            r"\\server\share\key",
            "it's",
            "say \"hi\"",
            "#hash",
            "",
            "tab\there",
            "ünïcödé path",
            r"back\slash\",
            r"\",
        ] {
            let quoted = quote_arg(v);
            assert_eq!(split_args(&quoted).0, [v], "{v:?} -> {quoted:?}");
        }
        assert_eq!(quote_arg("~/.ssh/id"), "~/.ssh/id");
        assert_eq!(quote_arg("~/my key"), "\"~/my key\"");
        assert_eq!(render_value("identityfile", "~/my key"), "\"~/my key\"");
        assert_eq!(render_value("identityfile", "\"~/my key\""), "\"~/my key\"");
        assert_eq!(render_value("identityfile", "'~/my key'"), "'~/my key'");
        assert_eq!(
            render_value("identityfile", "\"a\" \"b\""),
            r#""\"a\" \"b\"""#
        );
        assert_eq!(
            render_value("localforward", "8080 localhost:80"),
            "8080 localhost:80"
        );
        assert_eq!(
            render_value("proxycommand", "ssh -W \"%h:%p\" j"),
            "ssh -W \"%h:%p\" j"
        );
    }

    #[test]
    fn replaces_value_keeping_layout() {
        let d = directive("\tHostName = old.example.com   # prod");
        assert_eq!(
            d.with_value("new.example.com"),
            "\tHostName = new.example.com   # prod"
        );
        let d = directive("  User=alice   ");
        assert_eq!(d.with_value("bob"), "  User=bob");
        let d = directive("Host");
        assert_eq!(d.with_value("x"), "Host x");
    }

    #[test]
    fn lexing_never_panics_on_odd_input() {
        for line in [
            "=",
            "==",
            "a=",
            "a =",
            "\\",
            "\"",
            "x \\",
            "x '",
            "Ключ значение",
            "\u{feff}",
            "\u{feff}#",
            "a\u{a0}b",
            "IdentityFile \"a\\",
            "k \"\\\"",
        ] {
            let kind = lex(line);
            if let LineKind::Directive(d) = kind {
                assert_eq!(rebuild(&d), line);
                let _ = d.logical_value();
            }
            let _ = split_args(line);
            let _ = value_len_without_comment(line);
        }
    }
}
