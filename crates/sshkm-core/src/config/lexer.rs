//! Line-level lexing of `ssh_config`, following OpenSSH's `readconf.c`
//! (`process_config_line()`), `strdelim()` and `argv_split()`: quotes,
//! backslash escapes, `#` comments at token starts.
//!
//! Only spaces and tabs separate arguments and come before an inline
//! comment. A carriage return or form feed inside a line is an ordinary
//! character to `ssh` (`HostName a\r#b` is the name `a\r#b`); only at the
//! end of the line is it whitespace, which `ssh` strips before reading it.

/// Separates arguments, as in `argv_split()`.
fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

fn is_ws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

/// Whitespace around the keyword (`WHITESPACE` of `strdelim()`).
fn is_key_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// What `process_config_line()` strips from the end of a line before it
/// reads the line.
pub(crate) fn is_trailing_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0c')
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
    /// The keyword as written, quotes included (see [`keyword`]).
    pub(crate) key: &'a str,
    pub(crate) sep: &'a str,
    /// The value without trailing whitespace and without an inline comment.
    pub(crate) value: &'a str,
    /// Trailing whitespace and inline comment.
    pub(crate) tail: &'a str,
    /// How the value is read: by the keyword as `ssh` reads it, so
    /// `"ProxyCommand"` takes the rest of the line like `ProxyCommand`.
    pub(crate) style: ValueStyle,
}

impl Directive<'_> {
    pub(crate) fn key_lower(&self) -> String {
        self.key.to_ascii_lowercase()
    }

    /// The keyword as `ssh` reads it (see [`keyword`]).
    pub(crate) fn keyword(&self) -> Option<String> {
        keyword(self.key)
    }

    /// The value as the read view shows it (see [`ValueStyle`]).
    pub(crate) fn logical_value(&self) -> String {
        match self.style {
            ValueStyle::Single => split_args(self.value).0.join(" "),
            ValueStyle::RestOfLine | ValueStyle::Raw => self.value.to_owned(),
        }
    }

    /// The line with its value replaced, keeping indentation, keyword
    /// spelling, separator style and any inline comment.
    pub(crate) fn with_value(&self, value: &str) -> String {
        let sep = if self.sep.is_empty() { " " } else { self.sep };
        // A tail of only whitespace is dropped; an inline comment is kept.
        let tail = if self.tail.trim_matches(is_trailing_ws).is_empty() {
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
    let bom = text.len() - text.strip_prefix('\u{feff}').unwrap_or(text).len();
    // `ssh` strips trailing whitespace before anything else, so neither the
    // keyword nor the value reaches into it.
    let line = text[bom..].trim_end_matches(is_trailing_ws);
    let line_end = bom + line.len();
    let body = line.trim_start_matches(is_key_ws);
    if body.is_empty() {
        return LineKind::Blank;
    }
    if body.starts_with('#') {
        return LineKind::Comment;
    }
    let key_start = line_end - body.len();
    let key = &body[..keyword_len(body)];
    let style = keyword(key).map_or(ValueStyle::Raw, |k| value_style(&k));
    // `strdelim()` skips whitespace after the keyword, and a single `=` with
    // whitespace around it unless the keyword ended in a quote. A command
    // then skips any more whitespace and `=`.
    let r = body[key.len()..].trim_start_matches(is_key_ws);
    let r = match r.strip_prefix('=') {
        Some(after) if !key.contains('"') => after.trim_start_matches(is_key_ws),
        _ => r,
    };
    let r = if style == ValueStyle::RestOfLine {
        r.trim_start_matches(|c| is_key_ws(c) || c == '=')
    } else {
        r
    };
    let value_start = line_end - r.len();
    let value_len = if style == ValueStyle::RestOfLine {
        r.len()
    } else {
        value_len_without_comment(r)
    };
    LineKind::Directive(Directive {
        indent: &text[..key_start],
        key,
        sep: &text[key_start + key.len()..value_start],
        value: &r[..value_len],
        tail: &text[value_start + value_len..],
        style,
    })
}

/// Length of the keyword at the start of `body`, as `strdelim()` cuts it:
/// up to whitespace or `=`, or up to the closing quote of a quoted part
/// (`"ProxyCommand"`, `Proxy"Command"`). An unclosed quote runs to the end
/// of the line, which `ssh` then ignores.
fn keyword_len(body: &str) -> usize {
    for (i, b) in body.bytes().enumerate() {
        match b {
            b' ' | b'\t' | b'\r' | b'\n' | b'=' => return i,
            b'"' => {
                return body[i + 1..]
                    .find('"')
                    .map_or(body.len(), |close| i + 1 + close + 1);
            }
            _ => {}
        }
    }
    body.len()
}

/// The keyword as `ssh` reads it, in lower case: `key` (as [`lex`] cut it)
/// without the quotes `strdelim()` takes out. `None` unless that leaves
/// letters and digits, as every keyword is: `ssh` either rejects such a line
/// or reads it in a way this lexer does not follow (`=ProxyCommand …`).
pub(crate) fn keyword(key: &str) -> Option<String> {
    let unquoted = match key.split_once('"') {
        Some((before, quoted)) => format!("{before}{}", quoted.strip_suffix('"')?),
        None => key.to_owned(),
    };
    (!unquoted.is_empty() && unquoted.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| unquoted.to_ascii_lowercase())
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
    // A control character is quoted too: at the end of a line `ssh` would
    // strip a form feed or carriage return.
    let special = v.is_empty()
        || v.starts_with('#')
        || has_escape
        || chars
            .iter()
            .any(|&c| is_ws(c) || c.is_control() || c == '"' || c == '\'');
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
    fn carriage_returns_and_form_feeds_are_ordinary_inside_a_line() {
        // What `ssh -G` (OpenSSH 9.9) reads for each line.
        for (line, key, value, tail) in [
            ("HostName foo\r#$(id)", "HostName", "foo\r#$(id)", ""),
            ("HostName foo\x0c#bar", "HostName", "foo\x0c#bar", ""),
            (
                "Match host *,x\r#y exec \"z\"",
                "Match",
                "host *,x\r#y exec \"z\"",
                "",
            ),
            ("User a #b", "User", "a", " #b"),
            ("User a\t#b", "User", "a", "\t#b"),
            // Stripped at the end of the line, before anything is read.
            (
                "ProxyCommand x\x0c \x0c\r",
                "ProxyCommand",
                "x",
                "\x0c \x0c\r",
            ),
            ("Host foo #c\x0c", "Host", "foo", " #c\x0c"),
            ("User\x0c", "User", "", "\x0c"),
            // Whitespace before and after the keyword.
            ("\rProxyCommand x", "ProxyCommand", "x", ""),
            ("ProxyCommand\rx", "ProxyCommand", "x", ""),
            ("User\r=\rbob", "User", "bob", ""),
            ("User=\x0cbob", "User", "\x0cbob", ""),
        ] {
            let d = directive(line);
            assert_eq!((d.key, d.value, d.tail), (key, value, tail), "{line:?}");
            assert_eq!(rebuild(&d), line);
        }
        assert_eq!(split_args("a\rb\x0cc d").0, ["a\rb\x0cc", "d"]);
        assert_eq!(split_args("foo\r#$(id)").0, ["foo\r#$(id)"]);
        assert_eq!(lex(" \t\r\x0c"), LineKind::Blank);
        assert_eq!(lex("\r# c"), LineKind::Comment);
    }

    #[test]
    fn keywords_are_cut_and_unquoted_like_strdelim() {
        // Keyword, value and how the value is read; `ssh -G` reads the same.
        for (line, key, value, style) in [
            (
                "\"ProxyCommand\" none\r#$(id)",
                Some("proxycommand"),
                "none\r#$(id)",
                ValueStyle::RestOfLine,
            ),
            (
                "Proxy\"Command\"x foo",
                Some("proxycommand"),
                "x foo",
                ValueStyle::RestOfLine,
            ),
            (
                "\"ProxyCommand\"=none",
                Some("proxycommand"),
                "none",
                ValueStyle::RestOfLine,
            ),
            (
                "ProxyCommand = =none",
                Some("proxycommand"),
                "none",
                ValueStyle::RestOfLine,
            ),
            (
                "\"ProxyCommand\"\x0cnone",
                Some("proxycommand"),
                "\x0cnone",
                ValueStyle::RestOfLine,
            ),
            // After a quoted keyword `=` is part of the value.
            ("\"User\"=bob", Some("user"), "=bob", ValueStyle::Single),
            (
                "\"HostName\" a #b",
                Some("hostname"),
                "a",
                ValueStyle::Single,
            ),
            // `ssh` reads `proxy` or nothing here; this lexer reads no keyword.
            (
                "Pro\"xy\"Command none",
                Some("proxy"),
                "Command none",
                ValueStyle::Raw,
            ),
            ("\"Proxy Command\" x", None, "x", ValueStyle::Raw),
            ("\"ProxyCommand x", None, "", ValueStyle::Raw),
            (
                "\"\"ProxyCommand x",
                None,
                "ProxyCommand x",
                ValueStyle::Raw,
            ),
            ("=ProxyCommand x", None, "ProxyCommand x", ValueStyle::Raw),
            ("\x0cProxyCommand x", None, "x", ValueStyle::Raw),
        ] {
            let d = directive(line);
            assert_eq!(
                (d.keyword().as_deref(), d.value, d.style),
                (key, value, style),
                "{line:?}"
            );
            assert_eq!(rebuild(&d), line);
        }
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
            "\"\"",
            "\"a\"\"b\" c",
            "a\"=b",
            "=\"",
            "\r",
            "\x0c\"\r",
            "\u{feff}\r\"\u{feff}",
            "k\x0c\x0c=\r\"é",
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
