//! Splitting a command line into simple commands and their words, the way
//! the shell that ran it would, closely enough to find `ssh` and its
//! arguments: quotes, escapes, `;`, `&&`, `||`, `|`, comments and
//! redirections. Expansions (`$var`, `$(…)`, backquotes, globs) are not
//! made; a word with one is marked as not [`Word::literal`], so it is never
//! taken for a host or a file.

use std::iter::Peekable;
use std::str::Chars;

/// How a shell quotes and escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    /// zsh and bash: `\` escapes, `$'…'`, `$(…)` and backquotes.
    Posix,
    /// fish: `\` escapes, `(…)` is a command substitution.
    Fish,
    /// PowerShell: the backquote escapes, `\` is an ordinary character
    /// (Windows paths), `''` inside single quotes is a quote.
    PowerShell,
}

/// One word of a command, quotes and escapes removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Word {
    pub text: String,
    /// The program got exactly `text`: nothing in it was expanded.
    pub literal: bool,
}

/// The simple commands of `line`, each as its words. Commands end at `;`,
/// `&`, `&&`, `||`, `|`, a new line and parentheses; redirections and their
/// targets are left out.
pub(super) fn commands(line: &str, dialect: Dialect) -> Vec<Vec<Word>> {
    let mut lexer = Lexer {
        chars: line.chars().peekable(),
        dialect,
        commands: Vec::new(),
        words: Vec::new(),
        word: None,
        redirect: false,
    };
    lexer.run();
    lexer.commands
}

struct Lexer<'a> {
    chars: Peekable<Chars<'a>>,
    dialect: Dialect,
    commands: Vec<Vec<Word>>,
    words: Vec<Word>,
    /// The word being read, once something of it has been seen (`''` is an
    /// empty word, not none).
    word: Option<Word>,
    /// The next word is the target of a redirection.
    redirect: bool,
}

impl Lexer<'_> {
    fn run(&mut self) {
        while let Some(c) = self.chars.next() {
            match c {
                ' ' | '\t' | '\r' => self.end_word(),
                '(' if self.dialect == Dialect::Fish => self.substitution('(', ')'),
                '\n' | ';' | '(' | ')' => self.end_command(),
                '&' | '|' => {
                    // `&&`, `||`, `|&`, `&|` (fish) and the single ones.
                    if matches!(self.chars.peek(), Some('&' | '|')) {
                        self.chars.next();
                    } else if c == '&' && self.chars.peek() == Some(&'>') {
                        // bash's `&>file`.
                        self.end_word();
                        self.chars.next();
                        self.redirection();
                        continue;
                    }
                    self.end_command();
                }
                // PowerShell's script blocks, and groups elsewhere
                // (`{ ssh host; }`), which open and close with lone braces.
                '{' | '}'
                    if self.dialect == Dialect::PowerShell
                        || (self.word.is_none() && self.next_is_separator()) =>
                {
                    self.end_command();
                }
                // Brace expansion (`web{1,2}`) and globs.
                '{' | '*' | '?' => {
                    self.push(c);
                    self.expanded();
                }
                '<' | '>' => {
                    // A number right before is the descriptor (`2>`).
                    let descriptor = self.word.as_ref().is_some_and(|w| {
                        !w.text.is_empty() && w.text.bytes().all(|b| b.is_ascii_digit())
                    });
                    if descriptor {
                        self.word = None;
                    } else {
                        self.end_word();
                    }
                    self.redirection();
                }
                '#' if self.word.is_none() => self.comment(),
                '\'' => self.single_quoted(),
                '"' => self.double_quoted(),
                '\\' if self.dialect != Dialect::PowerShell => match self.chars.next() {
                    // A line continuation.
                    Some('\n') => {}
                    Some(next) => self.push(next),
                    None => self.push('\\'),
                },
                '`' if self.dialect == Dialect::PowerShell => match self.chars.next() {
                    Some('\n') => {}
                    Some(next) => self.push(powershell_escape(next)),
                    None => self.push('`'),
                },
                '`' => self.substitution('`', '`'),
                '$' => self.dollar(),
                _ => self.push(c),
            }
        }
        self.end_command();
    }

    fn next_is_separator(&mut self) -> bool {
        matches!(self.chars.peek(), None | Some(' ' | '\t' | '\n' | ';'))
    }

    fn word(&mut self) -> &mut Word {
        self.word.get_or_insert_with(|| Word {
            text: String::new(),
            literal: true,
        })
    }

    fn push(&mut self, c: char) {
        self.word().text.push(c);
    }

    fn expanded(&mut self) {
        self.word().literal = false;
    }

    fn end_word(&mut self) {
        if let Some(word) = self.word.take() {
            if self.redirect {
                self.redirect = false;
            } else {
                self.words.push(word);
            }
        }
    }

    fn end_command(&mut self) {
        self.end_word();
        self.redirect = false;
        if !self.words.is_empty() {
            self.commands.push(std::mem::take(&mut self.words));
        }
    }

    /// After `<` or `>`: the rest of the operator, then its target unless it
    /// names a descriptor (`2>&1`, `>&-`).
    fn redirection(&mut self) {
        while matches!(self.chars.peek(), Some('<' | '>' | '|')) {
            self.chars.next();
        }
        if self.chars.peek() == Some(&'&') {
            self.chars.next();
            while matches!(self.chars.peek(), Some(c) if c.is_ascii_digit() || *c == '-') {
                self.chars.next();
            }
            return;
        }
        self.redirect = true;
    }

    fn comment(&mut self) {
        while let Some(&c) = self.chars.peek() {
            if c == '\n' {
                break;
            }
            self.chars.next();
        }
    }

    fn single_quoted(&mut self) {
        self.word();
        while let Some(c) = self.chars.next() {
            match c {
                '\'' if self.dialect == Dialect::PowerShell && self.chars.peek() == Some(&'\'') => {
                    self.chars.next();
                    self.push('\'');
                }
                '\'' => return,
                '\\' if self.dialect == Dialect::Fish
                    && matches!(self.chars.peek(), Some('\'' | '\\')) =>
                {
                    let next = self.chars.next().unwrap_or('\\');
                    self.push(next);
                }
                _ => self.push(c),
            }
        }
    }

    fn double_quoted(&mut self) {
        self.word();
        while let Some(c) = self.chars.next() {
            match c {
                '"' if self.dialect == Dialect::PowerShell && self.chars.peek() == Some(&'"') => {
                    self.chars.next();
                    self.push('"');
                }
                '"' => return,
                '\\' if self.dialect != Dialect::PowerShell => match self.chars.peek() {
                    Some('\n') => {
                        self.chars.next();
                    }
                    Some(&next @ ('"' | '\\' | '$' | '`')) => {
                        self.chars.next();
                        self.push(next);
                    }
                    _ => self.push('\\'),
                },
                '`' if self.dialect == Dialect::PowerShell => {
                    if let Some(next) = self.chars.next() {
                        self.push(powershell_escape(next));
                    }
                }
                '`' => {
                    self.push(c);
                    self.expanded();
                }
                '$' => {
                    self.push(c);
                    if self.chars.peek().is_some_and(|n| starts_expansion(*n)) {
                        self.expanded();
                    }
                }
                _ => self.push(c),
            }
        }
    }

    fn dollar(&mut self) {
        match self.chars.peek() {
            Some('\'') if self.dialect == Dialect::Posix => {
                self.chars.next();
                self.ansi_c_quoted();
            }
            Some('(') => {
                self.chars.next();
                self.push('$');
                self.substitution('(', ')');
            }
            Some(&n) if starts_expansion(n) => {
                self.push('$');
                self.expanded();
            }
            _ => self.push('$'),
        }
    }

    /// `$'…'`: backslash escapes, of which only the common ones are decoded.
    fn ansi_c_quoted(&mut self) {
        self.word();
        while let Some(c) = self.chars.next() {
            match c {
                '\'' => return,
                '\\' => match self.chars.next() {
                    Some('n') => self.push('\n'),
                    Some('t') => self.push('\t'),
                    Some(next) => self.push(next),
                    None => {}
                },
                _ => self.push(c),
            }
        }
    }

    /// A command substitution up to its matching `close`, kept in the word,
    /// which is then not literal.
    fn substitution(&mut self, open: char, close: char) {
        self.push(open);
        self.expanded();
        let mut depth = 1;
        while let Some(c) = self.chars.next() {
            self.push(c);
            if c == '\\' {
                if let Some(next) = self.chars.next() {
                    self.push(next);
                }
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            } else if c == open && open != close {
                depth += 1;
            }
        }
    }
}

/// Whether `$` followed by `c` expands something.
fn starts_expansion(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '{' | '(' | '@' | '*' | '#' | '?' | '$' | '!')
}

/// What a backquote and `c` mean to PowerShell.
fn powershell_escape(c: char) -> char {
    match c {
        'n' => '\n',
        't' => '\t',
        '0' => '\0',
        other => other,
    }
}
