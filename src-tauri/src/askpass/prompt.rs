//! What `ssh` asks for, recognised from the text it passes to the askpass
//! program.
//!
//! The prompts are OpenSSH's own (`sshconnect2.c`, `sshconnect.c`,
//! `readpass.c`) plus whatever a server sends for keyboard-interactive
//! authentication (PAM, Google Authenticator, Duo, …), which OpenSSH 8.5 and
//! later prefix with `(user@host) `.

use serde::Serialize;

/// What a prompt asks for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum PromptKind {
    /// A login password: `alice@host's password: `, `(alice@host) Password: `
    /// or a server's own `Password: `.
    Password,
    /// A code from a second factor: `Verification code: `,
    /// `One-time password (OATH) for 'alice': `, `OTP: `, a Duo passcode, …
    OneTimeCode,
    /// The passphrase of a private key: `Enter passphrase for key '…': `.
    Passphrase {
        /// The key file as `ssh` names it, cut to 100 bytes by `ssh`.
        key: String,
    },
    /// Whether to trust a host key `ssh` does not know: `Are you sure you want
    /// to continue connecting (yes/no/[fingerprint])? `. Always answered "no".
    HostKeyConfirm,
    /// Any other yes/no question (`Allow use of key …?` from `ssh-agent`,
    /// `Accept updated hostkeys? (yes/no): `, …). Always answered "no".
    Confirm,
    /// Anything else: a PIN, a new password, an unknown question.
    Other,
}

impl PromptKind {
    /// A password, one-time code or passphrase.
    pub fn is_secret(&self) -> bool {
        matches!(
            self,
            Self::Password | Self::OneTimeCode | Self::Passphrase { .. }
        )
    }

    /// A yes/no question.
    pub fn is_confirmation(&self) -> bool {
        matches!(self, Self::HostKeyConfirm | Self::Confirm)
    }
}

/// The `user@host` a prompt names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct PromptAccount {
    pub user: String,
    /// The `HostName` (or `HostKeyAlias`) `ssh` connects to, not the alias.
    pub host: String,
}

impl PromptAccount {
    pub fn new(user: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            host: host.into(),
        }
    }

    /// Whether a prompt naming `self` is about `expected`. The password prompt
    /// cuts the user name to 30 bytes and the host to 128; host names are
    /// compared without case.
    pub fn matches(&self, expected: &Self) -> bool {
        fn same(got: &str, want: &str, limit: usize, ignore_case: bool) -> bool {
            let eq = |a: &[u8], b: &[u8]| {
                if ignore_case {
                    a.eq_ignore_ascii_case(b)
                } else {
                    a == b
                }
            };
            eq(got.as_bytes(), want.as_bytes())
                || (got.len() == limit
                    && want
                        .as_bytes()
                        .get(..limit)
                        .is_some_and(|cut| eq(got.as_bytes(), cut)))
        }
        same(&self.user, &expected.user, 30, false) && same(&self.host, &expected.host, 128, true)
    }
}

/// A prompt `ssh` passed to the askpass program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Prompt {
    /// The text as `ssh` gave it. It never contains a secret.
    pub text: String,
    pub kind: PromptKind,
    /// The account the prompt names, if it names one (password prompts, and
    /// keyboard-interactive prompts from OpenSSH 8.5 on).
    pub account: Option<PromptAccount>,
}

impl Prompt {
    /// Classifies `text`. `hint` is `SSH_ASKPASS_PROMPT` from the helper's
    /// environment (`confirm` for `ssh-agent` and multiplexing questions,
    /// OpenSSH 8.2 and later), or empty.
    pub fn parse(text: &str, hint: &str) -> Self {
        let (prefix_account, body) = split_kbdint_prefix(text);
        let question = last_line(body);
        let whole = text.to_lowercase();
        let lower = question.to_lowercase();

        let kind =
            if whole.contains("continue connecting") || whole.contains("authenticity of host") {
                PromptKind::HostKeyConfirm
            } else if hint.eq_ignore_ascii_case("confirm") || is_yes_no(&whole) {
                PromptKind::Confirm
            } else if let Some(key) = passphrase_key(question) {
                PromptKind::Passphrase { key }
            } else if is_one_time_code(&lower) {
                PromptKind::OneTimeCode
            } else if is_password(&lower) {
                PromptKind::Password
            } else {
                PromptKind::Other
            };

        let account = prefix_account.or_else(|| match kind {
            PromptKind::Password => password_account(question),
            _ => None,
        });
        Self {
            text: text.to_owned(),
            kind,
            account,
        }
    }
}

/// `(user@host) rest` → (`user@host`, `rest`), the prefix OpenSSH 8.5+ puts on
/// keyboard-interactive prompts.
fn split_kbdint_prefix(text: &str) -> (Option<PromptAccount>, &str) {
    let parsed = text.strip_prefix('(').and_then(|rest| {
        let (inside, rest) = rest.split_once(") ")?;
        let (user, host) = inside.rsplit_once('@')?;
        (!user.is_empty() && !host.is_empty() && !host.contains(char::is_whitespace))
            .then(|| (PromptAccount::new(user, host), rest))
    });
    match parsed {
        Some((account, rest)) => (Some(account), rest),
        None => (None, text),
    }
}

/// The question itself: the last line that is not blank, trimmed.
fn last_line(text: &str) -> &str {
    text.lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
}

fn is_yes_no(lower: &str) -> bool {
    let first = last_line(lower.lines().next().unwrap_or(""));
    lower.contains("yes/no")
        || lower.contains("accept updated hostkeys")
        // ssh-agent and multiplexing questions without the `confirm` hint.
        || ["allow ", "terminate shared", "disable further multiplexing", "open "]
            .iter()
            .any(|start| first.starts_with(start) && lower.trim_end().ends_with(['?', '.']))
}

/// `Enter passphrase for key '/path': ` (ssh), `Enter passphrase for /path: `
/// and `Bad passphrase, try again for /path: ` (ssh-add).
fn passphrase_key(question: &str) -> Option<String> {
    let rest = question
        .strip_prefix("Enter passphrase for ")
        .or_else(|| question.strip_prefix("Bad passphrase, try again for "))?;
    let rest = rest.trim_end().strip_suffix(':')?.trim_end();
    let rest = rest.strip_prefix("key ").unwrap_or(rest);
    let key = rest
        .strip_prefix('\'')
        .and_then(|r| r.strip_suffix('\''))
        .unwrap_or(rest);
    (!key.is_empty()).then(|| key.to_owned())
}

/// Words that make a prompt something other than "the password", such as a
/// password change.
fn names_other_password(lower: &str) -> bool {
    [
        "new", "old", "current", "retype", "again", "confirm", "change",
    ]
    .iter()
    .any(|word| has_word(lower, word))
}

fn is_one_time_code(lower: &str) -> bool {
    const PHRASES: [&str; 16] = [
        "verification code",
        "one-time",
        "one time",
        "onetime",
        "two-factor",
        "two factor",
        "second factor",
        "multi-factor",
        "authenticator",
        "authentication code",
        "security code",
        "token code",
        "tokencode",
        "passcode",
        "sms code",
        "6-digit",
    ];
    const WORDS: [&str; 7] = ["otp", "totp", "hotp", "2fa", "mfa", "duo", "oath"];
    !names_other_password(lower)
        && (PHRASES.iter().any(|phrase| lower.contains(phrase))
            || WORDS.iter().any(|word| has_word(lower, word)))
}

fn is_password(lower: &str) -> bool {
    (lower.contains("password") || has_word(lower, "passwd")) && !names_other_password(lower)
}

fn has_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|part| part == word)
}

/// `user@host's password: ` → `user@host`. The user name may itself contain
/// `@`; the host cannot.
fn password_account(question: &str) -> Option<PromptAccount> {
    let account = question.trim_end().strip_suffix("'s password:")?;
    let (user, host) = account.rsplit_once('@')?;
    (!user.is_empty() && !host.is_empty() && !account.contains(char::is_whitespace))
        .then(|| PromptAccount::new(user, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(text: &str) -> PromptKind {
        Prompt::parse(text, "").kind
    }

    #[test]
    fn passwords() {
        for text in [
            "alice@example.com's password: ",
            "alice@192.168.1.10's password: ",
            "(alice@example.com) Password: ",
            "(alice@example.com) Password for alice@example.com: ",
            "Password: ",
            "Password:",
            "password: ",
            "alice@corp.example@10.0.0.1's password: ",
        ] {
            assert_eq!(kind(text), PromptKind::Password, "{text:?}");
        }
    }

    #[test]
    fn password_accounts() {
        let account = |text| Prompt::parse(text, "").account;
        assert_eq!(
            account("alice@example.com's password: "),
            Some(PromptAccount::new("alice", "example.com"))
        );
        assert_eq!(
            account("alice@corp.example@10.0.0.1's password: "),
            Some(PromptAccount::new("alice@corp.example", "10.0.0.1"))
        );
        assert_eq!(
            account("(bob@jump.example) Password: "),
            Some(PromptAccount::new("bob", "jump.example"))
        );
        assert_eq!(
            account("(bob@jump.example) Verification code: "),
            Some(PromptAccount::new("bob", "jump.example"))
        );
        assert_eq!(account("Password: "), None);
        assert_eq!(account("Enter passphrase for key '/k': "), None);
    }

    #[test]
    fn password_changes_are_not_the_password() {
        for text in [
            "Enter alice@example.com's old password: ",
            "Enter alice@example.com's new password: ",
            "Retype alice@example.com's new password: ",
            "(alice@example.com) New password: ",
            "(alice@example.com) Retype new password: ",
            "(alice@example.com) Current password: ",
            "(current) UNIX password: ",
        ] {
            assert_eq!(kind(text), PromptKind::Other, "{text:?}");
        }
    }

    #[test]
    fn one_time_codes() {
        for text in [
            "(alice@example.com) Verification code: ",
            "Verification code: ",
            "(alice@example.com) One-time password (OATH) for `alice': ",
            "One-time password (OATH) for `alice': ",
            "(alice@example.com) OTP: ",
            "Enter your OTP code: ",
            "Authenticator code: ",
            "(alice@example.com) Two-factor authentication code: ",
            "Enter PASSCODE: ",
            "(alice@example.com) Duo two-factor login for alice\n\nEnter a passcode or select one \
             of the following options:\n\n 1. Duo Push to XXX-XXX-1234\n\nPasscode or option (1-1): ",
            "TOTP: ",
            "MFA token: ",
        ] {
            assert_eq!(kind(text), PromptKind::OneTimeCode, "{text:?}");
        }
    }

    #[test]
    fn passphrases() {
        assert_eq!(
            kind("Enter passphrase for key '/home/alice/.ssh/id_ed25519': "),
            PromptKind::Passphrase {
                key: "/home/alice/.ssh/id_ed25519".into()
            }
        );
        assert_eq!(
            kind("Enter passphrase for key 'C:\\Users\\alice/.ssh/id_rsa': "),
            PromptKind::Passphrase {
                key: "C:\\Users\\alice/.ssh/id_rsa".into()
            }
        );
        assert_eq!(
            kind("Enter passphrase for /home/alice/.ssh/id_rsa: "),
            PromptKind::Passphrase {
                key: "/home/alice/.ssh/id_rsa".into()
            }
        );
        assert_eq!(
            kind("Bad passphrase, try again for /home/alice/.ssh/id_rsa: "),
            PromptKind::Passphrase {
                key: "/home/alice/.ssh/id_rsa".into()
            }
        );
        // ssh-keygen asking for a new passphrase is not a key's passphrase.
        assert_eq!(
            kind("Enter passphrase (empty for no passphrase): "),
            PromptKind::Other
        );
        assert_eq!(kind("Enter same passphrase again: "), PromptKind::Other);
    }

    #[test]
    fn host_keys() {
        let modern = "The authenticity of host 'example.com (93.184.216.34)' can't be \
                      established.\nED25519 key fingerprint is \
                      SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\nThis key is not known \
                      by any other names.\nAre you sure you want to continue connecting \
                      (yes/no/[fingerprint])? ";
        let old = "The authenticity of host 'example.com (93.184.216.34)' can't be \
                   established.\nECDSA key fingerprint is SHA256:abc.\nAre you sure you want to \
                   continue connecting (yes/no)? ";
        let mismatch = "Warning: the ECDSA host key for 'example.com' differs from the key for \
                        the IP address '93.184.216.34'\nOffending key for IP in \
                        /home/alice/.ssh/known_hosts:3\nMatching host key in \
                        /home/alice/.ssh/known_hosts:7\nAre you sure you want to continue \
                        connecting (yes/no)? ";
        for text in [modern, old, mismatch] {
            assert_eq!(kind(text), PromptKind::HostKeyConfirm, "{text:?}");
        }
        // The question mentions no password even though the fingerprint is
        // free text.
        assert!(Prompt::parse(modern, "").account.is_none());
    }

    #[test]
    fn confirmations() {
        for (text, hint) in [
            (
                "Allow use of key /home/alice/.ssh/id_ed25519?\nKey fingerprint SHA256:abc.",
                "confirm",
            ),
            (
                "Allow use of key /home/alice/.ssh/id_ed25519?\nKey fingerprint SHA256:abc.",
                "",
            ),
            ("Allow shared connection to example.com? ", ""),
            ("Accept updated hostkeys? (yes/no): ", ""),
            ("Anything at all? ", "confirm"),
        ] {
            assert_eq!(
                Prompt::parse(text, hint).kind,
                PromptKind::Confirm,
                "{text:?}"
            );
        }
    }

    #[test]
    fn others() {
        for text in [
            "Enter PIN for ED25519-SK key /home/alice/.ssh/id_ed25519_sk: ",
            "Enter PIN for 'SoftHSM slot 0': ",
            "Confirm user presence for key ED25519-SK SHA256:abc",
            "What is your favourite colour? ",
            "",
        ] {
            assert_eq!(kind(text), PromptKind::Other, "{text:?}");
        }
    }

    #[test]
    fn accounts_match_with_truncation() {
        let expected = PromptAccount::new("alice", "Example.COM");
        assert!(PromptAccount::new("alice", "example.com").matches(&expected));
        assert!(!PromptAccount::new("Alice", "example.com").matches(&expected));
        assert!(!PromptAccount::new("bob", "example.com").matches(&expected));
        assert!(!PromptAccount::new("alice", "jump.example.com").matches(&expected));

        let long_user = "u".repeat(40);
        let long_host = format!("{}.example", "h".repeat(130));
        let expected = PromptAccount::new(&long_user, &long_host);
        assert!(PromptAccount::new(&long_user[..30], &long_host[..128]).matches(&expected));
        assert!(!PromptAccount::new(&long_user[..29], &long_host[..128]).matches(&expected));
    }

    #[test]
    fn serialises_with_a_type_tag() {
        let prompt = Prompt::parse("Enter passphrase for key '/k': ", "");
        assert_eq!(
            serde_json::to_value(&prompt).unwrap(),
            serde_json::json!({
                "text": "Enter passphrase for key '/k': ",
                "kind": { "type": "passphrase", "key": "/k" },
                "account": null,
            })
        );
        assert_eq!(
            serde_json::to_value(PromptKind::OneTimeCode).unwrap(),
            serde_json::json!({ "type": "oneTimeCode" })
        );
    }
}
