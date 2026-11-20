//! What a server's prompt asks for: the password, a one-time code or
//! something else.
//!
//! Servers word their keyboard-interactive prompts as they like (PAM,
//! Google Authenticator, Duo, …), and some word the password prompt too.
//! The desktop app reads them from what `ssh` passes to its askpass program,
//! the phone from the SSH messages themselves; both fill passwords and codes
//! from the vault by what these rules say. A prompt that names another
//! password (a new one, the old one, once again) is neither.

/// What a server's prompt asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerPrompt {
    /// The login password: `Password: `, `Password for alice@host: `.
    Password,
    /// A code from a second factor: `Verification code: `,
    /// `One-time password (OATH) for 'alice': `, `OTP: `, a Duo passcode, …
    OneTimeCode,
    /// Anything else: a new password, a PIN, a question.
    Other,
}

impl ServerPrompt {
    /// Classifies a prompt by its question: the last line that isn't blank
    /// (a Duo prompt lists the options first).
    pub fn of(text: &str) -> Self {
        let lower = last_line(text).to_lowercase();
        if is_one_time_code(&lower) {
            Self::OneTimeCode
        } else if is_password(&lower) {
            Self::Password
        } else {
            Self::Other
        }
    }
}

/// The question itself: the last line that is not blank, trimmed.
pub fn last_line(text: &str) -> &str {
    text.lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
}

/// Whether a question (in lower case) asks for a one-time code.
pub fn is_one_time_code(lower: &str) -> bool {
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

/// Whether a question (in lower case) asks for the password.
pub fn is_password(lower: &str) -> bool {
    (lower.contains("password") || has_word(lower, "passwd")) && !names_other_password(lower)
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

fn has_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|part| part == word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        for text in [
            "Password: ",
            "password:",
            "Password for alice@example.com: ",
            "alice@example.com's password: ",
            "Passwd: ",
        ] {
            assert_eq!(ServerPrompt::of(text), ServerPrompt::Password, "{text:?}");
        }
    }

    #[test]
    fn one_time_codes() {
        for text in [
            "Verification code: ",
            "One-time password (OATH) for `alice': ",
            "OTP: ",
            "Enter your OTP code: ",
            "Authenticator code: ",
            "Two-factor authentication code: ",
            "Enter PASSCODE: ",
            "Duo two-factor login for alice\n\nEnter a passcode or select one of the \
             following options:\n\n 1. Duo Push to XXX-XXX-1234\n\nPasscode or option (1-1): ",
            "TOTP: ",
            "MFA token: ",
        ] {
            assert_eq!(
                ServerPrompt::of(text),
                ServerPrompt::OneTimeCode,
                "{text:?}"
            );
        }
    }

    #[test]
    fn other_passwords_and_questions() {
        for text in [
            "New password: ",
            "Retype new password: ",
            "Current password: ",
            "(current) UNIX password: ",
            "Enter PIN: ",
            "What is your favourite colour? ",
            "",
        ] {
            assert_eq!(ServerPrompt::of(text), ServerPrompt::Other, "{text:?}");
        }
    }

    #[test]
    fn the_question_is_the_last_line() {
        assert_eq!(last_line("Welcome\n\n  Password:  \n\n"), "Password:");
        assert_eq!(last_line("   "), "");
    }
}
