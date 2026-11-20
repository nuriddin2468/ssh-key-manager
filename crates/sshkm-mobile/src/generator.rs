//! The vault's password generator and strength estimate.

use sshkm_core::vault::{self, GenerateOptions};
use sshkm_core::{ExposeSecret, SecretString};

use crate::CoreError;

/// What a random password is made of. The defaults are the desktop app's.
// One switch per kind of character, as the core's `GenerateOptions` and the
// generator's screen have them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct PasswordOptions {
    /// 8 to 128 characters.
    #[uniffi(default = 20)]
    pub length: u16,
    #[uniffi(default = true)]
    pub lowercase: bool,
    #[uniffi(default = true)]
    pub uppercase: bool,
    #[uniffi(default = true)]
    pub digits: bool,
    #[uniffi(default = true)]
    pub symbols: bool,
    /// Leave out `I l 1 O 0 o`.
    #[uniffi(default = false)]
    pub avoid_ambiguous: bool,
}

/// How hard a password is to guess, by the zxcvbn estimator.
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct PasswordStrength {
    /// 0 (guessed almost at once) to 4 (more than 10¹⁰ guesses).
    pub score: u8,
    /// Estimated number of guesses, as a power of ten.
    pub guesses_log10: f64,
}

/// A random password from the operating system's random number generator.
/// Every kind of character chosen appears at least once.
#[uniffi::export]
pub fn generate_password(options: PasswordOptions) -> Result<String, CoreError> {
    let secret = vault::generate(&GenerateOptions::Password {
        length: options.length,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
        avoid_ambiguous: options.avoid_ambiguous,
    })?;
    Ok(secret.expose_secret().to_owned())
}

/// How strong `password` looks. The core's copy is wiped when it is done.
#[uniffi::export]
pub fn password_strength(password: String) -> PasswordStrength {
    let strength = vault::strength(&SecretString::from(password), &[]);
    PasswordStrength {
        score: strength.score,
        guesses_log10: strength.guesses_log10,
    }
}

#[cfg(test)]
mod tests {
    use sshkm_core::ErrorCode;

    use super::*;

    fn defaults() -> PasswordOptions {
        PasswordOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }

    #[test]
    fn a_generated_password_has_the_length_asked_for_and_is_strong() {
        let password = generate_password(defaults()).unwrap();
        assert_eq!(password.chars().count(), 20);
        assert_eq!(password_strength(password).score, 4);
    }

    #[test]
    fn only_digits_gives_only_digits() {
        let password = generate_password(PasswordOptions {
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..defaults()
        })
        .unwrap();
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn a_length_out_of_range_is_invalid_input() {
        let error = generate_password(PasswordOptions {
            length: 7,
            ..defaults()
        })
        .unwrap_err();
        assert!(matches!(
            error,
            CoreError::Failed {
                code: ErrorCode::InvalidInput,
                ..
            }
        ));
    }

    #[test]
    fn an_empty_password_scores_nothing() {
        let strength = password_strength(String::new());
        assert_eq!(strength.score, 0);
    }
}
