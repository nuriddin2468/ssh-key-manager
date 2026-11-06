//! Guessing which variables are secrets, for an import the user reviews: by
//! the name (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*PASSWORD*`, `DATABASE_URL`,
//! …) and by the value (a private key, an address with a password in it, a
//! known token prefix, or a long random-looking string).

/// Whether the variable looks like a secret.
pub fn looks_secret(name: &str, value: &str) -> bool {
    name_looks_secret(name) || value_looks_secret(value)
}

/// Name endings and words that say secret.
const ENDINGS: [&str; 6] = ["_KEY", "_SECRET", "_TOKEN", "_PASS", "_PWD", "_DSN"];
const WORDS: [&str; 5] = [
    "PASSWORD",
    "PASSWD",
    "SECRET_",
    "PRIVATE_KEY",
    "CREDENTIALS",
];

fn name_looks_secret(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    // `NEXT_PUBLIC_*`, `STRIPE_PUBLISHABLE_KEY`, `SSH_PUBLIC_KEY`: meant to
    // be seen.
    if name.contains("PUBLIC") || name.contains("PUBLISHABLE") {
        return false;
    }
    if matches!(name.as_str(), "KEY" | "SECRET" | "TOKEN" | "PASSWORD") {
        return true;
    }
    // Of the addresses only a database's: it usually holds the password.
    if name.ends_with("_URL") {
        return name.ends_with("DATABASE_URL");
    }
    ENDINGS.iter().any(|end| name.ends_with(end)) || WORDS.iter().any(|word| name.contains(word))
}

/// Prefixes of well-known tokens.
const TOKEN_PREFIXES: [&str; 9] = [
    "ghp_",
    "gho_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
];

fn value_looks_secret(value: &str) -> bool {
    let value = value.trim();
    if value.contains("-----BEGIN ") {
        return true;
    }
    if has_password_in_url(value) {
        return true;
    }
    if TOKEN_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return true;
    }
    looks_random(value)
}

/// `scheme://user:password@host…`, or `scheme://:password@host…`.
fn has_password_in_url(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.rsplit_once('@').is_some_and(|(user_info, _)| {
        user_info
            .split_once(':')
            .is_some_and(|(_, p)| !p.is_empty())
    })
}

/// A long string of mixed letters and digits with about as many different
/// characters as a random one: a token, a hash, a generated password. Words,
/// paths, addresses and version numbers don't count.
fn looks_random(value: &str) -> bool {
    let length = value.chars().count();
    if length < 20
        || value.chars().any(char::is_whitespace)
        || value.starts_with(['/', '.', '~'])
        || value.contains("://")
        || value.contains("${")
    {
        return false;
    }
    let alphanumeric = value.chars().filter(char::is_ascii_alphanumeric).count();
    if alphanumeric * 2 < length {
        return false;
    }
    let classes = [
        value.chars().any(|c| c.is_ascii_lowercase()),
        value.chars().any(|c| c.is_ascii_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
    ]
    .into_iter()
    .filter(|has| *has)
    .count();
    if classes < 2 {
        return false;
    }
    let needed = if length < 32 { 4.0 } else { 3.5 };
    entropy(value) >= needed
}

/// Shannon entropy of the characters, in bits per character.
fn entropy(value: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0_u32;
    for c in value.chars() {
        *counts.entry(c).or_insert(0_u32) += 1;
        total += 1;
    }
    let total = f64::from(total);
    counts
        .values()
        .map(|&count| {
            let p = f64::from(count) / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_say_secret() {
        for name in [
            "API_KEY",
            "stripe_secret_key",
            "AWS_SECRET_ACCESS_KEY",
            "JWT_SECRET",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "PASSWORD_HASH_PEPPER",
            "SMTP_PASS",
            "MYSQL_ROOT_PWD",
            "DATABASE_URL",
            "READONLY_DATABASE_URL",
            "SENTRY_DSN",
            "SECRET_KEY_BASE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "TOKEN",
        ] {
            assert!(looks_secret(name, "x"), "{name}");
        }
        for name in [
            "PORT",
            "NODE_ENV",
            "API_URL",
            "REDIS_HOST",
            "AWS_ACCESS_KEY_ID",
            "NEXT_PUBLIC_API_KEY",
            "STRIPE_PUBLISHABLE_KEY",
            "SSH_PUBLIC_KEY",
            "LOG_LEVEL",
        ] {
            assert!(!looks_secret(name, "x"), "{name}");
        }
    }

    #[test]
    fn values_that_look_secret() {
        for value in [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "3f2a9c41d0b8e6f7a5c3d1e9b7f5a3c1d9e7b5f3",
            "dGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIHRlc3Q=",
            "Xk9#mP2$vL5@nQ8&wR3!zT6^",
            "postgres://app:s3cret@db.internal:5432/app",
            "redis://:hunter2@cache:6379/0",
            "ghp_abc",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
        ] {
            assert!(looks_secret("VALUE", value), "{value}");
        }
        for value in [
            "",
            "production",
            "3000",
            "true",
            "https://api.example.com/v1/endpoint",
            "postgres://app@db.internal:5432/app",
            "/usr/local/bin:/usr/bin:/bin",
            "info,warn,error,debug,trace",
            "my-app-production-bucket-eu",
            "v1.2.3-beta+build.20240101",
            "com.example.myapp.production",
            "12345678901234567890123",
            "${DB_USER}:${DB_PASSWORD}@${DB_HOST}",
            "a sentence that is long enough to count",
        ] {
            assert!(!looks_secret("VALUE", value), "{value}");
        }
    }
}
