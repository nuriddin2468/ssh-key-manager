//! Writing an environment out: as a `.env` file, JSON, YAML, shell `export`
//! lines, a Docker `--env-file`, or a Kubernetes Secret manifest. Every one
//! of them holds the values in plain text (the Kubernetes one in base64,
//! which hides nothing).
//!
//! Values are written exactly; references such as `${HOME}` stay as they
//! are. Shell lines quote every value in `'…'`, so sourcing the file runs
//! nothing that a value holds.

use std::fmt::Write as _;

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::EnvVariable;
use crate::{Error, ExposeSecret, Result};

/// The file formats an environment can be written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum EnvFormat {
    /// `NAME=value` lines, quoted where needed.
    Dotenv,
    /// One object of strings.
    Json,
    /// One mapping of strings.
    Yaml,
    /// `export NAME='value'` lines, to `source` in a shell.
    Shell,
    /// `NAME=value` lines taken as they are, for `docker run --env-file`.
    Docker,
    /// A `v1` Secret with every value in `data`.
    Kubernetes,
}

impl EnvFormat {
    /// The file name a save dialog suggests for the environment `name` of
    /// `project`.
    pub fn file_name(self, project: &str, name: &str) -> String {
        let stem = [file_part(project), file_part(name)]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let stem = if stem.is_empty() {
            "environment".to_owned()
        } else {
            stem.join(".")
        };
        match self {
            Self::Dotenv => ".env".to_owned(),
            Self::Json => format!("{stem}.json"),
            Self::Yaml => format!("{stem}.yaml"),
            Self::Shell => format!("{stem}.sh"),
            Self::Docker => format!("{stem}.env"),
            Self::Kubernetes => format!("{}-secret.yaml", stem.replace('.', "-")),
        }
    }

    /// The extension the save dialog filters by, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Dotenv | Self::Docker => "env",
            Self::Json => "json",
            Self::Yaml | Self::Kubernetes => "yaml",
            Self::Shell => "sh",
        }
    }
}

/// `text` with only letters, digits, `.`, `_` and `-`, for a file name.
fn file_part(text: &str) -> String {
    let mut out = String::new();
    for c in text.trim().chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches(['-', '.']).to_owned()
}

/// The environment `name` of `project` in `format`. Fails only for a Docker
/// file and a value with a line break, which that format can't hold.
pub fn render(
    format: EnvFormat,
    project: &str,
    name: &str,
    vars: &[EnvVariable],
) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::new());
    match format {
        EnvFormat::Dotenv => {
            for var in vars {
                comment(&mut out, &var.note);
                out.push_str(&var.name);
                out.push('=');
                dotenv_value(&mut out, var.value.expose_secret());
                out.push('\n');
            }
        }
        EnvFormat::Json => {
            if vars.is_empty() {
                out.push_str("{}\n");
            } else {
                out.push_str("{\n");
                for (index, var) in vars.iter().enumerate() {
                    out.push_str("  ");
                    quoted(&mut out, &var.name);
                    out.push_str(": ");
                    quoted(&mut out, var.value.expose_secret());
                    out.push_str(if index + 1 < vars.len() { ",\n" } else { "\n" });
                }
                out.push_str("}\n");
            }
        }
        EnvFormat::Yaml => {
            if vars.is_empty() {
                out.push_str("{}\n");
            }
            for var in vars {
                comment(&mut out, &var.note);
                yaml_key(&mut out, &var.name);
                out.push_str(": ");
                quoted(&mut out, var.value.expose_secret());
                out.push('\n');
            }
        }
        EnvFormat::Shell => {
            for var in vars {
                comment(&mut out, &var.note);
                out.push_str("export ");
                out.push_str(&var.name);
                out.push('=');
                single_quoted(&mut out, var.value.expose_secret());
                out.push('\n');
            }
        }
        EnvFormat::Docker => {
            if let Some(var) = vars
                .iter()
                .find(|var| var.value.expose_secret().contains(['\n', '\r']))
            {
                return Err(Error::invalid(format!(
                    "{} has a line break, which a Docker env file can't hold",
                    var.name
                )));
            }
            for var in vars {
                comment(&mut out, &var.note);
                out.push_str(&var.name);
                out.push('=');
                out.push_str(var.value.expose_secret());
                out.push('\n');
            }
        }
        EnvFormat::Kubernetes => {
            out.push_str("apiVersion: v1\nkind: Secret\nmetadata:\n  name: ");
            out.push_str(&kubernetes_name(project, name));
            out.push_str("\ntype: Opaque\n");
            if vars.is_empty() {
                out.push_str("data: {}\n");
            } else {
                out.push_str("data:\n");
                for var in vars {
                    out.push_str("  ");
                    yaml_key(&mut out, &var.name);
                    out.push_str(": ");
                    let encoded =
                        Zeroizing::new(Base64::encode_string(var.value.expose_secret().as_bytes()));
                    out.push_str(&encoded);
                    out.push('\n');
                }
            }
        }
    }
    Ok(out)
}

/// A variable's note as a `#` comment line, on one line.
fn comment(out: &mut String, note: &str) {
    let note: String = note
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if !note.is_empty() {
        let _ = writeln!(out, "# {note}");
    }
}

/// A `.env` value: bare when it is only safe characters, else in the
/// quotes every loader reads the same way, escaping only as a last resort.
fn dotenv_value(out: &mut String, value: &str) {
    let bare = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-./:@%+,=".contains(c));
    let line_break = value.contains(['\n', '\r']);
    if bare {
        out.push_str(value);
    } else if !line_break && !value.contains(['"', '\\']) {
        out.push('"');
        out.push_str(value);
        out.push('"');
    } else if !line_break && !value.contains('\'') {
        out.push('\'');
        out.push_str(value);
        out.push('\'');
    } else {
        out.push('"');
        for c in value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                other => out.push(other),
            }
        }
        out.push('"');
    }
}

/// A JSON string, which YAML reads the same in double quotes.
fn quoted(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A name as a YAML key: quoted when YAML 1.1 would read it as a boolean
/// or null (`ON`, `no`, `Y`).
fn yaml_key(out: &mut String, name: &str) {
    const SPECIAL: [&str; 9] = ["y", "yes", "n", "no", "true", "false", "on", "off", "null"];
    if SPECIAL.contains(&name.to_ascii_lowercase().as_str()) {
        quoted(out, name);
    } else {
        out.push_str(name);
    }
}

/// `'…'` for a POSIX shell: a `'` inside becomes `'\''`.
fn single_quoted(out: &mut String, value: &str) {
    out.push('\'');
    out.push_str(&value.replace('\'', "'\\''"));
    out.push('\'');
}

/// A Secret's name: a DNS subdomain of lowercase letters, digits, `-` and `.`.
fn kubernetes_name(project: &str, name: &str) -> String {
    let joined = format!("{project}-{name}").to_lowercase();
    let mut out = String::new();
    for c in joined.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out: String = out
        .trim_matches(['-', '.'])
        .chars()
        .take(253)
        .collect::<String>()
        .trim_end_matches(['-', '.'])
        .to_owned();
    if out.is_empty() {
        "environment".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretString;
    use crate::vault::envs::dotenv;

    fn var(name: &str, value: &str, note: &str) -> EnvVariable {
        EnvVariable {
            name: name.into(),
            value: SecretString::from(value),
            secret: false,
            note: note.into(),
        }
    }

    fn sample() -> Vec<EnvVariable> {
        vec![
            var("PORT", "3000", ""),
            var(
                "DATABASE_URL",
                "postgres://app:p@ss@db/app",
                "primary\ndatabase",
            ),
            var("GREETING", "it's \"quoted\"", ""),
            var("REF", "${HOME}/app", ""),
            var("ON", "yes", ""),
            var("KEY", "-----BEGIN KEY-----\nabc\n-----END KEY-----", ""),
            var("EMPTY", "", ""),
        ]
    }

    fn render_text(format: EnvFormat, vars: &[EnvVariable]) -> String {
        render(format, "My App", "prod", vars).unwrap().to_string()
    }

    #[test]
    fn dotenv_reads_back_the_same() {
        let text = render_text(EnvFormat::Dotenv, &sample());
        assert_eq!(
            text,
            "PORT=3000\n\
             # primary database\n\
             DATABASE_URL=postgres://app:p@ss@db/app\n\
             GREETING=\"it's \\\"quoted\\\"\"\n\
             REF=\"${HOME}/app\"\n\
             ON=yes\n\
             KEY=\"-----BEGIN KEY-----\\nabc\\n-----END KEY-----\"\n\
             EMPTY=\n"
        );
        let parsed = dotenv::parse(&text);
        assert_eq!(parsed.problems, Vec::<dotenv::ParseProblem>::new());
        let read: Vec<(String, String)> = parsed
            .vars
            .into_iter()
            .map(|v| (v.name, v.value.to_string()))
            .collect();
        let wanted: Vec<(String, String)> = sample()
            .into_iter()
            .map(|v| (v.name, v.value.expose_secret().to_owned()))
            .collect();
        assert_eq!(read, wanted);

        // Single quotes where double ones would need escapes.
        let text = render_text(EnvFormat::Dotenv, &[var("PATTERN", "a\\d+\"", "")]);
        assert_eq!(text, "PATTERN='a\\d+\"'\n");
        assert_eq!(dotenv::parse(&text).vars[0].value.as_str(), "a\\d+\"");
    }

    #[test]
    fn json_and_yaml_are_string_maps() {
        let vars = sample();
        let json = render_text(EnvFormat::Json, &vars);
        let parsed: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), vars.len());
        for var in &vars {
            assert_eq!(parsed[&var.name], var.value.expose_secret());
        }
        assert!(json.starts_with("{\n  \"PORT\": \"3000\",\n"));
        assert_eq!(render_text(EnvFormat::Json, &[]), "{}\n");

        let yaml = render_text(EnvFormat::Yaml, &vars);
        assert!(yaml.contains("PORT: \"3000\"\n"));
        assert!(
            yaml.contains("# primary database\nDATABASE_URL: \"postgres://app:p@ss@db/app\"\n")
        );
        assert!(yaml.contains("\"ON\": \"yes\"\n"));
        assert!(yaml.contains("KEY: \"-----BEGIN KEY-----\\nabc\\n-----END KEY-----\"\n"));
        assert_eq!(
            render_text(EnvFormat::Yaml, &[var("CTRL", "a\u{7}b", "")]),
            "CTRL: \"a\\u0007b\"\n"
        );
        assert_eq!(render_text(EnvFormat::Yaml, &[]), "{}\n");
    }

    #[test]
    fn shell_lines_quote_every_value() {
        let text = render_text(
            EnvFormat::Shell,
            &[
                var("GREETING", "it's $(rm -rf ~) `x`", "a note"),
                var("REF", "${HOME}", ""),
            ],
        );
        assert_eq!(
            text,
            "# a note\nexport GREETING='it'\\''s $(rm -rf ~) `x`'\nexport REF='${HOME}'\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_shell_reads_the_values_back_exactly() {
        let vars = [
            var("A", "it's $(echo no) `echo no` \\n", ""),
            var("B", "line one\nline two", ""),
        ];
        let script = format!(
            "{}printf '%s|%s' \"$A\" \"$B\"",
            render_text(EnvFormat::Shell, &vars)
        );
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "it's $(echo no) `echo no` \\n|line one\nline two"
        );
    }

    #[test]
    fn docker_files_take_values_as_they_are() {
        let text = render_text(
            EnvFormat::Docker,
            &[var("A", "x y \"z\" ${B}", "note"), var("E", "", "")],
        );
        assert_eq!(text, "# note\nA=x y \"z\" ${B}\nE=\n");
        let error = render(EnvFormat::Docker, "p", "e", &sample()).unwrap_err();
        assert!(error.to_string().contains("KEY has a line break"));
    }

    #[test]
    fn kubernetes_secrets_hold_base64() {
        let text = render_text(
            EnvFormat::Kubernetes,
            &[var("PORT", "3000", "skipped"), var("Y", "é\n", "")],
        );
        assert_eq!(
            text,
            "apiVersion: v1\n\
             kind: Secret\n\
             metadata:\n  name: my-app-prod\n\
             type: Opaque\n\
             data:\n  PORT: MzAwMA==\n  \"Y\": w6kK\n"
        );
        assert!(render_text(EnvFormat::Kubernetes, &[]).ends_with("data: {}\n"));
        assert_eq!(kubernetes_name("--", "__"), "environment");
        assert_eq!(kubernetes_name("Shop.API", "Prod EU"), "shop.api-prod-eu");
    }

    #[test]
    fn suggests_file_names() {
        let names: Vec<String> = [
            EnvFormat::Dotenv,
            EnvFormat::Json,
            EnvFormat::Yaml,
            EnvFormat::Shell,
            EnvFormat::Docker,
            EnvFormat::Kubernetes,
        ]
        .into_iter()
        .map(|format| format.file_name("My App/v2", "prod"))
        .collect();
        assert_eq!(
            names,
            [
                ".env",
                "My-App-v2.prod.json",
                "My-App-v2.prod.yaml",
                "My-App-v2.prod.sh",
                "My-App-v2.prod.env",
                "My-App-v2-prod-secret.yaml",
            ]
        );
        assert_eq!(EnvFormat::Json.file_name("", "  "), "environment.json");
    }
}
