//! Variables that make a program run code just by being in its
//! environment: the value runs as soon as a shell starts, shows its prompt,
//! or runs one of the tools listed here. Nothing refuses them, since a
//! project may rely on them (`NODE_OPTIONS=--max-old-space-size=…`), but
//! they never go anywhere unseen: a shell started with an environment
//! that has one is opened only after a system dialog that lists them with
//! their values, one sent to someone else is named as one in the dialog
//! that sends it, and one received is flagged and left out unless the user
//! picks it.
//!
//! - Shells: a startup file or folder (`BASH_ENV`, `ENV`, `ZDOTDIR`,
//!   `HOME`, `XDG_CONFIG_HOME`…), a prompt that is expanded each time it is
//!   shown (`PS1`, `PROMPT_COMMAND`, zsh's `RPROMPT`…), options and
//!   functions (`SHELLOPTS`, `BASH_FUNC_…`), where commands and functions
//!   are looked up (`PATH`, `FPATH`), and how words are split (`IFS`).
//! - The dynamic linker: every `LD_…` and `DYLD_…` variable.
//! - Git: every `GIT_…` variable, which covers the programs it starts
//!   (`GIT_SSH_COMMAND`, `GIT_PAGER`, `GIT_EDITOR`…) and the configuration
//!   it reads (`GIT_CONFIG_…`, `GIT_DIR`), but who a commit is by
//!   (`GIT_AUTHOR_…`, `GIT_COMMITTER_…`).
//! - Programs other tools start: pagers (`PAGER`, `LESSOPEN`, `LESS`…),
//!   editors, browsers and password prompts (`SSH_ASKPASS`…).
//! - Code a language runtime loads before any script, or where it looks for
//!   it: `NODE_OPTIONS`, `NODE_PATH`, `PYTHONSTARTUP`, `PYTHONPATH`,
//!   `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS`…
//! - Windows: `COMSPEC`, `PATHEXT`, `PSModulePath`.
//!
//! Names are compared without regard to case, as Windows does.

/// Variables named here exactly (in upper case).
const NAMES: &[&str] = &[
    // Shells.
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS0",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PROMPT_COMMAND",
    "PROMPT",
    "PROMPT2",
    "PROMPT3",
    "PROMPT4",
    "RPROMPT",
    "RPROMPT2",
    "RPS1",
    "RPS2",
    "SPROMPT",
    "ZDOTDIR",
    "FPATH",
    "IFS",
    "HOME",
    "SHELL",
    "PATH",
    "MAILPATH",
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    // Programs other tools start.
    "PAGER",
    "MANPAGER",
    "MANOPT",
    "LESS",
    "LESSOPEN",
    "LESSCLOSE",
    "EDITOR",
    "VISUAL",
    "BROWSER",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    // Language runtimes.
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "PERL5DB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    // Windows.
    "COMSPEC",
    "PATHEXT",
    "PSMODULEPATH",
];

/// Variables whose names start with one of these (in upper case).
const PREFIXES: &[&str] = &["LD_", "DYLD_", "GIT_", "BASH_FUNC_"];
/// Of those, the ones that only say who a commit is by.
const HARMLESS_PREFIXES: &[&str] = &["GIT_AUTHOR_", "GIT_COMMITTER_"];

/// Whether the variable `name` makes a shell, or a program started from
/// one, run code it names (see the module documentation).
pub fn runs_code(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let has = |prefixes: &[&str]| prefixes.iter().any(|prefix| upper.starts_with(prefix));
    NAMES.contains(&upper.as_str()) || (has(PREFIXES) && !has(HARMLESS_PREFIXES))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_variables_are_told_apart_from_look_alikes() {
        for name in [
            "BASH_ENV",
            "bash_env",
            "PROMPT_COMMAND",
            "PS1",
            "RPS1",
            "ZDOTDIR",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_COUNT",
            "LESSOPEN",
            "NODE_OPTIONS",
            "NODE_PATH",
            "PYTHONSTARTUP",
            "PERL5OPT",
            "Path",
            "PSModulePath",
        ] {
            assert!(runs_code(name), "{name}");
        }
        for name in [
            "DATABASE_URL",
            "API_KEY",
            "GITHUB_TOKEN",
            "GIT_AUTHOR_NAME",
            "git_committer_email",
            "NODE_ENV",
            "PORT",
            "HOME_URL",
            "MY_PATH",
            "LDAP_URL",
            "ENVIRONMENT",
        ] {
            assert!(!runs_code(name), "{name}");
        }
    }
}
