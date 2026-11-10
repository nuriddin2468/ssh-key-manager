//! The shells a local session can run (see [`super::local`]), as this
//! computer has them:
//!
//! - macOS and Linux: the user's own shell (`$SHELL`, else the one in the
//!   user database), those `/etc/shells` lists, and well-known shells in
//!   the `PATH` and Homebrew's folders. Each starts as a login shell.
//! - Windows: PowerShell 7, Windows PowerShell, Command Prompt, Git Bash and
//!   each WSL distribution. PowerShell (7 if installed) is the default, as in
//!   Windows Terminal.
//!
//! The UI names a shell only by the id this module gave it, and every start
//! looks for it again here: the page can't make the app run a program of its
//! choosing.
//!
//! The lists are worked out from what the computer looks like, passed in, so
//! the Windows one is tested on every platform.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use portable_pty::CommandBuilder;
use serde::Serialize;
use sshkm_core::{ExposeSecret, SecretString};

use crate::error::{AppError, AppResult};

/// A shell as the UI lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ShellInfo {
    /// What the UI sends back to start it: the program's path on macOS and
    /// Linux; `pwsh`, `powershell`, `cmd`, `git-bash` or `wsl:<distribution>`
    /// on Windows.
    pub id: String,
    /// Its usual name: `Zsh`, `PowerShell`, `Ubuntu`…
    pub name: String,
    /// The program, as the list shows it under the name.
    pub path: String,
    /// What it is, for the UI's wording.
    pub kind: ShellKind,
    /// Started when no shell is chosen.
    pub default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum ShellKind {
    /// A shell program on macOS or Linux.
    Unix,
    PowerShell,
    WindowsPowerShell,
    /// `cmd.exe`, which Windows calls Command Prompt.
    Cmd,
    GitBash,
    /// A WSL distribution, started with `wsl.exe -d`.
    Wsl,
}

/// A shell and how to start it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    pub info: ShellInfo,
    program: PathBuf,
    args: Vec<String>,
}

impl Shell {
    /// The command that starts it in `cwd` with `vars` in its environment.
    /// On macOS and Linux it runs as a login shell, as a terminal app starts
    /// one, with `SHELL` naming it. WSL gets the variables through `WSLENV`:
    /// Windows passes no others on to Linux.
    pub fn command(&self, vars: &[(String, SecretString)], cwd: &Path) -> CommandBuilder {
        let mut command = if self.info.kind == ShellKind::Unix {
            // portable-pty starts `$SHELL` of the command's own environment
            // as a login shell (`-zsh` as its argv[0]).
            CommandBuilder::new_default_prog()
        } else {
            let mut command = CommandBuilder::new(&self.program);
            command.args(&self.args);
            command
        };
        for (name, value) in vars {
            command.env(name, value.expose_secret());
        }
        if self.info.kind == ShellKind::Unix {
            command.env("SHELL", &self.program);
        }
        if self.info.kind == ShellKind::Wsl && !vars.is_empty() {
            let current = std::env::var("WSLENV").unwrap_or_default();
            command.env(
                "WSLENV",
                wslenv(&current, vars.iter().map(|(name, _)| &**name)),
            );
        }
        command.cwd(cwd);
        command
    }
}

/// The shells this computer has, the default first.
pub fn list() -> Vec<Shell> {
    platform::list()
}

/// The shell `id` names, or the default one. A shell that is gone (or never
/// was) isn't started in its place.
pub fn find(id: Option<&str>) -> AppResult<Shell> {
    let shells = list();
    let found = match id {
        Some(id) => shells.into_iter().find(|shell| shell.info.id == id),
        None => shells.into_iter().find(|shell| shell.info.default),
    };
    found.ok_or_else(|| AppError::not_found("this shell isn't on this computer anymore"))
}

/// `WSLENV` with `names` added, each passed to Linux only (`/u`), after what
/// it already lists.
fn wslenv<'a>(current: &str, names: impl Iterator<Item = &'a str>) -> String {
    let listed: HashSet<&str> = current
        .split(':')
        .map(|entry| entry.split('/').next().unwrap_or(entry))
        .collect();
    let mut entries: Vec<String> = current
        .split(':')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    for name in names {
        if !listed.contains(name) {
            entries.push(format!("{name}/u"));
        }
    }
    entries.join(":")
}

// ---------------------------------------------------------------------------
// macOS and Linux

#[cfg(any(unix, test))]
/// The shells listed by name, with their usual names, in the order the list
/// shows them after the default.
const UNIX_SHELLS: [(&str, &str); 13] = [
    ("zsh", "Zsh"),
    ("bash", "Bash"),
    ("fish", "fish"),
    ("nu", "Nushell"),
    ("pwsh", "PowerShell"),
    ("elvish", "Elvish"),
    ("xonsh", "xonsh"),
    ("ksh", "KornShell"),
    ("mksh", "mksh"),
    ("tcsh", "tcsh"),
    ("csh", "csh"),
    ("dash", "Dash"),
    ("sh", "sh"),
];

/// Folders a shell may be installed in that a GUI app's `PATH` often lacks.
#[cfg(unix)]
const UNIX_EXTRA_DIRS: [&str; 4] = [
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/home/linuxbrew/.linuxbrew/bin",
    "/run/current-system/sw/bin",
];

#[cfg(any(unix, test))]
/// What the list on macOS and Linux is made of.
struct UnixProbe<'a> {
    /// The user's shell: `$SHELL`, else the user database's.
    user_shell: Option<PathBuf>,
    /// `/etc/shells`.
    etc_shells: &'a str,
    /// Folders to look in for the shells of [`UNIX_SHELLS`].
    dirs: Vec<PathBuf>,
    is_executable: &'a dyn Fn(&Path) -> bool,
    /// The file a path leads to, to tell links to one shell apart.
    canonical: &'a dyn Fn(&Path) -> Option<PathBuf>,
}

#[cfg(any(unix, test))]
fn unix_shells(probe: &UnixProbe<'_>) -> Vec<Shell> {
    let listed = probe
        .etc_shells
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty())
        .map(PathBuf::from);
    let found = UNIX_SHELLS
        .iter()
        .flat_map(|(file, _)| probe.dirs.iter().map(move |dir| dir.join(file)));
    let mut seen = HashSet::new();
    let mut shells = Vec::new();
    let user_shell = probe.user_shell.iter().cloned();
    for (index, path) in user_shell.chain(listed).chain(found).enumerate() {
        let default = index == 0 && probe.user_shell.is_some();
        if !path.is_absolute() || !(probe.is_executable)(&path) {
            continue;
        }
        let Some(file) = path.file_name().and_then(|file| file.to_str()) else {
            continue;
        };
        let known = UNIX_SHELLS.iter().find(|(name, _)| *name == file);
        // Only shells: /etc/shells may list tmux, screen, nologin…, but the
        // user's own shell is listed whatever it is.
        if known.is_none() && !default {
            continue;
        }
        if !seen.insert((probe.canonical)(&path).unwrap_or_else(|| path.clone())) {
            continue;
        }
        let shown = path.to_string_lossy().into_owned();
        shells.push(Shell {
            info: ShellInfo {
                id: shown.clone(),
                name: known.map_or_else(|| file.to_owned(), |(_, name)| (*name).to_owned()),
                path: shown,
                kind: ShellKind::Unix,
                default,
            },
            program: path.clone(),
            args: Vec::new(),
        });
    }
    if !shells.iter().any(|shell| shell.info.default)
        && let Some(first) = shells.first_mut()
    {
        first.info.default = true;
    }
    let rank = |shell: &Shell| {
        let file = shell.program.file_name().and_then(|file| file.to_str());
        UNIX_SHELLS
            .iter()
            .position(|(name, _)| Some(*name) == file)
            .unwrap_or(UNIX_SHELLS.len())
    };
    shells.sort_by_key(|shell| (!shell.info.default, rank(shell)));
    shells
}

// ---------------------------------------------------------------------------
// Windows

#[cfg(any(windows, test))]
/// What the list on Windows is made of.
struct WindowsProbe<'a> {
    /// An environment variable of the app's.
    var: &'a dyn Fn(&str) -> Option<String>,
    /// The folders of `PATH`.
    path_dirs: Vec<PathBuf>,
    is_file: &'a dyn Fn(&Path) -> bool,
    /// The WSL distributions, as `wsl.exe --list --quiet` names them.
    wsl_distributions: &'a dyn Fn() -> Vec<String>,
}

#[cfg(any(windows, test))]
fn windows_shells(probe: &WindowsProbe<'_>) -> Vec<Shell> {
    let var = |name: &str| (probe.var)(name).filter(|value| !value.is_empty());
    let root = var("SystemRoot").unwrap_or_else(|| r"C:\Windows".to_owned());
    let system32 = win_join(&root, "System32");
    let program_files: Vec<String> = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(var)
        .collect();
    let in_program_files = |rest: &str| -> Vec<PathBuf> {
        program_files
            .iter()
            .map(|dir| win_join(dir, rest))
            .collect()
    };
    let first_file =
        |candidates: Vec<PathBuf>| candidates.into_iter().find(|path| (probe.is_file)(path));

    let mut shells = Vec::new();
    let mut add =
        |id: String, name: String, kind: ShellKind, program: PathBuf, args: Vec<String>| {
            let path = if kind == ShellKind::Wsl {
                format!("wsl.exe -d {name}")
            } else {
                program.to_string_lossy().into_owned()
            };
            shells.push(Shell {
                info: ShellInfo {
                    id,
                    name,
                    path,
                    kind,
                    default: false,
                },
                program,
                args,
            });
        };

    let mut pwsh = in_program_files(r"PowerShell\7\pwsh.exe");
    // The Microsoft Store's and `dotnet tool`'s, among others.
    pwsh.extend(probe.path_dirs.iter().map(|dir| win_join(dir, "pwsh.exe")));
    if let Some(program) = first_file(pwsh) {
        add(
            "pwsh".into(),
            "PowerShell".into(),
            ShellKind::PowerShell,
            program,
            Vec::new(),
        );
    }
    let powershell = win_join(&system32, r"WindowsPowerShell\v1.0\powershell.exe");
    if (probe.is_file)(&powershell) {
        add(
            "powershell".into(),
            "Windows PowerShell".into(),
            ShellKind::WindowsPowerShell,
            powershell,
            Vec::new(),
        );
    }
    // Always there; `%ComSpec%` names it unless something changed that.
    let cmd = var("ComSpec")
        .filter(|path| win_absolute(path))
        .map(PathBuf::from)
        .filter(|path| (probe.is_file)(path))
        .unwrap_or_else(|| win_join(&system32, "cmd.exe"));
    add(
        "cmd".into(),
        "Command Prompt".into(),
        ShellKind::Cmd,
        cmd,
        Vec::new(),
    );

    let mut git = in_program_files(r"Git\bin\bash.exe");
    if let Some(local) = var("LOCALAPPDATA") {
        git.push(win_join(&local, r"Programs\Git\bin\bash.exe"));
    }
    if let Some(program) = first_file(git) {
        // As Git's own Start menu entry starts it.
        add(
            "git-bash".into(),
            "Git Bash".into(),
            ShellKind::GitBash,
            program,
            vec!["--login".into(), "-i".into()],
        );
    }

    let wsl = win_join(&system32, "wsl.exe");
    if (probe.is_file)(&wsl) {
        for distribution in (probe.wsl_distributions)() {
            let args = vec!["-d".into(), distribution.clone(), "--cd".into(), "~".into()];
            add(
                format!("wsl:{distribution}"),
                distribution,
                ShellKind::Wsl,
                wsl.clone(),
                args,
            );
        }
    }

    // PowerShell 7, else Windows PowerShell, else Command Prompt.
    if let Some(first) = shells.first_mut() {
        first.info.default = true;
    }
    shells
}

#[cfg(any(windows, test))]
/// `dir\rest`, a Windows path built the same way on every platform.
fn win_join(dir: impl AsRef<std::ffi::OsStr>, rest: &str) -> PathBuf {
    let dir = dir.as_ref().to_string_lossy();
    PathBuf::from(format!("{}\\{rest}", dir.trim_end_matches(['\\', '/'])))
}

#[cfg(any(windows, test))]
/// `C:\…` or `\\server\…`.
fn win_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(r"\\")
        || (bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

#[cfg(any(windows, test))]
/// The distributions in `wsl.exe --list --quiet`'s output. It is UTF-16
/// unless `WSL_UTF8` is set (older WSL ignores that), read as UTF-8: a
/// distribution's name is ASCII, so dropping the NULs and the mangled byte
/// order mark leaves it. Docker Desktop's own aren't for logging in to.
fn parse_wsl_list(output: &str) -> Vec<String> {
    let text: String = output
        .chars()
        .filter(|c| !matches!(c, '\0' | '\u{feff}' | '\u{fffd}'))
        .collect();
    text.lines()
        .map(str::trim)
        .filter(|name| {
            !name.is_empty() && !name.starts_with('-') && !name.starts_with("docker-desktop")
        })
        // A name is passed to `wsl.exe -d` as one argument; WSL itself
        // allows letters, digits, `.`, `_` and `-`.
        .filter(|name| {
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        })
        .map(str::to_owned)
        .collect()
}

/// How long `wsl.exe --list` may take: it may have to start WSL's service.
#[cfg(windows)]
const WSL_LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(windows)]
mod platform {
    use std::path::Path;

    use super::{Shell, WSL_LIST_TIMEOUT, WindowsProbe, parse_wsl_list, windows_shells};
    use crate::process;

    pub fn list() -> Vec<Shell> {
        let path_dirs = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        windows_shells(&WindowsProbe {
            var: &|name| std::env::var(name).ok(),
            path_dirs,
            is_file: &|path: &Path| path.is_file(),
            wsl_distributions: &wsl_distributions,
        })
    }

    fn wsl_distributions() -> Vec<String> {
        let Ok(root) = std::env::var("SystemRoot") else {
            return Vec::new();
        };
        let wsl = Path::new(&root).join("System32").join("wsl.exe");
        let mut command = process::command(&wsl.to_string_lossy());
        command.args(["--list", "--quiet"]).env("WSL_UTF8", "1");
        match process::run_command(&mut command, None, WSL_LIST_TIMEOUT) {
            // Without a distribution it prints how to install one, and fails.
            Ok(output) if output.success => parse_wsl_list(&output.stdout),
            _ => Vec::new(),
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::path::{Path, PathBuf};

    use super::{Shell, UNIX_EXTRA_DIRS, UnixProbe, unix_shells};

    pub fn list() -> Vec<Shell> {
        let etc_shells = std::fs::read_to_string("/etc/shells").unwrap_or_default();
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        dirs.extend(UNIX_EXTRA_DIRS.iter().map(PathBuf::from));
        unix_shells(&UnixProbe {
            user_shell: user_shell(),
            etc_shells: &etc_shells,
            dirs,
            is_executable: &is_executable,
            canonical: &|path: &Path| std::fs::canonicalize(path).ok(),
        })
    }

    /// `$SHELL`, else the user database's shell: what portable-pty starts
    /// when told nothing.
    fn user_shell() -> Option<PathBuf> {
        std::env::var_os("SHELL")
            .map(PathBuf::from)
            .filter(|path| is_executable(path))
            .or_else(|| {
                nix::unistd::User::from_uid(nix::unistd::getuid())
                    .ok()
                    .flatten()
                    .map(|user| user.shell)
            })
    }

    fn is_executable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn unix(
        user_shell: Option<&str>,
        etc_shells: &str,
        dirs: &[&str],
        files: &[&str],
        links: &[(&str, &str)],
    ) -> Vec<ShellInfo> {
        let links: HashMap<&str, &str> = links.iter().copied().collect();
        let is_executable = |path: &Path| files.contains(&path.to_str().unwrap());
        let canonical = |path: &Path| {
            let path = path.to_str().unwrap();
            Some(PathBuf::from(links.get(path).copied().unwrap_or(path)))
        };
        unix_shells(&UnixProbe {
            user_shell: user_shell.map(PathBuf::from),
            etc_shells,
            dirs: dirs.iter().map(PathBuf::from).collect(),
            is_executable: &is_executable,
            canonical: &canonical,
        })
        .into_iter()
        .map(|shell| shell.info)
        .collect()
    }

    fn ids(shells: &[ShellInfo]) -> Vec<&str> {
        shells.iter().map(|shell| shell.id.as_str()).collect()
    }

    /// macOS: the user's zsh first, the rest of /etc/shells in the usual
    /// order, Homebrew's fish found though /etc/shells doesn't list it.
    #[test]
    fn macos_lists_the_users_shell_first() {
        let shells = unix(
            Some("/bin/zsh"),
            "# List of acceptable shells\n/bin/bash\n/bin/csh\n/bin/dash\n/bin/ksh\n/bin/sh\n/bin/tcsh\n/bin/zsh\n",
            &["/usr/bin", "/bin", "/opt/homebrew/bin"],
            &[
                "/bin/bash",
                "/bin/csh",
                "/bin/dash",
                "/bin/ksh",
                "/bin/sh",
                "/bin/tcsh",
                "/bin/zsh",
                "/opt/homebrew/bin/fish",
            ],
            &[],
        );
        assert_eq!(
            ids(&shells),
            [
                "/bin/zsh",
                "/bin/bash",
                "/opt/homebrew/bin/fish",
                "/bin/ksh",
                "/bin/tcsh",
                "/bin/csh",
                "/bin/dash",
                "/bin/sh",
            ]
        );
        assert!(shells[0].default);
        assert_eq!(shells[0].name, "Zsh");
        assert!(shells[1..].iter().all(|shell| !shell.default));
        assert!(shells.iter().all(|shell| shell.kind == ShellKind::Unix));
    }

    /// Debian: /bin and /usr/bin are one folder, sh is dash, and tmux and
    /// rbash aren't shells to offer.
    #[test]
    fn linux_lists_each_shell_once() {
        let shells = unix(
            Some("/bin/bash"),
            "/bin/sh\n/usr/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n/usr/bin/rbash\n/usr/bin/dash\n/usr/bin/tmux\n",
            &["/usr/local/bin", "/usr/bin", "/bin"],
            &[
                "/bin/sh",
                "/usr/bin/sh",
                "/bin/bash",
                "/usr/bin/bash",
                "/bin/rbash",
                "/usr/bin/rbash",
                "/usr/bin/dash",
                "/bin/dash",
                "/usr/bin/tmux",
            ],
            &[
                ("/bin/sh", "/usr/bin/dash"),
                ("/usr/bin/sh", "/usr/bin/dash"),
                ("/bin/bash", "/usr/bin/bash"),
                ("/bin/dash", "/usr/bin/dash"),
            ],
        );
        assert_eq!(ids(&shells), ["/bin/bash", "/bin/sh"]);
        assert!(shells[0].default);
    }

    /// A shell that isn't on the well-known list is listed when it's the
    /// user's; without a user shell the first one found is the default.
    #[test]
    fn the_users_own_shell_is_always_there() {
        let shells = unix(
            Some("/usr/local/bin/oil"),
            "/bin/bash\n",
            &[],
            &["/usr/local/bin/oil", "/bin/bash"],
            &[],
        );
        assert_eq!(ids(&shells), ["/usr/local/bin/oil", "/bin/bash"]);
        assert_eq!(shells[0].name, "oil");
        assert!(shells[0].default);

        let shells = unix(
            None,
            "/bin/zsh\n/bin/bash\n",
            &[],
            &["/bin/bash", "/bin/zsh"],
            &[],
        );
        assert_eq!(ids(&shells), ["/bin/zsh", "/bin/bash"]);
        assert!(shells[0].default);

        let shells = unix(Some("relative/zsh"), "nope\n", &[], &["relative/zsh"], &[]);
        assert_eq!(shells, []);
    }

    fn windows(files: &[&str], vars: &[(&str, &str)], distributions: &[&str]) -> Vec<Shell> {
        let vars: HashMap<&str, &str> = vars.iter().copied().collect();
        let path_dirs = vars
            .get("PATH")
            .map(|path| path.split(';').map(PathBuf::from).collect())
            .unwrap_or_default();
        windows_shells(&WindowsProbe {
            var: &|name| vars.get(name).map(|value| (*value).to_owned()),
            path_dirs,
            is_file: &|path: &Path| files.contains(&path.to_str().unwrap()),
            wsl_distributions: &|| distributions.iter().map(|d| (*d).to_owned()).collect(),
        })
    }

    const WINDOWS_VARS: [(&str, &str); 4] = [
        ("SystemRoot", r"C:\Windows"),
        ("ProgramFiles", r"C:\Program Files"),
        ("ComSpec", r"C:\Windows\system32\cmd.exe"),
        ("LOCALAPPDATA", r"C:\Users\me\AppData\Local"),
    ];

    /// Everything installed: PowerShell 7 is the default, Git Bash starts
    /// as a login shell, each distribution starts in its home folder.
    #[test]
    fn windows_lists_powershell_first() {
        let shells = windows(
            &[
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"C:\Windows\system32\cmd.exe",
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Windows\System32\wsl.exe",
            ],
            &WINDOWS_VARS,
            &["Ubuntu-24.04", "Debian"],
        );
        let infos: Vec<_> = shells.iter().map(|shell| shell.info.clone()).collect();
        assert_eq!(
            ids(&infos),
            [
                "pwsh",
                "powershell",
                "cmd",
                "git-bash",
                "wsl:Ubuntu-24.04",
                "wsl:Debian"
            ]
        );
        assert!(infos[0].default);
        assert!(infos[1..].iter().all(|shell| !shell.default));
        assert_eq!(infos[0].path, r"C:\Program Files\PowerShell\7\pwsh.exe");
        assert_eq!(infos[2].path, r"C:\Windows\system32\cmd.exe");
        assert_eq!(shells[3].args, ["--login", "-i"]);
        assert_eq!(infos[4].name, "Ubuntu-24.04");
        assert_eq!(infos[4].path, "wsl.exe -d Ubuntu-24.04");
        assert_eq!(shells[4].program, Path::new(r"C:\Windows\System32\wsl.exe"));
        assert_eq!(shells[4].args, ["-d", "Ubuntu-24.04", "--cd", "~"]);
    }

    /// A bare Windows: Windows PowerShell is the default; WSL without a
    /// distribution adds nothing. PowerShell 7 from the Store is found in
    /// the `PATH`, Git installed for the user alone in its folder.
    #[test]
    fn windows_finds_what_is_there() {
        let shells = windows(
            &[
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"C:\Windows\system32\cmd.exe",
                r"C:\Windows\System32\wsl.exe",
            ],
            &WINDOWS_VARS,
            &[],
        );
        let infos: Vec<_> = shells.into_iter().map(|shell| shell.info).collect();
        assert_eq!(ids(&infos), ["powershell", "cmd"]);
        assert!(infos[0].default);

        let mut vars = WINDOWS_VARS.to_vec();
        vars.push((
            "PATH",
            r"C:\Windows\system32;C:\Users\me\AppData\Local\Microsoft\WindowsApps",
        ));
        let shells = windows(
            &[
                r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\pwsh.exe",
                r"C:\Users\me\AppData\Local\Programs\Git\bin\bash.exe",
            ],
            &vars,
            &[],
        );
        let infos: Vec<_> = shells.into_iter().map(|shell| shell.info).collect();
        assert_eq!(ids(&infos), ["pwsh", "cmd", "git-bash"]);
        assert_eq!(
            infos[0].path,
            r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\pwsh.exe"
        );
        // `%ComSpec%` doesn't point at a file: cmd.exe in System32 anyway.
        assert_eq!(infos[1].path, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn wsl_lists_are_read_in_either_encoding() {
        // UTF-16 as `process::run_command` reads it.
        let utf16: Vec<u8> = "\u{feff}Ubuntu\r\ndocker-desktop\r\nDebian\r\n\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let read = String::from_utf8_lossy(&utf16);
        assert_eq!(parse_wsl_list(&read), ["Ubuntu", "Debian"]);
        assert_eq!(
            parse_wsl_list("Ubuntu-22.04\nkali-linux\nbad name\n-x;y\nÜbuntu\n"),
            ["Ubuntu-22.04", "kali-linux"]
        );
        assert_eq!(parse_wsl_list(""), Vec::<String>::new());
        assert!(win_absolute(r"C:\Windows\cmd.exe"));
        assert!(win_absolute(r"\\server\share\cmd.exe"));
        assert!(!win_absolute("cmd.exe"));
        assert!(!win_absolute(r"Windows\cmd.exe"));
    }

    #[test]
    fn wslenv_passes_the_variables_to_linux() {
        let names = ["API_KEY", "PORT"];
        assert_eq!(wslenv("", names.into_iter()), "API_KEY/u:PORT/u");
        assert_eq!(
            wslenv("USERPROFILE/p:PORT", names.into_iter()),
            "USERPROFILE/p:PORT:API_KEY/u"
        );
    }

    /// The command for a WSL distribution carries `WSLENV`; a Unix shell
    /// runs as `$SHELL`, whatever the variables say.
    #[test]
    fn commands_set_what_the_shell_needs() {
        let shells = windows(
            &[r"C:\Windows\System32\wsl.exe"],
            &WINDOWS_VARS,
            &["Ubuntu"],
        );
        let wsl = shells
            .iter()
            .find(|shell| shell.info.kind == ShellKind::Wsl)
            .unwrap();
        let vars = [("TOKEN".to_owned(), SecretString::from("x"))];
        let command = wsl.command(&vars, Path::new("/home"));
        let wslenv = command.get_env("WSLENV").unwrap().to_str().unwrap();
        assert!(wslenv.ends_with("TOKEN/u"), "{wslenv}");
        let listed = wslenv.split(':').filter(|entry| *entry == "TOKEN/u");
        assert_eq!(listed.count(), 1, "{wslenv}");

        let shells = unix(Some("/bin/zsh"), "", &[], &["/bin/zsh"], &[]);
        let zsh = Shell {
            info: shells[0].clone(),
            program: PathBuf::from("/bin/zsh"),
            args: Vec::new(),
        };
        let vars = [("SHELL".to_owned(), SecretString::from("/bin/false"))];
        let command = zsh.command(&vars, Path::new("/tmp"));
        assert!(command.is_default_prog());
        assert_eq!(command.get_env("SHELL").unwrap(), "/bin/zsh");
    }
}
