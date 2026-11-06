//! The port forwards of the Tunnels tool: what one is, the checks it passes,
//! the `ssh` command that holds it open, and the file that keeps them.
//!
//! A tunnel is one forward over one `ssh -N` connection to a host alias:
//!
//! - **local** (`-L`): a port on this computer reaches a host and port as
//!   the server sees them;
//! - **remote** (`-R`): a port on the server reaches a host and port as this
//!   computer sees them;
//! - **dynamic** (`-D`): a SOCKS proxy on this computer whose connections
//!   leave from the server.
//!
//! Tunnels live in `tunnels.json` in the app's data folder, not in
//! `~/.ssh/config`; [`Tunnel::config_line`] is the `LocalForward`,
//! `RemoteForward` or `DynamicForward` line for a user who wants one there.
//!
//! Every value that reaches `ssh`'s command line is checked first: a plain
//! alias (as the app's other `ssh` runs check it), ports 1–65535, and
//! addresses and host names without anything `ssh` would read as more than
//! a name.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, fsutil};

/// The most tunnels the file keeps.
pub const MAX_TUNNELS: usize = 200;
const MAX_NAME: usize = 64;
const MAX_HOST: usize = 253;
const FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum TunnelKind {
    /// `-L`: a port here reaches a host as the server sees it.
    Local,
    /// `-R`: a port on the server reaches a host as this computer sees it.
    Remote,
    /// `-D`: a SOCKS proxy here; connections leave from the server.
    Dynamic,
}

/// A saved tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Tunnel {
    /// Empty for a tunnel not saved yet; [`TunnelStore::save`] gives one.
    #[serde(default)]
    pub id: String,
    /// The user's name for it; empty for none.
    #[serde(default)]
    pub name: String,
    /// The `Host` alias `ssh` connects to.
    pub alias: String,
    pub kind: TunnelKind,
    /// Where the forward listens: on this computer for local and dynamic
    /// tunnels (`None`: `localhost`, this computer only), on the server for
    /// remote ones (`None`: as the server's `GatewayPorts` says, by default
    /// its loopback only). `*` is every address.
    #[serde(default)]
    pub bind_address: Option<String>,
    pub listen_port: u16,
    /// Local and remote tunnels: the host connections go to, as the other
    /// end sees it (`localhost` is the server for a local tunnel, this
    /// computer for a remote one).
    #[serde(default)]
    pub target_host: Option<String>,
    #[serde(default)]
    pub target_port: Option<u16>,
    /// Start again when the connection drops or can't be made.
    #[serde(default)]
    pub auto_reconnect: bool,
}

impl Tunnel {
    /// Checks every field (see the [module docs](self)).
    pub fn validate(&self) -> Result<()> {
        if !is_plain_alias(&self.alias) {
            return Err(Error::invalid(
                "not a host alias: only letters, digits and . _ - @ : [ ] can be used",
            ));
        }
        if self.name.chars().count() > MAX_NAME || self.name.chars().any(char::is_control) {
            return Err(Error::invalid(format!(
                "the name must be one line of at most {MAX_NAME} characters"
            )));
        }
        if self.listen_port == 0 {
            return Err(Error::invalid("the port must be from 1 to 65535"));
        }
        if let Some(bind) = &self.bind_address
            && !(bind == "*" || bind == "localhost" || bind.parse::<IpAddr>().is_ok())
        {
            return Err(Error::invalid(
                "the listening address must be localhost, * or an IP address",
            ));
        }
        match self.kind {
            TunnelKind::Local | TunnelKind::Remote => {
                let host = self.target_host.as_deref().unwrap_or_default();
                if !is_host(host) {
                    return Err(Error::invalid(
                        "the destination must be a host name or an IP address",
                    ));
                }
                if self.target_port.unwrap_or(0) == 0 {
                    return Err(Error::invalid(
                        "the destination port must be from 1 to 65535",
                    ));
                }
            }
            TunnelKind::Dynamic => {
                if self.target_host.is_some() || self.target_port.is_some() {
                    return Err(Error::invalid("a SOCKS proxy has no destination"));
                }
            }
        }
        Ok(())
    }

    /// The forward as `ssh` takes it after `-L`, `-R` or `-D`:
    /// `[bind:]port:host:hostport` or `[bind:]port`, IPv6 addresses in
    /// brackets.
    pub fn forward_spec(&self) -> String {
        let bind = self.listen_address();
        let listen = match bind {
            Some(bind) => format!("{}:{}", bracketed(bind), self.listen_port),
            None => self.listen_port.to_string(),
        };
        match self.kind {
            TunnelKind::Dynamic => listen,
            TunnelKind::Local | TunnelKind::Remote => format!(
                "{listen}:{}:{}",
                bracketed(self.target_host.as_deref().unwrap_or_default()),
                self.target_port.unwrap_or_default()
            ),
        }
    }

    /// The address the forward is bound to, as written: `localhost` when a
    /// local or dynamic tunnel names none.
    fn listen_address(&self) -> Option<&str> {
        match (self.kind, self.bind_address.as_deref()) {
            (_, Some(bind)) => Some(bind),
            (TunnelKind::Local | TunnelKind::Dynamic, None) => Some("localhost"),
            (TunnelKind::Remote, None) => None,
        }
    }

    /// `ssh`'s arguments for the tunnel, before the environment the askpass
    /// session adds:
    ///
    /// - `-N`: no command, only the forward;
    /// - `ExitOnForwardFailure`: a port that can't be had ends `ssh` instead
    ///   of leaving a connection that forwards nothing;
    /// - `ServerAliveInterval` and `ServerAliveCountMax`: a dead connection
    ///   ends `ssh` within 45 seconds, so the tunnel can start again;
    /// - no connection sharing (`ControlPath none`), so the tunnel neither
    ///   rides on another `ssh` nor carries others that would end with it;
    /// - `LogLevel=VERBOSE`, whose `Authenticated to …` line tells when
    ///   signing in is done.
    pub fn ssh_args(&self) -> Vec<String> {
        let flag = match self.kind {
            TunnelKind::Local => "-L",
            TunnelKind::Remote => "-R",
            TunnelKind::Dynamic => "-D",
        };
        let mut args: Vec<String> = [
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "RemoteCommand=none",
            "-o",
            "RequestTTY=no",
            "-o",
            "BatchMode=no",
            "-o",
            "LogLevel=VERBOSE",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        args.push(flag.to_owned());
        args.push(self.forward_spec());
        args.push("--".to_owned());
        args.push(self.alias.clone());
        args
    }

    /// The tunnel as a line of its host's block in `~/.ssh/config`.
    pub fn config_line(&self) -> (String, String) {
        let listen = match self.listen_address() {
            Some(bind) => format!("{}:{}", bracketed(bind), self.listen_port),
            None => self.listen_port.to_string(),
        };
        let target = || {
            format!(
                "{}:{}",
                bracketed(self.target_host.as_deref().unwrap_or_default()),
                self.target_port.unwrap_or_default()
            )
        };
        match self.kind {
            TunnelKind::Local => ("LocalForward".into(), format!("{listen} {}", target())),
            TunnelKind::Remote => ("RemoteForward".into(), format!("{listen} {}", target())),
            TunnelKind::Dynamic => ("DynamicForward".into(), listen),
        }
    }

    /// Where "Open in browser" goes for a local tunnel: `http://` (or
    /// `https://` when the destination port is 443 or 8443) on the address
    /// it listens on, `localhost` for every address.
    pub fn browser_url(&self) -> Option<String> {
        if self.kind != TunnelKind::Local {
            return None;
        }
        let host = match self.bind_address.as_deref() {
            None | Some("*" | "0.0.0.0" | "::") => "localhost".to_owned(),
            Some(bind) => bracketed(bind),
        };
        let scheme = if matches!(self.target_port, Some(443 | 8443)) {
            "https"
        } else {
            "http"
        };
        Some(format!("{scheme}://{host}:{}/", self.listen_port))
    }

    /// The forward listens beyond the computer it is on: every address, or
    /// one that isn't loopback. Others on that network can use it.
    pub fn exposed(&self) -> bool {
        match self.bind_address.as_deref() {
            None | Some("localhost") => false,
            Some("*") => true,
            Some(other) => other.parse::<IpAddr>().is_ok_and(|ip| !ip.is_loopback()),
        }
    }

    /// What the tray menu calls it: its name, else the forward.
    pub fn label(&self) -> String {
        if !self.name.trim().is_empty() {
            return format!("{} ({})", self.name.trim(), self.alias);
        }
        let target = || {
            format!(
                "{}:{}",
                self.target_host.as_deref().unwrap_or_default(),
                self.target_port.unwrap_or_default()
            )
        };
        match self.kind {
            TunnelKind::Local => format!("{} → {} ({})", self.listen_port, target(), self.alias),
            TunnelKind::Remote => format!("{} ← {} ({})", self.listen_port, target(), self.alias),
            TunnelKind::Dynamic => format!("SOCKS {} ({})", self.listen_port, self.alias),
        }
    }

    /// Whether this tunnel and `other` would listen on the same port: both
    /// on this computer, or both on the same server.
    fn clashes_with(&self, other: &Self) -> bool {
        let here = |t: &Self| t.kind != TunnelKind::Remote;
        self.id != other.id
            && self.listen_port == other.listen_port
            && here(self) == here(other)
            && (here(self) || self.alias == other.alias)
    }
}

/// An alias the app runs `ssh` with: letters, digits and `. _ - @ : [ ]`,
/// not starting with `-` (what `check_alias` in the app allows).
pub fn is_plain_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.starts_with('-')
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@:[]".contains(c))
}

/// A host name (letters, digits, `.`, `-`, `_`, not starting with `-` or
/// `.`) or an IP address.
fn is_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= MAX_HOST
        && !host.starts_with(['-', '.'])
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// An IPv6 address in brackets, as `ssh` reads it in a forward.
fn bracketed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// What `tunnels.json` holds.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TunnelFile {
    version: u32,
    tunnels: Vec<Tunnel>,
}

/// `tunnels.json` in the app's data folder.
#[derive(Debug, Clone)]
pub struct TunnelStore {
    path: PathBuf,
}

impl TunnelStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The saved tunnels in the order they were added. A missing file is
    /// none; an entry that no longer passes the checks is left out.
    pub fn load(&self) -> Result<Vec<Tunnel>> {
        let bytes = match fsutil::read_limited(&self.path, 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(Error::NotFound(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let file: TunnelFile = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Parse(format!("{}: {e}", self.path.display())))?;
        Ok(file
            .tunnels
            .into_iter()
            .filter(|t| !t.id.is_empty() && t.validate().is_ok())
            .take(MAX_TUNNELS)
            .collect())
    }

    /// Adds `tunnel` (an empty `id`) or replaces the one with its id, after
    /// the checks; fails with `already_exists` if another one listens on
    /// the same port. Returns it as saved.
    pub fn save(&self, mut tunnel: Tunnel) -> Result<Tunnel> {
        tunnel.name = tunnel.name.trim().to_owned();
        tunnel.bind_address = tunnel
            .bind_address
            .map(|b| b.trim().to_owned())
            .filter(|b| !b.is_empty());
        tunnel.target_host = tunnel
            .target_host
            .map(|h| h.trim().to_owned())
            .filter(|h| !h.is_empty());
        tunnel.validate()?;
        let mut tunnels = self.load()?;
        if tunnel.id.is_empty() {
            if tunnels.len() >= MAX_TUNNELS {
                return Err(Error::invalid(format!(
                    "at most {MAX_TUNNELS} tunnels can be saved"
                )));
            }
            tunnel.id = new_id();
        } else if !tunnels.iter().any(|t| t.id == tunnel.id) {
            return Err(Error::NotFound(format!("tunnel {}", tunnel.id)));
        }
        if let Some(other) = tunnels.iter().find(|t| t.clashes_with(&tunnel)) {
            return Err(Error::AlreadyExists(format!(
                "port {} is already used by the tunnel {}",
                tunnel.listen_port,
                other.label()
            )));
        }
        match tunnels.iter_mut().find(|t| t.id == tunnel.id) {
            Some(saved) => *saved = tunnel.clone(),
            None => tunnels.push(tunnel.clone()),
        }
        self.write(tunnels)?;
        Ok(tunnel)
    }

    /// Removes the tunnel `id`; one that isn't saved is no error.
    pub fn remove(&self, id: &str) -> Result<()> {
        let mut tunnels = self.load()?;
        let before = tunnels.len();
        tunnels.retain(|t| t.id != id);
        if tunnels.len() != before {
            self.write(tunnels)?;
        }
        Ok(())
    }

    fn write(&self, tunnels: Vec<Tunnel>) -> Result<()> {
        let file = TunnelFile {
            version: FILE_VERSION,
            tunnels,
        };
        let mut json = serde_json::to_vec_pretty(&file)
            .map_err(|e| Error::Parse(format!("encoding tunnels: {e}")))?;
        json.push(b'\n');
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| Error::io(e, dir))?;
        }
        fsutil::atomic_write(&self.path, &json, 0o600)
    }
}

/// 128 random bits in hex.
fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().fold(String::new(), |mut hex, b| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn local(port: u16) -> Tunnel {
        Tunnel {
            id: String::new(),
            name: String::new(),
            alias: "web".into(),
            kind: TunnelKind::Local,
            bind_address: None,
            listen_port: port,
            target_host: Some("localhost".into()),
            target_port: Some(80),
            auto_reconnect: false,
        }
    }

    #[test]
    fn forwards_and_config_lines() {
        let mut tunnel = local(8080);
        assert_eq!(tunnel.forward_spec(), "localhost:8080:localhost:80");
        assert_eq!(
            tunnel.config_line(),
            ("LocalForward".into(), "localhost:8080 localhost:80".into())
        );
        assert_eq!(
            tunnel.browser_url().as_deref(),
            Some("http://localhost:8080/")
        );
        assert!(!tunnel.exposed());

        tunnel.bind_address = Some("::1".into());
        tunnel.target_host = Some("fd00::5".into());
        tunnel.target_port = Some(443);
        assert_eq!(tunnel.forward_spec(), "[::1]:8080:[fd00::5]:443");
        assert_eq!(tunnel.browser_url().as_deref(), Some("https://[::1]:8080/"));

        tunnel.kind = TunnelKind::Remote;
        tunnel.bind_address = None;
        tunnel.target_host = Some("127.0.0.1".into());
        tunnel.target_port = Some(3000);
        assert_eq!(tunnel.forward_spec(), "8080:127.0.0.1:3000");
        assert_eq!(
            tunnel.config_line(),
            ("RemoteForward".into(), "8080 127.0.0.1:3000".into())
        );
        assert_eq!(tunnel.browser_url(), None);

        let socks = Tunnel {
            kind: TunnelKind::Dynamic,
            bind_address: Some("*".into()),
            target_host: None,
            target_port: None,
            ..local(1080)
        };
        assert_eq!(socks.forward_spec(), "*:1080");
        assert_eq!(socks.config_line().1, "*:1080");
        assert!(socks.exposed());
        let args = socks.ssh_args();
        assert_eq!(args[0], "-N");
        assert!(args.contains(&"ExitOnForwardFailure=yes".to_owned()));
        assert!(args.contains(&"ServerAliveInterval=15".to_owned()));
        assert_eq!(&args[args.len() - 4..], ["-D", "*:1080", "--", "web"]);
    }

    #[test]
    fn checks_what_reaches_ssh() {
        assert!(local(8080).validate().is_ok());
        let bad = [
            Tunnel {
                alias: "-oProxyCommand=x".into(),
                ..local(1)
            },
            Tunnel {
                alias: "a b".into(),
                ..local(1)
            },
            local(0),
            Tunnel {
                bind_address: Some("example.com".into()),
                ..local(1)
            },
            Tunnel {
                target_host: Some("-x".into()),
                ..local(1)
            },
            Tunnel {
                target_host: Some("a:b@c".into()),
                ..local(1)
            },
            Tunnel {
                target_host: None,
                ..local(1)
            },
            Tunnel {
                target_port: Some(0),
                ..local(1)
            },
            Tunnel {
                kind: TunnelKind::Dynamic,
                ..local(1)
            },
            Tunnel {
                name: "two\nlines".into(),
                ..local(1)
            },
        ];
        for tunnel in bad {
            let error = tunnel.validate().expect_err(&format!("{tunnel:?}"));
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }

    #[test]
    fn the_store_keeps_tunnels_and_refuses_a_taken_port() {
        let dir = tempfile::tempdir().unwrap();
        let store = TunnelStore::new(dir.path().join("data/tunnels.json"));
        assert_eq!(store.load().unwrap(), []);

        let saved = store
            .save(Tunnel {
                name: "  Web  ".into(),
                bind_address: Some(" ".into()),
                ..local(8080)
            })
            .unwrap();
        assert_eq!(saved.id.len(), 32);
        assert_eq!(saved.name, "Web");
        assert_eq!(saved.bind_address, None);
        assert_eq!(store.load().unwrap(), std::slice::from_ref(&saved));

        let error = store.save(local(8080)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        // The server's port 8080 is another port.
        let remote = Tunnel {
            kind: TunnelKind::Remote,
            ..local(8080)
        };
        let remote = store.save(remote).unwrap();
        // Editing a tunnel keeps its own port.
        let edited = store
            .save(Tunnel {
                auto_reconnect: true,
                ..saved.clone()
            })
            .unwrap();
        assert!(edited.auto_reconnect);
        assert_eq!(store.load().unwrap(), [edited, remote.clone()]);

        let unknown = store
            .save(Tunnel {
                id: "nope".into(),
                ..local(9)
            })
            .unwrap_err();
        assert_eq!(unknown.code(), ErrorCode::NotFound);

        store.remove(&saved.id).unwrap();
        store.remove("missing").unwrap();
        assert_eq!(store.load().unwrap(), [remote]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_file_edited_by_hand_loses_only_what_fails_the_checks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnels.json");
        std::fs::write(
            &path,
            r#"{"version":1,"tunnels":[
                {"id":"a","alias":"web","kind":"local","listenPort":80,"targetHost":"x","targetPort":1},
                {"id":"b","alias":"$(id)","kind":"local","listenPort":81,"targetHost":"x","targetPort":1},
                {"id":"","alias":"web","kind":"dynamic","listenPort":82}
            ]}"#,
        )
        .unwrap();
        let tunnels = TunnelStore::new(&path).load().unwrap();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].id, "a");
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(
            TunnelStore::new(&path).load().unwrap_err().code(),
            ErrorCode::Parse
        );
    }

    #[test]
    fn labels() {
        assert_eq!(local(8080).label(), "8080 → localhost:80 (web)");
        let named = Tunnel {
            name: "Grafana".into(),
            ..local(3000)
        };
        assert_eq!(named.label(), "Grafana (web)");
    }
}
