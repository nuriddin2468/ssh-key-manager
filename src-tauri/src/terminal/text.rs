//! Reading what `ssh` says: its host-key question, its configuration
//! (`ssh -G`) and the messages it prints before signing in.

use std::path::Path;

/// The parts of a host-key question the "Trust" dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyQuestion {
    pub host: String,
    pub key_type: String,
    pub fingerprint: String,
    /// The lines besides the plain question, as `ssh` wrote them: the other
    /// names the key is known by, what DNS says, anything unrecognised.
    pub extra: Vec<String>,
    /// `ssh` says "but keys of different type are already known for this
    /// host": the host is known, by another key.
    pub other_types_known: bool,
}

/// Reads `ssh`'s question about an unknown host key:
///
/// ```text
/// The authenticity of host 'example.com (93.184.216.34)' can't be established.
/// ED25519 key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
/// This key is not known by any other names.
/// Are you sure you want to continue connecting (yes/no/[fingerprint])?
/// ```
///
/// Any other line (the key's random art aside) goes to
/// [`extra`](HostKeyQuestion::extra). `None` for anything else, such as the
/// warning that a host's key differs from its IP address's: those are not
/// offered for trust.
pub fn host_key_question(text: &str) -> Option<HostKeyQuestion> {
    let host = text
        .split_once("authenticity of host '")
        .and_then(|(_, rest)| rest.split_once('\''))
        .map(|(host, _)| host.trim().to_owned())?;
    let (key_type, fingerprint) = text.lines().find_map(|line| {
        let (before, after) = line.trim().split_once(" key fingerprint is ")?;
        let fingerprint = after.split_whitespace().next()?.trim_end_matches('.');
        let key_type = before.split_whitespace().last()?;
        (!fingerprint.is_empty()).then(|| (key_type.to_owned(), fingerprint.to_owned()))
    })?;
    let plain = |line: &str| {
        line.is_empty()
            || line.starts_with("The authenticity of host '")
            || line.contains(" key fingerprint is ")
            || line.starts_with("This key is not known by any other names")
            || line.starts_with("Are you sure you want to continue connecting")
            // VisualHostKey's random art.
            || line.starts_with(['+', '|'])
    };
    let extra: Vec<String> = text
        .lines()
        .map(str::trim_end)
        .filter(|line| !plain(line.trim_start()))
        .map(str::to_owned)
        .collect();
    let other_types_known = extra
        .iter()
        .any(|line| line.contains("keys of different type are already known"));
    Some(HostKeyQuestion {
        host,
        key_type,
        fingerprint,
        extra,
        other_types_known,
    })
}

/// What `ssh -G <alias>` says about the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    pub user: Option<String>,
    pub host_name: Option<String>,
    pub host_key_alias: Option<String>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub pubkey_authentication: bool,
    pub keyboard_interactive: bool,
    pub identities_only: bool,
    pub identity_files: Vec<String>,
}

impl Resolved {
    /// Reads `ssh -G` output: one `keyword value` per line, keywords in
    /// lower case.
    pub fn parse(text: &str) -> Self {
        let mut resolved = Self {
            pubkey_authentication: true,
            keyboard_interactive: true,
            ..Self::default()
        };
        for line in text.lines() {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            let value = value.trim();
            match key {
                "user" => {
                    resolved.user.get_or_insert_with(|| value.to_owned());
                }
                "hostname" => {
                    resolved.host_name.get_or_insert_with(|| value.to_owned());
                }
                "hostkeyalias" => {
                    resolved
                        .host_key_alias
                        .get_or_insert_with(|| value.to_owned());
                }
                "proxyjump" if value != "none" => {
                    resolved.proxy_jump.get_or_insert_with(|| value.to_owned());
                }
                "proxycommand" if value != "none" => {
                    resolved
                        .proxy_command
                        .get_or_insert_with(|| value.to_owned());
                }
                "pubkeyauthentication" => resolved.pubkey_authentication = value != "no",
                "kbdinteractiveauthentication" => resolved.keyboard_interactive = value != "no",
                "identitiesonly" => resolved.identities_only = value == "yes",
                "identityfile" => resolved.identity_files.push(value.to_owned()),
                _ => {}
            }
        }
        resolved
    }

    /// Whether `ssh` offers a key before a password: public-key login is on
    /// and one of its key files exists (or, unless `IdentitiesOnly`, the agent
    /// holds keys; `agent_has_keys` is asked only then).
    pub fn offers_key(&self, home: &Path, agent_has_keys: impl FnOnce() -> bool) -> bool {
        if !self.pubkey_authentication {
            return false;
        }
        let file_exists = self.identity_files.iter().any(|file| {
            if file.contains('%') {
                return false;
            }
            let path = match file.strip_prefix("~/") {
                Some(rest) => home.join(rest),
                None => Path::new(file).to_path_buf(),
            };
            path.exists()
        });
        file_exists || (!self.identities_only && agent_has_keys())
    }

    /// Through a `ProxyJump` or `ProxyCommand`.
    pub fn proxied(&self) -> bool {
        self.proxy_jump.is_some() || self.proxy_command.is_some()
    }
}

/// Removes terminal escape sequences (colours, cursor moves, titles) and
/// carriage returns, leaving the text.
pub fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                // CSI: parameters and intermediates, then a final byte.
                Some('[') => {
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: up to BEL or ST.
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' {
                            chars.next_if_eq(&'\\');
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\r' => {}
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

/// Messages `ssh` prints before signing in (and on failing to), as opposed
/// to the remote session's output.
pub fn is_ssh_message(line: &str) -> bool {
    const STARTS: [&str; 18] = [
        "Warning: Permanently added",
        "Warning: ",
        "@@@",
        "ssh: ",
        "Could not ",
        "kex_exchange_identification",
        "Connection ",
        "Permission denied",
        "Host key verification failed",
        "Authenticated with partial success",
        "Received disconnect",
        "Disconnected from",
        "banner exchange",
        "Bad owner or permissions",
        "Load key",
        "no such identity",
        "Too many authentication failures",
        "Enter passphrase",
    ];
    let line = line.trim();
    line.is_empty() || STARTS.iter().any(|start| line.starts_with(start))
}

/// Whether all of `chunk` is `ssh`'s own messages (see [`is_ssh_message`]).
pub fn only_ssh_messages(chunk: &str) -> bool {
    strip_escapes(chunk).lines().all(is_ssh_message)
}

/// `ssh` printed that the server's key changed.
pub fn says_host_key_changed(output: &str) -> bool {
    output.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
        || output.contains("HOST KEY HAS CHANGED")
}

pub fn says_host_key_failed(output: &str) -> bool {
    output.contains("Host key verification failed")
}

pub fn says_unreachable(output: &str) -> bool {
    const SIGNS: [&str; 12] = [
        "Could not resolve hostname",
        "Name or service not known",
        "nodename nor servname",
        "No such host is known",
        "Connection refused",
        "Connection timed out",
        "Operation timed out",
        "No route to host",
        "Network is unreachable",
        "kex_exchange_identification",
        "Connection closed by UNKNOWN",
        ": connect to host ",
    ];
    SIGNS.iter().any(|sign| output.contains(sign))
}

pub fn says_permission_denied(output: &str) -> bool {
    output.contains("Permission denied") || output.contains("Too many authentication failures")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_host_key_questions() {
        let modern = "The authenticity of host 'bastion.example.net (203.0.113.7)' can't be \
                      established.\nED25519 key fingerprint is \
                      SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.\nThis key is not known \
                      by any other names.\nAre you sure you want to continue connecting \
                      (yes/no/[fingerprint])? ";
        assert_eq!(
            host_key_question(modern),
            Some(HostKeyQuestion {
                host: "bastion.example.net (203.0.113.7)".into(),
                key_type: "ED25519".into(),
                fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".into(),
                extra: Vec::new(),
                other_types_known: false,
            })
        );
        let proxied = "The authenticity of host 'prod (<no hostip for proxy command>)' can't be \
                       established.\nECDSA key fingerprint is MD5:aa:bb:cc.\n+---[ECDSA \
                       256]---+\n|   art   |\n+----[MD5]-----+\nAre you sure you want to \
                       continue connecting (yes/no)? ";
        let question = host_key_question(proxied).unwrap();
        assert_eq!(question.key_type, "ECDSA");
        assert_eq!(question.fingerprint, "MD5:aa:bb:cc");
        assert_eq!(question.host, "prod (<no hostip for proxy command>)");
        assert!(question.extra.is_empty(), "{:?}", question.extra);

        let mismatch = "Warning: the ECDSA host key for 'example.com' differs from the key for \
                        the IP address '93.184.216.34'\nOffending key for IP in \
                        /home/alice/.ssh/known_hosts:3\nAre you sure you want to continue \
                        connecting (yes/no)? ";
        assert_eq!(host_key_question(mismatch), None);
        assert_eq!(host_key_question("Password: "), None);
    }

    #[test]
    fn keeps_what_host_key_questions_say_besides() {
        // sshconnect.c, when the host is known by a key of another type.
        let other_type = "The authenticity of host 'prod.example (10.0.4.12)' can't be \
                          established\nbut keys of different type are already known for this \
                          host.\nECDSA key fingerprint is SHA256:abc.\nAre you sure you want to \
                          continue connecting (yes/no/[fingerprint])? ";
        let question = host_key_question(other_type).unwrap();
        assert!(question.other_types_known);
        assert_eq!(
            question.extra,
            ["but keys of different type are already known for this host."]
        );

        let other_names = "The authenticity of host 'db (10.0.4.20)' can't be established.\n\
                           ED25519 key fingerprint is SHA256:abc.\nThis host key is known by the \
                           following other names/addresses:\n    ~/.ssh/known_hosts:3: \
                           db.example\n    ~/.ssh/known_hosts:9: 10.0.4.20\nNo matching host \
                           key fingerprint found in DNS.\nAre you sure you want to continue \
                           connecting (yes/no/[fingerprint])? ";
        let question = host_key_question(other_names).unwrap();
        assert!(!question.other_types_known);
        assert_eq!(
            question.extra,
            [
                "This host key is known by the following other names/addresses:",
                "    ~/.ssh/known_hosts:3: db.example",
                "    ~/.ssh/known_hosts:9: 10.0.4.20",
                "No matching host key fingerprint found in DNS.",
            ]
        );
    }

    #[test]
    fn reads_ssh_g() {
        let text = "host prod\nuser ubuntu\nhostname 10.0.4.12\nport 22\nproxyjump bastion\n\
                    pubkeyauthentication true\nidentitiesonly yes\nidentityfile \
                    ~/.ssh/id_ed25519_work\nidentityfile ~/.ssh/id_rsa\n";
        let resolved = Resolved::parse(text);
        assert_eq!(resolved.user.as_deref(), Some("ubuntu"));
        assert_eq!(resolved.host_name.as_deref(), Some("10.0.4.12"));
        assert_eq!(resolved.proxy_jump.as_deref(), Some("bastion"));
        assert!(resolved.pubkey_authentication && resolved.identities_only);
        assert_eq!(resolved.identity_files.len(), 2);

        assert!(resolved.proxied() && resolved.keyboard_interactive);

        let plain = Resolved::parse(
            "user a\nhostname h\nproxyjump none\nproxycommand none\npubkeyauthentication \
             no\nkbdinteractiveauthentication no\n",
        );
        assert_eq!(plain.proxy_jump, None);
        assert!(!plain.pubkey_authentication);
        assert!(!plain.proxied() && !plain.keyboard_interactive);

        let command = Resolved::parse("user a\nhostname h\nproxycommand nc %h %p\n");
        assert_eq!(command.proxy_command.as_deref(), Some("nc %h %p"));
        assert!(command.proxied());
    }

    #[test]
    fn knows_when_a_key_is_offered() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let mut resolved = Resolved::parse("identityfile ~/.ssh/id_ed25519\n");
        assert!(!resolved.offers_key(home.path(), || false));
        assert!(
            resolved.offers_key(home.path(), || true),
            "the agent's keys"
        );
        resolved.identities_only = true;
        assert!(!resolved.offers_key(home.path(), || true));
        std::fs::write(home.path().join(".ssh/id_ed25519"), "key").unwrap();
        assert!(resolved.offers_key(home.path(), || unreachable!("a file is enough")));
        resolved.pubkey_authentication = false;
        assert!(!resolved.offers_key(home.path(), || true));
    }

    #[test]
    fn strips_escapes() {
        assert_eq!(
            strip_escapes("\u{1b}[1;32mok\u{1b}[0m\r\n\u{1b}]0;title\u{7}done\u{1b}]2;t\u{1b}\\!"),
            "ok\ndone!"
        );
        assert_eq!(strip_escapes("a\u{7}b\tc"), "ab\tc");
    }

    #[test]
    fn tells_ssh_messages_from_the_session() {
        assert!(only_ssh_messages(
            "Warning: Permanently added 'h' (ED25519) to the list of known hosts.\r\n"
        ));
        assert!(only_ssh_messages(
            "ssh: connect to host h port 22: Connection refused\r\n"
        ));
        assert!(only_ssh_messages("\r\n"));
        assert!(!only_ssh_messages(
            "Welcome to Ubuntu 24.04.1 LTS\r\nubuntu@prod:~$ "
        ));
    }

    #[test]
    fn recognises_failures() {
        assert!(says_host_key_changed(
            "@@@@@@@@\r\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"
        ));
        assert!(says_host_key_failed("Host key verification failed.\r\n"));
        for text in [
            "ssh: Could not resolve hostname nope: nodename nor servname provided, or not known",
            "ssh: connect to host 10.0.0.1 port 22: Connection refused",
            "ssh: connect to host 10.0.0.1 port 22: Operation timed out",
            "kex_exchange_identification: read: Connection reset by peer",
        ] {
            assert!(says_unreachable(text), "{text}");
        }
        assert!(!says_unreachable(
            "ubuntu@h: Permission denied (publickey)."
        ));
        assert!(says_permission_denied(
            "ubuntu@h: Permission denied (publickey,password)."
        ));
    }
}
