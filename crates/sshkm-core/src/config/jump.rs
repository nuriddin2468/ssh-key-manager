//! `ProxyJump` for several hosts at once, as the ProxyJump wizard sets it.

use super::{HostEdit, HostKind, HostOption, SshConfig};
use crate::{Error, Result};

impl SshConfig {
    /// Sets `ProxyJump` to `jump` in each of the `targets` blocks, or
    /// removes it (`None`), through [`upsert_host`](Self::upsert_host): only
    /// that line of each block changes. A block's later `ProxyJump` lines,
    /// which `ssh` ignores, go too.
    ///
    /// `jump` is one or more `[user@]host[:port]`, comma-separated, plain
    /// names only (as the app's `ssh` runs check aliases). Fails if a
    /// target isn't a `Host` block, if `jump` names one of the targets, or
    /// if the jump host's own block jumps through one of them: either way
    /// `ssh` would go round in a circle.
    pub fn set_proxy_jump(&mut self, targets: &[u32], jump: Option<&str>) -> Result<()> {
        let jump = jump.map(str::trim).filter(|j| !j.is_empty());
        if let Some(jump) = jump
            && !is_jump(jump)
        {
            return Err(Error::invalid(
                "the jump host must be [user@]host[:port], comma-separated, \
                 with letters, digits and . _ - only",
            ));
        }
        let hosts = self.hosts();
        let mut edits = Vec::new();
        for id in targets {
            let host = hosts
                .iter()
                .find(|h| h.id == *id)
                .ok_or_else(|| Error::NotFound(format!("host block {id}")))?;
            if host.kind != HostKind::Host {
                return Err(Error::Unsupported("ProxyJump in Match blocks".into()));
            }
            if let Some(jump) = jump {
                let hops: Vec<&str> = jump.split(',').map(hop_host).collect();
                if host.patterns.iter().any(|p| hops.contains(&p.as_str())) {
                    return Err(Error::invalid(format!(
                        "{} can't jump through itself",
                        host.patterns.join(" ")
                    )));
                }
                // The first hop's own block, if it jumps through this one.
                let through_target = hosts
                    .iter()
                    .filter(|h| h.kind == HostKind::Host && h.patterns.iter().any(|p| p == hops[0]))
                    .filter_map(|h| h.proxy_jump.as_deref())
                    .flat_map(|j| j.split(','))
                    .any(|hop| host.patterns.iter().any(|p| p == hop_host(hop)));
                if through_target {
                    return Err(Error::invalid(format!(
                        "{} already jumps through {}",
                        hops[0],
                        host.patterns.join(" ")
                    )));
                }
            }
            let mut options = Vec::with_capacity(host.options.len() + 1);
            let mut set = false;
            for option in &host.options {
                if !option.key.eq_ignore_ascii_case("proxyjump") {
                    options.push(option.clone());
                } else if let (Some(jump), false) = (jump, set) {
                    options.push(HostOption::new(option.key.clone(), jump));
                    set = true;
                }
            }
            if let (Some(jump), false) = (jump, set) {
                options.push(HostOption::new("ProxyJump", jump));
            }
            edits.push(HostEdit {
                id: Some(*id),
                patterns: host.patterns.clone(),
                options,
            });
        }
        for edit in &edits {
            self.upsert_host(edit)?;
        }
        Ok(())
    }
}

/// One or more `[user@]host[:port]`, or `none`.
fn is_jump(jump: &str) -> bool {
    jump == "none"
        || jump.split(',').all(|hop| {
            let (user, rest) = hop.split_once('@').unwrap_or(("x", hop));
            let (host, port) = rest.rsplit_once(':').unwrap_or((rest, "22"));
            let name = |s: &str| {
                !s.is_empty()
                    && !s.starts_with(['-', '.'])
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            };
            name(user) && name(host) && port.parse::<u16>().is_ok_and(|p| p > 0)
        })
}

/// The host of a hop: `alice@bastion:2222` → `bastion`.
fn hop_host(hop: &str) -> &str {
    let rest = hop.rsplit_once('@').map_or(hop, |(_, rest)| rest);
    rest.split_once(':').map_or(rest, |(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    const CONFIG: &str = "\
Host bastion
  HostName bastion.example.com
  User admin

Host web db
  HostName 10.0.0.5
  ProxyJump old
  ProxyJump ignored

Host cache
  HostName 10.0.0.6

Host *
  ServerAliveInterval 30
";

    fn ids(config: &SshConfig, names: &[&str]) -> Vec<u32> {
        config
            .hosts()
            .into_iter()
            .filter(|h| names.iter().any(|n| h.patterns.contains(&(*n).to_owned())))
            .map(|h| h.id)
            .collect()
    }

    #[test]
    fn sets_and_removes_only_proxyjump_lines() {
        let mut config = SshConfig::parse(CONFIG);
        let targets = ids(&config, &["web", "cache"]);
        config.set_proxy_jump(&targets, Some("bastion")).unwrap();
        let text = config.to_string();
        assert_eq!(
            text,
            CONFIG
                .replace(
                    "  ProxyJump old\n  ProxyJump ignored\n",
                    "  ProxyJump bastion\n"
                )
                .replace(
                    "  HostName 10.0.0.6\n",
                    "  HostName 10.0.0.6\n  ProxyJump bastion\n"
                )
        );
        config.set_proxy_jump(&targets, None).unwrap();
        assert!(!config.to_string().contains("ProxyJump"));
    }

    #[test]
    fn refuses_circles_and_odd_values() {
        let mut config = SshConfig::parse(CONFIG);
        let web = ids(&config, &["web"]);
        let bastion = ids(&config, &["bastion"]);
        for bad in [
            "web",
            "admin@db:22",
            "bastion;id",
            "-oProxyCommand=x",
            "a b",
            "h:0",
        ] {
            let error = config.set_proxy_jump(&web, Some(bad)).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{bad}");
        }
        // bastion → web while web → bastion would be a circle.
        config.set_proxy_jump(&bastion, Some("cache")).unwrap();
        let cache = ids(&config, &["cache"]);
        let error = config.set_proxy_jump(&cache, Some("bastion")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        let missing = config.set_proxy_jump(&[999], Some("bastion")).unwrap_err();
        assert_eq!(missing.code(), ErrorCode::NotFound);
        // A chain and a user and port are fine.
        config
            .set_proxy_jump(&web, Some("admin@bastion:2222,cache"))
            .unwrap();
    }
}
