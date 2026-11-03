//! Which saved logins belong to a web page.
//!
//! A login is offered on a page only when both are on the same *site*: the
//! same registrable domain, the name one label under a public suffix such as
//! `com`, `co.uk` or `github.io` (Mozilla's Public Suffix List, ICANN and
//! private sections). Names are compared exactly, after IDNA turns them into
//! lowercase ASCII. Nothing is fuzzy: a login for `example.com` gets nothing
//! on `examp1e.com`, `example.com.evil.io` or the same name spelt with a
//! Cyrillic `а`, and one for `alice.github.io` nothing on `bob.github.io`.
//!
//! Further:
//!
//! - only `https` and `http` pages and addresses take part;
//! - a login saved for `https` is never offered on `http`, so an attacker on
//!   the network cannot make an insecure copy of the page collect it;
//! - the port must be the same, the scheme's default when none is given;
//! - IP addresses, `localhost` and other names without a registrable domain
//!   must be the same host exactly;
//! - a saved address may lack the scheme (`github.com/login`): `https` is
//!   assumed.

use std::fmt;

use url::{Host, Url};

use crate::{Error, Result};

/// A web page's origin as the browser reports it, `https://host[:port]`, or a
/// saved login's address reduced to the same parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    secure: bool,
    /// Lowercase ASCII without a trailing dot; IPv6 in brackets.
    host: String,
    /// `None` for the scheme's default port.
    port: Option<u16>,
    /// The registrable domain, if the host has one.
    site: Option<String>,
}

/// How a saved address fits a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fit {
    /// Another host of the same site, e.g. `www.example.com` on
    /// `accounts.example.com`.
    Site,
    /// The same host.
    Host,
}

impl Origin {
    /// Parses the origin of a page. Fails for anything but `https://` and
    /// `http://` origins with a host, including the opaque origin `null`.
    pub fn parse(origin: &str) -> Result<Self> {
        let url = Url::parse(origin.trim()).map_err(|_| Error::invalid("not a web origin"))?;
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(Error::invalid("not a web origin"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::invalid("not a web origin"));
        }
        Self::from_url(&url).ok_or_else(|| Error::invalid("not a web origin"))
    }

    /// The address a login is saved under, if it is a web address.
    pub fn of_saved(address: &str) -> Option<Self> {
        let address = address.trim();
        if address.is_empty() || address.chars().any(char::is_whitespace) {
            return None;
        }
        let url = if address.contains("://") {
            Url::parse(address).ok()?
        } else {
            Url::parse(&format!("https://{address}")).ok()?
        };
        Self::from_url(&url)
    }

    fn from_url(url: &Url) -> Option<Self> {
        let secure = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let (host, site) = match url.host()? {
            Host::Domain(domain) => {
                let host = domain.strip_suffix('.').unwrap_or(domain);
                if host.is_empty() || host.contains("..") {
                    return None;
                }
                (host.to_owned(), registrable_domain(host))
            }
            Host::Ipv4(ip) => (ip.to_string(), None),
            Host::Ipv6(ip) => (format!("[{ip}]"), None),
        };
        Some(Self {
            secure,
            host,
            port: url.port(),
            site,
        })
    }

    /// The host, as ASCII.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// A short name for a new login: the site, or the host if it has none.
    pub fn name(&self) -> &str {
        self.site.as_deref().unwrap_or(&self.host)
    }

    /// How a saved address fits this page, or `None` if its login must not
    /// be offered here.
    pub fn fit(&self, saved_address: &str) -> Option<Fit> {
        let saved = Self::of_saved(saved_address)?;
        if saved.secure && !self.secure {
            return None;
        }
        if saved.port != self.port {
            return None;
        }
        if saved.host == self.host {
            return Some(Fit::Host);
        }
        match (&saved.site, &self.site) {
            (Some(saved), Some(page)) if saved == page => Some(Fit::Site),
            _ => None,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.secure { "https" } else { "http" };
        write!(f, "{scheme}://{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

/// The registrable domain of a lowercase ASCII host, `None` when the host is
/// a public suffix itself or has a single label (`localhost`).
fn registrable_domain(host: &str) -> Option<String> {
    let domain = psl::domain(host.as_bytes())?;
    let domain = std::str::from_utf8(domain.as_bytes()).ok()?;
    // The list's default rule makes any unknown last label a suffix, so a
    // two-label name like `printer.local` is a site of its own; a single label
    // never is.
    domain.contains('.').then(|| domain.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fit(saved: &str, page: &str) -> Option<Fit> {
        Origin::parse(page).unwrap().fit(saved)
    }

    #[test]
    fn same_host_and_same_site_match() {
        assert_eq!(
            fit("https://github.com", "https://github.com"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("https://github.com/login?x=1", "https://github.com"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("https://github.com", "https://gist.github.com"),
            Some(Fit::Site)
        );
        assert_eq!(
            fit("https://www.example.co.uk", "https://example.co.uk"),
            Some(Fit::Site)
        );
        assert_eq!(
            fit("HTTPS://GitHub.COM", "https://github.com"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("https://github.com.", "https://github.com"),
            Some(Fit::Host)
        );
    }

    #[test]
    fn look_alike_and_other_sites_get_nothing() {
        for page in [
            "https://github.com.evil.io",
            "https://githuh.com",
            "https://evilgithub.com",
            "https://github.co",
            "https://github.com-login.io",
            // Cyrillic "і" in place of the Latin "i".
            "https://g\u{0456}thub.com",
        ] {
            assert_eq!(fit("https://github.com", page), None, "{page}");
        }
        assert_eq!(fit("https://example.co.uk", "https://evil.co.uk"), None);
        assert_eq!(fit("https://example.co.uk", "https://co.uk"), None);
    }

    #[test]
    fn private_suffixes_separate_their_users() {
        assert_eq!(
            fit("https://alice.github.io", "https://bob.github.io"),
            None
        );
        assert_eq!(
            fit("https://alice.github.io", "https://alice.github.io"),
            Some(Fit::Host)
        );
        assert_eq!(fit("https://github.io", "https://alice.github.io"), None);
    }

    #[test]
    fn idna_names_compare_in_ascii() {
        assert_eq!(
            fit("https://bücher.de", "https://xn--bcher-kva.de"),
            Some(Fit::Host)
        );
        assert_eq!(fit("https://buecher.de", "https://xn--bcher-kva.de"), None);
    }

    #[test]
    fn https_logins_stay_off_http_pages() {
        assert_eq!(fit("https://example.com", "http://example.com"), None);
        assert_eq!(
            fit("http://example.com", "https://example.com"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("http://example.com", "http://example.com"),
            Some(Fit::Host)
        );
    }

    #[test]
    fn ports_must_agree() {
        assert_eq!(fit("https://example.com", "https://example.com:8443"), None);
        assert_eq!(fit("https://example.com:8443", "https://example.com"), None);
        assert_eq!(
            fit("https://example.com:443", "https://example.com"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("https://example.com:8443/admin", "https://example.com:8443"),
            Some(Fit::Host)
        );
    }

    #[test]
    fn addresses_and_local_names_match_exactly() {
        assert_eq!(
            fit("https://192.168.1.1:8443", "https://192.168.1.1:8443"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("https://192.168.1.1:8443", "https://192.168.1.10:8443"),
            None
        );
        assert_eq!(fit("https://10.0.0.1", "https://10.0.0.2"), None);
        assert_eq!(
            fit("http://[::1]:3000", "http://[::1]:3000"),
            Some(Fit::Host)
        );
        assert_eq!(
            fit("http://localhost:3000", "http://localhost:3000"),
            Some(Fit::Host)
        );
        assert_eq!(fit("http://localhost:3000", "http://localhost:3001"), None);
        assert_eq!(fit("http://intranet", "http://wiki.intranet"), None);
        assert_eq!(
            fit("http://a.printer.lan", "http://b.printer.lan"),
            Some(Fit::Site)
        );
        assert_eq!(fit("http://intranet", "http://intranet"), Some(Fit::Host));
        assert_eq!(fit("http://localhost", "http://other"), None);
    }

    #[test]
    fn saved_addresses_without_scheme_mean_https() {
        assert_eq!(
            fit("github.com/login", "https://github.com"),
            Some(Fit::Host)
        );
        assert_eq!(fit("github.com", "http://github.com"), None);
        assert_eq!(fit("www.github.com", "https://github.com"), Some(Fit::Site));
    }

    #[test]
    fn other_schemes_and_garbage_never_match() {
        for saved in [
            "",
            "   ",
            "ssh://github.com",
            "ftp://github.com",
            "android://com.github.android",
            "github com",
            "https://",
            "javascript:alert(1)",
        ] {
            assert_eq!(fit(saved, "https://github.com"), None, "{saved:?}");
        }
    }

    #[test]
    fn page_origins_must_be_web_origins() {
        for origin in [
            "null",
            "",
            "file:///etc/passwd",
            "chrome-extension://abc/",
            "moz-extension://abc",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com/?q",
            "data:text/html,hi",
        ] {
            assert!(Origin::parse(origin).is_err(), "{origin:?}");
        }
        let origin = Origin::parse("https://Accounts.Example.com:8443").unwrap();
        assert_eq!(origin.to_string(), "https://accounts.example.com:8443");
        assert_eq!(origin.host(), "accounts.example.com");
        assert_eq!(origin.name(), "example.com");
        assert_eq!(
            Origin::parse("http://localhost:3000").unwrap().name(),
            "localhost"
        );
        assert_eq!(
            Origin::parse("https://[::1]").unwrap().to_string(),
            "https://[::1]"
        );
    }
}
