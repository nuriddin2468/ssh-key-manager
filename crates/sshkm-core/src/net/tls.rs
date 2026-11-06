//! A server's TLS certificate: the chain it sends, whether this computer
//! trusts it for the host, and when it expires.
//!
//! The handshake goes on with a certificate the system doesn't trust, so the
//! chain can still be shown: the system verifier's verdict is recorded, not
//! enforced. That is safe only because nothing is ever sent over the
//! connection; it is closed right after the handshake.

use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, ProtocolVersion,
    SignatureScheme,
};
use serde::Serialize;
use time::OffsetDateTime;

use super::tcp::{check_port, connect_any};
use super::x509::{self, CertSummary};
use super::{Host, PortState, check_timeout, resolve};
use crate::{Error, Result};

/// Why the system doesn't trust a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum CertProblem {
    Expired,
    NotYetValid,
    /// Not issued by an authority the system trusts (or self-signed), or
    /// the server left out an intermediate certificate.
    UnknownIssuer,
    /// Not issued for this host name.
    NameMismatch,
    Revoked,
    Other,
}

/// A TLS handshake with a server, as far as its certificate goes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct TlsReport {
    /// What became of the TCP connection.
    pub state: PortState,
    pub address: Option<String>,
    pub addresses: Vec<String>,
    /// Why the connection or the handshake failed.
    pub message: Option<String>,
    /// The handshake finished.
    pub handshake: bool,
    /// What answered doesn't speak TLS.
    pub not_tls: bool,
    /// `TLS 1.3`.
    pub protocol: Option<String>,
    /// `TLS13_AES_256_GCM_SHA384`.
    pub cipher: Option<String>,
    /// The system trusts the certificate for the host.
    pub trusted: bool,
    pub problem: Option<CertProblem>,
    /// The verifier's words for the problem.
    pub problem_message: Option<String>,
    /// As the server sent it: its own certificate first.
    pub chain: Vec<CertSummary>,
}

/// Connects to `host:port`, makes a TLS handshake and checks the
/// certificate the way the operating system does (Security framework on
/// macOS, `CryptoAPI` on Windows, the system's certificates on Linux), which
/// may ask the certificate's authority whether it was revoked.
pub fn tls_check(host: &str, port: u16, timeout: Duration) -> Result<TlsReport> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(|e| Error::Unsupported(format!("the system's certificates: {e}")))?;
    check(
        host,
        port,
        timeout,
        &Settings {
            provider,
            verifier: Arc::new(verifier),
            time: Arc::new(DefaultTimeProvider),
        },
    )
}

impl TlsReport {
    fn blank() -> Self {
        Self {
            state: PortState::NoAddress,
            address: None,
            addresses: Vec::new(),
            message: None,
            handshake: false,
            not_tls: false,
            protocol: None,
            cipher: None,
            trusted: false,
            problem: None,
            problem_message: None,
            chain: Vec::new(),
        }
    }
}

struct Settings {
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
    time: Arc<dyn TimeProvider>,
}

fn check(host: &str, port: u16, timeout: Duration, settings: &Settings) -> Result<TlsReport> {
    let host = Host::parse(host)?;
    check_port(port)?;
    check_timeout(timeout)?;
    let name = match &host {
        Host::Name(name) => {
            ServerName::try_from(name.clone()).map_err(|_| Error::invalid("not a host name"))?
        }
        Host::Ip(ip) => ServerName::IpAddress((*ip).into()),
    };
    let mut report = TlsReport::blank();
    let addresses = match resolve(&host, port, timeout) {
        Ok(found) if !found.is_empty() => found,
        Ok(_) => {
            report.message = Some("no address".to_owned());
            return Ok(report);
        }
        Err(message) => {
            report.message = Some(message);
            return Ok(report);
        }
    };
    report.addresses = addresses.iter().map(|a| a.ip().to_string()).collect();
    let attempt = connect_any(&addresses, timeout);
    report.state = attempt.state;
    report.address = Some(attempt.address.ip().to_string());
    report.message = attempt.error.map(|e| e.to_string());
    if let Some((stream, _)) = attempt.connected {
        handshake(stream, name, timeout, settings, &mut report);
    }
    Ok(report)
}

fn handshake(
    mut stream: TcpStream,
    name: ServerName<'static>,
    timeout: Duration,
    settings: &Settings,
    report: &mut TlsReport,
) {
    let recording = Arc::new(Recording {
        inner: Arc::clone(&settings.verifier),
        seen: Mutex::new(None),
    });
    let config = ClientConfig::builder_with_details(
        Arc::clone(&settings.provider),
        Arc::clone(&settings.time),
    )
    .with_safe_default_protocol_versions()
    .map(|builder| {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::clone(&recording) as Arc<dyn ServerCertVerifier>)
            .with_no_client_auth()
    });
    let connection = config.and_then(|config| ClientConnection::new(Arc::new(config), name));
    let mut connection = match connection {
        Ok(connection) => connection,
        Err(error) => {
            report.message = Some(error.to_string());
            return;
        }
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let until = Instant::now() + timeout;
    let mut failure: Option<io::Error> = None;
    while connection.is_handshaking() {
        if Instant::now() >= until {
            failure = Some(io::ErrorKind::TimedOut.into());
            break;
        }
        if let Err(error) = connection.complete_io(&mut stream) {
            failure = Some(error);
            break;
        }
    }
    match failure {
        None => {
            report.handshake = true;
            report.protocol = connection.protocol_version().map(protocol_name);
            report.cipher = connection
                .negotiated_cipher_suite()
                .map(|suite| format!("{:?}", suite.suite()));
            connection.send_close_notify();
            let _ = connection.complete_io(&mut stream);
        }
        Some(error) => {
            let inner = error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>());
            report.not_tls = matches!(
                inner,
                Some(rustls::Error::InvalidMessage(_) | rustls::Error::InappropriateMessage { .. })
            );
            report.message = Some(match error.kind() {
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "no answer".to_owned(),
                _ => error.to_string(),
            });
        }
    }

    let now = settings
        .time
        .current_time()
        .and_then(|t| i64::try_from(t.as_secs()).ok())
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .unwrap_or_else(OffsetDateTime::now_utc);
    let seen = recording
        .seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(seen) = seen {
        report.chain = seen
            .chain
            .iter()
            .filter_map(|der| x509::summarize(der, now))
            .collect();
        match seen.verdict {
            Ok(()) => report.trusted = true,
            Err(error) => {
                report.problem = Some(problem_of(&error));
                report.problem_message = Some(error.to_string());
            }
        }
    }
}

fn protocol_name(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLS 1.3".to_owned(),
        ProtocolVersion::TLSv1_2 => "TLS 1.2".to_owned(),
        other => format!("{other:?}"),
    }
}

fn problem_of(error: &rustls::Error) -> CertProblem {
    let rustls::Error::InvalidCertificate(error) = error else {
        return CertProblem::Other;
    };
    match error {
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => CertProblem::Expired,
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            CertProblem::NotYetValid
        }
        CertificateError::UnknownIssuer => CertProblem::UnknownIssuer,
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            CertProblem::NameMismatch
        }
        CertificateError::Revoked => CertProblem::Revoked,
        _ => CertProblem::Other,
    }
}

/// The chain the server sent and the system's verdict on it.
struct Seen {
    chain: Vec<CertificateDer<'static>>,
    verdict: std::result::Result<(), rustls::Error>,
}

/// Asks `inner` about the certificate and keeps its answer, but lets the
/// handshake go on either way. Handshake signatures are still checked.
#[derive(Debug)]
struct Recording {
    inner: Arc<dyn ServerCertVerifier>,
    seen: Mutex<Option<Seen>>,
}

impl std::fmt::Debug for Seen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seen")
            .field("chain", &self.chain.len())
            .field("verdict", &self.verdict)
            .finish()
    }
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verdict = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map(|_| ());
        let chain = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|der| der.clone().into_owned())
            .collect();
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(Seen { chain, verdict });
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, ServerConnection};

    use super::*;
    use crate::net::fixtures::{CA, KEY, LEAF, OTHER};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// A TLS server on a loopback port that sends the test chain and then
    /// waits for the client to close.
    fn tls_server() -> u16 {
        let chain = vec![
            CertificateDer::from(LEAF.to_vec()),
            CertificateDer::from(CA.to_vec()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec()));
        let config = Arc::new(
            ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                while connection.is_handshaking() {
                    if connection.complete_io(&mut stream).is_err() {
                        break;
                    }
                }
            }
        });
        port
    }

    fn settings(root: &[u8], time: Arc<dyn TimeProvider>) -> Settings {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root.to_vec())).unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .unwrap();
        Settings {
            provider: provider(),
            verifier,
            time,
        }
    }

    #[derive(Debug)]
    struct Fixed(u64);

    impl TimeProvider for Fixed {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
        }
    }

    /// 2030-01-01, inside the test certificates' validity.
    fn in_2030() -> Arc<dyn TimeProvider> {
        Arc::new(Fixed(1_893_456_000))
    }

    #[test]
    fn a_trusted_chain_is_read() {
        let port = tls_server();
        let report = check("127.0.0.1", port, TIMEOUT, &settings(CA, in_2030())).unwrap();
        assert_eq!(report.state, PortState::Open);
        assert!(report.handshake, "{:?}", report.message);
        assert!(report.trusted, "{:?}", report.problem_message);
        assert_eq!(report.problem, None);
        assert_eq!(report.protocol.as_deref(), Some("TLS 1.3"));
        assert!(report.cipher.as_deref().unwrap().starts_with("TLS13_"));
        assert_eq!(report.chain.len(), 2);
        assert_eq!(report.chain[0].subject.as_deref(), Some("localhost"));
        assert_eq!(report.chain[1].subject.as_deref(), Some("SSHKM Test CA"));
        assert_eq!(report.chain[0].days_left, 6148);
    }

    #[test]
    fn an_unknown_issuer_still_shows_the_chain() {
        let port = tls_server();
        let report = check("127.0.0.1", port, TIMEOUT, &settings(OTHER, in_2030())).unwrap();
        assert!(report.handshake);
        assert!(!report.trusted);
        assert_eq!(report.problem, Some(CertProblem::UnknownIssuer));
        assert!(report.problem_message.is_some());
        assert_eq!(report.chain.len(), 2);
    }

    #[test]
    fn an_expired_certificate_is_reported() {
        let port = tls_server();
        let in_2050: Arc<dyn TimeProvider> = Arc::new(Fixed(2_524_608_000));
        let report = check("127.0.0.1", port, TIMEOUT, &settings(CA, in_2050)).unwrap();
        assert_eq!(report.problem, Some(CertProblem::Expired));
        assert!(report.chain[0].days_left < 0);
    }

    #[test]
    fn a_certificate_for_another_name_is_reported() {
        let port = tls_server();
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut report = TlsReport::blank();
        let name = ServerName::try_from("example.test").unwrap();
        handshake(stream, name, TIMEOUT, &settings(CA, in_2030()), &mut report);
        assert!(report.handshake);
        assert_eq!(report.problem, Some(CertProblem::NameMismatch));
        assert!(!report.trusted);
        assert_eq!(report.chain.len(), 2);
    }

    #[test]
    fn a_port_that_is_not_tls_is_told_apart() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.9\r\n");
            thread::sleep(Duration::from_millis(500));
        });
        let report = check("127.0.0.1", port, TIMEOUT, &settings(CA, in_2030())).unwrap();
        assert_eq!(report.state, PortState::Open);
        assert!(!report.handshake);
        assert!(report.not_tls, "{:?}", report.message);
        assert_eq!(report.chain, []);
    }

    #[test]
    fn a_closed_port_makes_no_handshake() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let report = check("127.0.0.1", port, TIMEOUT, &settings(CA, in_2030())).unwrap();
        assert_eq!(report.state, PortState::Closed);
        assert!(!report.handshake && !report.not_tls);
    }
}
