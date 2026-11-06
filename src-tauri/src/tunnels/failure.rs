//! Why a tunnel's `ssh` stopped, from what it printed and what was asked.

use serde::Serialize;

use crate::terminal::text;
use crate::terminal::types::{FailReason, Failure};

/// Why a tunnel is not up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum TunnelFailReason {
    /// The port can't be had here: another program listens on it, or it
    /// needs administrator rights.
    PortUnavailable,
    /// The server refused to listen on the port of a remote tunnel.
    ForwardRefused,
    /// Signed in, then the connection ended: the network or the server went
    /// away.
    ConnectionLost,
    PasswordRejected,
    OneTimeCodeRejected,
    OneTimeCodeMissing,
    /// The server refused the keys and no password was asked.
    NotAccepted,
    HostKeyNotTrusted,
    HostKeyChanged,
    Unreachable,
    /// A password or passphrase prompt was cancelled or not answered.
    Cancelled,
    Other,
}

impl TunnelFailReason {
    /// Worth trying again by itself: the network, a busy port, a server that
    /// went away. Not what needs the user: a password, a host key.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::ConnectionLost | Self::Unreachable | Self::PortUnavailable | Self::Other
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct TunnelFailure {
    pub reason: TunnelFailReason,
    /// The exit code of `ssh`, if it exited by itself.
    pub exit_code: Option<i32>,
    /// What `ssh` printed, without its own sign-in notes. Never holds an
    /// answer: those go through askpass.
    pub output: String,
}

/// `ssh`'s lines a user needn't read: the `LogLevel=VERBOSE` notes the
/// tunnel watches for, and the byte counts printed on the way out.
pub fn shown_output(output: &str) -> String {
    output
        .lines()
        .filter(|line| {
            !line.starts_with("Authenticated to ")
                && !line.starts_with("Transferred: ")
                && !line.starts_with("Bytes per second: ")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

/// Why `ssh` stopped. `output` is what it printed; `signed_in`, whether it
/// got that far; `login` the prompt bridge's reading of the sign-in.
pub fn classify(output: &str, signed_in: bool, login: &Failure) -> TunnelFailReason {
    if says_port_unavailable(output) {
        TunnelFailReason::PortUnavailable
    } else if output.contains("remote port forwarding failed") {
        TunnelFailReason::ForwardRefused
    } else if signed_in {
        TunnelFailReason::ConnectionLost
    } else {
        match login.reason {
            FailReason::PasswordRejected => TunnelFailReason::PasswordRejected,
            FailReason::OneTimeCodeRejected => TunnelFailReason::OneTimeCodeRejected,
            FailReason::OneTimeCodeMissing => TunnelFailReason::OneTimeCodeMissing,
            FailReason::NotAccepted => TunnelFailReason::NotAccepted,
            FailReason::HostKeyNotTrusted => TunnelFailReason::HostKeyNotTrusted,
            FailReason::HostKeyChanged => TunnelFailReason::HostKeyChanged,
            FailReason::Unreachable => TunnelFailReason::Unreachable,
            FailReason::Cancelled => TunnelFailReason::Cancelled,
            FailReason::Other if text::says_unreachable(output) => TunnelFailReason::Unreachable,
            FailReason::Other => TunnelFailReason::Other,
        }
    }
}

/// `bind [127.0.0.1]:8080: Address already in use`, `… Permission denied`,
/// `Could not request local forwarding.`
fn says_port_unavailable(output: &str) -> bool {
    output.lines().any(|line| {
        (line.starts_with("bind ") && line.contains("]:"))
            || line.contains("cannot listen to port")
            || line.contains("Could not request local forwarding")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(reason: FailReason) -> Failure {
        Failure {
            reason,
            saved: false,
            exit_code: Some(255),
            output: String::new(),
            diagnosis: None,
        }
    }

    /// What OpenSSH 9.9 prints with `LogLevel=VERBOSE`.
    #[test]
    fn reads_what_ssh_prints() {
        let busy = "Authenticated to 127.0.0.1 ([127.0.0.1]:52702) using \"publickey\".\n\
                    bind [127.0.0.1]:18081: Address already in use\n\
                    channel_setup_fwd_listener_tcpip: cannot listen to port: 18081\n\
                    Could not request local forwarding.\n";
        assert_eq!(
            classify(busy, true, &login(FailReason::Other)),
            TunnelFailReason::PortUnavailable
        );
        assert_eq!(
            shown_output(busy),
            "bind [127.0.0.1]:18081: Address already in use\n\
             channel_setup_fwd_listener_tcpip: cannot listen to port: 18081\n\
             Could not request local forwarding."
        );
        let refused = "Authenticated to h ([10.0.0.1]:22) using \"publickey\".\n\
                       Error: remote port forwarding failed for listen port 80\n";
        assert_eq!(
            classify(refused, true, &login(FailReason::Other)),
            TunnelFailReason::ForwardRefused
        );
        let lost = "Authenticated to h ([10.0.0.1]:22) using \"publickey\".\n\
                    Timeout, server h not responding.\n";
        assert_eq!(
            classify(lost, true, &login(FailReason::Other)),
            TunnelFailReason::ConnectionLost
        );
        assert_eq!(
            classify(
                "ssh: connect to host h port 22: Connection refused\n",
                false,
                &login(FailReason::Unreachable)
            ),
            TunnelFailReason::Unreachable
        );
        assert_eq!(
            classify(
                "Permission denied (publickey).\n",
                false,
                &login(FailReason::NotAccepted)
            ),
            TunnelFailReason::NotAccepted
        );
        assert!(TunnelFailReason::ConnectionLost.retryable());
        assert!(!TunnelFailReason::HostKeyNotTrusted.retryable());
        assert!(!TunnelFailReason::ForwardRefused.retryable());
    }
}
