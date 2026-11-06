//! What became of each connection check and each in-app terminal session,
//! by host alias, so the hosts list can show where each server stands.
//!
//! Kept in `connection-history.json` in the app's data folder, newest first,
//! at most [`KEPT`] events a host. Only times and outcomes are kept: never
//! what `ssh` or the server printed, nor anything that was typed. Sessions
//! in an external terminal are not seen, so they are not recorded.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use sshkm_core::{ErrorCode, fsutil};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::askpass::{AskedPrompt, PromptKind, PromptOutcome};
use crate::error::{AppError, AppResult};
use crate::terminal::text;
use crate::terminal::types::FailReason;
use crate::types::ConnectionTest;

/// Events kept for each host.
pub const KEPT: usize = 20;

const FILE: &str = "connection-history.json";

/// One check or session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ConnectionEvent {
    /// When it started; RFC 3339, UTC.
    pub at: String,
    pub via: Via,
    pub outcome: Outcome,
    /// A session that signed in and has ended: how long it lasted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(test, ts(optional))]
    pub duration_secs: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    test,
    derive(ts_rs::TS),
    ts(export, export_to = crate::types::BINDINGS, rename = "ConnectionVia")
)]
pub enum Via {
    /// "Check connection".
    Check,
    /// A session in the in-app terminal.
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    test,
    derive(ts_rs::TS),
    ts(export, export_to = crate::types::BINDINGS, rename = "ConnectionOutcome")
)]
pub enum Outcome {
    SignedIn,
    PasswordRejected,
    OneTimeCodeRejected,
    /// A 2FA code was asked and none was given.
    OneTimeCodeMissing,
    /// A check: a password was asked and none is saved.
    PasswordMissing,
    /// A check: a key's passphrase was asked and neither the agent nor the
    /// vault has it.
    PassphraseMissing,
    /// The server refused the keys and no password was asked.
    KeysRejected,
    HostKeyUnknown,
    HostKeyChanged,
    Unreachable,
    Failed,
}

impl Outcome {
    /// What a check's run means; the same reading as the UI's `explain`.
    pub fn of_check(test: &ConnectionTest) -> Self {
        let asked = |kind: fn(&PromptKind) -> bool, outcome| {
            test.prompts
                .iter()
                .any(|p: &AskedPrompt| kind(&p.prompt.kind) && p.outcome == outcome)
        };
        let password = |k: &PromptKind| *k == PromptKind::Password;
        let code = |k: &PromptKind| *k == PromptKind::OneTimeCode;
        let passphrase = |k: &PromptKind| matches!(k, PromptKind::Passphrase { .. });
        let output = test.output.as_str();
        let denied = text::says_permission_denied(output);
        if test.ok {
            Self::SignedIn
        } else if text::says_host_key_changed(output) {
            Self::HostKeyChanged
        } else if asked(
            |k| *k == PromptKind::HostKeyConfirm,
            PromptOutcome::Declined,
        ) || text::says_host_key_failed(output)
        {
            Self::HostKeyUnknown
        } else if asked(password, PromptOutcome::Repeated) {
            Self::PasswordRejected
        } else if asked(code, PromptOutcome::Missing) {
            Self::OneTimeCodeMissing
        } else if asked(code, PromptOutcome::Repeated) {
            Self::OneTimeCodeRejected
        } else if asked(password, PromptOutcome::Missing) {
            Self::PasswordMissing
        } else if text::says_unreachable(output) {
            Self::Unreachable
        } else if asked(password, PromptOutcome::Answered) {
            // `ssh` asks for a password once: refused, or signed in and
            // `exit` failed.
            if denied {
                Self::PasswordRejected
            } else {
                Self::Failed
            }
        } else if asked(passphrase, PromptOutcome::Missing) {
            Self::PassphraseMissing
        } else if denied {
            Self::KeysRejected
        } else {
            Self::Failed
        }
    }

    /// Why a session stopped before signing in; `None` when the user
    /// cancelled, which says nothing about the server.
    pub fn of_failure(reason: FailReason) -> Option<Self> {
        Some(match reason {
            FailReason::PasswordRejected => Self::PasswordRejected,
            FailReason::OneTimeCodeRejected => Self::OneTimeCodeRejected,
            FailReason::OneTimeCodeMissing => Self::OneTimeCodeMissing,
            FailReason::NotAccepted => Self::KeysRejected,
            FailReason::HostKeyNotTrusted => Self::HostKeyUnknown,
            FailReason::HostKeyChanged => Self::HostKeyChanged,
            FailReason::Unreachable => Self::Unreachable,
            FailReason::Cancelled => return None,
            FailReason::Other => Self::Failed,
        })
    }
}

/// Events by alias, newest first.
pub type HostHistory = HashMap<String, Vec<ConnectionEvent>>;

/// The history file, read on first use.
pub struct History {
    path: PathBuf,
    hosts: Mutex<Option<HostHistory>>,
}

impl History {
    /// The history in the app's data folder `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(FILE),
            hosts: Mutex::new(None),
        }
    }

    pub fn all(&self) -> HostHistory {
        self.read().clone().unwrap_or_default()
    }

    /// Records `event` for `alias`, as the newest.
    pub fn record(&self, alias: &str, event: ConnectionEvent) -> AppResult<()> {
        self.change(|hosts| {
            let events = hosts.entry(alias.to_owned()).or_default();
            events.insert(0, event);
            events.truncate(KEPT);
            true
        })
    }

    /// Records a check run now.
    pub fn record_check(&self, alias: &str, test: &ConnectionTest) -> AppResult<()> {
        self.record(
            alias,
            ConnectionEvent {
                at: now(),
                via: Via::Check,
                outcome: Outcome::of_check(test),
                duration_secs: None,
            },
        )
    }

    /// The session of `alias` that started at `at` has ended after
    /// `duration_secs` signed in.
    pub fn session_ended(&self, alias: &str, at: &str, duration_secs: u32) -> AppResult<()> {
        self.change(|hosts| {
            let event = hosts.get_mut(alias).and_then(|events| {
                events
                    .iter_mut()
                    .find(|e| e.via == Via::Terminal && e.at == at && e.duration_secs.is_none())
            });
            match event {
                Some(event) => {
                    event.duration_secs = Some(duration_secs);
                    true
                }
                None => false,
            }
        })
    }

    /// Forgets the history of `alias`.
    pub fn clear(&self, alias: &str) -> AppResult<()> {
        self.change(|hosts| hosts.remove(alias).is_some())
    }

    fn read(&self) -> MutexGuard<'_, Option<HostHistory>> {
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        if hosts.is_none() {
            // A file that cannot be read starts the history over.
            *hosts = Some(
                std::fs::read(&self.path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                    .unwrap_or_default(),
            );
        }
        hosts
    }

    /// Applies `edit` and writes the file if it says it changed something.
    fn change(&self, edit: impl FnOnce(&mut HostHistory) -> bool) -> AppResult<()> {
        let mut guard = self.read();
        let hosts = guard.get_or_insert_with(HashMap::new);
        if !edit(hosts) {
            return Ok(());
        }
        if let Some(dir) = self.path.parent() {
            fsutil::ensure_private_dir(dir)?;
        }
        let json = serde_json::to_vec(hosts)
            .map_err(|e| AppError::new(ErrorCode::Io, format!("connection history: {e}")))?;
        fsutil::atomic_write(&self.path, &json, 0o600)?;
        Ok(())
    }
}

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::askpass::Prompt;

    fn test_run(ok: bool, output: &str, prompts: &[(PromptKind, PromptOutcome)]) -> ConnectionTest {
        ConnectionTest {
            ok,
            output: output.to_owned(),
            diagnosis: None,
            prompts: prompts
                .iter()
                .map(|(kind, outcome)| AskedPrompt {
                    prompt: Prompt {
                        text: String::new(),
                        kind: kind.clone(),
                        account: None,
                        from_server: false,
                    },
                    outcome: *outcome,
                })
                .collect(),
        }
    }

    fn event(at: &str, via: Via, outcome: Outcome) -> ConnectionEvent {
        ConnectionEvent {
            at: at.to_owned(),
            via,
            outcome,
            duration_secs: None,
        }
    }

    #[test]
    fn reads_what_a_check_says() {
        use PromptKind::{HostKeyConfirm, OneTimeCode, Password};
        use PromptOutcome::{Answered, Declined, Missing, Repeated};
        let denied = "git@example.com: Permission denied (publickey).";
        let passphrase = PromptKind::Passphrase {
            key: "/home/a/.ssh/id_ed25519".into(),
        };
        let cases = [
            (test_run(true, "", &[]), Outcome::SignedIn),
            (
                test_run(
                    false,
                    "@@@ REMOTE HOST IDENTIFICATION HAS CHANGED! @@@",
                    &[],
                ),
                Outcome::HostKeyChanged,
            ),
            (
                test_run(
                    false,
                    "Host key verification failed.",
                    &[(HostKeyConfirm, Declined)],
                ),
                Outcome::HostKeyUnknown,
            ),
            (
                test_run(false, denied, &[(Password, Repeated)]),
                Outcome::PasswordRejected,
            ),
            (
                test_run(false, denied, &[(Password, Answered)]),
                Outcome::PasswordRejected,
            ),
            (
                test_run(
                    false,
                    denied,
                    &[(Password, Answered), (OneTimeCode, Missing)],
                ),
                Outcome::OneTimeCodeMissing,
            ),
            (
                test_run(false, denied, &[(OneTimeCode, Repeated)]),
                Outcome::OneTimeCodeRejected,
            ),
            (
                test_run(false, denied, &[(Password, Missing)]),
                Outcome::PasswordMissing,
            ),
            (
                test_run(false, denied, &[(passphrase.clone(), Missing)]),
                Outcome::PassphraseMissing,
            ),
            (test_run(false, denied, &[]), Outcome::KeysRejected),
            (
                test_run(
                    false,
                    "ssh: connect to host 10.0.0.9 port 22: Connection refused",
                    &[],
                ),
                Outcome::Unreachable,
            ),
            (
                test_run(false, "Bad configuration option: foo", &[]),
                Outcome::Failed,
            ),
        ];
        for (run, outcome) in cases {
            assert_eq!(Outcome::of_check(&run), outcome, "{}", run.output);
        }
    }

    #[test]
    fn a_cancelled_session_is_not_an_outcome() {
        assert_eq!(Outcome::of_failure(FailReason::Cancelled), None);
        assert_eq!(
            Outcome::of_failure(FailReason::NotAccepted),
            Some(Outcome::KeysRejected)
        );
    }

    #[test]
    fn keeps_the_newest_events_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(dir.path());
        for i in 0..KEPT + 3 {
            let at = format!("2026-11-04T10:{i:02}:00Z");
            history
                .record("prod", event(&at, Via::Check, Outcome::SignedIn))
                .unwrap();
        }
        history
            .record(
                "other",
                event("2026-11-04T09:00:00Z", Via::Check, Outcome::Unreachable),
            )
            .unwrap();

        let again = History::new(dir.path()).all();
        assert_eq!(again["prod"].len(), KEPT);
        assert_eq!(
            again["prod"][0].at,
            format!("2026-11-04T10:{:02}:00Z", KEPT + 2)
        );
        assert_eq!(again["other"][0].outcome, Outcome::Unreachable);
    }

    #[test]
    fn an_ended_session_gets_its_duration() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(dir.path());
        let at = "2026-11-04T10:00:00Z";
        history
            .record("prod", event(at, Via::Terminal, Outcome::SignedIn))
            .unwrap();
        history
            .record(
                "prod",
                event("2026-11-04T10:05:00Z", Via::Check, Outcome::SignedIn),
            )
            .unwrap();
        history.session_ended("prod", at, 840).unwrap();
        // Another session's end, or a check's, changes nothing.
        history
            .session_ended("prod", "2026-11-04T10:05:00Z", 5)
            .unwrap();
        history.session_ended("gone", at, 5).unwrap();

        let events = &History::new(dir.path()).all()["prod"];
        assert_eq!(events[0].duration_secs, None);
        assert_eq!(events[1].duration_secs, Some(840));
    }

    #[test]
    fn clearing_forgets_one_host() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(dir.path());
        history
            .record(
                "a",
                event("2026-11-04T10:00:00Z", Via::Check, Outcome::SignedIn),
            )
            .unwrap();
        history
            .record(
                "b",
                event("2026-11-04T10:00:00Z", Via::Check, Outcome::SignedIn),
            )
            .unwrap();
        history.clear("a").unwrap();
        let all = History::new(dir.path()).all();
        assert!(!all.contains_key("a"));
        assert!(all.contains_key("b"));
    }

    #[test]
    fn an_unreadable_file_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        let history = History::new(dir.path());
        assert!(history.all().is_empty());
        history
            .record(
                "a",
                event("2026-11-04T10:00:00Z", Via::Check, Outcome::SignedIn),
            )
            .unwrap();
        assert_eq!(History::new(dir.path()).all()["a"].len(), 1);
    }
}
