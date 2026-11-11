//! A shell on this computer in the in-app terminal (`terminal_open_local`),
//! or one started with a secret environment's variables (`envs_run`). The
//! variables go only into the shell's environment, from where the programs
//! it starts inherit them: nothing is written to disk. The shell is one
//! [`shells`] found, the user's choice or the default, started in the home
//! folder.
//!
//! Such a session starts connected, asks nothing through askpass and stays
//! out of the connection history.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use sshkm_core::SecretString;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::bridge::{self, Bridge, SaveTarget, Store};
use super::shells::Shell;
use super::types::{Phase, SaveOffer, TerminalInfo};
use super::{Sink, Terminal, Terminals, lock};
use crate::error::{AppError, AppResult};

impl Terminals {
    /// Starts `shell` in a `cols`×`rows` terminal in `home`, with `vars`
    /// added to its environment. `label` names the session.
    pub fn open_local(
        self: &Arc<Self>,
        label: &str,
        shell: &Shell,
        vars: &[(String, SecretString)],
        home: &Path,
        size: (u16, u16),
        sink: Arc<dyn Sink>,
    ) -> AppResult<TerminalInfo> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        // Nothing asks it anything: the shell gets no askpass session.
        let bridge = Arc::new(Bridge::new(
            NoStore,
            Arc::clone(&sink),
            bridge::Options {
                key_offered: false,
                ask_password: false,
                can_save: false,
                timeout: bridge::ANSWER_TIMEOUT,
            },
        ));
        let info = TerminalInfo {
            id,
            alias: label.to_owned(),
            user: None,
            host: None,
            proxy_jump: None,
            shell: Some(shell.info.name.clone()),
            started_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            phase: Phase::Connected,
        };
        let command = shell.command(vars, home);
        let mut sessions = lock(&self.sessions);
        let terminal = Terminal::spawn(
            info.clone(),
            command,
            size,
            bridge,
            None,
            sink,
            Arc::downgrade(self),
        )?;
        sessions.insert(id, terminal);
        Ok(info)
    }
}

/// The vault behind a local shell's bridge, which no prompt ever reaches.
struct NoStore;

impl Store for NoStore {
    fn password(&self) -> Option<SecretString> {
        None
    }

    fn one_time_code(&self) -> Option<SecretString> {
        None
    }

    fn passphrase(&self, _key: &str) -> Option<SecretString> {
        None
    }

    fn offer(&self, _target: &SaveTarget) -> SaveOffer {
        SaveOffer::None
    }

    fn save(&self, _target: &SaveTarget, _secret: &SecretString) -> AppResult<()> {
        Err(AppError::invalid("a local shell saves nothing"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::terminal::types::{SessionState, TerminalEvent};

    #[derive(Default)]
    struct Collect {
        events: Mutex<Vec<TerminalEvent>>,
        output: Mutex<Vec<u8>>,
    }

    impl Sink for Collect {
        fn event(&self, event: &TerminalEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
        fn output(&self, bytes: &[u8]) {
            self.output.lock().unwrap().extend_from_slice(bytes);
        }
    }

    /// The shell sees the variables, the session starts connected and ends
    /// when the shell does, and leaves the list.
    #[test]
    fn a_local_shell_gets_the_variables() {
        let terminals = Arc::new(Terminals::default());
        let sink = Arc::new(Collect::default());
        let home = tempfile::tempdir().unwrap();
        let vars = [
            ("SSHKM_TEST_TOKEN".to_owned(), SecretString::from("t0k en")),
            ("SSHKM_TEST_PORT".to_owned(), SecretString::from("3000")),
        ];
        let shell = crate::terminal::shells::find(None).unwrap();
        let info = terminals
            .open_local(
                "app · dev",
                &shell,
                &vars,
                home.path(),
                (80, 24),
                Arc::clone(&sink) as Arc<dyn Sink>,
            )
            .unwrap();
        assert_eq!(info.phase, Phase::Connected);
        assert_eq!(info.alias, "app · dev");
        assert_eq!(terminals.list().len(), 1);
        terminals
            .write(
                info.id,
                b"printf '<%s|%s>' \"$SSHKM_TEST_TOKEN\" \"$SSHKM_TEST_PORT\"; exit\n".to_vec(),
            )
            .unwrap();
        let started = Instant::now();
        while !terminals.list().is_empty() {
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the shell didn't end"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let output = String::from_utf8_lossy(&sink.output.lock().unwrap()).into_owned();
        assert!(output.contains("<t0k en|3000>"), "{output}");
        let events = sink.events.lock().unwrap();
        assert!(matches!(
            events.first(),
            Some(TerminalEvent::State {
                state: SessionState::Connected { .. }
            })
        ));
        assert!(matches!(
            events.last(),
            Some(TerminalEvent::State {
                state: SessionState::Ended { .. }
            })
        ));
    }
}
