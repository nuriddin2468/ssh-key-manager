//! Screen locks from systemd-logind, or from the desktop's screensaver
//! service when logind is not reachable.
//!
//! A blocking zbus connection per watcher; a thread of this crate reads its
//! signals. Dropping the watcher closes the connection, which ends the thread.

use std::{
    collections::HashMap,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use zbus::{
    MatchRule, Message,
    blocking::{Connection, MessageIterator, fdo::DBusProxy},
    message::Type as MessageType,
    names::BusName,
    zvariant::{OwnedObjectPath, OwnedValue},
};

use super::Shared;
use crate::{Error, Result};

const LOGIND: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const LOCKED_HINT: &str = "LockedHint";

/// Session-bus services whose `ActiveChanged` signal is the fallback.
const SCREENSAVERS: [&str; 2] = ["org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"];

/// How long after a `Lock` signal a `LockedHint` change counts as the same
/// lock: the screen locker sets the hint once it has locked.
const SAME_LOCK: Duration = Duration::from_secs(10);

/// Signals buffered while the callback runs.
const QUEUE: usize = 64;

pub(super) struct Watcher {
    connection: Connection,
}

pub(super) fn watch(shared: Arc<Shared>) -> Result<Watcher> {
    let listener = Listener::logind()
        .or_else(|_| Listener::screensaver())
        .map_err(|_| Error::Unsupported)?;
    let connection = listener.connection.clone();
    thread::Builder::new()
        .name("sshkm-screen-lock".into())
        .spawn(move || listener.run(&shared))
        .map_err(|err| Error::Failed(format!("cannot start the screen-lock thread: {err}")))?;
    Ok(Watcher { connection })
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // Closing the socket ends the message iterator, and with it the
        // thread. Errors only mean it is already closed.
        let _ = self.connection.clone().close();
    }
}

struct Listener {
    connection: Connection,
    messages: MessageIterator,
    source: Source,
}

enum Source {
    Logind {
        path: OwnedObjectPath,
        state: LogindState,
    },
    ScreenSaver,
}

impl Listener {
    /// Subscribes to the signals of the caller's logind session ("auto": the
    /// caller's session, or else the user's graphical session).
    fn logind() -> zbus::Result<Self> {
        let connection = Connection::system()?;
        let reply = connection.call_method(
            Some(LOGIND),
            LOGIND_PATH,
            Some(MANAGER_IFACE),
            "GetSession",
            &("auto",),
        )?;
        let path: OwnedObjectPath = reply.body().deserialize()?;
        // Signals carry the session's real path, not "auto".
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(LOGIND)?
            .path(path.clone())?
            .build();
        let messages = MessageIterator::for_match_rule(rule, &connection, Some(QUEUE))?;
        // Read after subscribing, so no change can slip in between.
        let locked = locked_hint(&connection, &path).unwrap_or(false);
        Ok(Self {
            connection,
            messages,
            source: Source::Logind {
                path,
                state: LogindState::new(locked),
            },
        })
    }

    /// Subscribes to `ActiveChanged` of the desktop's screensaver service.
    fn screensaver() -> zbus::Result<Self> {
        let connection = Connection::session()?;
        let dbus = DBusProxy::new(&connection)?;
        let mut present = false;
        for name in SCREENSAVERS {
            present |= dbus.name_has_owner(BusName::try_from(name)?)?;
        }
        if !present {
            return Err(zbus::Error::Failure("no screensaver service".into()));
        }
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .member("ActiveChanged")?
            .build();
        let messages = MessageIterator::for_match_rule(rule, &connection, Some(QUEUE))?;
        Ok(Self {
            connection,
            messages,
            source: Source::ScreenSaver,
        })
    }

    fn run(mut self, shared: &Shared) {
        while let Some(Ok(message)) = self.messages.next() {
            if !shared.is_active() {
                break;
            }
            if self.source.is_lock(&self.connection, &message) {
                shared.notify();
            }
        }
    }
}

impl Source {
    fn is_lock(&mut self, connection: &Connection, message: &Message) -> bool {
        let header = message.header();
        let (Some(interface), Some(member)) = (header.interface(), header.member()) else {
            return false;
        };
        match self {
            Self::Logind { path, state } => match (interface.as_str(), member.as_str()) {
                (SESSION_IFACE, "Lock") => state.lock_signal(Instant::now()),
                (PROPERTIES_IFACE, "PropertiesChanged") => {
                    match locked_hint_change(connection, path, message) {
                        Some(locked) => state.locked_hint(locked, Instant::now()),
                        None => false,
                    }
                }
                _ => false,
            },
            Self::ScreenSaver => {
                member.as_str() == "ActiveChanged"
                    && interface.as_str().ends_with(".ScreenSaver")
                    && message.body().deserialize::<bool>().unwrap_or(false)
            }
        }
    }
}

/// The new `LockedHint`, if this `PropertiesChanged` signal reports one.
fn locked_hint_change(
    connection: &Connection,
    path: &OwnedObjectPath,
    message: &Message,
) -> Option<bool> {
    let body = message.body();
    let (interface, changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        body.deserialize().ok()?;
    if interface != SESSION_IFACE {
        return None;
    }
    if let Some(value) = changed.get(LOCKED_HINT) {
        return bool::try_from(value).ok();
    }
    if invalidated.iter().any(|name| name == LOCKED_HINT) {
        return locked_hint(connection, path).ok();
    }
    None
}

fn locked_hint(connection: &Connection, path: &OwnedObjectPath) -> zbus::Result<bool> {
    let reply = connection.call_method(
        Some(LOGIND),
        path,
        Some(PROPERTIES_IFACE),
        "Get",
        &(SESSION_IFACE, LOCKED_HINT),
    )?;
    let value: OwnedValue = reply.body().deserialize()?;
    Ok(bool::try_from(value)?)
}

/// Decides which logind events are a new lock.
///
/// `loginctl lock-session` (and suspend, with some settings) emits `Lock`, and
/// the screen locker then sets `LockedHint`; a locker started by the user
/// (Super+L) only sets `LockedHint`. Each lock is reported once.
#[derive(Debug)]
struct LogindState {
    locked: bool,
    last_lock_signal: Option<Instant>,
}

impl LogindState {
    fn new(locked: bool) -> Self {
        Self {
            locked,
            last_lock_signal: None,
        }
    }

    /// A `Lock` signal: a lock request, unless the session is already locked.
    fn lock_signal(&mut self, now: Instant) -> bool {
        self.last_lock_signal = Some(now);
        !self.locked
    }

    /// A new `LockedHint` value: a lock when it turns true, unless a `Lock`
    /// signal just announced the same lock.
    fn locked_hint(&mut self, locked: bool, now: Instant) -> bool {
        let was_locked = std::mem::replace(&mut self.locked, locked);
        if !locked || was_locked {
            return false;
        }
        self.last_lock_signal
            .is_none_or(|at| now.saturating_duration_since(at) >= SAME_LOCK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_hint_reports_each_lock_once() {
        let t = Instant::now();
        let mut state = LogindState::new(false);
        assert!(state.locked_hint(true, t));
        assert!(!state.locked_hint(true, t));
        assert!(!state.locked_hint(false, t));
        assert!(state.locked_hint(true, t));
    }

    #[test]
    fn already_locked_is_not_a_new_lock() {
        let mut state = LogindState::new(true);
        assert!(!state.locked_hint(true, Instant::now()));
        assert!(!state.lock_signal(Instant::now()));
    }

    #[test]
    fn lock_signal_then_hint_is_one_lock() {
        let t = Instant::now();
        let mut state = LogindState::new(false);
        assert!(state.lock_signal(t));
        assert!(!state.locked_hint(true, t + Duration::from_secs(1)));
        assert!(!state.locked_hint(false, t + Duration::from_secs(60)));
        // A later lock started by the user counts again.
        assert!(state.locked_hint(true, t + Duration::from_secs(120)));
    }

    #[test]
    fn lock_signal_without_a_locker_does_not_hide_the_next_lock() {
        let t = Instant::now();
        let mut state = LogindState::new(false);
        assert!(state.lock_signal(t));
        assert!(state.locked_hint(true, t + SAME_LOCK));
    }
}
