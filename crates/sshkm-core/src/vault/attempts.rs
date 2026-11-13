//! Master password checks: one at a time, and slower after wrong ones.
//!
//! Every check of the master password — unlocking, and the checks before an
//! export, a new recovery key, a new master password or a new own device —
//! derives a key with Argon2id (128 MiB), and opening the database with a
//! recovery key or a KeePass file's own password derives one too. Whichever
//! window or command asks, they run one at a time, so requests sent all at
//! once take no more memory than one. After [`FREE_FAILURES`] wrong
//! passwords in a row, the next attempt is refused with
//! [`Error::TooManyAttempts`] until a wait has passed: [`FIRST_WAIT`] at
//! first, doubling with every further wrong one up to [`LONGEST_WAIT`]. A
//! right password starts the count again. The count is kept in memory only.
//!
//! A refused attempt derives nothing, so it is answered at once: a caller
//! holding the unlocked vault never waits here for the time to pass.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::{Error, Result};

/// Wrong passwords in a row that cost no wait.
const FREE_FAILURES: u32 = 3;
/// The wait after the first wrong password past [`FREE_FAILURES`].
const FIRST_WAIT: Duration = Duration::from_secs(1);
/// The longest wait between attempts.
const LONGEST_WAIT: Duration = Duration::from_secs(30);

/// Wrong passwords in a row, and when the last one was tried.
#[derive(Debug, Default)]
struct Failures {
    count: u32,
    last: Option<Instant>,
}

impl Failures {
    /// How long the next attempt still has to wait at `now`, if at all.
    fn wait(&self, now: Instant) -> Option<Duration> {
        let last = self.last?;
        let doublings = self.count.checked_sub(FREE_FAILURES)?;
        let factor = 1u32.checked_shl(doublings).unwrap_or(u32::MAX);
        let wait = FIRST_WAIT.saturating_mul(factor).min(LONGEST_WAIT);
        let remaining = last.checked_add(wait)?.checked_duration_since(now)?;
        (!remaining.is_zero()).then_some(remaining)
    }

    fn record(&mut self, wrong: bool, now: Instant) {
        if wrong {
            self.count = self.count.saturating_add(1);
            self.last = Some(now);
        } else {
            *self = Self::default();
        }
    }
}

/// Lets one master password check run at a time and counts wrong ones.
struct Gate(Mutex<Failures>);

impl Gate {
    const fn new() -> Self {
        Self(Mutex::new(Failures {
            count: 0,
            last: None,
        }))
    }

    /// Runs `check` — a key derivation that fails with
    /// [`Error::WrongPassphrase`] for a wrong password — unless the last
    /// wrong ones ask for a wait, and counts its result. Other errors
    /// (a missing or unreadable file) count neither way.
    fn attempt<T>(
        &self,
        now: impl Fn() -> Instant,
        check: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut failures = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(wait) = failures.wait(now()) {
            return Err(Error::TooManyAttempts {
                retry_in_secs: wait.as_secs() + u64::from(wait.subsec_nanos() > 0),
            });
        }
        let result = check();
        match &result {
            Ok(_) => failures.record(false, now()),
            Err(Error::WrongPassphrase) => failures.record(true, now()),
            Err(_) => {}
        }
        result
    }
}

/// Runs a check of the master password, the recovery key or a KeePass
/// file's password through the [gate](self) of this process.
#[cfg(not(test))]
pub(crate) fn attempt<T>(check: impl FnOnce() -> Result<T>) -> Result<T> {
    static GATE: Gate = Gate::new();
    GATE.attempt(Instant::now, check)
}

/// This crate's tests try wrong passwords on many threads at once: each
/// test thread keeps its own count, so they don't hold each other up.
#[cfg(test)]
pub(crate) fn attempt<T>(check: impl FnOnce() -> Result<T>) -> Result<T> {
    thread_local! {
        static GATE: Gate = const { Gate::new() };
    }
    GATE.with(|gate| gate.attempt(Instant::now, check))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    use super::*;

    fn wrong() -> Result<()> {
        Err(Error::WrongPassphrase)
    }

    #[test]
    fn a_few_wrong_passwords_cost_nothing_and_more_wait_longer_and_longer() {
        let gate = Gate::new();
        let start = Instant::now();
        let clock = Cell::new(start);
        let now = || clock.get();
        let after = |secs: u64| start + Duration::from_secs(secs);
        for _ in 0..FREE_FAILURES {
            assert!(matches!(
                gate.attempt(now, wrong),
                Err(Error::WrongPassphrase)
            ));
        }
        // One second after the third wrong password, then two, four, …
        let mut at = 0;
        for wait in [1, 2, 4, 8, 16, 30, 30] {
            clock.set(after(at + wait - 1));
            let refused = gate.attempt(now, || -> Result<()> { panic!("derived during the wait") });
            assert!(
                matches!(refused, Err(Error::TooManyAttempts { retry_in_secs: 1 })),
                "{refused:?}"
            );
            at += wait;
            clock.set(after(at));
            assert!(matches!(
                gate.attempt(now, wrong),
                Err(Error::WrongPassphrase)
            ));
        }
        // The right password, once the wait is over, starts again from zero.
        clock.set(after(at + 30));
        assert!(gate.attempt(now, || Ok(())).is_ok());
        for _ in 0..FREE_FAILURES {
            assert!(matches!(
                gate.attempt(now, wrong),
                Err(Error::WrongPassphrase)
            ));
        }
        assert!(matches!(
            gate.attempt(now, wrong),
            Err(Error::TooManyAttempts { retry_in_secs: 1 })
        ));
    }

    #[test]
    fn other_errors_are_not_wrong_passwords() {
        let gate = Gate::new();
        for _ in 0..10 {
            let missing = gate.attempt(Instant::now, || -> Result<()> {
                Err(Error::NotFound("vault.keys".into()))
            });
            assert!(matches!(missing, Err(Error::NotFound(_))));
        }
        assert!(matches!(
            gate.attempt(Instant::now, wrong),
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn checks_asked_for_at_once_run_one_after_another() {
        let gate = Arc::new(Gate::new());
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (gate, running, most, start) = (
                    Arc::clone(&gate),
                    Arc::clone(&running),
                    Arc::clone(&most),
                    Arc::clone(&start),
                );
                std::thread::spawn(move || {
                    start.wait();
                    gate.attempt(Instant::now, || {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        running.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        assert_eq!(most.load(Ordering::SeqCst), 1);
    }
}
