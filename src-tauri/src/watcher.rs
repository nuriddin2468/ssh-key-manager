//! Tells the UI when anything in `~/.ssh` or the system hosts file changes, so
//! edits made in a terminal or another app show up without a manual refresh.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tauri::{AppHandle, Emitter, Manager};

pub const EVENT: &str = "ssh-files-changed";

/// A burst of changes closer together than this is reported once.
pub(crate) const QUIET: Duration = Duration::from_millis(400);

/// Keeps the watchers alive for the lifetime of the app.
struct WatcherHandle(#[allow(dead_code)] Vec<RecommendedWatcher>);

pub fn start(app: &AppHandle, ssh_dir: &Path, hosts_file: &Path) {
    let notify_ui = || {
        let emitter = app.clone();
        move || {
            let _ = emitter.emit(EVENT, ());
        }
    };
    let mut watchers = Vec::new();
    // Editors and `sed -i` replace the hosts file instead of writing it, so
    // its folder is watched for changes to that one name.
    let targets = [
        (Some(ssh_dir), None),
        (hosts_file.parent(), hosts_file.file_name()),
    ];
    for (dir, only) in targets {
        let Some(dir) = dir.filter(|dir| dir.is_dir()) else {
            continue;
        };
        match watch(dir, only.map(OsStr::to_owned), notify_ui()) {
            Ok(watcher) => watchers.push(watcher),
            Err(error) => log::warn!("not watching {}: {error}", dir.display()),
        }
    }
    app.manage(WatcherHandle(watchers));
}

/// Calls `on_change` once each burst of changes to the files in `dir` (or
/// only to the file named `only`) settles.
fn watch(
    dir: &Path,
    only: Option<OsString>,
    on_change: impl Fn() + Send + 'static,
) -> notify::Result<RecommendedWatcher> {
    let (signal, signals) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        if result.is_ok_and(|event| is_change(&event) && concerns(&event, only.as_deref())) {
            let _ = signal.send(());
        }
    })?;
    watcher.watch(dir, RecursiveMode::NonRecursive)?;
    thread::spawn(move || debounce(&signals, QUIET, on_change));
    Ok(watcher)
}

/// Reads are not changes. Linux reports every open and close, including the
/// app's own reads while it refreshes, so passing them on would refresh forever.
pub(crate) fn is_change(event: &Event) -> bool {
    !matches!(event.kind, EventKind::Access(_))
}

/// Whether the event touches a file named `only` (any file when `None`).
fn concerns(event: &Event, only: Option<&OsStr>) -> bool {
    only.is_none_or(|name| {
        event
            .paths
            .iter()
            .any(|path| path.file_name() == Some(name))
    })
}

/// Calls `on_change` after each burst of signals, once `quiet` has passed
/// without another. Returns when the sending side is dropped.
pub(crate) fn debounce(signals: &Receiver<()>, quiet: Duration, on_change: impl Fn()) {
    while signals.recv().is_ok() {
        while signals.recv_timeout(quiet).is_ok() {}
        on_change();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use notify::event::{
        AccessKind, AccessMode, CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind,
    };

    use super::*;

    #[test]
    fn reads_are_not_changes() {
        let change = |kind| is_change(&Event::new(kind));
        assert!(!change(EventKind::Access(AccessKind::Open(
            AccessMode::Any
        ))));
        assert!(!change(EventKind::Access(AccessKind::Close(
            AccessMode::Read
        ))));
        assert!(change(EventKind::Create(CreateKind::File)));
        assert!(change(EventKind::Modify(ModifyKind::Data(DataChange::Any))));
        assert!(change(EventKind::Modify(ModifyKind::Metadata(
            MetadataKind::Permissions
        ))));
        assert!(change(EventKind::Remove(RemoveKind::File)));
    }

    #[test]
    fn a_named_file_ignores_its_neighbours() {
        let event = |path: &str| Event::new(EventKind::Any).add_path(path.into());
        let hosts = Some(OsStr::new("hosts"));
        assert!(concerns(&event("/private/etc/hosts"), hosts));
        assert!(!concerns(&event("/etc/hosts.allow"), hosts));
        assert!(!concerns(&event("/etc/resolv.conf"), hosts));
        assert!(concerns(&event("/etc/resolv.conf"), None));
    }

    #[test]
    fn each_burst_is_reported_once() {
        let (signal, signals) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let worker = thread::spawn(move || {
            debounce(&signals, Duration::from_millis(50), move || {
                counter.fetch_add(1, Ordering::SeqCst);
            });
        });

        for _ in 0..5 {
            signal.send(()).unwrap();
        }
        thread::sleep(Duration::from_millis(250));
        signal.send(()).unwrap();
        drop(signal);
        worker.join().unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // Only inotify reports reads, so only Linux could loop.
    #[cfg(target_os = "linux")]
    #[test]
    fn reading_a_file_is_not_reported_but_writing_is() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config");
        std::fs::write(&file, "Host a\n").unwrap();
        let (signal, changes) = mpsc::channel();
        let _watcher = watch(dir.path(), None, move || {
            let _ = signal.send(());
        })
        .unwrap();

        std::fs::read_to_string(&file).unwrap();
        assert!(
            changes.recv_timeout(Duration::from_secs(1)).is_err(),
            "reading the file was reported as a change"
        );

        std::fs::write(&file, "Host b\n").unwrap();
        assert!(
            changes.recv_timeout(Duration::from_secs(5)).is_ok(),
            "writing the file was not reported"
        );
    }
}
