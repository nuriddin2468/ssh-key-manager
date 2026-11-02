//! Tells the UI when anything in `~/.ssh` changes, so edits made in a terminal
//! or another app show up without a manual refresh.

use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tauri::{AppHandle, Emitter, Manager};

pub const EVENT: &str = "ssh-files-changed";

/// A burst of changes closer together than this is reported once.
const QUIET: Duration = Duration::from_millis(400);

/// Keeps the watcher alive for the lifetime of the app.
struct WatcherHandle(#[allow(dead_code)] RecommendedWatcher);

pub fn start(app: &AppHandle, dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    let emitter = app.clone();
    match watch(dir, move || {
        let _ = emitter.emit(EVENT, ());
    }) {
        Ok(watcher) => {
            app.manage(WatcherHandle(watcher));
        }
        Err(error) => log::warn!("not watching {}: {error}", dir.display()),
    }
}

/// Calls `on_change` once each burst of changes to the files in `dir` settles.
fn watch(dir: &Path, on_change: impl Fn() + Send + 'static) -> notify::Result<RecommendedWatcher> {
    let (signal, signals) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        if result.is_ok_and(|event| is_change(&event)) {
            let _ = signal.send(());
        }
    })?;
    watcher.watch(dir, RecursiveMode::NonRecursive)?;
    thread::spawn(move || debounce(&signals, QUIET, on_change));
    Ok(watcher)
}

/// Reads are not changes. Linux reports every open and close, including the
/// app's own reads while it refreshes, so passing them on would refresh forever.
fn is_change(event: &Event) -> bool {
    !matches!(event.kind, EventKind::Access(_))
}

/// Calls `on_change` after each burst of signals, once `quiet` has passed
/// without another. Returns when the sending side is dropped.
fn debounce(signals: &Receiver<()>, quiet: Duration, on_change: impl Fn()) {
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
        let _watcher = watch(dir.path(), move || {
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
