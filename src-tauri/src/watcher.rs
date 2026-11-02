//! Tells the UI when anything in `~/.ssh` changes, so edits made in a terminal
//! or another app show up without a manual refresh.

use std::path::Path;
use std::time::Duration;

use notify_debouncer_mini::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{DebounceEventResult, Debouncer, new_debouncer};
use tauri::{AppHandle, Emitter, Manager};

pub const EVENT: &str = "ssh-files-changed";

/// Keeps the watcher alive for the lifetime of the app.
struct WatcherHandle(#[allow(dead_code)] Debouncer<RecommendedWatcher>);

pub fn start(app: &AppHandle, dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    let emitter = app.clone();
    let debouncer = new_debouncer(
        Duration::from_millis(400),
        move |result: DebounceEventResult| {
            if result.is_ok() {
                let _ = emitter.emit(EVENT, ());
            }
        },
    );
    match debouncer {
        Ok(mut debouncer) => {
            if let Err(error) = debouncer.watcher().watch(dir, RecursiveMode::NonRecursive) {
                log::warn!("not watching {}: {error}", dir.display());
                return;
            }
            app.manage(WatcherHandle(debouncer));
        }
        Err(error) => log::warn!("file watcher unavailable: {error}"),
    }
}
