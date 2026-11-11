//! The leak scanner in Audit ([`sshkm_core::leaks`]): finds the vault's
//! secrets in AI tools' session history, the shell history and folders the
//! user picked.
//!
//! The values are read from the vault here, when a scan starts, and stay in
//! this process: the page gets the scan's progress and findings that name
//! a secret, a file and a line. The scan runs on a thread of its own,
//! reads files and sends nothing anywhere; the page polls
//! [`leaks_status`] and can cancel it. Where it looks is fixed
//! (`sshkm_core::leaks::sources`) or picked in a folder dialog this side
//! opens ([`leaks_add_folders`]); the page never names a file to read. The
//! one write, [`leaks_redact`], replaces a secret in an AI session file the
//! last scan found it in, named by its finding's id, after the user
//! confirmed on the page. Findings name the vault's contents, so they are
//! dropped when the vault locks, as the breach check's results are.

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use std::collections::{BTreeMap, HashSet};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Once, PoisonError};

use serde::{Deserialize, Serialize};
use sshkm_core::leaks::{
    self, AiToolInfo, Cancelled, GitFiles, GitLister, LeakFinding, Matcher, Plan, ScanControl,
};
use sshkm_core::{ErrorCode, fsutil, shell_history};
use tauri::{AppHandle, Listener, Manager, State};
use tauri_plugin_dialog::DialogExt;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{Shared, blocking};
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::process;
use crate::state::AppState;

const SETTINGS_FILE: &str = "leak-scan.json";
/// Most folders the scan keeps.
const MAX_FOLDERS: usize = 50;

/// Where the scan looks; kept in [`SETTINGS_FILE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct LeakSettings {
    /// AI tools' session history.
    pub ai: bool,
    /// The shell history.
    pub history: bool,
    /// Folders picked in the dialog, absolute.
    pub folders: Vec<String>,
}

impl Default for LeakSettings {
    fn default() -> Self {
        Self {
            ai: true,
            history: true,
            folders: Vec::new(),
        }
    }
}

/// What a running scan is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum LeakPhase {
    /// Walking the folders and asking Git what it would commit.
    Listing,
    /// Searching the files.
    Reading,
}

/// Why the last scan didn't finish, or didn't start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum LeakStop {
    /// The user cancelled it; the results of the scan before stay.
    Cancelled,
    /// No source is chosen.
    NoSources,
    /// The vault has no secret long and unusual enough to look for.
    NothingToFind,
    /// The vault locked while it ran.
    Locked,
}

/// The scan as the page shows it. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct LeakStatus {
    pub settings: LeakSettings,
    /// The AI tools whose history the scan knows, and which are here.
    pub tools: Vec<AiToolInfo>,
    /// `None` unless a scan is running.
    pub phase: Option<LeakPhase>,
    /// Of the running scan.
    pub files_done: u32,
    pub files_total: u32,
    #[cfg_attr(test, ts(type = "number"))]
    pub bytes_done: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub bytes_total: u64,
    /// The secrets the running or last scan looked for.
    pub secrets: u32,
    /// When the last scan finished (RFC 3339), since the vault was unlocked.
    pub scanned_at: Option<String>,
    /// Files it read.
    pub files_scanned: u32,
    /// Files with a secret in them, one per secret and file.
    pub findings: u32,
    /// Secrets found at least once.
    pub leaked: u32,
    /// Files it couldn't read.
    pub unreadable: u32,
    /// It stopped at `sshkm_core::leaks::sources::MAX_FILES` files.
    pub truncated: bool,
    /// Why the last attempt stopped early.
    pub stopped: Option<LeakStop>,
}

/// What [`leaks_redact`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct LeakRedaction {
    /// Files changed.
    pub files: u32,
    /// Places in them the value was replaced at.
    pub replaced: u32,
    /// Occurrences still found after, in files changed or not.
    pub left: u32,
    /// Findings left as they are because the value or the file changed since
    /// the scan (rotated, removed from the vault, or the file replaced):
    /// scanning again shows where it is now.
    pub stale: u32,
}

/// A running scan.
struct Running {
    control: Arc<ScanControl>,
    phase: LeakPhase,
    files_total: u32,
    bytes_total: u64,
}

/// A finished scan.
struct Finished {
    findings: Vec<LeakFinding>,
    at: OffsetDateTime,
    files: u32,
    unreadable: u32,
    truncated: bool,
}

#[derive(Default)]
struct Scans {
    /// Bumped by each scan and when results are dropped, so an older scan's
    /// results are thrown away.
    generation: u64,
    running: Option<Running>,
    last: Option<Finished>,
    secrets: u32,
    stopped: Option<LeakStop>,
}

static SCANS: LazyLock<Mutex<Scans>> = LazyLock::new(Mutex::default);
static WATCH_LOCK: Once = Once::new();
/// One change of the settings file at a time.
static SETTINGS: Mutex<()> = Mutex::new(());

fn scans(app: &AppHandle) -> MutexGuard<'static, Scans> {
    // Findings name the vault's secrets: they go when it locks.
    WATCH_LOCK.call_once(|| {
        app.listen_any(crate::vault::LOCKED_EVENT, |_| {
            forget(Some(LeakStop::Locked));
        });
    });
    current()
}

fn current() -> MutexGuard<'static, Scans> {
    SCANS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stops a running scan and drops the results.
fn forget(stopped: Option<LeakStop>) {
    let mut scans = current();
    if let Some(running) = &scans.running {
        running.control.cancel.store(true, Ordering::Relaxed);
    }
    let was_running = scans.running.is_some();
    *scans = Scans {
        generation: scans.generation + 1,
        stopped: if was_running { stopped } else { None },
        ..Scans::default()
    };
}

fn settings_path(state: &AppState) -> PathBuf {
    state.vault.data_dir().join(SETTINGS_FILE)
}

fn load_settings(state: &AppState) -> LeakSettings {
    std::fs::read(settings_path(state))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn change_settings(
    state: &AppState,
    edit: impl FnOnce(&mut LeakSettings),
) -> AppResult<LeakSettings> {
    let _guard = SETTINGS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut settings = load_settings(state);
    edit(&mut settings);
    let mut json = serde_json::to_vec_pretty(&settings)
        .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
    json.push(b'\n');
    let path = settings_path(state);
    if let Some(dir) = path.parent() {
        fsutil::ensure_private_dir(dir)?;
    }
    fsutil::atomic_write(&path, &json, 0o600)?;
    Ok(settings)
}

fn status(app: &AppHandle, state: &AppState) -> LeakStatus {
    let settings = load_settings(state);
    let tools = leaks::detect_ai_tools(&leaks::default_ai_locations(&state.paths.home));
    let scans = scans(app);
    let running = scans.running.as_ref();
    let last = scans.last.as_ref();
    LeakStatus {
        settings,
        tools,
        phase: running.map(|r| r.phase),
        files_done: running.map_or(0, |r| r.control.files_done.load(Ordering::Relaxed)),
        files_total: running.map_or(0, |r| r.files_total),
        bytes_done: running.map_or(0, |r| r.control.bytes_done.load(Ordering::Relaxed)),
        bytes_total: running.map_or(0, |r| r.bytes_total),
        secrets: scans.secrets,
        scanned_at: last.and_then(|l| l.at.format(&Rfc3339).ok()),
        files_scanned: last.map_or(0, |l| l.files),
        findings: last.map_or(0, |l| count(l.findings.len())),
        leaked: last.map_or(0, |l| {
            let secrets: HashSet<String> = l.findings.iter().map(|f| f.secret.key()).collect();
            count(secrets.len())
        }),
        unreadable: last.map_or(0, |l| l.unreadable),
        truncated: last.is_some_and(|l| l.truncated),
        stopped: scans.stopped,
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[tauri::command]
pub async fn leaks_status(app: AppHandle, state: State<'_, Shared>) -> AppResult<LeakStatus> {
    blocking(&state, move |state| Ok(status(&app, state))).await
}

/// Turns AI tools' history and the shell history on or off as sources.
#[tauri::command]
pub async fn leaks_set_sources(
    app: AppHandle,
    state: State<'_, Shared>,
    ai: bool,
    history: bool,
) -> AppResult<LeakStatus> {
    blocking(&state, move |state| {
        change_settings(state, |settings| {
            settings.ai = ai;
            settings.history = history;
        })?;
        Ok(status(&app, state))
    })
    .await
}

/// Opens a folder dialog and adds the folders picked there.
#[tauri::command]
pub async fn leaks_add_folders(app: AppHandle, state: State<'_, Shared>) -> AppResult<LeakStatus> {
    blocking(&state, move |state| {
        let picked = pick_folders(&app);
        if !picked.is_empty() {
            change_settings(state, |settings| {
                for folder in picked {
                    let folder = folder.display().to_string();
                    if !settings.folders.contains(&folder) && settings.folders.len() < MAX_FOLDERS {
                        settings.folders.push(folder);
                    }
                }
            })?;
        }
        Ok(status(&app, state))
    })
    .await
}

/// Stops scanning a folder. Only removes it from the list.
#[tauri::command]
pub async fn leaks_remove_folder(
    app: AppHandle,
    state: State<'_, Shared>,
    folder: String,
) -> AppResult<LeakStatus> {
    blocking(&state, move |state| {
        change_settings(state, |settings| settings.folders.retain(|f| *f != folder))?;
        Ok(status(&app, state))
    })
    .await
}

/// Reads the vault's secrets and starts a scan in the background, unless
/// one is running. Fails with `vault_locked` while the vault is locked.
#[tauri::command]
pub async fn leaks_start(app: AppHandle, state: State<'_, Shared>) -> AppResult<LeakStatus> {
    blocking(&state, move |state| {
        start(&app, state)?;
        Ok(status(&app, state))
    })
    .await
}

fn start(app: &AppHandle, state: &AppState) -> AppResult<()> {
    // Locking the vault meanwhile changes it, and the scan doesn't start.
    let before = {
        let scans = scans(app);
        if scans.running.is_some() {
            return Ok(());
        }
        scans.generation
    };
    let settings = load_settings(state);
    let folders: Vec<PathBuf> = settings
        .folders
        .iter()
        .map(PathBuf::from)
        .filter(|folder| folder.is_absolute())
        .collect();
    let ai = if settings.ai {
        leaks::default_ai_locations(&state.paths.home)
    } else {
        Vec::new()
    };
    let history = if settings.history {
        shell_history::default_history_files(&state.paths.home)
    } else {
        Vec::new()
    };
    if ai.is_empty() && history.is_empty() && folders.is_empty() {
        scans(app).stopped = Some(LeakStop::NoSources);
        return Ok(());
    }
    let matcher = state
        .vault
        .with(app, |vault| Ok(Matcher::new(vault.known_secrets())))?;
    let mut scans = scans(app);
    // Another start got here first, or the vault locked meanwhile.
    if scans.running.is_some() || scans.generation != before {
        return Ok(());
    }
    scans.secrets = count(matcher.len());
    if matcher.is_empty() {
        scans.stopped = Some(LeakStop::NothingToFind);
        return Ok(());
    }
    scans.generation += 1;
    scans.stopped = None;
    let control = Arc::new(ScanControl::default());
    scans.running = Some(Running {
        control: Arc::clone(&control),
        phase: LeakPhase::Listing,
        files_total: 0,
        bytes_total: 0,
    });
    let generation = scans.generation;
    drop(scans);
    let job = Job {
        ai,
        history,
        folders,
    };
    let spawned = std::thread::Builder::new()
        .name("leak-scan".into())
        .spawn(move || {
            // Clears the scan if this thread ends without doing so (a panic).
            let _guard = RunningGuard(generation);
            let outcome = job.run(&matcher, &control, &SystemGit, |files, bytes| {
                let mut scans = current();
                if scans.generation == generation
                    && let Some(running) = scans.running.as_mut()
                {
                    running.phase = LeakPhase::Reading;
                    running.files_total = files;
                    running.bytes_total = bytes;
                }
            });
            // The values go with the matcher, before anything else.
            drop(matcher);
            let mut scans = current();
            if scans.generation != generation {
                return;
            }
            scans.running = None;
            match outcome {
                Ok(finished) => scans.last = Some(finished),
                Err(Cancelled) => scans.stopped = Some(LeakStop::Cancelled),
            }
        });
    if let Err(error) = spawned {
        current().running = None;
        return Err(AppError::new(
            ErrorCode::Io,
            format!("couldn't start the scan: {error}"),
        ));
    }
    Ok(())
}

/// Ends the scan of its generation when dropped, unless it ended already.
struct RunningGuard(u64);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        let mut scans = current();
        if scans.generation == self.0 {
            scans.running = None;
        }
    }
}

/// What one scan reads.
struct Job {
    ai: Vec<leaks::AiLocation>,
    history: Vec<shell_history::HistoryFile>,
    folders: Vec<PathBuf>,
}

impl Job {
    /// Lists the files, tells `listed` how many and how large, and searches
    /// them. Logs counts only.
    fn run(
        &self,
        matcher: &Matcher,
        control: &ScanControl,
        git: &dyn GitLister,
        listed: impl FnOnce(u32, u64),
    ) -> Result<Finished, Cancelled> {
        let plan = Plan {
            ai: &self.ai,
            history: &self.history,
            folders: &self.folders,
        };
        let listing = leaks::list_files(&plan, git, control)?;
        let bytes = listing.files.iter().map(|f| f.size).sum();
        listed(count(listing.files.len()), bytes);
        let outcome = leaks::scan_files(&listing.files, matcher, control)?;
        log::info!(
            "leak scan: {} secrets, {} files, {} findings, {} unreadable{}",
            matcher.len(),
            listing.files.len(),
            outcome.findings.len(),
            outcome.unreadable,
            if listing.truncated { ", truncated" } else { "" }
        );
        Ok(Finished {
            findings: outcome.findings,
            at: OffsetDateTime::now_utc(),
            files: count(listing.files.len()),
            unreadable: outcome.unreadable,
            truncated: listing.truncated,
        })
    }
}

/// Stops the running scan; the results of the one before stay.
#[tauri::command]
pub fn leaks_cancel() {
    if let Some(running) = &current().running {
        running.control.cancel.store(true, Ordering::Relaxed);
    }
}

/// The last scan's findings, most severe first; none while the vault is
/// locked, since they name its secrets.
#[tauri::command]
pub fn leaks_findings(app: AppHandle, state: State<'_, Shared>) -> Vec<LeakFinding> {
    if !state.vault.is_unlocked() {
        return Vec::new();
    }
    scans(&app)
        .last
        .as_ref()
        .map(|last| last.findings.clone())
        .unwrap_or_default()
}

/// Replaces the secret of each finding `ids` names with a marker in its
/// file, in place, then searches the file again. Only findings of the last
/// scan in an AI tool's session history are done; others are skipped.
/// Fails with `vault_locked` while the vault is locked: the values come
/// from there.
#[tauri::command]
pub async fn leaks_redact(
    app: AppHandle,
    state: State<'_, Shared>,
    ids: Vec<String>,
) -> AppResult<LeakRedaction> {
    blocking(&state, move |state| redact(&app, state, &ids)).await
}

fn redact(app: &AppHandle, state: &AppState, ids: &[String]) -> AppResult<LeakRedaction> {
    let targets = {
        let scans = scans(app);
        if scans.running.is_some() {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "wait for the scan to finish",
            ));
        }
        let findings = scans.last.as_ref().map_or(&[][..], |last| &last.findings);
        redaction_targets(findings, ids)
    };
    let applied = apply_redaction(&targets, |key| {
        state.vault.with(app, |vault| Ok(vault.known_secret(key)))
    })?;
    let done = applied.summary;
    log::info!(
        "leak scan: redacted {} places in {} files, {} left, {} changed since the scan",
        done.replaced,
        done.files,
        done.left,
        done.stale
    );
    let mut scans = scans(app);
    if let Some(last) = scans.last.as_mut() {
        for (id, left) in applied.left {
            if left == 0 {
                last.findings.retain(|f| f.id != id);
            } else if let Some(finding) = last.findings.iter_mut().find(|f| f.id == id) {
                finding.occurrences = left;
            }
        }
    }
    Ok(done)
}

/// The findings `ids` names that may be redacted: the last scan's, in an AI
/// tool's session history. Others, and ids the scan didn't give, are left
/// out.
fn redaction_targets(findings: &[LeakFinding], ids: &[String]) -> Vec<LeakFinding> {
    findings
        .iter()
        .filter(|f| f.redactable && ids.contains(&f.id))
        .cloned()
        .collect()
}

/// What [`apply_redaction`] did.
struct Applied {
    summary: LeakRedaction,
    /// For each finding redacted, the occurrences left in its file. Those
    /// that changed since the scan aren't listed: they stay as they are.
    left: Vec<(String, u32)>,
}

/// Redacts each target's secret in its file, the value read with `secret`
/// (`None`: the vault no longer has it as a secret). A target whose value
/// or file changed since the scan is counted as stale and kept, so the user
/// scans again rather than reading "done".
fn apply_redaction(
    targets: &[LeakFinding],
    mut secret: impl FnMut(&str) -> AppResult<Option<leaks::KnownSecret>>,
) -> AppResult<Applied> {
    let mut by_secret: BTreeMap<String, Vec<&LeakFinding>> = BTreeMap::new();
    for finding in targets {
        by_secret
            .entry(finding.secret.key())
            .or_default()
            .push(finding);
    }
    let mut done = LeakRedaction::default();
    let mut left = Vec::new();
    for (key, findings) in by_secret {
        let matcher = Matcher::new(secret(&key)?.into_iter().collect());
        for finding in findings {
            if matcher.is_empty() {
                done.stale += 1;
                continue;
            }
            match leaks::redact(Path::new(&finding.path), finding.file, &matcher) {
                Ok(outcome) if outcome.replaced == 0 && outcome.left == 0 => done.stale += 1,
                Ok(outcome) => {
                    done.files += u32::from(outcome.replaced > 0);
                    done.replaced = done.replaced.saturating_add(outcome.replaced);
                    done.left = done.left.saturating_add(outcome.left);
                    left.push((finding.id.clone(), outcome.left));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData | io::ErrorKind::NotFound
                    ) =>
                {
                    done.stale += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(Applied {
        summary: done,
        left,
    })
}

/// The scan's folder dialog: several folders at once.
fn pick_folders(app: &AppHandle) -> Vec<PathBuf> {
    let mut dialog = app.dialog().file().set_title(
        Localized::new(
            "Choose folders to scan",
            "Выберите папки для проверки",
            "Tekshiriladigan papkalarni tanlang",
        )
        .pick(),
    );
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog
        .blocking_pick_folders()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|picked| picked.into_path().ok())
        .filter(|path| path.is_absolute() && path.is_dir())
        .collect()
}

/// `git ls-files`, with nothing a repository's own config could make it
/// run: no file system monitor.
struct SystemGit;

impl SystemGit {
    /// The paths `git ls-files -z <args>` lists in `folder`, read as Git
    /// writes them, at most [`leaks::sources::MAX_FILES`] (then `true`);
    /// `None` if Git failed or `control` was cancelled, which stops it.
    fn ls_files(
        folder: &Path,
        args: &[&str],
        control: &ScanControl,
    ) -> Option<(Vec<PathBuf>, bool)> {
        let mut command = process::command("git");
        command
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.quotePath=off",
                "-C",
            ])
            .arg(folder)
            .args(["ls-files", "-z"])
            .args(args)
            .stderr(Stdio::null());
        let mut child = command.spawn().ok()?;
        let mut reader = BufReader::new(child.stdout.take()?);
        let stop = |child: &mut std::process::Child| {
            let _ = child.kill();
            let _ = child.wait();
        };
        let mut paths = Vec::new();
        let mut truncated = false;
        let mut entry = Vec::new();
        loop {
            entry.clear();
            match reader.read_until(0, &mut entry) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    stop(&mut child);
                    return None;
                }
            }
            if control.cancelled() {
                stop(&mut child);
                return None;
            }
            if entry.last() == Some(&0) {
                entry.pop();
            }
            // A nested repository is listed as its folder.
            if entry.is_empty() || entry.ends_with(b"/") {
                continue;
            }
            if paths.len() >= leaks::sources::MAX_FILES {
                truncated = true;
                stop(&mut child);
                break;
            }
            if let Ok(path) = std::str::from_utf8(&entry) {
                paths.push(PathBuf::from(path));
            }
        }
        if !truncated && !child.wait().ok()?.success() {
            return None;
        }
        Some((paths, truncated))
    }
}

impl GitLister for SystemGit {
    fn list(&self, folder: &Path, control: &ScanControl) -> Option<GitFiles> {
        let (tracked, cut) = Self::ls_files(folder, &["--cached"], control)?;
        let (untracked, cut_too) =
            Self::ls_files(folder, &["--others", "--exclude-standard"], control)?;
        Some(GitFiles {
            tracked,
            untracked,
            truncated: cut || cut_too,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::sync::Mutex;

    use sshkm_core::SecretString;
    use sshkm_core::leaks::{AiLocation, AiTool, KnownSecret, LeakSecret};

    use super::*;

    /// Everything logged while the tests run.
    static LOGGED: Mutex<String> = Mutex::new(String::new());

    struct Capture;

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            let mut logged = LOGGED.lock().unwrap();
            let _ = writeln!(logged, "{}", record.args());
        }
        fn flush(&self) {}
    }

    static CAPTURE: Capture = Capture;

    struct NoGit;

    impl GitLister for NoGit {
        fn list(&self, _: &Path, _: &ScanControl) -> Option<GitFiles> {
            None
        }
    }

    #[test]
    fn no_value_reaches_a_finding_a_status_or_the_log() {
        let _ = log::set_logger(&CAPTURE);
        log::set_max_level(log::LevelFilter::Trace);
        let value = "Zr8-kP2w-Qm5x-Lv7n";
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("session.jsonl");
        std::fs::write(
            &session,
            format!("{{\"content\":\"TOKEN={value}\"}}\n{{\"content\":\"ok\"}}\n"),
        )
        .unwrap();
        let matcher = Matcher::new(vec![KnownSecret {
            secret: LeakSecret::Variable {
                env_id: "e1".into(),
                project: "shop".into(),
                environment: "prod".into(),
                name: "TOKEN".into(),
            },
            value: SecretString::from(value),
        }]);
        let job = Job {
            ai: vec![AiLocation {
                tool: AiTool::Codex,
                path: dir.path().to_path_buf(),
            }],
            history: Vec::new(),
            folders: Vec::new(),
        };
        let control = ScanControl::default();
        let mut listed = (0, 0);
        let finished = job
            .run(&matcher, &control, &NoGit, |files, bytes| {
                listed = (files, bytes);
            })
            .unwrap();
        assert_eq!(listed.0, 1);
        assert_eq!(finished.findings.len(), 1);
        assert_eq!(finished.findings[0].line, 1);

        let json = serde_json::to_string(&finished.findings).unwrap();
        assert!(json.contains("\"name\":\"TOKEN\""));
        assert!(!json.contains(value) && !json.contains("Zr8"));
        let logged = LOGGED.lock().unwrap().clone();
        assert!(logged.contains("leak scan: 1 secrets, 1 files, 1 findings"));
        assert!(!logged.contains(value) && !logged.contains("Zr8"));
        assert!(!format!("{matcher:?}").contains("Zr8"));
    }

    #[test]
    fn a_cancelled_job_stops() {
        let control = ScanControl::default();
        control.cancel.store(true, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.jsonl"), "x").unwrap();
        let job = Job {
            ai: vec![AiLocation {
                tool: AiTool::ClaudeCode,
                path: dir.path().to_path_buf(),
            }],
            history: Vec::new(),
            folders: Vec::new(),
        };
        let matcher = Matcher::new(Vec::new());
        assert!(job.run(&matcher, &control, &NoGit, |_, _| {}).is_err());
    }

    #[test]
    fn the_status_names_no_value() {
        let status = LeakStatus {
            settings: LeakSettings::default(),
            tools: vec![AiToolInfo {
                tool: AiTool::ClaudeCode,
                found: true,
            }],
            phase: Some(LeakPhase::Reading),
            files_done: 2,
            files_total: 5,
            bytes_done: 10,
            bytes_total: 50,
            secrets: 3,
            scanned_at: None,
            files_scanned: 0,
            findings: 0,
            leaked: 0,
            unreadable: 0,
            truncated: false,
            stopped: Some(LeakStop::Cancelled),
        };
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "settings": { "ai": true, "history": true, "folders": [] },
                "tools": [{ "tool": "claudeCode", "found": true }],
                "phase": "reading",
                "filesDone": 2,
                "filesTotal": 5,
                "bytesDone": 10,
                "bytesTotal": 50,
                "secrets": 3,
                "scannedAt": null,
                "filesScanned": 0,
                "findings": 0,
                "leaked": 0,
                "unreadable": 0,
                "truncated": false,
                "stopped": "cancelled",
            })
        );
    }

    #[test]
    fn forgetting_stops_a_scan_and_drops_the_results() {
        let control = Arc::new(ScanControl::default());
        {
            let mut scans = current();
            scans.generation = 4;
            scans.running = Some(Running {
                control: Arc::clone(&control),
                phase: LeakPhase::Reading,
                files_total: 1,
                bytes_total: 1,
            });
            scans.last = Some(Finished {
                findings: Vec::new(),
                at: OffsetDateTime::now_utc(),
                files: 1,
                unreadable: 0,
                truncated: false,
            });
        }
        forget(Some(LeakStop::Locked));
        assert!(control.cancelled());
        let scans = current();
        assert_eq!(scans.generation, 5);
        assert!(scans.running.is_none() && scans.last.is_none());
        assert_eq!(scans.stopped, Some(LeakStop::Locked));
    }

    #[test]
    fn git_lists_what_it_would_commit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !git(&["init", "-q"]) {
            return; // No Git here.
        }
        std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();
        std::fs::write(repo.join("app.js"), "x").unwrap();
        std::fs::write(repo.join("draft.md"), "x").unwrap();
        std::fs::write(repo.join(".env"), "x").unwrap();
        assert!(git(&["add", "app.js", ".gitignore"]));
        let control = ScanControl::default();
        let files = SystemGit.list(repo, &control).unwrap();
        let mut tracked = files.tracked.clone();
        tracked.sort();
        assert_eq!(
            tracked,
            [PathBuf::from(".gitignore"), PathBuf::from("app.js")]
        );
        assert_eq!(files.untracked, [PathBuf::from("draft.md")]);
        assert!(!files.truncated);
        assert!(SystemGit.list(&repo.join("missing"), &control).is_none());
        control.cancel.store(true, Ordering::Relaxed);
        assert!(SystemGit.list(repo, &control).is_none());
    }

    fn token_finding(path: &Path, redactable: bool) -> LeakFinding {
        let files = [leaks::ScanFile {
            path: path.to_path_buf(),
            place: if redactable {
                leaks::LeakPlace::AiSession {
                    tool: AiTool::Codex,
                }
            } else {
                leaks::LeakPlace::ShellHistory {
                    shell: shell_history::Shell::Zsh,
                }
            },
            size: 0,
        }];
        let matcher = Matcher::new(vec![token("Zr8-kP2w-Qm5x-Lv7n")]);
        leaks::scan_files(&files, &matcher, &ScanControl::default())
            .unwrap()
            .findings
            .remove(0)
    }

    fn token(value: &str) -> KnownSecret {
        KnownSecret {
            secret: LeakSecret::Variable {
                env_id: "e1".into(),
                project: "shop".into(),
                environment: "prod".into(),
                name: "TOKEN".into(),
            },
            value: SecretString::from(value),
        }
    }

    #[test]
    fn only_findings_of_ai_sessions_from_the_scan_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("s.jsonl");
        let history = dir.path().join(".zsh_history");
        std::fs::write(&session, "{\"c\":\"Zr8-kP2w-Qm5x-Lv7n\"}\n").unwrap();
        std::fs::write(&history, "export TOKEN=Zr8-kP2w-Qm5x-Lv7n\n").unwrap();
        let findings = [
            token_finding(&session, true),
            token_finding(&history, false),
        ];
        let ids = |list: &[LeakFinding]| list.iter().map(|f| f.id.clone()).collect::<Vec<_>>();

        let asked = vec![
            findings[0].id.clone(),
            findings[1].id.clone(),
            "leak:00000000000000000000000000000000".to_owned(),
        ];
        assert_eq!(
            ids(&redaction_targets(&findings, &asked)),
            [findings[0].id.clone()]
        );
        assert_eq!(redaction_targets(&findings, &["made up".to_owned()]), []);

        let applied = apply_redaction(&redaction_targets(&findings, &asked), |_| {
            Ok(Some(token("Zr8-kP2w-Qm5x-Lv7n")))
        })
        .unwrap();
        assert_eq!(
            applied.summary,
            LeakRedaction {
                files: 1,
                replaced: 1,
                left: 0,
                stale: 0
            }
        );
        assert_eq!(applied.left, [(findings[0].id.clone(), 0)]);
        assert!(!std::fs::read_to_string(&session).unwrap().contains("Zr8"));
        assert!(std::fs::read_to_string(&history).unwrap().contains("Zr8"));
    }

    #[test]
    fn a_value_changed_since_the_scan_is_not_reported_as_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("s.jsonl");
        std::fs::write(&session, "{\"c\":\"Zr8-kP2w-Qm5x-Lv7n\"}\n").unwrap();
        let target = [token_finding(&session, true)];

        // Rotated in the vault: the new value isn't in the file.
        let rotated = apply_redaction(&target, |_| Ok(Some(token("Nw4-Jx8q-Hb2t-Pc6r")))).unwrap();
        // Gone from the vault, or no longer a secret.
        let gone = apply_redaction(&target, |_| Ok(None)).unwrap();
        for applied in [rotated, gone] {
            assert_eq!(applied.summary.stale, 1);
            assert_eq!(applied.summary.replaced, 0);
            assert_eq!(applied.left, [], "the finding stays");
        }
        assert!(std::fs::read_to_string(&session).unwrap().contains("Zr8"));
    }
}
