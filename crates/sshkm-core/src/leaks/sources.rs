//! Where the scanner looks: AI tools' session history where the tools
//! keep it, the shell history, and the folders the user picked.
//!
//! | Tool | Session history |
//! |---|---|
//! | Claude Code | `~/.claude/projects/` (transcripts, tool output), `~/.claude/file-history/` (copies of edited files), `~/.claude/history.jsonl` (prompts); `$CLAUDE_CONFIG_DIR` instead of `~/.claude` |
//! | Codex | `~/.codex/sessions/`, `~/.codex/archived_sessions/`, `~/.codex/history.jsonl`; `$CODEX_HOME` instead of `~/.codex` |
//! | Gemini CLI | `~/.gemini/tmp/` (chats, logs, checkpoints) |
//! | Continue | `~/.continue/sessions/`, `~/.continue/dev_data/` |
//! | Cline, Roo Code | `tasks/` in the extension's global storage of VS Code, VS Code Insiders, VSCodium, Cursor and Windsurf |
//! | Aider | `.aider.chat.history.md`, `.aider.input.history`, `.aider.llm.history` in the picked folders |
//!
//! In a picked folder, each Git working tree gives the files Git would
//! commit (`git ls-files`, through [`GitLister`]); `.env` files and the
//! like are found by walking the folder, which skips folders of
//! dependencies and builds (`node_modules`, `target`…), so ignored ones and
//! those outside any working tree are found too. Symbolic links are not
//! followed.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{Cancelled, GitState, LeakPlace, ScanControl, ScanFile};
use crate::shell_history::HistoryFile;

/// Most files one scan reads.
pub const MAX_FILES: usize = 200_000;
/// Largest file of a picked folder that is read. Session histories are read
/// whatever their size.
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;
/// Deepest folder a walk goes into, below the one picked.
const MAX_DEPTH: usize = 16;
/// Folders a walk doesn't go into: dependencies, builds, caches, and the
/// system's own.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".pnpm-store",
    "bower_components",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    ".m2",
    "Pods",
    "DerivedData",
    ".cache",
    ".npm",
    ".yarn",
    ".cargo",
    ".rustup",
    ".Trash",
    "Library",
    "$RECYCLE.BIN",
];
/// Files that are never text.
const BINARY: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "bmp", "tif", "tiff", "heic", "pdf", "zip",
    "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "jar", "war", "class", "so", "dylib", "dll",
    "exe", "bin", "o", "a", "lib", "wasm", "mp3", "mp4", "m4a", "mov", "avi", "mkv", "wav", "flac",
    "ogg", "webm", "woff", "woff2", "ttf", "otf", "eot", "psd", "sketch", "db", "sqlite",
    "sqlite3", "kdbx", "dmg", "iso", "pyc", "node", "pack", "idx",
];
/// Aider's history files, in the folder it runs in.
const AIDER_FILES: &[&str] = &[
    ".aider.chat.history.md",
    ".aider.input.history",
    ".aider.llm.history",
];

/// An AI coding tool whose session history is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum AiTool {
    ClaudeCode,
    Codex,
    GeminiCli,
    Continue,
    Cline,
    RooCode,
    Aider,
}

/// A file or folder of a tool's session history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiLocation {
    pub tool: AiTool,
    pub path: PathBuf,
}

/// A tool and whether its history is on this computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AiToolInfo {
    pub tool: AiTool,
    pub found: bool,
}

/// Editors whose extensions' storage Cline and Roo Code keep their tasks
/// in: their folder in the system's configuration folder.
const EDITORS: &[&str] = &["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"];

/// The session histories of the AI tools in the table above, for the user
/// whose home is `home`. `config` is the system's configuration folder
/// (`~/Library/Application Support`, `%APPDATA%`, `$XDG_CONFIG_HOME`);
/// `claude` and `codex` are `$CLAUDE_CONFIG_DIR` and `$CODEX_HOME` if set.
pub fn ai_locations(
    home: &Path,
    config: Option<&Path>,
    claude: Option<&Path>,
    codex: Option<&Path>,
) -> Vec<AiLocation> {
    let at = |tool, path: PathBuf| AiLocation { tool, path };
    let claude = claude.map_or_else(|| home.join(".claude"), Path::to_path_buf);
    let codex = codex.map_or_else(|| home.join(".codex"), Path::to_path_buf);
    let mut out = vec![
        at(AiTool::ClaudeCode, claude.join("projects")),
        at(AiTool::ClaudeCode, claude.join("file-history")),
        at(AiTool::ClaudeCode, claude.join("history.jsonl")),
        at(AiTool::Codex, codex.join("sessions")),
        at(AiTool::Codex, codex.join("archived_sessions")),
        at(AiTool::Codex, codex.join("history.jsonl")),
        at(AiTool::GeminiCli, home.join(".gemini").join("tmp")),
        at(AiTool::Continue, home.join(".continue").join("sessions")),
        at(AiTool::Continue, home.join(".continue").join("dev_data")),
    ];
    if let Some(config) = config {
        for editor in EDITORS {
            let storage = config.join(editor).join("User").join("globalStorage");
            for (tool, extension) in [
                (AiTool::Cline, "saoudrizwan.claude-dev"),
                (AiTool::RooCode, "rooveterinaryinc.roo-cline"),
            ] {
                out.push(at(tool, storage.join(extension).join("tasks")));
            }
        }
    }
    out
}

/// [`ai_locations`] on this computer.
pub fn default_ai_locations(home: &Path) -> Vec<AiLocation> {
    let var = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    ai_locations(
        home,
        dirs::config_dir().as_deref(),
        var("CLAUDE_CONFIG_DIR").as_deref(),
        var("CODEX_HOME").as_deref(),
    )
}

/// The tools of `locations`, in order, and whether any of their places
/// exists. Aider, whose history is in the picked folders, is not one.
pub fn detect_ai_tools(locations: &[AiLocation]) -> Vec<AiToolInfo> {
    let mut out: Vec<AiToolInfo> = Vec::new();
    for location in locations {
        let found = fs::symlink_metadata(&location.path).is_ok();
        match out.iter_mut().find(|info| info.tool == location.tool) {
            Some(info) => info.found |= found,
            None => out.push(AiToolInfo {
                tool: location.tool,
                found,
            }),
        }
    }
    out
}

/// The files of a Git working tree: what `git ls-files` says, as paths
/// relative to the folder asked about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitFiles {
    /// In the index: committed or added.
    pub tracked: Vec<PathBuf>,
    /// Neither tracked nor ignored.
    pub untracked: Vec<PathBuf>,
    /// Git listed more than [`MAX_FILES`]; the rest are left out.
    pub truncated: bool,
}

/// Asks Git which files of a working tree it would commit.
pub trait GitLister {
    /// The files under `folder`, which is in a working tree, at most
    /// [`MAX_FILES`] of each kind; `None` when Git can't say (it isn't
    /// installed, or failed) or `control` was cancelled.
    fn list(&self, folder: &Path, control: &ScanControl) -> Option<GitFiles>;
}

/// What to search, and where it was found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    pub files: Vec<ScanFile>,
    /// More than [`MAX_FILES`] were found; the rest are left out.
    pub truncated: bool,
}

/// What to scan: AI tools' histories, shell histories and picked folders.
#[derive(Debug, Clone, Copy)]
pub struct Plan<'a> {
    pub ai: &'a [AiLocation],
    pub history: &'a [HistoryFile],
    pub folders: &'a [PathBuf],
}

/// The files of `plan` that exist, with what each is.
pub fn list_files(
    plan: &Plan<'_>,
    git: &dyn GitLister,
    control: &ScanControl,
) -> Result<Listing, Cancelled> {
    let mut list = Lister::default();
    for location in plan.ai {
        let place = LeakPlace::AiSession {
            tool: location.tool,
        };
        list.walk_all(&location.path, &place, control)?;
    }
    for file in plan.history {
        list.add(
            &file.path,
            LeakPlace::ShellHistory { shell: file.shell },
            None,
        );
    }
    for folder in plan.folders {
        list.folder(folder, git, control)?;
    }
    Ok(Listing {
        files: list.files,
        truncated: list.truncated,
    })
}

#[derive(Default)]
struct Lister {
    files: Vec<ScanFile>,
    seen: HashSet<PathBuf>,
    truncated: bool,
}

/// A Git working tree in a picked folder, and whether Git listed it.
struct Repository {
    root: PathBuf,
    listed: bool,
}

impl Lister {
    /// Adds the regular file at `path` if it exists and is not binary or,
    /// with `limit`, larger than that.
    fn add(&mut self, path: &Path, place: LeakPlace, limit: Option<u64>) {
        if self.files.len() >= MAX_FILES {
            self.truncated = true;
            return;
        }
        if is_binary_name(path) || self.seen.contains(path) {
            return;
        }
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        if !meta.is_file() || limit.is_some_and(|limit| meta.len() > limit) {
            return;
        }
        self.seen.insert(path.to_path_buf());
        self.files.push(ScanFile {
            path: path.to_path_buf(),
            place,
            size: meta.len(),
        });
    }

    /// Every file at or under `path`.
    fn walk_all(
        &mut self,
        path: &Path,
        place: &LeakPlace,
        control: &ScanControl,
    ) -> Result<(), Cancelled> {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return Ok(());
        };
        if meta.is_file() {
            self.add(path, place.clone(), None);
            return Ok(());
        }
        let mut stack = vec![(path.to_path_buf(), 0_usize)];
        while let Some((dir, depth)) = stack.pop() {
            if control.cancelled() {
                return Err(Cancelled);
            }
            for (entry, is_dir) in entries(&dir) {
                if is_dir {
                    if depth < MAX_DEPTH {
                        stack.push((entry, depth + 1));
                    }
                } else {
                    self.add(&entry, place.clone(), None);
                }
            }
        }
        Ok(())
    }

    /// A picked folder: the files Git would commit in its working trees,
    /// and `.env` files and Aider's history anywhere.
    fn folder(
        &mut self,
        folder: &Path,
        git: &dyn GitLister,
        control: &ScanControl,
    ) -> Result<(), Cancelled> {
        if !folder.is_dir() {
            return Ok(());
        }
        // Working trees: the one the folder is in, and those under it.
        let mut trees: Vec<(PathBuf, PathBuf)> = Vec::new();
        if let Some(root) = work_tree(folder) {
            trees.push((root, folder.to_path_buf()));
        }
        let mut loose: Vec<PathBuf> = Vec::new();
        let mut stack = vec![(folder.to_path_buf(), 0_usize)];
        while let Some((dir, depth)) = stack.pop() {
            if control.cancelled() {
                return Err(Cancelled);
            }
            for (entry, is_dir) in entries(&dir) {
                let name = entry
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if is_dir {
                    if SKIP_DIRS.contains(&name) || depth >= MAX_DEPTH {
                        continue;
                    }
                    if entry.join(".git").exists() {
                        trees.push((entry.clone(), entry.clone()));
                    }
                    stack.push((entry, depth + 1));
                } else if is_env_file(name) || AIDER_FILES.contains(&name) {
                    loose.push(entry);
                }
            }
        }

        let mut repositories: Vec<Repository> = Vec::new();
        for (root, listed_from) in trees {
            let files = git.list(&listed_from, control);
            if control.cancelled() {
                return Err(Cancelled);
            }
            self.truncated |= files.as_ref().is_some_and(|files| files.truncated);
            let repository = Some(root.display().to_string());
            if let Some(files) = &files {
                for (paths, state) in [
                    (&files.tracked, GitState::Tracked),
                    (&files.untracked, GitState::Untracked),
                ] {
                    for relative in paths {
                        let path = listed_from.join(relative);
                        let place = place_of(&path, state, repository.clone());
                        self.add(&path, place, Some(MAX_FILE_SIZE));
                    }
                }
            }
            repositories.push(Repository {
                root,
                listed: files.is_some(),
            });
        }
        // What Git didn't list in a tree it listed, it ignores.
        for path in loose {
            let tree = repositories
                .iter()
                .filter(|repo| path.starts_with(&repo.root))
                .max_by_key(|repo| repo.root.components().count());
            let (state, repository) = match tree {
                Some(repo) if repo.listed => {
                    (GitState::Ignored, Some(repo.root.display().to_string()))
                }
                Some(repo) => (GitState::Outside, Some(repo.root.display().to_string())),
                None => (GitState::Outside, None),
            };
            let place = place_of(&path, state, repository);
            self.add(&path, place, Some(MAX_FILE_SIZE));
        }
        Ok(())
    }
}

/// Aider's history is a session history wherever it is; anything else is
/// a file in what Git makes of it.
fn place_of(path: &Path, git: GitState, repository: Option<String>) -> LeakPlace {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if AIDER_FILES.contains(&name) {
        LeakPlace::AiSession {
            tool: AiTool::Aider,
        }
    } else {
        LeakPlace::File { git, repository }
    }
}

/// The top folder of the Git working tree `folder` is in, if any.
fn work_tree(folder: &Path) -> Option<PathBuf> {
    folder
        .ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
}

/// The entries of `dir` with whether each is a folder; symbolic links are
/// left out, unreadable folders are empty.
fn entries(dir: &Path) -> Vec<(PathBuf, bool)> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, bool)> = read
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let kind = entry.file_type().ok()?;
            if kind.is_symlink() {
                return None;
            }
            Some((entry.path(), kind.is_dir()))
        })
        .collect();
    // The same order on every run.
    out.sort();
    out
}

/// `.env`, `.env.local`, `prod.env`, `.envrc`, `.dev.vars`: files that hold
/// variables.
pub fn is_env_file(name: &str) -> bool {
    name == ".env"
        || name.starts_with(".env.")
        || name == ".envrc"
        || name == ".dev.vars"
        || Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("env"))
}

fn is_binary_name(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| BINARY.contains(&ext.to_ascii_lowercase().as_str()))
}
