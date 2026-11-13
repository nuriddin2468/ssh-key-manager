//! What the page can't take out of the vault in bulk without the user.
//!
//! The page drives the in-app terminal, so a script running in it could run
//! commands (SECURITY.md, "Locked-down webview"). Secrets it could read
//! through such a terminal, or that reach it in the clear, are gated here,
//! with native dialogs through [`crate::confirm`]:
//!
//! - an environment's secret values going into a shell's environment or into
//!   a file the app writes ([`confirm_env_secrets`]): asked once per
//!   environment and use while the vault stays unlocked;
//! - single secrets shown on the page or copied to the clipboard
//!   ([`take_secret`]): a few a minute are free, each one past that is asked
//!   for.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Mutex, MutexGuard, Once, PoisonError};
use std::time::{Duration, Instant};

use sshkm_core::vault::envs::{self, EnvFile};
use tauri::{AppHandle, Listener};

use crate::confirm::{self, Localized};
use crate::error::AppResult;
use crate::state::AppState;

// --- An environment's values, all at once -------------------------------------

/// Where an environment's values go.
pub enum EnvUse<'a> {
    /// A shell's environment: Run in terminal, a project's terminal.
    Shell,
    /// A file the app writes them to (all the time, while unlocked, or a
    /// pipe), as the binding names it.
    File(&'a EnvFile),
}

impl EnvUse<'_> {
    fn key(&self, env: &str) -> String {
        match self {
            Self::Shell => format!("shell:{env}"),
            Self::File(_) => format!("file:{env}"),
        }
    }
}

/// The environments, by use, whose secret values the user let out, until
/// the vault locks or unlocks again.
static LET_OUT: Mutex<LetOut> = Mutex::new(LetOut::new());
/// Set up the first time an environment is asked for.
static WATCH_LOCK: Once = Once::new();

/// Asks in a native dialog, naming the environment `env` and how many secret
/// values it has, before they go into a shell or a file (`to`). Fails with
/// `cancelled` on a no; an environment without secret values goes without
/// asking.
///
/// Asked once per environment and use while the vault stays unlocked, not
/// for every shell or file: once a shell or a file holds the values, a
/// script in the page could read them there anyway, so asking again would
/// add clicks, not protection. The next lock or unlock forgets every answer.
pub fn confirm_env_secrets(
    app: &AppHandle,
    state: &AppState,
    env: &str,
    to: &EnvUse<'_>,
) -> AppResult<()> {
    let (label, secrets) = state.vault.with(app, |vault| {
        let summary = vault.environment(env)?.summary;
        Ok((
            envs::label(Some(&vault.env_label(&summary)), &summary.name),
            summary.secret_count,
        ))
    })?;
    if secrets == 0 {
        return Ok(());
    }
    WATCH_LOCK.call_once(|| {
        for event in [crate::vault::LOCKED_EVENT, crate::vault::UNLOCKED_EVENT] {
            app.listen_any(event, |_| let_out().forget());
        }
    });
    let key = to.key(env);
    let Some(asked) = let_out().ask(&key) else {
        return Ok(());
    };
    let (title, body, approve) = env_question(&label, secrets, to);
    confirm::require(app, &title, &body, &approve)?;
    let_out().record(&key, asked);
    Ok(())
}

/// The dialog's title, text and button: the environment, as its label names
/// it, how many of its values are secret, and where they go.
fn env_question(label: &str, secrets: u32, to: &EnvUse<'_>) -> (Localized, Localized, Localized) {
    let env = confirm::shown(label, 120);
    let count = if secrets == 1 {
        "1 secret value".to_owned()
    } else {
        format!("{secrets} secret values")
    };
    match to {
        EnvUse::Shell => (
            Localized::new(
                "Open a terminal with secret values?",
                "Открыть терминал с секретными значениями?",
                "Terminal maxfiy qiymatlar bilan ochilsinmi?",
            ),
            Localized::new(
                format!(
                    "The shell gets the variables of “{env}”, including {count}. Any program \
                     you run in it can read them.\n\nYou won’t be asked again for this \
                     environment until the vault locks. Continue only if you opened this \
                     terminal yourself."
                ),
                format!(
                    "Оболочка получит переменные окружения «{env}»; секретных среди них: \
                     {secrets}. Любая программа, запущенная в ней, сможет их прочитать.\n\nДля \
                     этого окружения вопрос не повторится, пока хранилище не заблокируется. \
                     Продолжайте, только если этот терминал открыли вы."
                ),
                format!(
                    "Shell «{env}» muhitining oʻzgaruvchilarini oladi, ulardan {secrets} tasi \
                     maxfiy. Unda ishga tushirilgan har qanday dastur ularni oʻqiy oladi.\n\nOmbor \
                     qulflanmaguncha bu muhit uchun qayta soʻralmaydi. Bu terminalni oʻzingiz \
                     ochgan boʻlsangizgina davom eting."
                ),
            ),
            Localized::new("Open terminal", "Открыть терминал", "Terminalni ochish"),
        ),
        EnvUse::File(file) => {
            let path = confirm::shown(&file.path, 200);
            let folder = confirm::shown(&file.folder, 200);
            (
                Localized::new(
                    "Write secret values to a file?",
                    "Записать секретные значения в файл?",
                    "Maxfiy qiymatlar faylga yozilsinmi?",
                ),
                Localized::new(
                    format!(
                        "The file {path} in {folder} gets the variables of “{env}”, including \
                         {count}. Any program that can read the file can read them.\n\nYou won’t \
                         be asked again for this environment until the vault locks. Continue \
                         only if you set up this file yourself."
                    ),
                    format!(
                        "Файл {path} в папке {folder} получит переменные окружения «{env}»; \
                         секретных среди них: {secrets}. Любая программа, которая может \
                         прочитать файл, сможет их прочитать.\n\nДля этого окружения вопрос не \
                         повторится, пока хранилище не заблокируется. Продолжайте, только если \
                         этот файл настроили вы."
                    ),
                    format!(
                        "{folder} papkasidagi {path} fayli «{env}» muhitining oʻzgaruvchilarini \
                         oladi, ulardan {secrets} tasi maxfiy. Faylni oʻqiy oladigan har qanday \
                         dastur ularni oʻqiy oladi.\n\nOmbor qulflanmaguncha bu muhit uchun qayta \
                         soʻralmaydi. Bu faylni oʻzingiz sozlagan boʻlsangizgina davom eting."
                    ),
                ),
                Localized::new("Write file", "Записать файл", "Faylni yozish"),
            )
        }
    }
}

/// What was let out, and how many times the answers were forgotten, so a
/// yes that comes after the vault locked isn't kept.
struct LetOut {
    forgotten: u64,
    keys: BTreeSet<String>,
}

impl LetOut {
    const fn new() -> Self {
        Self {
            forgotten: 0,
            keys: BTreeSet::new(),
        }
    }

    /// `None` if `key` was let out already; otherwise the count to give
    /// [`Self::record`] with the user's yes.
    fn ask(&self, key: &str) -> Option<u64> {
        (!self.keys.contains(key)).then_some(self.forgotten)
    }

    /// Keeps a yes to a question asked at `asked`, unless the answers were
    /// forgotten since.
    fn record(&mut self, key: &str, asked: u64) {
        if asked == self.forgotten {
            self.keys.insert(key.to_owned());
        }
    }

    fn forget(&mut self) {
        self.forgotten += 1;
        self.keys.clear();
    }
}

fn let_out() -> MutexGuard<'static, LetOut> {
    LET_OUT.lock().unwrap_or_else(PoisonError::into_inner)
}

// --- Single secrets -----------------------------------------------------------

/// How many secrets may be shown or copied in a minute before each further
/// one is asked for.
pub const FREE_PER_MINUTE: usize = 10;
const MINUTE: Duration = Duration::from_secs(60);

/// When the secrets of the last minute were shown or copied.
static TAKEN: Mutex<Taken> = Mutex::new(Taken::new());

/// What happens to a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taking {
    /// It is shown on the page.
    Show,
    /// It goes to the clipboard, which any program can read.
    Copy,
}

/// Lets one more secret out, to the page (`Show`) or the clipboard
/// (`Copy`): free while fewer than [`FREE_PER_MINUTE`] went out in the last
/// minute, otherwise only after a yes in a native dialog naming `what`, so a
/// script can't read the vault out one secret after another. Fails with
/// `cancelled` on a no. Call it before the secret is read, outside the
/// vault's lock: the dialog waits for the user.
pub fn take_secret(app: &AppHandle, taking: Taking, what: &Localized) -> AppResult<()> {
    if taken().try_take(Instant::now()) {
        return Ok(());
    }
    let (title, body, approve) = take_question(taking, what);
    confirm::require(app, &title, &body, &approve)?;
    taken().record(Instant::now());
    Ok(())
}

/// [`take_secret`] for the value of the variable `name` of the environment
/// `env`, if it is a secret one; other values go without counting.
pub fn take_env_value(
    app: &AppHandle,
    state: &AppState,
    env: &str,
    name: &str,
    taking: Taking,
) -> AppResult<()> {
    let found = state.vault.with_quietly(app, |vault| {
        let detail = vault.environment(env)?;
        let secret = detail
            .variables
            .iter()
            .any(|var| var.name == name && var.secret);
        Ok(secret.then(|| {
            envs::label(
                Some(&vault.env_label(&detail.summary)),
                &detail.summary.name,
            )
        }))
    })?;
    match found {
        Some(label) => take_secret(app, taking, &env_value(name, &label)),
        None => Ok(()),
    }
}

/// [`take_secret`] for the password of the vault's entry `id`.
pub fn take_entry_password(
    app: &AppHandle,
    state: &AppState,
    id: &str,
    taking: Taking,
) -> AppResult<()> {
    let title = state
        .vault
        .with_quietly(app, |vault| Ok(vault.entry(id)?.summary.title))?;
    take_secret(app, taking, &entry_password(&title))
}

/// The dialog for one more secret past the free ones.
fn take_question(taking: Taking, what: &Localized) -> (Localized, Localized, Localized) {
    let free = FREE_PER_MINUTE;
    let (en, ru, uz) = (&what.en, &what.ru, &what.uz);
    let body = Localized::new(
        format!(
            "More than {free} secrets were shown or copied in the last minute, so each further \
             one is asked for. This one is {en}.\n\nContinue only if you asked for it yourself."
        ),
        format!(
            "За последнюю минуту показано или скопировано больше {free} секретов, поэтому о \
             каждом следующем приложение спрашивает. Сейчас это {ru}.\n\nПродолжайте, только \
             если запросили его сами."
        ),
        format!(
            "Oxirgi bir daqiqada {free} tadan ortiq sir koʻrsatildi yoki nusxalandi, shuning \
             uchun har bir keyingisi soʻraladi. Bu safar: {uz}.\n\nUni oʻzingiz soʻragan \
             boʻlsangizgina davom eting."
        ),
    );
    match taking {
        Taking::Show => (
            Localized::new(
                "Show another secret?",
                "Показать ещё один секрет?",
                "Yana bir sir koʻrsatilsinmi?",
            ),
            body,
            Localized::new("Show", "Показать", "Koʻrsatish"),
        ),
        Taking::Copy => (
            Localized::new(
                "Copy another secret?",
                "Скопировать ещё один секрет?",
                "Yana bir sir nusxalansinmi?",
            ),
            body,
            Localized::new("Copy", "Скопировать", "Nusxalash"),
        ),
    }
}

/// An entry's password, for [`take_secret`]: `title` is the entry's.
pub fn entry_password(title: &str) -> Localized {
    let title = confirm::shown(title, 80);
    Localized::new(
        format!("the password of “{title}”"),
        format!("пароль записи «{title}»"),
        format!("«{title}» yozuvining paroli"),
    )
}

/// A variable's value, for [`take_secret`]: `label` is its environment's.
pub fn env_value(name: &str, label: &str) -> Localized {
    let name = confirm::shown(name, 80);
    let env = confirm::shown(label, 120);
    Localized::new(
        format!("{name} of “{env}”"),
        format!("{name} из окружения «{env}»"),
        format!("«{env}» muhitidagi {name}"),
    )
}

/// The vault's password for a login being imported, for [`take_secret`].
pub fn import_password() -> Localized {
    Localized::new(
        "the password in the vault for a login being imported",
        "пароль из хранилища для импортируемого логина",
        "import qilinayotgan login uchun ombordagi parol",
    )
}

/// When secrets were let out in the last minute.
struct Taken {
    at: VecDeque<Instant>,
}

impl Taken {
    const fn new() -> Self {
        Self {
            at: VecDeque::new(),
        }
    }

    /// Counts one more taken at `now` if fewer than [`FREE_PER_MINUTE`]
    /// were in the minute before; returns whether it did.
    fn try_take(&mut self, now: Instant) -> bool {
        while self
            .at
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= MINUTE)
        {
            self.at.pop_front();
        }
        if self.at.len() < FREE_PER_MINUTE {
            self.at.push_back(now);
            true
        } else {
            false
        }
    }

    /// Counts one taken at `now` after the user said yes.
    fn record(&mut self, now: Instant) {
        self.at.push_back(now);
        // Only the newest matter for the count.
        while self.at.len() > FREE_PER_MINUTE {
            self.at.pop_front();
        }
    }
}

fn taken() -> MutexGuard<'static, Taken> {
    TAKEN.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_environment_is_asked_for_once_per_use_until_the_vault_locks() {
        let file = EnvFile {
            folder: "~/code/shop".into(),
            path: ".env".into(),
        };
        let shell = EnvUse::Shell.key("env-1");
        let to_file = EnvUse::File(&file).key("env-1");
        let mut let_out = LetOut::new();
        let asked = let_out.ask(&shell).expect("asked the first time");
        let_out.record(&shell, asked);
        assert_eq!(let_out.ask(&shell), None);
        // A shell's yes doesn't let the values into a file, nor another
        // environment's.
        assert!(let_out.ask(&to_file).is_some());
        assert!(let_out.ask(&EnvUse::Shell.key("env-2")).is_some());

        // The vault locks: everything is asked for again.
        let_out.forget();
        assert!(let_out.ask(&shell).is_some());
    }

    #[test]
    fn a_yes_given_after_the_vault_locked_is_not_kept() {
        let mut let_out = LetOut::new();
        let asked = let_out.ask("shell:env-1").unwrap();
        // The vault locks while the dialog is open.
        let_out.forget();
        let_out.record("shell:env-1", asked);
        assert!(let_out.ask("shell:env-1").is_some());
    }

    #[test]
    fn the_dialog_names_the_environment_its_secret_values_and_the_file() {
        let (_, body, _) = env_question("Shop · backend · prod", 3, &EnvUse::Shell);
        assert!(
            body.en
                .contains("“Shop · backend · prod”, including 3 secret values")
        );
        assert!(
            body.ru
                .contains("«Shop · backend · prod»; секретных среди них: 3")
        );
        assert!(body.uz.contains("ulardan 3 tasi maxfiy"));
        let (_, body, _) = env_question("dev", 1, &EnvUse::Shell);
        assert!(body.en.contains("including 1 secret value."));

        let file = EnvFile {
            folder: "~/code/shop".into(),
            path: "apps/web/.env.local".into(),
        };
        let (title, body, _) = env_question("Shop · prod", 2, &EnvUse::File(&file));
        assert_eq!(title.en, "Write secret values to a file?");
        assert!(body.en.contains(
            "The file apps/web/.env.local in ~/code/shop gets the variables of “Shop · prod”, \
             including 2 secret values"
        ));

        // A name received from a contact can't add lines or turn text around.
        let (_, body, _) =
            env_question("prod\n\nYou were asked already\u{202E}", 2, &EnvUse::Shell);
        assert!(
            body.en
                .contains("“prod<U+000A><U+000A>You were asked already<U+202E>”")
        );
    }

    #[test]
    fn a_few_secrets_a_minute_are_free_and_each_one_past_that_is_asked() {
        let start = Instant::now();
        let mut taken = Taken::new();
        for i in 0..FREE_PER_MINUTE {
            assert!(
                taken.try_take(start + Duration::from_secs(u64::try_from(i).unwrap())),
                "{i}"
            );
        }
        // The next one in the same minute is asked for, and so is the one after
        // a yes.
        let soon = start + Duration::from_secs(30);
        assert!(!taken.try_take(soon));
        taken.record(soon);
        assert!(!taken.try_take(soon + Duration::from_secs(1)));
        // A minute after the first ones, they are free again.
        assert!(taken.try_take(start + Duration::from_secs(95)));
        assert!(taken.at.len() <= FREE_PER_MINUTE);
    }

    #[test]
    fn the_question_names_the_secret() {
        let what = entry_password("GitHub\u{202E}");
        let (title, body, approve) = take_question(Taking::Show, &what);
        assert_eq!(title.en, "Show another secret?");
        assert_eq!(approve.en, "Show");
        assert!(body.en.contains("More than 10 secrets"));
        assert!(
            body.en
                .contains("This one is the password of “GitHub<U+202E>”.")
        );
        let what = env_value("DATABASE_URL", "Shop · prod");
        let (title, body, _) = take_question(Taking::Copy, &what);
        assert_eq!(title.ru, "Скопировать ещё один секрет?");
        assert!(body.ru.contains("DATABASE_URL из окружения «Shop · prod»"));
        assert!(body.uz.contains("«Shop · prod» muhitidagi DATABASE_URL"));
    }
}
