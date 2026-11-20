//! Signing in to one machine: the phone's key, then the server's own
//! prompts (keyboard-interactive), then a password, as OpenSSH orders them
//! (`PreferredAuthentications`), each only if the server offers it.
//!
//! The key is offered first without a signature; the app is asked to sign
//! (and the user to unlock the key) only once the server has said it would
//! take it. A server that asks for more after one method succeeded
//! (`partial success`: a key and then a code) gets the next one.
//!
//! Every question is counted by what it asks (the password, a one-time
//! code, or another question by its text), across rounds, keyboard-
//! interactive exchanges and the password method alike. The prompt the app
//! gets says how often (`attempt`), so a value filled from the vault isn't
//! sent again unasked, and a question asked three times
//! (`NumberOfPasswordPrompts`) isn't answered a fourth: the client answers
//! the pending request with nothing (russh lets no other request through
//! until it is answered), and once the server ends the exchange it moves on
//! to another method; a server that keeps asking even then is given up on.
//! So a server that keeps asking can't lock the account with the vault's
//! password. Rounds and steps are bounded too.
//!
//! The client wipes its own copies of answers. russh wipes the password it
//! sends with the password method, but not keyboard-interactive answers,
//! which it takes as plain strings.

use std::collections::HashMap;

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::HashAlg;
use russh::keys::agent::AgentIdentity;
use russh::{MethodKind, MethodSet};
use sshkm_core::prompt::ServerPrompt;
use zeroize::Zeroizing;

use crate::callbacks::{AuthMethod, AuthPrompt, CallbackError, Callbacks, PromptItem, SignRequest};
use crate::client::HopHandler;
use crate::error::Error;
use crate::key::PhoneKey;
use crate::route::Endpoint;

/// Times the same question is answered, as OpenSSH's
/// `NumberOfPasswordPrompts`.
const ATTEMPTS: u32 = 3;
/// Rounds of one keyboard-interactive exchange.
const ROUNDS: u32 = 16;
/// Methods tried, in all, on one machine.
const STEPS: u32 = 16;
/// Empty answers given to leave a keyboard-interactive exchange.
const LEAVING: u32 = 2;

/// What a question asks, for counting: the password and one-time codes by
/// kind, anything else by its text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Question {
    Password,
    OneTimeCode,
    Other(String),
}

impl Question {
    fn of(item: &PromptItem) -> Self {
        match item.kind {
            ServerPrompt::Password => Self::Password,
            ServerPrompt::OneTimeCode => Self::OneTimeCode,
            ServerPrompt::Other => Self::Other(item.text.trim().to_owned()),
        }
    }
}

/// How often each question has been asked on this machine.
#[derive(Debug, Default)]
struct Asked(HashMap<Question, u32>);

impl Asked {
    /// The attempt `items` would be: one more than the most any of them was
    /// asked. `None` once one of them has been asked [`ATTEMPTS`] times.
    fn next_attempt(&self, items: &[PromptItem]) -> Option<u32> {
        let most = items
            .iter()
            .map(|item| self.0.get(&Question::of(item)).copied().unwrap_or(0))
            .max()
            .unwrap_or(0);
        (most < ATTEMPTS).then_some(most + 1)
    }

    fn count(&mut self, items: &[PromptItem]) {
        for item in items {
            *self.0.entry(Question::of(item)).or_default() += 1;
        }
    }
}

/// How a method ended.
enum Outcome {
    Server(AuthResult),
    /// The client stopped before asking (the password asked too often).
    GaveUp,
}

/// How a keyboard-interactive exchange ended.
enum Interactive {
    /// The server ended it.
    Server(AuthResult),
    /// The client stopped answering (a question asked too often, too many
    /// rounds) and the server ended it on empty answers: no more
    /// keyboard-interactive on this machine.
    Left(AuthResult),
    /// The server keeps asking even then. russh lets no other request
    /// through until the pending one is answered, so nothing else can be
    /// tried.
    Stuck,
}

/// Signs in to `endpoint` as `user`.
pub(crate) async fn authenticate(
    handle: &mut Handle<HopHandler>,
    endpoint: &Endpoint,
    user: &str,
    key: Option<&PhoneKey>,
    callbacks: &dyn Callbacks,
) -> Result<(), Error> {
    let failed = |methods: &MethodSet| Error::AuthFailed {
        alias: endpoint.alias.clone(),
        user: user.to_owned(),
        methods: methods.iter().map(String::from).collect(),
    };
    let mut methods = match handle.authenticate_none(user).await? {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    let mut asked = Asked::default();
    let mut key_tried = false;
    let mut interactive_done = false;
    let mut password_done = false;
    for _ in 0..STEPS {
        let outcome = if let Some(key) = key.filter(|_| !key_tried)
            && methods.contains(&MethodKind::PublicKey)
        {
            key_tried = true;
            let mut signer = AppSigner {
                key,
                callbacks,
                alias: &endpoint.alias,
                user,
            };
            Outcome::Server(
                handle
                    .authenticate_publickey_with(user, key.public_key().clone(), None, &mut signer)
                    .await
                    .map_err(|e| e.into_error(&endpoint.alias))?,
            )
        } else if !interactive_done && methods.contains(&MethodKind::KeyboardInteractive) {
            match keyboard_interactive(handle, endpoint, user, &mut asked, callbacks).await? {
                Interactive::Server(result) => Outcome::Server(result),
                Interactive::Left(result) => {
                    interactive_done = true;
                    Outcome::Server(result)
                }
                Interactive::Stuck => return Err(failed(&methods)),
            }
        } else if !password_done && methods.contains(&MethodKind::Password) {
            let outcome = password(handle, endpoint, user, &mut asked, callbacks).await?;
            password_done = matches!(outcome, Outcome::GaveUp);
            outcome
        } else {
            return Err(failed(&methods));
        };
        match outcome {
            Outcome::Server(AuthResult::Success) => return Ok(()),
            Outcome::Server(AuthResult::Failure {
                remaining_methods, ..
            }) => methods = remaining_methods,
            Outcome::GaveUp => {}
        }
    }
    Err(failed(&methods))
}

/// One keyboard-interactive exchange, as many rounds as the server asks
/// (up to [`ROUNDS`]).
async fn keyboard_interactive(
    handle: &mut Handle<HopHandler>,
    endpoint: &Endpoint,
    user: &str,
    asked: &mut Asked,
    callbacks: &dyn Callbacks,
) -> Result<Interactive, Error> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    let mut rounds = 0;
    loop {
        let (name, instructions, prompts) = match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(Interactive::Server(AuthResult::Success));
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(Interactive::Server(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                }));
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => (name, instructions, prompts),
        };
        rounds += 1;
        let items: Vec<PromptItem> = prompts
            .iter()
            .map(|p| PromptItem {
                kind: ServerPrompt::of(&p.prompt),
                text: p.prompt.clone(),
                echo: p.echo,
            })
            .collect();
        let attempt = if rounds > ROUNDS {
            None
        } else {
            asked.next_attempt(&items)
        };
        let Some(attempt) = attempt else {
            return leave(handle, items.len()).await;
        };
        let answers = if items.is_empty() {
            // Nothing to ask (some servers send an empty round).
            Vec::new()
        } else {
            asked.count(&items);
            let count = items.len();
            let answers = ask(
                callbacks,
                AuthPrompt {
                    alias: endpoint.alias.clone(),
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                    user: user.to_owned(),
                    method: AuthMethod::KeyboardInteractive,
                    name,
                    instructions,
                    prompts: items,
                    attempt,
                },
            )
            .await?;
            if answers.len() != count {
                return Err(Error::Cancelled);
            }
            answers
        };
        // russh takes plain `String`s and doesn't wipe them; ours are
        // wiped as they go.
        let sent = answers.iter().map(|a| String::clone(a)).collect();
        drop(answers);
        response = handle
            .authenticate_keyboard_interactive_respond(sent)
            .await?;
    }
}

/// Leaves a keyboard-interactive exchange with a request pending (`count`
/// questions). russh waits for its answer and drops any other request
/// meanwhile, so it is answered with nothing, which the server takes as a
/// failed attempt, until the server says how the exchange ended.
async fn leave(handle: &mut Handle<HopHandler>, mut count: usize) -> Result<Interactive, Error> {
    for _ in 0..LEAVING {
        match handle
            .authenticate_keyboard_interactive_respond(vec![String::new(); count])
            .await?
        {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(Interactive::Left(AuthResult::Success));
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(Interactive::Left(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                }));
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => count = prompts.len(),
        }
    }
    Ok(Interactive::Stuck)
}

/// One `password` attempt, unless the password was asked too often.
async fn password(
    handle: &mut Handle<HopHandler>,
    endpoint: &Endpoint,
    user: &str,
    asked: &mut Asked,
    callbacks: &dyn Callbacks,
) -> Result<Outcome, Error> {
    let items = vec![PromptItem {
        text: format!("{user}@{}'s password: ", endpoint.host),
        echo: false,
        kind: ServerPrompt::Password,
    }];
    let Some(attempt) = asked.next_attempt(&items) else {
        return Ok(Outcome::GaveUp);
    };
    asked.count(&items);
    let mut answers = ask(
        callbacks,
        AuthPrompt {
            alias: endpoint.alias.clone(),
            host: endpoint.host.clone(),
            port: endpoint.port,
            user: user.to_owned(),
            method: AuthMethod::Password,
            name: String::new(),
            instructions: String::new(),
            prompts: items,
            attempt,
        },
    )
    .await?;
    if answers.len() != 1 {
        return Err(Error::Cancelled);
    }
    let password: Zeroizing<String> = answers.remove(0);
    // russh wipes its copy when the request is gone.
    Ok(Outcome::Server(
        handle
            .authenticate_password(user, String::clone(&password))
            .await?,
    ))
}

/// Asks the app; `None` and a cancelled callback cancel.
async fn ask(
    callbacks: &dyn Callbacks,
    prompt: AuthPrompt,
) -> Result<Vec<Zeroizing<String>>, Error> {
    match callbacks.answer(prompt).await {
        Ok(Some(answers)) => Ok(answers),
        Ok(None) | Err(CallbackError::Cancelled) => Err(Error::Cancelled),
        Err(CallbackError::Failed(detail)) => Err(Error::App { detail }),
    }
}

/// Signs through the app, converting Keystore's DER signature.
struct AppSigner<'a> {
    key: &'a PhoneKey,
    callbacks: &'a dyn Callbacks,
    alias: &'a str,
    user: &'a str,
}

/// Why signing through the app failed, for russh's [`Signer`] trait.
///
/// [`Signer`]: russh::Signer
#[derive(Debug)]
enum SignerError {
    Gone,
    App(CallbackError),
    Key(crate::key::KeyError),
}

impl From<russh::SendError> for SignerError {
    fn from(_: russh::SendError) -> Self {
        Self::Gone
    }
}

impl SignerError {
    fn into_error(self, alias: &str) -> Error {
        match self {
            Self::Gone => Error::Disconnected {
                detail: "the connection closed while signing in".to_owned(),
            },
            Self::App(CallbackError::Cancelled) => Error::Cancelled,
            Self::App(CallbackError::Failed(detail)) => Error::Signer {
                alias: alias.to_owned(),
                detail,
            },
            Self::Key(error) => Error::Signer {
                alias: alias.to_owned(),
                detail: error.to_string(),
            },
        }
    }
}

impl russh::Signer for AppSigner<'_> {
    type Error = SignerError;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        let der = self
            .callbacks
            .sign(SignRequest {
                alias: self.alias.to_owned(),
                user: self.user.to_owned(),
                data: to_sign.clone(),
            })
            .await
            .map_err(SignerError::App)?;
        let blob = self
            .key
            .ssh_signature(&to_sign, &der)
            .map_err(SignerError::Key)?;
        // russh sends what follows the data: the signature as a string.
        crate::key::put_string(&mut to_sign, &blob);
        Ok(to_sign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ServerPrompt, text: &str) -> PromptItem {
        PromptItem {
            text: text.to_owned(),
            echo: false,
            kind,
        }
    }

    #[test]
    fn questions_are_counted_by_what_they_ask() {
        let mut asked = Asked::default();
        let password = [item(ServerPrompt::Password, "Password: ")];
        let both = [
            item(ServerPrompt::Password, "Password for alice: "),
            item(ServerPrompt::OneTimeCode, "Verification code: "),
        ];
        let pin = [item(ServerPrompt::Other, "PIN: ")];
        assert_eq!(asked.next_attempt(&password), Some(1));
        asked.count(&password);
        // The password worded otherwise is still the password.
        assert_eq!(asked.next_attempt(&both), Some(2));
        asked.count(&both);
        assert_eq!(asked.next_attempt(&pin), Some(1));
        assert_eq!(asked.next_attempt(&password), Some(3));
        asked.count(&password);
        assert_eq!(asked.next_attempt(&password), None);
        assert_eq!(asked.next_attempt(&both), None);
        assert_eq!(asked.next_attempt(&pin), Some(1));
        assert_eq!(asked.next_attempt(&[]), Some(1));
    }
}
