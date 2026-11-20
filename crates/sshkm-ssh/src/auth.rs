//! Signing in to one machine: the phone's key, then the server's own
//! prompts (keyboard-interactive), then a password, as OpenSSH orders them
//! (`PreferredAuthentications`), each only if the server offers it.
//!
//! The key is offered first without a signature; the app is asked to sign
//! (and the user to unlock the key) only once the server has said it would
//! take it. A server that asks for more after one method succeeded
//! (`partial success`: a key and then a code) gets the next one. Prompts
//! and passwords are asked of the app each time, three times at most per
//! method (`NumberOfPasswordPrompts`); answers are wiped once sent.

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::HashAlg;
use russh::keys::agent::AgentIdentity;
use russh::{MethodKind, MethodSet};
use sshkm_core::prompt::ServerPrompt;
use zeroize::Zeroizing;

use crate::callbacks::{AuthMethod, AuthPrompt, Callbacks, PromptItem, SignError, SignRequest};
use crate::client::HopHandler;
use crate::error::Error;
use crate::key::PhoneKey;
use crate::route::Endpoint;

/// Attempts per method, as OpenSSH's `NumberOfPasswordPrompts`.
const ATTEMPTS: u32 = 3;

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
    let mut key_tried = false;
    let mut interactive_attempts = 0;
    let mut password_attempts = 0;
    loop {
        let result = if let Some(key) = key.filter(|_| !key_tried)
            && methods.contains(&MethodKind::PublicKey)
        {
            key_tried = true;
            let mut signer = AppSigner {
                key,
                callbacks,
                alias: &endpoint.alias,
                user,
            };
            handle
                .authenticate_publickey_with(user, key.public_key().clone(), None, &mut signer)
                .await
                .map_err(|e| e.into_error(&endpoint.alias))?
        } else if interactive_attempts < ATTEMPTS
            && methods.contains(&MethodKind::KeyboardInteractive)
        {
            interactive_attempts += 1;
            keyboard_interactive(handle, endpoint, user, interactive_attempts, callbacks).await?
        } else if password_attempts < ATTEMPTS && methods.contains(&MethodKind::Password) {
            password_attempts += 1;
            password(handle, endpoint, user, password_attempts, callbacks).await?
        } else {
            return Err(failed(&methods));
        };
        match result {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure {
                remaining_methods,
                partial_success,
            } => {
                if partial_success {
                    // A new step: its prompts are new questions.
                    interactive_attempts = 0;
                    password_attempts = 0;
                }
                methods = remaining_methods;
            }
        }
    }
}

/// One keyboard-interactive exchange, as many rounds as the server asks.
async fn keyboard_interactive(
    handle: &mut Handle<HopHandler>,
    endpoint: &Endpoint,
    user: &str,
    attempt: u32,
    callbacks: &dyn Callbacks,
) -> Result<AuthResult, Error> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                });
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let answers = if prompts.is_empty() {
                    // Nothing to ask (some servers send an empty round).
                    Vec::new()
                } else {
                    let items = prompts
                        .iter()
                        .map(|p| PromptItem {
                            kind: ServerPrompt::of(&p.prompt),
                            text: p.prompt.clone(),
                            echo: p.echo,
                        })
                        .collect::<Vec<_>>();
                    let count = items.len();
                    let answers = callbacks
                        .answer(AuthPrompt {
                            alias: endpoint.alias.clone(),
                            host: endpoint.host.clone(),
                            port: endpoint.port,
                            user: user.to_owned(),
                            method: AuthMethod::KeyboardInteractive,
                            name,
                            instructions,
                            prompts: items,
                            attempt,
                        })
                        .await
                        .ok_or(Error::Cancelled)?;
                    if answers.len() != count {
                        return Err(Error::Cancelled);
                    }
                    answers
                };
                // russh takes `String`s; ours are wiped when they go.
                let sent = answers.iter().map(|a| String::clone(a)).collect();
                drop(answers);
                response = handle
                    .authenticate_keyboard_interactive_respond(sent)
                    .await?;
            }
        }
    }
}

/// One `password` attempt.
async fn password(
    handle: &mut Handle<HopHandler>,
    endpoint: &Endpoint,
    user: &str,
    attempt: u32,
    callbacks: &dyn Callbacks,
) -> Result<AuthResult, Error> {
    let text = format!("{user}@{}'s password: ", endpoint.host);
    let mut answers = callbacks
        .answer(AuthPrompt {
            alias: endpoint.alias.clone(),
            host: endpoint.host.clone(),
            port: endpoint.port,
            user: user.to_owned(),
            method: AuthMethod::Password,
            name: String::new(),
            instructions: String::new(),
            prompts: vec![PromptItem {
                text,
                echo: false,
                kind: ServerPrompt::Password,
            }],
            attempt,
        })
        .await
        .ok_or(Error::Cancelled)?;
    if answers.len() != 1 {
        return Err(Error::Cancelled);
    }
    let password: Zeroizing<String> = answers.remove(0);
    // russh wipes its copy when the request is gone.
    Ok(handle
        .authenticate_password(user, String::clone(&password))
        .await?)
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
    App(SignError),
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
            Self::App(SignError::Cancelled) => Error::Cancelled,
            Self::App(SignError::Failed(detail)) => Error::Signer {
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
