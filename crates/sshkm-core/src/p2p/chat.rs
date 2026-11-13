//! Chats: the frames two apps send each other in a chat session, as
//! [`Message::Chat`](super::Message::Chat), only to a peer whose `Hello`
//! named [`CHAT`](super::protocol::CHAT).
//!
//! - **Messages.** A text, a secret with its term (`ttl`, in seconds) and
//!   variables with theirs go at once; the receiver answers
//!   [`ChatFrame::Delivered`] once it has stored them, and drops a message
//!   whose id it has seen already.
//! - **Cards.** An item goes as Nearby sends one: what it is
//!   ([`ChatFrame::Offer`], nothing secret), the other user's answer
//!   ([`ChatFrame::Reply`]), then the item ([`ChatFrame::Payload`]), which
//!   must be what was offered, and whether it was saved
//!   ([`ChatFrame::Saved`]).
//! - **Checks.** [`ChatFrame::check`] says whether a frame is one this side
//!   takes; one it doesn't is answered with [`ChatFrame::Refused`]. A frame
//!   of a kind this version doesn't know parses as [`ChatFrame::Unknown`]
//!   and is dropped.
//! - **Rate.** [`RateLimit`] bounds how many frames a peer may send.
//!
//! Secret and variables frames are padded ([`ChatFrame::padded`]), so the
//! length of a frame doesn't tell the length of a password.

use std::fmt;
use std::time::Instant;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::protocol::{
    EnvVariable, Item, ItemSummary, MAX_ENVIRONMENT_BYTES, Message, SecretText, text,
};
use crate::vault::envs;

/// Longest text, in bytes.
pub const MAX_TEXT: usize = 16 * 1024;
/// Longest secret value, in bytes.
pub const MAX_SECRET: usize = 16 * 1024;
/// Longest label of a secret, in characters.
pub const MAX_LABEL: usize = 64;
/// Longest label of variables (a project and an environment), in characters.
pub const MAX_VARIABLES_LABEL: usize = 160;
/// Shortest and longest term of a secret or variables, in seconds.
pub const MIN_TTL: u64 = 5 * 60;
pub const MAX_TTL: u64 = 7 * 24 * 60 * 60;
/// The terms the app offers: an hour, a day, a week.
pub const TERMS: [u64; 3] = [60 * 60, 24 * 60 * 60, 7 * 24 * 60 * 60];
/// Most ids one receipt names.
pub const MAX_RECEIPTS: usize = 64;
/// Frames a peer may send at once, and how many more each second.
const BURST: f64 = 30.0;
const REFILL: f64 = 2.0;
/// Secret frames are padded to a multiple of this many bytes of JSON.
const PAD_TO: usize = 512;
/// Bytes of a message id, before hex.
const ID_BYTES: usize = 16;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ChatFrame {
    Text {
        id: String,
        text: String,
    },
    /// A value shown only when the user asks, gone `ttl` seconds after it
    /// arrives.
    Secret {
        id: String,
        /// What it is, e.g. "staging DB password"; may be empty.
        #[serde(default)]
        label: String,
        value: SecretText,
        ttl: u64,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pad: String,
    },
    /// Variables of an environment, with their values, gone `ttl` seconds
    /// after they arrive; the receiver may add them to an environment.
    Variables {
        id: String,
        /// Where they come from, e.g. "shop · prod".
        #[serde(default)]
        label: String,
        variables: Vec<EnvVariable>,
        ttl: u64,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pad: String,
    },
    /// An item, without its secrets, for the other user to accept.
    Offer {
        id: String,
        item: ItemSummary,
    },
    /// The other user's answer to offer `id`; with `unsupported`, this
    /// version can't take it.
    Reply {
        id: String,
        accepted: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        unsupported: bool,
    },
    /// The item of offer `id`, after the other user accepted it.
    Payload {
        id: String,
        item: Item,
    },
    /// Whether the receiver saved the item of offer `id`.
    Saved {
        id: String,
        saved: bool,
    },
    /// The receiver stored these messages.
    Delivered {
        ids: Vec<String>,
    },
    /// The receiver didn't take message `id`.
    Refused {
        id: String,
        reason: Refusal,
    },
    /// The sender wiped the secret or variables `id` before their term.
    Revoke {
        id: String,
    },
    Ping {
        n: u64,
    },
    Pong {
        n: u64,
    },
    /// A frame of a kind a later version sends: dropped, never sent.
    #[serde(other)]
    Unknown,
}

/// Why a message was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Refusal {
    /// Larger than this side takes.
    TooLarge,
    /// Something in it this side may not store.
    Invalid,
    /// Too many offers wait already.
    TooMany,
    /// Of a kind this version doesn't know.
    Unsupported,
    /// A reason a later version gives.
    #[serde(other)]
    Other,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes a reference"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

impl ChatFrame {
    /// The message this frame is or answers, if it names one.
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Text { id, .. }
            | Self::Secret { id, .. }
            | Self::Variables { id, .. }
            | Self::Offer { id, .. }
            | Self::Reply { id, .. }
            | Self::Payload { id, .. }
            | Self::Saved { id, .. }
            | Self::Refused { id, .. }
            | Self::Revoke { id } => Some(id),
            Self::Delivered { .. } | Self::Ping { .. } | Self::Pong { .. } | Self::Unknown => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Text { .. } => "text",
            Self::Secret { .. } => "secret",
            Self::Variables { .. } => "variables",
            Self::Offer { .. } => "offer",
            Self::Reply { .. } => "reply",
            Self::Payload { .. } => "payload",
            Self::Saved { .. } => "saved",
            Self::Delivered { .. } => "delivered",
            Self::Refused { .. } => "refused",
            Self::Revoke { .. } => "revoke",
            Self::Ping { .. } => "ping",
            Self::Pong { .. } => "pong",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this side takes the frame: ids as [`new_id`] makes them, no
    /// control characters but line breaks and tabs in values, sizes and
    /// terms in bounds, variables an environment may have, an item that
    /// passes [`Item::check`].
    pub fn check(&self) -> Result<(), Refusal> {
        if let Some(id) = self.id()
            && !is_id(id)
        {
            return Err(Refusal::Invalid);
        }
        match self {
            Self::Text { text: value, .. } => {
                if value.len() > MAX_TEXT {
                    return Err(Refusal::TooLarge);
                }
                if value.trim().is_empty() {
                    return Err(Refusal::Invalid);
                }
                text(value, true).map_err(|_| Refusal::Invalid)
            }
            Self::Secret {
                label, value, ttl, ..
            } => {
                check_label(label, MAX_LABEL)?;
                let value = value.expose();
                if value.len() > MAX_SECRET {
                    return Err(Refusal::TooLarge);
                }
                if value.is_empty() {
                    return Err(Refusal::Invalid);
                }
                text(value, true).map_err(|_| Refusal::Invalid)?;
                check_ttl(*ttl)
            }
            Self::Variables {
                label,
                variables,
                ttl,
                ..
            } => {
                check_label(label, MAX_VARIABLES_LABEL)?;
                check_variables(variables)?;
                check_ttl(*ttl)
            }
            Self::Offer { item, .. } => match item {
                ItemSummary::Unknown => Err(Refusal::Unsupported),
                _ => Ok(()),
            },
            Self::Payload { item, .. } => match item {
                Item::Unknown => Err(Refusal::Unsupported),
                item => item.check().map_err(|_| Refusal::Invalid),
            },
            Self::Delivered { ids } => {
                if ids.is_empty() || ids.len() > MAX_RECEIPTS || !ids.iter().all(|id| is_id(id)) {
                    return Err(Refusal::Invalid);
                }
                Ok(())
            }
            Self::Reply { .. }
            | Self::Saved { .. }
            | Self::Refused { .. }
            | Self::Revoke { .. }
            | Self::Ping { .. }
            | Self::Pong { .. } => Ok(()),
            Self::Unknown => Err(Refusal::Unsupported),
        }
    }

    /// The frame with padding, so that its message's JSON is a multiple of
    /// 512 bytes: a secret's or variables' length doesn't show. Other
    /// frames come back as they are.
    #[must_use]
    pub fn padded(mut self) -> Self {
        // `,"pad":""` around the spaces.
        const FIELD: usize = 9;
        let len = |frame: &Self| {
            serde_json::to_vec(&Message::Chat {
                frame: frame.clone(),
            })
            .map_or(0, |json| json.len())
        };
        let bare = match &mut self {
            Self::Secret { pad, .. } | Self::Variables { pad, .. } => {
                pad.clear();
                true
            }
            _ => false,
        };
        if !bare {
            return self;
        }
        let total = len(&self) + FIELD;
        let spaces = total.next_multiple_of(PAD_TO) - total;
        if let Self::Secret { pad, .. } | Self::Variables { pad, .. } = &mut self {
            *pad = " ".repeat(spaces);
        }
        self
    }
}

impl fmt::Debug for ChatFrame {
    /// The kind and the id: never a text, a value or an item.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id() {
            Some(id) => write!(f, "ChatFrame::{}({id})", self.kind()),
            None => write!(f, "ChatFrame::{}", self.kind()),
        }
    }
}

fn check_label(label: &str, max: usize) -> Result<(), Refusal> {
    if label.chars().count() > max {
        return Err(Refusal::TooLarge);
    }
    text(label, false).map_err(|_| Refusal::Invalid)
}

fn check_ttl(ttl: u64) -> Result<(), Refusal> {
    if (MIN_TTL..=MAX_TTL).contains(&ttl) {
        Ok(())
    } else {
        Err(Refusal::Invalid)
    }
}

/// The rules of an environment's variables ([`Item::check`]), and at least one.
fn check_variables(variables: &[EnvVariable]) -> Result<(), Refusal> {
    if variables.is_empty() {
        return Err(Refusal::Invalid);
    }
    if variables.len() > envs::MAX_VARIABLES {
        return Err(Refusal::TooLarge);
    }
    let mut bytes = 0;
    for (index, var) in variables.iter().enumerate() {
        if !envs::is_valid_name(&var.name)
            || variables[..index]
                .iter()
                .any(|other| other.name == var.name)
        {
            return Err(Refusal::Invalid);
        }
        text(&var.value, true).map_err(|_| Refusal::Invalid)?;
        text(&var.note, false).map_err(|_| Refusal::Invalid)?;
        bytes += var.name.len() + var.value.len() + var.note.len();
    }
    if bytes > MAX_ENVIRONMENT_BYTES {
        return Err(Refusal::TooLarge);
    }
    Ok(())
}

/// A new message id: 16 random bytes, as 32 lowercase hex digits.
pub fn new_id() -> String {
    let mut bytes = [0; ID_BYTES];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(2 * ID_BYTES), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// Whether `id` is a message id as [`new_id`] makes them.
pub fn is_id(id: &str) -> bool {
    id.len() == 2 * ID_BYTES && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// How many frames a peer may still send: thirty at once, two more each
/// second.
#[derive(Debug, Clone)]
pub struct RateLimit {
    tokens: f64,
    last: Instant,
}

impl RateLimit {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: BURST,
            last: now,
        }
    }

    /// Counts one frame at `now`; `false` once the peer sent too many.
    pub fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * REFILL).min(BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn id() -> String {
        new_id()
    }

    fn var(name: &str, value: &str) -> EnvVariable {
        EnvVariable {
            name: name.into(),
            value: value.into(),
            secret: true,
            note: String::new(),
        }
    }

    #[test]
    fn frames_round_trip_as_tagged_json() {
        let text = ChatFrame::Text {
            id: "0123456789abcdef0123456789abcdef".into(),
            text: "on my way".into(),
        };
        let json = serde_json::to_string(&Message::Chat {
            frame: text.clone(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"type":"chat","frame":{"kind":"text","id":"0123456789abcdef0123456789abcdef","text":"on my way"}}"#
        );
        assert_eq!(
            serde_json::from_str::<Message>(&json).unwrap(),
            Message::Chat { frame: text }
        );
        let frames = [
            ChatFrame::Secret {
                id: id(),
                label: "db".into(),
                value: SecretText::new("s3cret"),
                ttl: TERMS[0],
                pad: String::new(),
            },
            ChatFrame::Variables {
                id: id(),
                label: "shop · prod".into(),
                variables: vec![var("API_KEY", "x")],
                ttl: TERMS[1],
                pad: String::new(),
            },
            ChatFrame::Reply {
                id: id(),
                accepted: false,
                unsupported: true,
            },
            ChatFrame::Delivered {
                ids: vec![id(), id()],
            },
            ChatFrame::Refused {
                id: id(),
                reason: Refusal::TooMany,
            },
            ChatFrame::Revoke { id: id() },
            ChatFrame::Ping { n: 7 },
        ];
        for frame in frames {
            let json = serde_json::to_string(&frame).unwrap();
            assert_eq!(serde_json::from_str::<ChatFrame>(&json).unwrap(), frame);
        }
    }

    #[test]
    fn unknown_kinds_and_reasons_parse() {
        let frame: ChatFrame =
            serde_json::from_str(r#"{"kind":"reaction","id":"x","emoji":"+1"}"#).unwrap();
        assert_eq!(frame, ChatFrame::Unknown);
        assert_eq!(frame.check(), Err(Refusal::Unsupported));
        let refused: ChatFrame = serde_json::from_str(&format!(
            r#"{{"kind":"refused","id":"{}","reason":"busy"}}"#,
            id()
        ))
        .unwrap();
        assert!(matches!(
            refused,
            ChatFrame::Refused {
                reason: Refusal::Other,
                ..
            }
        ));
    }

    #[test]
    fn secrets_stay_out_of_debug() {
        let frame = ChatFrame::Secret {
            id: id(),
            label: "label".into(),
            value: SecretText::new("hunter2"),
            ttl: TERMS[0],
            pad: String::new(),
        };
        let debug = format!("{frame:?}");
        assert!(!debug.contains("hunter2") && !debug.contains("label"));
        assert!(debug.starts_with("ChatFrame::secret("));
        let text = ChatFrame::Text {
            id: id(),
            text: "private words".into(),
        };
        assert!(!format!("{:?}", Message::Chat { frame: text }).contains("private"));
    }

    #[test]
    fn checks_what_may_be_stored() {
        let ok = |frame: ChatFrame| frame.check();
        assert_eq!(
            ok(ChatFrame::Text {
                id: id(),
                text: "line one\nline two\ttab".into()
            }),
            Ok(())
        );
        for bad in ["", "  ", "bell \u{7}", "esc \u{1b}[2J"] {
            assert_eq!(
                ok(ChatFrame::Text {
                    id: id(),
                    text: bad.into()
                }),
                Err(Refusal::Invalid),
                "{bad:?}"
            );
        }
        assert_eq!(
            ok(ChatFrame::Text {
                id: id(),
                text: "x".repeat(MAX_TEXT + 1)
            }),
            Err(Refusal::TooLarge)
        );
        assert_eq!(
            ok(ChatFrame::Text {
                id: "NOT-AN-ID".into(),
                text: "hi".into()
            }),
            Err(Refusal::Invalid)
        );
        let secret = |label: &str, value: &str, ttl: u64| ChatFrame::Secret {
            id: id(),
            label: label.into(),
            value: SecretText::new(value),
            ttl,
            pad: String::new(),
        };
        assert_eq!(ok(secret("", "v", TERMS[2])), Ok(()));
        assert_eq!(
            ok(secret("two\nlines", "v", TERMS[0])),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            ok(secret(&"l".repeat(65), "v", TERMS[0])),
            Err(Refusal::TooLarge)
        );
        assert_eq!(ok(secret("", "", TERMS[0])), Err(Refusal::Invalid));
        assert_eq!(ok(secret("", "v", MIN_TTL - 1)), Err(Refusal::Invalid));
        assert_eq!(ok(secret("", "v", MAX_TTL + 1)), Err(Refusal::Invalid));
        assert_eq!(
            ok(secret("", &"v".repeat(MAX_SECRET + 1), TERMS[0])),
            Err(Refusal::TooLarge)
        );
        let variables = |vars: Vec<EnvVariable>| ChatFrame::Variables {
            id: id(),
            label: String::new(),
            variables: vars,
            ttl: TERMS[0],
            pad: String::new(),
        };
        assert_eq!(ok(variables(vec![var("A", "1"), var("B", "2")])), Ok(()));
        assert_eq!(ok(variables(vec![])), Err(Refusal::Invalid));
        assert_eq!(ok(variables(vec![var("$(x)", "1")])), Err(Refusal::Invalid));
        assert_eq!(
            ok(variables(vec![var("A", "1"), var("A", "2")])),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            ok(variables(vec![var("A", "\u{1b}[2J")])),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            ok(ChatFrame::Offer {
                id: id(),
                item: ItemSummary::Unknown
            }),
            Err(Refusal::Unsupported)
        );
        assert_eq!(
            ok(ChatFrame::Delivered { ids: vec![] }),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            ok(ChatFrame::Delivered {
                ids: vec![id(); MAX_RECEIPTS + 1]
            }),
            Err(Refusal::Invalid)
        );
    }

    #[test]
    fn secret_frames_are_padded_to_512_bytes() {
        for value in ["a", "correct horse battery staple", &"z".repeat(700)] {
            let frame = ChatFrame::Secret {
                id: id(),
                label: "db".into(),
                value: SecretText::new(value),
                ttl: TERMS[0],
                pad: String::new(),
            }
            .padded();
            let json = serde_json::to_vec(&Message::Chat {
                frame: frame.clone(),
            })
            .unwrap();
            assert_eq!(json.len() % PAD_TO, 0, "{value}");
            assert_eq!(frame.check(), Ok(()));
        }
        let text = ChatFrame::Text {
            id: id(),
            text: "hi".into(),
        };
        assert_eq!(text.clone().padded(), text);
    }

    #[test]
    fn ids_are_random_hex() {
        let (a, b) = (new_id(), new_id());
        assert!(is_id(&a) && is_id(&b));
        assert_ne!(a, b);
        assert!(!is_id(&a.to_uppercase()));
        assert!(!is_id(&a[1..]));
    }

    #[test]
    fn the_rate_limit_allows_a_burst_then_two_a_second() {
        let start = Instant::now();
        let mut limit = RateLimit::new(start);
        for _ in 0..30 {
            assert!(limit.take(start));
        }
        assert!(!limit.take(start));
        let later = start + Duration::from_secs(1);
        assert!(limit.take(later));
        assert!(limit.take(later));
        assert!(!limit.take(later));
        let much_later = later + Duration::from_secs(3600);
        for _ in 0..30 {
            assert!(limit.take(much_later));
        }
        assert!(!limit.take(much_later));
    }
}
