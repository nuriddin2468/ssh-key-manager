//! The ssh-agent wire protocol (draft-miller-ssh-agent): message encoding and
//! reply parsing. Framing (`u32` length prefix) lives in `transport`.

use base64ct::{Base64, Base64Unpadded, Encoding};
use sha2::{Digest, Sha256};
use ssh_encoding::{Decode, Encode};
use ssh_key::{Certificate, private::KeypairData, public::KeyData};
use zeroize::Zeroizing;

use super::AgentIdentity;
use crate::{
    Error, Result,
    keys::{KeyAlgorithm, fingerprint, key_bits},
};

pub(crate) const FAILURE: u8 = 5;
pub(crate) const SUCCESS: u8 = 6;
pub(crate) const REQUEST_IDENTITIES: u8 = 11;
pub(crate) const IDENTITIES_ANSWER: u8 = 12;
pub(crate) const ADD_IDENTITY: u8 = 17;
pub(crate) const REMOVE_IDENTITY: u8 = 18;
pub(crate) const REMOVE_ALL_IDENTITIES: u8 = 19;
pub(crate) const ADD_ID_CONSTRAINED: u8 = 25;
pub(crate) const EXTENSION_FAILURE: u8 = 28;
/// `SSH_COM_AGENT2_FAILURE`, sent by some third-party agents.
const COM_AGENT2_FAILURE: u8 = 102;
pub(crate) const CONSTRAIN_LIFETIME: u8 = 1;
pub(crate) const CONSTRAIN_CONFIRM: u8 = 2;

fn encoding_error(e: impl std::fmt::Display) -> Error {
    Error::invalid(format!("cannot encode agent request: {e}"))
}

/// `SSH_AGENTC_ADD_IDENTITY` (or `ADD_ID_CONSTRAINED` with constraints). The
/// key is encoded exactly like a key in the OpenSSH private key format (type
/// name followed by the key fields), then the comment and the constraints. The
/// buffer is allocated once at its final size and zeroized on drop.
pub(crate) fn add_identity(
    keypair: &KeypairData,
    comment: &str,
    lifetime_secs: Option<u32>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let constrained = lifetime_secs.is_some() || confirm;
    let capacity = 1 + keypair.encoded_len().map_err(encoding_error)? + 4 + comment.len() + 6;
    let mut msg = Zeroizing::new(Vec::with_capacity(capacity));
    msg.push(if constrained {
        ADD_ID_CONSTRAINED
    } else {
        ADD_IDENTITY
    });
    keypair.encode(&mut *msg).map_err(encoding_error)?;
    comment.encode(&mut *msg).map_err(encoding_error)?;
    if let Some(secs) = lifetime_secs {
        msg.push(CONSTRAIN_LIFETIME);
        secs.encode(&mut *msg).map_err(encoding_error)?;
    }
    if confirm {
        msg.push(CONSTRAIN_CONFIRM);
    }
    Ok(msg)
}

/// `SSH_AGENTC_REMOVE_IDENTITY` for a key blob.
pub(crate) fn remove_identity(blob: &[u8]) -> Result<Vec<u8>> {
    let mut msg = vec![REMOVE_IDENTITY];
    blob.encode(&mut msg).map_err(encoding_error)?;
    Ok(msg)
}

/// Interprets a reply that must be `SSH_AGENT_SUCCESS`.
pub(crate) fn expect_success(reply: &[u8], what: &str) -> Result<()> {
    match reply.first() {
        Some(&SUCCESS) => Ok(()),
        Some(&(FAILURE | EXTENSION_FAILURE | COM_AGENT2_FAILURE)) => {
            Err(Error::AgentRefused(what.to_owned()))
        }
        Some(other) => Err(Error::AgentUnavailable(format!(
            "unexpected reply {other} to {what}"
        ))),
        None => Err(Error::AgentUnavailable(format!("empty reply to {what}"))),
    }
}

/// Parses `SSH_AGENT_IDENTITIES_ANSWER`.
pub(crate) fn parse_identities(reply: &[u8]) -> Result<Vec<AgentIdentity>> {
    let protocol =
        |detail: &str| Error::AgentUnavailable(format!("malformed identities answer: {detail}"));
    let Some((&kind, mut body)) = reply.split_first() else {
        return Err(protocol("empty"));
    };
    match kind {
        IDENTITIES_ANSWER => {}
        FAILURE | EXTENSION_FAILURE | COM_AGENT2_FAILURE => {
            return Err(Error::AgentRefused("listing identities".into()));
        }
        other => return Err(protocol(&format!("message type {other}"))),
    }
    let count = u32::decode(&mut body).map_err(|_| protocol("count"))?;
    let mut out = Vec::new();
    for _ in 0..count {
        let blob = Vec::<u8>::decode(&mut body).map_err(|_| protocol("key blob"))?;
        let comment = Vec::<u8>::decode(&mut body).map_err(|_| protocol("comment"))?;
        out.push(identity(&blob, &String::from_utf8_lossy(&comment)));
    }
    Ok(out)
}

/// Describes a key blob reported by the agent. Plain keys and certificates are
/// decoded; unknown key types are still listed with what the blob reveals.
pub(crate) fn identity(blob: &[u8], comment: &str) -> AgentIdentity {
    let key_type = blob_type(blob).unwrap_or_default().to_owned();
    let public_key = if comment.is_empty() {
        format!("{key_type} {}", Base64::encode_string(blob))
    } else {
        format!("{key_type} {} {comment}", Base64::encode_string(blob))
    };
    let plain = KeyData::decode(&mut &blob[..]).ok();
    let (key, certificate) = match plain {
        Some(kd) => (Some(kd), false),
        None => match Certificate::from_bytes(blob) {
            Ok(cert) => (Some(cert.public_key().clone()), true),
            Err(_) => (None, false),
        },
    };
    match key {
        Some(kd) => AgentIdentity {
            // `ssh-add -l` fingerprints the plain key, also for certificates.
            fingerprint: fingerprint(&kd),
            algorithm: KeyAlgorithm::from_ssh(&kd.algorithm()),
            bits: key_bits(&kd),
            key_type,
            comment: comment.to_owned(),
            public_key,
            certificate,
        },
        None => AgentIdentity {
            fingerprint: format!(
                "SHA256:{}",
                Base64Unpadded::encode_string(&Sha256::digest(blob))
            ),
            algorithm: KeyAlgorithm::Other,
            bits: None,
            key_type,
            comment: comment.to_owned(),
            public_key,
            certificate: false,
        },
    }
}

/// Decodes the blob of a one-line OpenSSH public key (`type base64 [comment]`).
pub(crate) fn public_key_blob(line: &str) -> Result<Vec<u8>> {
    let mut fields = line.split_ascii_whitespace();
    let (Some(key_type), Some(b64)) = (fields.next(), fields.next()) else {
        return Err(Error::invalid("expected an OpenSSH public key line"));
    };
    let blob = Base64::decode_vec(b64)
        .or_else(|_| Base64Unpadded::decode_vec(b64))
        .map_err(|_| Error::invalid("public key is not valid Base64"))?;
    if blob_type(&blob) != Some(key_type) {
        return Err(Error::invalid("public key type does not match its data"));
    }
    Ok(blob)
}

/// The type name at the start of a key blob.
fn blob_type(blob: &[u8]) -> Option<&str> {
    let mut reader = blob;
    let len = usize::try_from(u32::decode(&mut reader).ok()?).ok()?;
    std::str::from_utf8(reader.get(..len)?).ok()
}
