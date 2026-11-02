//! The messages between the askpass helper and the server.
//!
//! - Request: a big-endian `u32` length, then `token NUL hint NUL prompt`
//!   (UTF-8). The token is 64 hex digits; `hint` is `SSH_ASKPASS_PROMPT`.
//! - Answer: `0`, a big-endian `u32` length and the reply; or `1` for a
//!   refusal. An unknown token gets no answer at all: the server hangs up.

use std::io::{self, Read};

use sshkm_core::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Longest request accepted. Prompts are short; a host-key question with its
/// fingerprint is a few hundred bytes.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Longest reply accepted. `ssh` reads at most 1023 bytes of askpass output.
pub const MAX_ANSWER: usize = 16 * 1024;

const ANSWER: u8 = 0;
const REFUSED: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub token: String,
    pub hint: String,
    pub prompt: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn encode_request(token: &str, hint: &str, prompt: &str) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(token.len() + hint.len() + prompt.len() + 2);
    for (i, part) in [token, hint, prompt].into_iter().enumerate() {
        if i > 0 {
            payload.push(0);
        }
        // A NUL would shift the fields; `ssh` passes C strings, which have none.
        payload.extend(part.bytes().filter(|&b| b != 0));
    }
    if payload.len() > MAX_REQUEST {
        return Err(invalid("askpass prompt too long"));
    }
    let len = u32::try_from(payload.len()).map_err(|_| invalid("askpass prompt too long"))?;
    let mut message = len.to_be_bytes().to_vec();
    message.extend(payload);
    Ok(message)
}

/// The payload length from a request's 4-byte header, if acceptable.
pub fn request_len(header: [u8; 4]) -> io::Result<usize> {
    usize::try_from(u32::from_be_bytes(header))
        .ok()
        .filter(|&len| len <= MAX_REQUEST)
        .ok_or_else(|| invalid("askpass request too long"))
}

pub fn decode_request(payload: &[u8]) -> io::Result<Request> {
    let mut parts = payload.splitn(3, |&b| b == 0);
    let mut next = || {
        parts
            .next()
            .ok_or_else(|| invalid("malformed askpass request"))
    };
    let (token, hint, prompt) = (next()?, next()?, next()?);
    Ok(Request {
        token: String::from_utf8_lossy(token).into_owned(),
        hint: String::from_utf8_lossy(hint).into_owned(),
        prompt: String::from_utf8_lossy(prompt).into_owned(),
    })
}

// The Windows server reads and writes asynchronously.
#[cfg(any(unix, test))]
pub fn read_request(reader: &mut impl Read) -> io::Result<Request> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let mut payload = vec![0; request_len(header)?];
    reader.read_exact(&mut payload)?;
    decode_request(&payload)
}

/// An answer as a header and a body, written one after the other so the
/// secret is never copied into another buffer. `None` is a refusal.
pub fn answer_frame(reply: Option<&SecretString>) -> io::Result<(Vec<u8>, &[u8])> {
    match reply {
        None => Ok((vec![REFUSED], &[])),
        Some(secret) => {
            let body = secret.expose_secret().as_bytes();
            if body.len() > MAX_ANSWER {
                return Err(invalid("askpass reply too long"));
            }
            let len = u32::try_from(body.len()).map_err(|_| invalid("askpass reply too long"))?;
            let mut header = vec![ANSWER];
            header.extend(len.to_be_bytes());
            Ok((header, body))
        }
    }
}

#[cfg(any(unix, test))]
pub fn write_answer(writer: &mut impl io::Write, reply: Option<&SecretString>) -> io::Result<()> {
    let (header, body) = answer_frame(reply)?;
    writer.write_all(&header)?;
    writer.write_all(body)?;
    writer.flush()
}

/// Reads an answer: `Some` reply, or `None` for a refusal.
pub fn read_answer(reader: &mut impl Read) -> io::Result<Option<SecretString>> {
    let mut status = [0; 1];
    reader.read_exact(&mut status)?;
    match status[0] {
        REFUSED => Ok(None),
        ANSWER => {
            let mut header = [0; 4];
            reader.read_exact(&mut header)?;
            let len = usize::try_from(u32::from_be_bytes(header))
                .ok()
                .filter(|&len| len <= MAX_ANSWER)
                .ok_or_else(|| invalid("askpass reply too long"))?;
            // Exactly `len` bytes, so turning it into a `SecretString` does not
            // reallocate and leave a copy behind.
            let mut bytes = vec![0; len];
            if let Err(e) = reader.read_exact(&mut bytes) {
                bytes.zeroize();
                return Err(e);
            }
            match String::from_utf8(bytes) {
                Ok(text) => Ok(Some(SecretString::from(text))),
                Err(e) => {
                    e.into_bytes().zeroize();
                    Err(invalid("askpass reply is not UTF-8"))
                }
            }
        }
        _ => Err(invalid("malformed askpass answer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let message = encode_request("ab".repeat(32).as_str(), "confirm", "Password: ").unwrap();
        let request = read_request(&mut message.as_slice()).unwrap();
        assert_eq!(
            request,
            Request {
                token: "ab".repeat(32),
                hint: "confirm".into(),
                prompt: "Password: ".into(),
            }
        );
    }

    #[test]
    fn prompts_keep_newlines_and_lose_nuls() {
        let message = encode_request("t", "", "line 1\nline\u{0}2").unwrap();
        let request = read_request(&mut message.as_slice()).unwrap();
        assert_eq!(request.prompt, "line 1\nline2");
        assert_eq!(request.hint, "");
    }

    #[test]
    fn oversized_messages_are_rejected() {
        assert!(encode_request("t", "", &"x".repeat(MAX_REQUEST)).is_err());
        let header = u32::try_from(MAX_REQUEST + 1).unwrap().to_be_bytes();
        assert!(read_request(&mut header.as_slice()).is_err());
        let mut answer = vec![ANSWER];
        answer.extend(u32::try_from(MAX_ANSWER + 1).unwrap().to_be_bytes());
        assert!(read_answer(&mut answer.as_slice()).is_err());
    }

    #[test]
    fn answers_round_trip() {
        let mut buffer = Vec::new();
        write_answer(&mut buffer, Some(&SecretString::from("hunter2"))).unwrap();
        let answer = read_answer(&mut buffer.as_slice()).unwrap().unwrap();
        assert_eq!(answer.expose_secret(), "hunter2");

        let mut buffer = Vec::new();
        write_answer(&mut buffer, None).unwrap();
        assert!(read_answer(&mut buffer.as_slice()).unwrap().is_none());

        assert!(read_answer(&mut [7_u8].as_slice()).is_err());
        assert!(read_answer(&mut [].as_slice()).is_err());
    }
}
