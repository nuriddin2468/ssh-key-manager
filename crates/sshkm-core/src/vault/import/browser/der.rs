//! Just enough DER to read the few structures NSS stores in Firefox's
//! `key4.db` and `logins.json`: sequences, octet strings, object identifiers
//! and small integers. Anything malformed reads as `None`.

pub(super) const SEQUENCE: u8 = 0x30;
pub(super) const OCTET_STRING: u8 = 0x04;
pub(super) const OBJECT_ID: u8 = 0x06;
pub(super) const INTEGER: u8 = 0x02;

/// Object identifiers, as their DER content bytes.
pub(super) mod oid {
    /// PKCS #5 PBES2, 1.2.840.113549.1.5.13.
    pub(in super::super) const PBES2: &[u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
    /// PKCS #5 PBKDF2, 1.2.840.113549.1.5.12.
    pub(in super::super) const PBKDF2: &[u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
    /// hmacWithSHA1, 1.2.840.113549.2.7.
    pub(in super::super) const HMAC_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07];
    /// hmacWithSHA256, 1.2.840.113549.2.9.
    pub(in super::super) const HMAC_SHA256: &[u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09];
    /// AES-256-CBC, 2.16.840.1.101.3.4.1.42.
    pub(in super::super) const AES256_CBC: &[u8] =
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];
    /// DES-EDE3-CBC, 1.2.840.113549.3.7.
    pub(in super::super) const DES_EDE3_CBC: &[u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];
    /// pbeWithSHA1AndTripleDES-CBC, 1.2.840.113549.1.12.5.1.3.
    pub(in super::super) const PBE_SHA1_3DES: &[u8] = &[
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x05, 0x01, 0x03,
    ];
}

/// Reads DER values one after another.
#[derive(Debug, Clone, Copy)]
pub(super) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next value's tag, without reading it.
    pub(super) fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// The next value: its tag and content.
    pub(super) fn any(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.rest.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7F);
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let (bytes, after) = rest.split_at(count);
            rest = after;
            bytes
                .iter()
                .fold(0usize, |len, &b| (len << 8) | usize::from(b))
        };
        if rest.len() < len {
            return None;
        }
        let (content, after) = rest.split_at(len);
        self.rest = after;
        Some((tag, content))
    }

    /// The next value's content if it has `tag`.
    pub(super) fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        match self.any()? {
            (t, content) if t == tag => Some(content),
            _ => None,
        }
    }

    pub(super) fn sequence(&mut self) -> Option<Reader<'a>> {
        self.expect(SEQUENCE).map(Reader::new)
    }

    pub(super) fn octets(&mut self) -> Option<&'a [u8]> {
        self.expect(OCTET_STRING)
    }

    pub(super) fn oid(&mut self) -> Option<&'a [u8]> {
        self.expect(OBJECT_ID)
    }

    /// A non-negative integer that fits in a `u32`.
    pub(super) fn small_int(&mut self) -> Option<u32> {
        let bytes = self.expect(INTEGER)?;
        let bytes = match bytes {
            [0, rest @ ..] => rest,
            [first, ..] if first & 0x80 != 0 => return None,
            _ => bytes,
        };
        if bytes.len() > 4 {
            return None;
        }
        Some(bytes.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b)))
    }
}

#[cfg(test)]
pub(super) mod write {
    //! DER writing for the tests' fixtures.

    pub(in super::super) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            out.push(0x80 | u8::try_from(bytes.len()).unwrap());
            out.extend(bytes);
        }
        out.extend_from_slice(content);
        out
    }

    pub(in super::super) fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(super::SEQUENCE, &parts.concat())
    }

    pub(in super::super) fn int(n: u32) -> Vec<u8> {
        let mut bytes: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        if bytes.first().is_none_or(|&b| b & 0x80 != 0) {
            bytes.insert(0, 0);
        }
        tlv(super::INTEGER, &bytes)
    }
}
