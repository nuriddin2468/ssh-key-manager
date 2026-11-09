#![allow(unsafe_code)]

use secrecy::zeroize::Zeroizing;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};

use crate::{Error, Result};

pub(super) fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len =
        u32::try_from(blob.len()).map_err(|_| Error::Failed("the data is too large".into()))?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: len,
        // DPAPI only reads the input.
        pbData: blob.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` points at `blob`, which outlives the call; `output` is
    // a valid out-parameter that the call fills with memory it allocates
    // with `LocalAlloc`. No prompt is allowed, so the call doesn't wait for
    // the user.
    unsafe {
        CryptUnprotectData(
            &raw const input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    }
    .map_err(|e| Error::Failed(format!("DPAPI could not decrypt the data: {e}")))?;
    if output.pbData.is_null() {
        return Ok(Zeroizing::default());
    }
    let len = output.cbData as usize;
    // SAFETY: on success `output.pbData` points at `output.cbData` bytes that
    // DPAPI allocated and nothing else uses; they are copied, wiped and freed
    // here, once.
    let plain = unsafe {
        let bytes = std::slice::from_raw_parts_mut(output.pbData, len);
        let plain = Zeroizing::new(bytes.to_vec());
        secrecy::zeroize::Zeroize::zeroize(bytes);
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        plain
    };
    Ok(plain)
}
