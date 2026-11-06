//! Throw-away key fixtures generated with `ssh-keygen` / `openssl` for tests.
//! None of these keys is used anywhere else.

pub(crate) const RSA_PEM: &str = include_str!("testdata/rsa_pem");
pub(crate) const RSA_PEM_PUB: &str = include_str!("testdata/rsa_pem.pub");
pub(crate) const RSA_PKCS8: &str = include_str!("testdata/rsa_pkcs8");
/// Passphrase `legacy-pass`.
pub(crate) const RSA_PEM_ENCRYPTED: &str = include_str!("testdata/rsa_pem_encrypted");
/// Passphrase `legacy-pass`.
pub(crate) const RSA_PKCS8_ENCRYPTED: &str = include_str!("testdata/rsa_pkcs8_encrypted");
/// `ssh-keygen -m PEM -t ecdsa` with `LibreSSL`: explicit curve parameters.
pub(crate) const EC_PEM_EXPLICIT: &str = include_str!("testdata/ec_pem_explicit");
pub(crate) const EC_PEM_EXPLICIT_PUB: &str = include_str!("testdata/ec_pem_explicit.pub");
pub(crate) const EC_PKCS8_EXPLICIT: &str = include_str!("testdata/ec_pkcs8_explicit");
/// `openssl ecparam -name prime256v1 -genkey`: named curve.
pub(crate) const EC_NAMED: &str = include_str!("testdata/ec_named");
/// RFC 8410 layout with seed 00..1f.
pub(crate) const ED25519_PKCS8: &str = include_str!("testdata/ed25519_pkcs8");
pub(crate) const OPENSSH_ED25519: &str = include_str!("testdata/openssh_ed25519");
pub(crate) const OPENSSH_ED25519_PUB: &str = include_str!("testdata/openssh_ed25519.pub");
/// Encrypted by `ssh-keygen` with passphrase [`KEYGEN_PASSPHRASE`].
pub(crate) const OPENSSH_ED25519_ENCRYPTED: &str =
    include_str!("testdata/openssh_ed25519_encrypted");
pub(crate) const OPENSSH_ED25519_ENCRYPTED_PUB: &str =
    include_str!("testdata/openssh_ed25519_encrypted.pub");
pub(crate) const KEYGEN_PASSPHRASE: &str = "correct horse";

// PuTTY keys made by `puttygen` for the `ssh-key` crate's tests (see
// `testdata/ppk/README.md`); `_ENC` ones have the passphrase `123`.
pub(crate) const PPK_RSA_3072: &str = include_str!("testdata/ppk/id_rsa_3072.ppk");
pub(crate) const PPK_RSA_3072_ENC: &str = include_str!("testdata/ppk/id_rsa_3072_enc.ppk");
pub(crate) const PPK2_RSA_3072: &str = include_str!("testdata/ppk/id_rsa_3072.ppk2");
pub(crate) const PPK2_RSA_3072_ENC: &str = include_str!("testdata/ppk/id_rsa_3072_enc.ppk2");
pub(crate) const PPK_RSA_3072_OPENSSH: &str = include_str!("testdata/ppk/id_rsa_3072");
pub(crate) const PPK_ECDSA_P256: &str = include_str!("testdata/ppk/id_ecdsa_p256.ppk");
pub(crate) const PPK_ECDSA_P256_ENC: &str = include_str!("testdata/ppk/id_ecdsa_p256_enc.ppk");
pub(crate) const PPK_ECDSA_P256_OPENSSH: &str = include_str!("testdata/ppk/id_ecdsa_p256");
pub(crate) const PPK_DSA_1024: &str = include_str!("testdata/ppk/id_dsa_1024.ppk");
