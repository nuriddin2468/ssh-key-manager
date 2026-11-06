# PuTTY key fixtures

Throw-away keys for the `.ppk` tests in `keys/ppk.rs`, generated with
`puttygen` by the RustCrypto project for the tests of the `ssh-key` crate
(`ssh-key` 0.7, `tests/examples/`, MIT or Apache-2.0). The files without an
extension are the same keys in OpenSSH format. That crate's Ed25519 example
is left out: its public key is registered on a GitHub account, so GitHub
refuses it as a leaked key; Ed25519 is covered by round trips of
`../openssh_ed25519` instead. The `_enc` files are encrypted
with the passphrase `123`.

None of these keys is used anywhere else.
