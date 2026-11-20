# sshkm-ssh

The phone's SSH client. Computers run the system `ssh`; Android doesn't let an
app run programs of its own, so the phone speaks SSH itself, through
[russh](https://github.com/warp-tech/russh). The desktop app doesn't depend on
this crate, so it builds neither russh nor tokio. `sshkm-mobile` exposes it to
Kotlin.

It connects by a host's name with what computers sync and the phone carries as
text: the host blocks (`ssh_config`) and the `known_hosts` lines.

## Host settings

`sshkm-core` works out the settings in effect for a name
(`SshConfig::effective`), with `ssh_config`'s first-match and pattern rules,
`Match` included. The phone honours `HostName` (`%h`, `%%`), `User`, `Port`,
`ProxyJump`, `ServerAliveInterval`, `ServerAliveCountMax` and
`ConnectTimeout`, and ignores the rest (`IdentityFile`: the phone has its own
key). A host whose settings in effect include `ProxyCommand`, `LocalCommand`,
`PermitLocalCommand`, `KnownHostsCommand`, `Match … exec`, `Include`, a `Match`
only `ssh` can evaluate, or a line `ssh` may read differently is **not
available on the phone**: nothing is sent over the network. The core's
risky-directive rules decide which values are harmless (`ProxyCommand none`,
`PermitLocalCommand no`).

`ProxyJump a,b` is followed as `ssh -J a -W … b` does: `a` with its own
settings and its own `ProxyJump`, `b` through `a` without its `ProxyJump` or
`ProxyCommand`, then the destination through `b`, each through a
`direct-tcpip` channel. A circle or more than 8 machines is refused.

## Server keys

Every machine on the way is checked against `known_hosts` by the name
connected to and port (`[host]:port`), through hashed lines too:

| `known_hosts` has | Result |
|---|---|
| the same key | connects |
| `@revoked` for this key | `HostKeyRevoked` |
| another key of the same type | `HostKeyChanged` with both fingerprints; never resolved here |
| nothing (or only `@cert-authority`) | the app asks; on yes it gets the new line to store, which syncs to computers |
| keys of other types only | asks too, naming those types |

Known key types are asked for first, as OpenSSH does.

## Signing in

The phone's key (P-256 in Android Keystore, never exportable) is offered first
without a signature; only once the server says it would take it, the app is
asked to sign (`SHA256withECDSA`, DER). The client converts the DER signature
to SSH's `ecdsa-sha2-nistp256` form and checks it against the key before it
sends it. Then keyboard-interactive and password, each answered by the app (from
the vault or the user), up to three attempts each, partial success (key then
code) included. Prompts are classified with `sshkm_core::prompt`, the rules the
desktop's askpass uses: password, one-time code or other.

## Algorithms

Those of current OpenSSH clients that russh has: `mlkem768x25519-sha256`,
`curve25519-sha256`, DH group exchange and groups 14/16/18 with SHA-2; host keys
Ed25519, ECDSA, `rsa-sha2-512/256` (no `ssh-rsa` with SHA-1, no DSS);
ChaCha20-Poly1305, AES-GCM, AES-CTR; SHA-2 MACs only; no compression. Strict key
exchange (Terrapin) is on.

russh's crypto backend is `ring`: it builds for Android with the NDK's C
compiler alone and is already in the workspace (rustls). russh's default,
`aws-lc-rs`, needs cmake and its own cross-compiling setup for each Android
ABI.

## Shell

`Connection::open_shell` asks for a terminal (`TERM=xterm-256color`, the
size, backspace as DEL, UTF-8) and a shell. `Shell` gives output as events
(`next_event`, pulled, so a slow screen holds the server back through SSH's
window) and takes input, a new size and keepalives; reading and writing run at
once. `close` ends the shell and every connection on the way.

Agent and X11 forwarding are never asked for. Nothing here logs; answers to
prompts are wiped once sent, and russh wipes its copy of a password.

## Tests

`cargo test -p sshkm-ssh`: unit tests, and `tests/connect.rs` against russh
servers in the same process (host key match, change, revocation, unknown with
yes and no; key with an external DER signer, password with a retry,
keyboard-interactive with a one-time code, key then code; a jump chain with each
hop's key checked; hosts that need `ssh`; refused, timed out and unknown names;
the shell's output, input, size, end and close).
