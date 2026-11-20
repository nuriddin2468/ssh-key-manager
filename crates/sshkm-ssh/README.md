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
(`SshConfig::effective_as`), with `ssh_config`'s rules as OpenSSH 9.9 applies
them (checked with `ssh -G`): first value obtained wins, `Host` patterns
compare with the name as typed (case counts), `Match host`/`originalhost`
ignore case, `Match user` doesn't, and a user from a jump spec comes first as
`ssh -l` would. The phone honours `HostName` (`%h`, `%%`, then in lower case,
as `ssh`), `User`, `Port`, `ProxyJump`, `ServerAliveInterval`,
`ServerAliveCountMax` and `ConnectTimeout`, and ignores the rest
(`IdentityFile`: the phone has its own key).

A host is **not available on the phone** (nothing is sent over the network)
when, in its settings or a hop's, any line in effect would run a program
(`ProxyCommand`, `LocalCommand`, `PermitLocalCommand`, `KnownHostsCommand`,
`Match … exec`, `Include`, and anything else the core's risky-directive rules
say runs code, except what the phone never does: `RemoteCommand`, key
libraries and agents, `XAuthLocation`, `HostKeyAlias`); when a `Match` only
`ssh` can evaluate may apply; when `CanonicalizeHostname` is on (`ssh` reads
the files again with the name it finds); and when the file has a line `ssh`
may read differently from the parser, wherever it is, since it may start
another block (`=Host web` is `Host web` to `ssh`). Harmless values stay
harmless (`ProxyCommand none`, `PermitLocalCommand no`).

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

Known key types are asked for first, as OpenSSH does. The returned line is
written as computers write the lines sync adds (`KnownHosts::add_key`: plain,
the name in lower case, `[host]:port` off port 22). The key is checked at the
first key exchange; russh doesn't check it again at later re-exchanges, as
OpenSSH does.

## Signing in

The phone's key (P-256 in Android Keystore, never exportable) is offered first
without a signature; only once the server says it would take it (`PK_OK`), the
app is asked to sign (`SHA256withECDSA`, DER). The client converts the DER
signature to SSH's `ecdsa-sha2-nistp256` form and checks it against the key
before it sends it. Then keyboard-interactive and password, answered by the
app (from the vault or the user), partial success (key then code) included.
Prompts are classified with `sshkm_core::prompt`, the rules the desktop's
askpass uses: password, one-time code or other.

Every question is counted by what it asks (the password, a one-time code, or
another question by its text) across rounds, exchanges and methods. The prompt
says how often (`attempt`), so the app doesn't refill a refused vault value
unasked, and no question is answered a fourth time: a server that keeps asking
can't lock the account with the vault's password. Rounds (16 per exchange) and
methods (16 per machine) are bounded too.

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
size, backspace as DEL, UTF-8) and a shell, within 30 seconds and keeping at
most 1 MiB of output until the server answers. `Shell` gives output as events
(`next_event`) and takes input, a new size and keepalives; reading and writing
run at once.

**The app must keep reading.** russh widens SSH's window as data arrives, not
as the app reads it; what bounds memory is the channel between russh's session
task and the reader, 100 messages long. When it is full the session task
waits, and with it everything on the connection, keepalive answers included.
So the terminal (step H) needs one coroutine that asks for the next event for
as long as the shell is open, even while it is off screen.

`close` ends the shell and every connection on the way. Agent and X11
forwarding are never asked for. Nothing here logs.

## What is wiped

The client wipes its own copies of answers once sent, and the bridge wipes the
bytes typed into the shell after they go. russh wipes the password it sends
with the password method, but keeps keyboard-interactive answers (on PAM
servers, the password) in plain strings it doesn't wipe. Across the bridge,
UniFFI's buffer that carries Kotlin's answers and Kotlin's own strings aren't
wiped either.

## Tests

`cargo test -p sshkm-ssh`: unit tests, and `tests/connect.rs` against russh
servers in the same process (host key match, change, revocation, unknown with
yes and no; key with an external DER signer, no signing for a refused key,
password with a retry, keyboard-interactive with a one-time code, key then
code, a server that keeps asking; a jump chain with each hop's key checked;
hosts that need `ssh`, odd lines included; failing callbacks; refused, timed
out and unknown names; keepalives ending a connection the network dropped; the
shell's output, input, size, end and close).
