//! Two copies of the app talking to each other over the local network.
//!
//! - [`identity`]: the device's key pair. Its public half is how contacts
//!   know the device.
//! - [`session`]: a Noise `XX` handshake over any byte stream, the six-digit
//!   pairing code, and the messages after them.
//! - [`protocol`]: those messages.
//! - [`own`]: how the user's own devices recognise each other.
//! - [`contact`]: the key two paired devices share, and how a chat's
//!   presence and knock use it.
//! - [`chat`]: the frames of a chat session.
//! - [`deadline`]: one deadline for a connection's first steps.
//!
//! Finding devices and opening sockets is the app's business: nothing here
//! touches the network, so the tests run sessions over in-memory pipes.

pub mod chat;
pub mod contact;
pub mod deadline;
pub mod identity;
pub mod own;
pub mod protocol;
pub mod session;

pub use identity::{Identity, PeerKey};
pub use protocol::Message;
pub use session::{Session, accept, accept_own, accept_with, connect, connect_own, connect_with};
