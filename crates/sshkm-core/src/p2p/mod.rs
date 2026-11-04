//! Two copies of the app talking to each other over the local network.
//!
//! - [`identity`]: the device's key pair. Its public half is how contacts
//!   know the device.
//! - [`session`]: a Noise `XX` handshake over any byte stream, the six-digit
//!   pairing code, and the messages after them.
//! - [`protocol`]: those messages.
//!
//! Finding devices and opening sockets is the app's business: nothing here
//! touches the network, so the tests run sessions over in-memory pipes.

pub mod identity;
pub mod protocol;
pub mod session;

pub use identity::{Identity, PeerKey};
pub use protocol::Message;
pub use session::{Session, accept, connect};
