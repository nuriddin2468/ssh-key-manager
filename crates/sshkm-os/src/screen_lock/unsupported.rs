//! Platforms that cannot report screen locks.

use std::sync::Arc;

use super::Shared;
use crate::{Error, Result};

pub(super) enum Watcher {}

pub(super) fn watch(_shared: Arc<Shared>) -> Result<Watcher> {
    Err(Error::Unsupported)
}
