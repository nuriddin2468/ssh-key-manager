//! `com.apple.screenIsLocked` from the distributed notification center.
//!
//! The notification arrives through the main thread's run loop no matter
//! which thread registered the observer (checked by posting a private
//! notification name from a background-registered observer). The block then
//! runs on a private serial operation queue.

#![allow(unsafe_code)]

use std::{ptr::NonNull, sync::Arc};

use block2::RcBlock;
use objc2::{
    rc::Retained,
    runtime::{AnyObject, ProtocolObject},
};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotification, NSObjectProtocol, NSOperationQueue, NSString,
};

use super::Shared;
use crate::Result;

const SCREEN_IS_LOCKED: &str = "com.apple.screenIsLocked";

pub(super) struct Watcher {
    observer: Observer,
    /// Kept alive for as long as the observer exists.
    _queue: Retained<NSOperationQueue>,
}

/// The token returned when the observer was added.
struct Observer(Retained<ProtocolObject<dyn NSObjectProtocol>>);

// SAFETY: the token is an opaque object that is never used except to be passed
// back to `removeObserver:`, and `NSNotificationCenter` (including the
// distributed center) is documented as thread-safe, so the token may be moved
// to and shared with any thread.
unsafe impl Send for Observer {}
// SAFETY: see `Send` above; the token is never mutated or messaged through `&`.
unsafe impl Sync for Observer {}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the same signature as on the other platforms"
)]
pub(super) fn watch(shared: Arc<Shared>) -> Result<Watcher> {
    let center = NSDistributedNotificationCenter::defaultCenter();
    let queue = NSOperationQueue::new();
    queue.setMaxConcurrentOperationCount(1);
    queue.setName(Some(&NSString::from_str("sshkm-screen-lock")));
    let block = RcBlock::new(move |_: NonNull<NSNotification>| shared.notify());
    let name = NSString::from_str(SCREEN_IS_LOCKED);
    // SAFETY: `name` is a valid notification name and no sender filter is
    // used. The queue is a valid operation queue, kept alive by the watcher.
    // The center copies the block, which may then run on any thread of the
    // queue: it only captures an `Arc<Shared>`, which is `Send + Sync`.
    let token = unsafe {
        center.addObserverForName_object_queue_usingBlock(Some(&name), None, Some(&queue), &block)
    };
    Ok(Watcher {
        observer: Observer(token),
        _queue: queue,
    })
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let center = NSDistributedNotificationCenter::defaultCenter();
        let token: &AnyObject = self.observer.0.as_ref();
        // SAFETY: the token was returned by `addObserverForName:…` on this same
        // center and is removed exactly once; removal is thread-safe.
        unsafe { center.removeObserver(token) };
    }
}
