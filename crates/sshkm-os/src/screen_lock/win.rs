//! `WTS_SESSION_LOCK` through a hidden message-only window.
//!
//! The window lives on a thread of its own with its own message loop, so the
//! crate needs no window handle from the app. Dropping the watcher posts a
//! private message that ends the loop; the thread then unregisters and
//! destroys the window.

#![allow(unsafe_code)]

use std::{
    cell::RefCell,
    sync::{Arc, mpsc},
    thread,
};

use windows::{
    Win32::{
        Foundation::{ERROR_CLASS_ALREADY_EXISTS, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            RemoteDesktop::{
                NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
                WTSUnRegisterSessionNotification,
            },
            Threading::GetCurrentThreadId,
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
            HWND_MESSAGE, MSG, PostThreadMessageW, RegisterClassExW, WINDOW_EX_STYLE, WINDOW_STYLE,
            WM_APP, WM_WTSSESSION_CHANGE, WNDCLASSEXW, WTS_SESSION_LOCK,
        },
    },
    core::{PCWSTR, w},
};

use super::Shared;
use crate::{Error, Result};

/// The window class shared by all watchers of the process.
const CLASS_NAME: PCWSTR = w!("sshkm-os-screen-lock");

/// Thread message that ends a watcher's message loop. A thread message never
/// reaches a window procedure, so this does not clash with other `WM_APP`
/// uses.
const STOP: u32 = WM_APP + 0x5c4b;

thread_local! {
    /// The callback of the watcher whose window lives on this thread.
    static SHARED: RefCell<Option<Arc<Shared>>> = const { RefCell::new(None) };
}

pub(super) struct Watcher {
    thread_id: u32,
}

pub(super) fn watch(shared: Arc<Shared>) -> Result<Watcher> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("sshkm-screen-lock".into())
        .spawn(move || run(shared, &ready_tx))
        .map_err(|err| Error::Failed(format!("cannot start the screen-lock thread: {err}")))?;
    match ready_rx.recv() {
        Ok(Ok(thread_id)) => Ok(Watcher { thread_id }),
        Ok(Err(err)) => Err(err),
        Err(mpsc::RecvError) => Err(Error::Failed("the screen-lock thread stopped".into())),
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: posting a message has no memory-safety preconditions. If the
        // thread has already ended the call fails, which is fine.
        let _ = unsafe { PostThreadMessageW(self.thread_id, STOP, WPARAM(0), LPARAM(0)) };
    }
}

/// The watcher thread: creates the window, reports back, pumps messages.
fn run(shared: Arc<Shared>, ready: &mpsc::SyncSender<Result<u32>>) {
    SHARED.with(|slot| *slot.borrow_mut() = Some(shared));
    let window = match Window::create() {
        Ok(window) => window,
        Err(err) => {
            let _ = ready.send(Err(err));
            return;
        }
    };
    // Creating the window gave this thread its message queue, so the stop
    // message posted by `Drop` cannot be lost from here on.
    // SAFETY: `GetCurrentThreadId` has no preconditions.
    let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));

    let mut msg = MSG::default();
    // SAFETY: `msg` is a valid, writable `MSG`; no window filter is used.
    // `GetMessageW` returns 0 for `WM_QUIT` and -1 on error.
    while unsafe { GetMessageW(&raw mut msg, None, 0, 0) }.0 > 0 {
        if msg.message == STOP && msg.hwnd.is_invalid() {
            break;
        }
        // SAFETY: `msg` was just filled in by `GetMessageW`.
        unsafe { DispatchMessageW(&raw const msg) };
    }
    drop(window);
    SHARED.with(|slot| slot.borrow_mut().take());
}

/// A message-only window registered for session notifications.
struct Window(HWND);

impl Window {
    fn create() -> Result<Self> {
        // SAFETY: `None` asks for the executable's own module, which stays
        // loaded for the life of the process.
        let instance: HINSTANCE = unsafe { GetModuleHandleW(None) }
            .map_err(|err| failed("GetModuleHandleW", &err))?
            .into();
        register_class(instance)?;
        // SAFETY: the class is registered for this module with a valid window
        // procedure. `HWND_MESSAGE` makes a message-only window: never shown,
        // no broadcasts, owned by this thread.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                CLASS_NAME,
                w!(""),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(instance),
                None,
            )
        }
        .map_err(|err| failed("CreateWindowExW", &err))?;
        // SAFETY: `hwnd` is a live window owned by this thread.
        if let Err(err) = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } {
            // SAFETY: as above; the window is destroyed exactly once.
            let _ = unsafe { DestroyWindow(hwnd) };
            return Err(failed("WTSRegisterSessionNotification", &err));
        }
        Ok(Self(hwnd))
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // SAFETY: the window is live, owned by this thread (the only place a
        // `Window` exists), registered above and destroyed exactly once here.
        unsafe {
            let _ = WTSUnRegisterSessionNotification(self.0);
            let _ = DestroyWindow(self.0);
        }
    }
}

/// Registers the window class once per process; it stays registered, which is
/// harmless and lets several watchers share it.
fn register_class(instance: HINSTANCE) -> Result<()> {
    let class = WNDCLASSEXW {
        cbSize: u32::try_from(size_of::<WNDCLASSEXW>()).expect("WNDCLASSEXW is small"),
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: CLASS_NAME,
        ..WNDCLASSEXW::default()
    };
    // SAFETY: `class` is fully initialised; the class name is a static string
    // and the window procedure a static function.
    if unsafe { RegisterClassExW(&raw const class) } == 0 {
        let err = windows::core::Error::from_thread();
        if err.code() != ERROR_CLASS_ALREADY_EXISTS.to_hresult() {
            return Err(failed("RegisterClassExW", &err));
        }
    }
    Ok(())
}

extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_WTSSESSION_CHANGE && u32::try_from(wparam.0) == Ok(WTS_SESSION_LOCK) {
        SHARED.with(|slot| {
            if let Some(shared) = slot.borrow().as_ref() {
                shared.notify();
            }
        });
        return LRESULT(0);
    }
    // SAFETY: the message is passed on unchanged to the default procedure.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn failed(call: &str, err: &windows::core::Error) -> Error {
    Error::Failed(format!("{call} failed: {err}"))
}
