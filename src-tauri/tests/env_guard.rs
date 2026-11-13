//! The guard of the `.env` files written only while the vault is unlocked,
//! as the app starts it: the built app executable with its flag, waiting on
//! a pipe. When the pipe closes, as it does when the app goes, the files on
//! the list that are still as the app left them go too.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sshkm_app_lib::env_guard::FLAG;
use sshkm_core::vault::envs::files::{Leftover, Leftovers};

const APP: &str = env!("CARGO_BIN_EXE_sshkm-app");

#[test]
fn the_guard_removes_the_files_once_the_app_goes() {
    let dir = tempfile::tempdir().unwrap();
    let kept = dir.path().join(".env");
    let edited = dir.path().join(".env.local");
    std::fs::write(&kept, "API_TOKEN=tok-1\n").unwrap();
    std::fs::write(&edited, "API_TOKEN=tok-1\n").unwrap();
    // A file kept all the time, which the app was writing when it went:
    // its temporary file goes, the file stays.
    let always = dir.path().join(".env.test");
    let writing = dir.path().join(".env.test.sshkm-Ab12Cd.tmp");
    std::fs::write(&always, "API_TOKEN=tok-1\n").unwrap();
    std::fs::write(&writing, "API_TOKEN=tok-2\n").unwrap();
    let list = dir.path().join("env-files-unlocked.json");
    Leftovers::new(vec![
        Leftover::of(&kept).unwrap(),
        Leftover::of(&edited).unwrap(),
        Leftover::temps_of(&always),
    ])
    .save(&list)
    .unwrap();

    let mut guard = Command::new(APP)
        .arg(FLAG)
        .arg(&list)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut pipe = guard.stdin.take().unwrap();
    pipe.write_all(b"anything").unwrap();
    // Still waiting while the app is there.
    std::thread::sleep(Duration::from_millis(300));
    assert!(guard.try_wait().unwrap().is_none());
    assert!(kept.exists());
    // An edit the vault didn't take yet stays.
    std::fs::write(&edited, "API_TOKEN=tok-2, longer\n").unwrap();

    // The app goes.
    drop(pipe);
    let started = Instant::now();
    while guard.try_wait().unwrap().is_none() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the guard didn't exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(guard.wait().unwrap().success());
    assert!(!kept.exists());
    assert!(edited.exists());
    assert!(always.exists() && !writing.exists());
    assert!(!list.exists());
}
