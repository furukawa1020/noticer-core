use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use noticer_protocol::TokenId;
use noticer_verifier::{FileReplayError, FileReplayStore, ReplayStore};

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "noticer-replay-{label}-{}-{nonce}.bin",
        std::process::id()
    ))
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

#[test]
fn restart_preserves_consumption_and_second_writer_is_refused() {
    let path = temporary_path("restart");
    let first = TokenId([1; 16]);
    let second = TokenId([2; 16]);
    let store = FileReplayStore::open(&path, 7).unwrap();
    assert!(store.accept_once(7, first));
    assert!(!store.accept_once(7, first));
    assert!(!store.accept_once(8, second));
    assert!(matches!(
        FileReplayStore::open(&path, 7),
        Err(FileReplayError::Io(_))
    ));
    drop(store);

    let reopened = FileReplayStore::open(&path, 7).unwrap();
    assert!(!reopened.accept_once(7, first));
    assert!(reopened.accept_once(7, second));
    drop(reopened);
    fs::remove_file(path).unwrap();
}

#[test]
fn truncated_tail_and_wrong_epoch_never_reinitialize_store() {
    let path = temporary_path("corrupt");
    let store = FileReplayStore::open(&path, 11).unwrap();
    assert!(store.accept_once(11, TokenId([3; 16])));
    drop(store);
    assert!(matches!(
        FileReplayStore::open(&path, 12),
        Err(FileReplayError::EpochMismatch)
    ));
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0x55]).unwrap();
    drop(file);
    let before = fs::metadata(&path).unwrap().len();
    assert!(matches!(
        FileReplayStore::open(&path, 11),
        Err(FileReplayError::Corrupt)
    ));
    assert_eq!(fs::metadata(&path).unwrap().len(), before);
    fs::remove_file(path).unwrap();
}

#[test]
fn stale_lock_blocks_open_until_operator_removes_it() {
    let path = temporary_path("lock");
    let lock = lock_path(&path);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .unwrap();
    drop(file);
    assert!(matches!(
        FileReplayStore::open(&path, 5),
        Err(FileReplayError::Io(_))
    ));
    fs::remove_file(lock).unwrap();
    let store = FileReplayStore::open(&path, 5).unwrap();
    drop(store);
    fs::remove_file(path).unwrap();
}
