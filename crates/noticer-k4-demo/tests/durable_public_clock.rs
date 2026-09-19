use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use noticer_k4_demo::public_clock::{DurablePublicClock, PublicClockError};

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "noticer-clock-{label}-{}-{nonce}.bin",
        std::process::id()
    ))
}

#[test]
fn restart_preserves_watermark_and_rejects_rollback() {
    let path = temporary_path("restart");
    let mut clock = DurablePublicClock::open(&path, 7, 100).unwrap();
    clock.advance(120).unwrap();
    assert_eq!(clock.current_slot(), 120);
    drop(clock);

    assert!(matches!(
        DurablePublicClock::open(&path, 7, 119),
        Err(PublicClockError::Rollback)
    ));
    let clock = DurablePublicClock::open(&path, 7, 120).unwrap();
    assert_eq!(clock.current_slot(), 120);
    drop(clock);
    fs::remove_file(path).unwrap();
}

#[test]
fn epoch_mismatch_corruption_and_second_writer_fail_closed() {
    let path = temporary_path("failure");
    let clock = DurablePublicClock::open(&path, 9, 40).unwrap();
    assert!(matches!(
        DurablePublicClock::open(&path, 9, 40),
        Err(PublicClockError::Io(_))
    ));
    drop(clock);
    assert!(matches!(
        DurablePublicClock::open(&path, 10, 40),
        Err(PublicClockError::EpochMismatch)
    ));
    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(28)).unwrap();
    file.write_all(&[0; 8]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(
        DurablePublicClock::open(&path, 9, 40),
        Err(PublicClockError::Corrupt)
    ));
    fs::remove_file(path).unwrap();
}

#[test]
fn opening_with_newer_trusted_slot_persists_it() {
    let path = temporary_path("startup");
    drop(DurablePublicClock::open(&path, 4, 10).unwrap());
    drop(DurablePublicClock::open(&path, 4, 15).unwrap());
    let clock = DurablePublicClock::open(&path, 4, 15).unwrap();
    assert_eq!(clock.current_slot(), 15);
    drop(clock);
    fs::remove_file(path).unwrap();
}
