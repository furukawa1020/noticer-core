use noticer_k4_demo::authenticated_public_clock::*;
use std::{
    fs,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    time::{SystemTime, UNIX_EPOCH},
};
fn path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-auth-clock-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn key() -> PublicClockAuthKey {
    PublicClockAuthKey::new([7; 32])
}
#[test]
fn restart_tamper_and_bindings_fail_closed() {
    let p = path();
    let mut c = AuthenticatedDurablePublicClock::open(&p, 5, 9, 10, key()).unwrap();
    c.advance(11).unwrap();
    drop(c);
    let c = AuthenticatedDurablePublicClock::open(&p, 5, 9, 11, key()).unwrap();
    assert_eq!(c.slot(), 11);
    drop(c);
    assert!(matches!(
        AuthenticatedDurablePublicClock::open(&p, 6, 9, 11, key()),
        Err(AuthenticatedClockError::EpochMismatch)
    ));
    assert!(matches!(
        AuthenticatedDurablePublicClock::open(&p, 5, 10, 11, key()),
        Err(AuthenticatedClockError::GenerationMismatch)
    ));
    let mut f = OpenOptions::new().write(true).open(&p).unwrap();
    f.seek(SeekFrom::Start(30)).unwrap();
    f.write_all(&[99]).unwrap();
    f.sync_all().unwrap();
    drop(f);
    assert!(matches!(
        AuthenticatedDurablePublicClock::open(&p, 5, 9, 11, key()),
        Err(AuthenticatedClockError::Authentication)
    ));
    fs::remove_file(p).unwrap();
}
