use noticer_crypto::StateAuthenticationKey;
use noticer_k4_demo::{
    durable_recovery_ledger::{FileRecoveryLedger, FileRecoveryLedgerError},
    recovery::RecoveryLedger,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
fn path(l: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-recovery-ledger-{l}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([71; 32])
}
#[test]
fn restart_preserves_consumed_permit_and_binding() {
    let p = path("restart");
    let mut l = FileRecoveryLedger::open(&p, 5, 7, key()).unwrap();
    assert!(l.consume([1; 16]).unwrap());
    drop(l);
    let mut l = FileRecoveryLedger::open(&p, 5, 7, key()).unwrap();
    assert!(!l.consume([1; 16]).unwrap());
    drop(l);
    assert!(matches!(
        FileRecoveryLedger::open(&p, 6, 7, key()),
        Err(FileRecoveryLedgerError::EpochMismatch)
    ));
    assert!(matches!(
        FileRecoveryLedger::open(&p, 5, 8, key()),
        Err(FileRecoveryLedgerError::GenerationMismatch)
    ));
    fs::remove_file(p).unwrap();
}
#[test]
fn tamper_partial_record_and_second_writer_fail_closed() {
    let p = path("faults");
    let mut l = FileRecoveryLedger::open(&p, 5, 7, key()).unwrap();
    l.consume([2; 16]).unwrap();
    assert!(FileRecoveryLedger::open(&p, 5, 7, key()).is_err());
    drop(l);
    let mut f = OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(&[9]).unwrap();
    f.sync_all().unwrap();
    drop(f);
    assert!(matches!(
        FileRecoveryLedger::open(&p, 5, 7, key()),
        Err(FileRecoveryLedgerError::Corrupt)
    ));
    fs::remove_file(p).unwrap();
    let p = path("tamper");
    let l = FileRecoveryLedger::open(&p, 5, 7, key()).unwrap();
    drop(l);
    let mut b = fs::read(&p).unwrap();
    b[30] ^= 1;
    fs::write(&p, b).unwrap();
    assert!(matches!(
        FileRecoveryLedger::open(&p, 5, 7, key()),
        Err(FileRecoveryLedgerError::Authentication)
    ));
    fs::remove_file(p).unwrap();
}
