use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use noticer_crypto::StateAuthenticationKey;
use noticer_k4_demo::generation_transition_journal::{
    GenerationTransitionJournal, GenerationTransitionJournalError, GenerationTransitionState,
};

fn path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-generation-journal-{label}-{}-{}",
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
fn transition_survives_each_restart_boundary() {
    let path = path("restart");
    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    assert_eq!(journal.state(), GenerationTransitionState::Clean);
    journal.prepare(9, 10).unwrap();
    assert_eq!(journal.sequence(), 1);
    drop(journal);

    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    assert_eq!(
        journal.state(),
        GenerationTransitionState::Prepared {
            from_slot: 9,
            to_slot: 10
        }
    );
    journal.commit().unwrap();
    drop(journal);

    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    assert!(matches!(
        journal.state(),
        GenerationTransitionState::Committed { .. }
    ));
    journal.clear().unwrap();
    drop(journal);

    let journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    assert_eq!(journal.state(), GenerationTransitionState::Clean);
    assert_eq!(journal.sequence(), 3);
    drop(journal);
    fs::remove_file(path).unwrap();
}

#[test]
fn invalid_order_and_second_writer_fail_closed() {
    let path = path("order");
    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    assert!(matches!(
        journal.commit(),
        Err(GenerationTransitionJournalError::InvalidTransition)
    ));
    assert!(GenerationTransitionJournal::open(&path, 5, 7, key()).is_err());
    journal.prepare(4, 4).unwrap_err();
    drop(journal);
    fs::remove_file(path).unwrap();
}

#[test]
fn partial_write_tamper_and_binding_mismatch_are_rejected() {
    let path = path("faults");
    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    journal.prepare(9, 10).unwrap();
    drop(journal);
    assert!(matches!(
        GenerationTransitionJournal::open(&path, 6, 7, key()),
        Err(GenerationTransitionJournalError::EpochMismatch)
    ));
    assert!(matches!(
        GenerationTransitionJournal::open(&path, 5, 8, key()),
        Err(GenerationTransitionJournalError::GenerationMismatch)
    ));
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[1]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(
        GenerationTransitionJournal::open(&path, 5, 7, key()),
        Err(GenerationTransitionJournalError::Corrupt)
    ));
    fs::remove_file(&path).unwrap();

    let path = path("tamper");
    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    journal.prepare(9, 10).unwrap();
    drop(journal);
    let mut bytes = fs::read(&path).unwrap();
    bytes[70] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        GenerationTransitionJournal::open(&path, 5, 7, key()),
        Err(GenerationTransitionJournalError::Authentication)
    ));
    fs::remove_file(path).unwrap();
}
