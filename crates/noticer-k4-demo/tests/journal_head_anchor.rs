use noticer_crypto::StateAuthenticationKey;
use noticer_k4_demo::{
    generation_transition_journal::{GenerationJournalHead, GenerationTransitionJournal},
    journal_head_anchor::{
        AnchoredGenerationTransitionJournal, AnchoredJournalError, JournalHeadAnchor,
        JournalHeadAnchorError,
    },
    monotonic_anchor::AnchorBinding,
};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
struct Anchor(Arc<Mutex<(GenerationJournalHead, bool)>>);
impl JournalHeadAnchor for Anchor {
    fn current(
        &mut self,
        _: AnchorBinding,
    ) -> Result<GenerationJournalHead, JournalHeadAnchorError> {
        Ok(self.0.lock().unwrap().0)
    }
    fn advance(
        &mut self,
        _: AnchorBinding,
        expected: GenerationJournalHead,
        next: GenerationJournalHead,
    ) -> Result<(), JournalHeadAnchorError> {
        let mut state = self.0.lock().unwrap();
        if state.1 {
            return Err(JournalHeadAnchorError::UpdateFailed);
        }
        if state.0 != expected {
            return Err(JournalHeadAnchorError::Stale);
        }
        state.0 = next;
        Ok(())
    }
}
fn path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-journal-anchor-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([91; 32])
}
fn binding() -> AnchorBinding {
    AnchorBinding {
        epoch: 5,
        generation: 7,
    }
}

#[test]
fn valid_old_prefix_is_rejected_after_external_head_advances() {
    let path = path("rollback");
    let journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    let old_bytes = fs::read(&path).unwrap();
    let shared = Arc::new(Mutex::new((journal.head(), false)));
    let mut anchored =
        AnchoredGenerationTransitionJournal::open(journal, Anchor(shared.clone()), binding())
            .unwrap();
    anchored.prepare(9, 10).unwrap();
    drop(anchored);
    fs::write(&path, old_bytes).unwrap();
    let rolled_back = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    assert!(matches!(
        AnchoredGenerationTransitionJournal::open(rolled_back, Anchor(shared), binding()),
        Err(AnchoredJournalError::HeadMismatch)
    ));
    fs::remove_file(path).unwrap();
}

#[test]
fn anchor_update_failure_poisons_wrapper() {
    let path = path("failure");
    let journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    let shared = Arc::new(Mutex::new((journal.head(), true)));
    let mut anchored =
        AnchoredGenerationTransitionJournal::open(journal, Anchor(shared), binding()).unwrap();
    assert!(matches!(
        anchored.prepare(9, 10),
        Err(AnchoredJournalError::Anchor(
            JournalHeadAnchorError::UpdateFailed
        ))
    ));
    assert!(matches!(
        anchored.commit(),
        Err(AnchoredJournalError::Poisoned)
    ));
    drop(anchored);
    fs::remove_file(path).unwrap();
}
