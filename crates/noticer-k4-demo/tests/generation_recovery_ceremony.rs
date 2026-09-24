use noticer_aetp::ServiceBinding;
use noticer_crypto::{derive_issuer_keys, CryptographicRootSecret, StateAuthenticationKey};
use noticer_k4_demo::{
    generation_reconciliation::{
        reconcile_generation_transition_with_durable_ledger, GenerationReconciliationError,
        GenerationRecoveryObservation,
    },
    generation_transition_journal::{
        GenerationJournalHead, GenerationTransitionJournal, GenerationTransitionState,
    },
    journal_head_anchor::{
        AnchoredGenerationTransitionJournal, JournalHeadAnchor, JournalHeadAnchorError,
    },
    monotonic_anchor::AnchorBinding,
    recovery::issue_recovery_permit,
};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
struct Anchor(Arc<Mutex<GenerationJournalHead>>);
impl JournalHeadAnchor for Anchor {
    fn current(
        &mut self,
        _: AnchorBinding,
    ) -> Result<GenerationJournalHead, JournalHeadAnchorError> {
        Ok(*self.0.lock().unwrap())
    }
    fn advance(
        &mut self,
        _: AnchorBinding,
        expected: GenerationJournalHead,
        next: GenerationJournalHead,
    ) -> Result<(), JournalHeadAnchorError> {
        let mut head = self.0.lock().unwrap();
        if *head != expected {
            return Err(JournalHeadAnchorError::Stale);
        }
        *head = next;
        Ok(())
    }
}
fn path(label: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-ceremony-{label}-{}-{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        extension
    ))
}
fn journal_key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([101; 32])
}
fn ledger_key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([102; 32])
}
fn binding() -> AnchorBinding {
    AnchorBinding {
        epoch: 5,
        generation: 7,
    }
}

#[test]
fn durable_ceremony_restarts_clean_and_rejects_replay() {
    let journal_path = path("e2e", "journal");
    let ledger_path = path("e2e", "ledger");
    let mut raw = GenerationTransitionJournal::open(&journal_path, 5, 7, journal_key()).unwrap();
    raw.prepare(9, 10).unwrap();
    let shared = Arc::new(Mutex::new(raw.head()));
    drop(raw);
    let domain = ServiceBinding([8; 16]);
    let issuer = derive_issuer_keys(&CryptographicRootSecret::new([9; 32]), domain, 5).unwrap();
    let verifier = issuer.verifier_material();
    let permit = issue_recovery_permit(&issuer, domain, 7, 9, 9, 10, 100, [7; 16]);
    let observation = GenerationRecoveryObservation {
        record_slot: 9,
        anchor_slot: 9,
        generation_at_target: false,
    };
    reconcile_generation_transition_with_durable_ledger(
        &journal_path,
        journal_key(),
        Anchor(shared.clone()),
        &ledger_path,
        ledger_key(),
        &verifier,
        domain,
        binding(),
        50,
        &permit,
        observation,
    )
    .unwrap();
    let raw = GenerationTransitionJournal::open(&journal_path, 5, 7, journal_key()).unwrap();
    let mut anchored =
        AnchoredGenerationTransitionJournal::open(raw, Anchor(shared.clone()), binding()).unwrap();
    assert_eq!(anchored.state(), GenerationTransitionState::Clean);
    anchored.prepare(9, 10).unwrap();
    drop(anchored);
    assert!(matches!(
        reconcile_generation_transition_with_durable_ledger(
            &journal_path,
            journal_key(),
            Anchor(shared),
            &ledger_path,
            ledger_key(),
            &verifier,
            domain,
            binding(),
            50,
            &permit,
            observation
        ),
        Err(GenerationReconciliationError::Replay)
    ));
    fs::remove_file(journal_path).unwrap();
    fs::remove_file(ledger_path).unwrap();
}
