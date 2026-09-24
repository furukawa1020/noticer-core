use noticer_aetp::ServiceBinding;
use noticer_crypto::{derive_issuer_keys, CryptographicRootSecret, StateAuthenticationKey};
use noticer_k4_demo::{
    generation_reconciliation::{
        reconcile_generation_transition, GenerationReconciliationError,
        GenerationRecoveryObservation,
    },
    generation_transition_journal::{GenerationTransitionJournal, GenerationTransitionState},
    monotonic_anchor::AnchorBinding,
    recovery::{issue_recovery_permit, RecoveryLedger, RecoveryLedgerError},
};
use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct Ledger(HashSet<[u8; 16]>);
impl RecoveryLedger for Ledger {
    fn consume(&mut self, id: [u8; 16]) -> Result<bool, RecoveryLedgerError> {
        Ok(self.0.insert(id))
    }
}
fn path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-generation-reconcile-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([81; 32])
}
fn binding() -> AnchorBinding {
    AnchorBinding {
        epoch: 5,
        generation: 7,
    }
}

#[test]
fn signed_permit_resolves_only_complete_old_or_new_observations() {
    let domain = ServiceBinding([8; 16]);
    let issuer = derive_issuer_keys(&CryptographicRootSecret::new([9; 32]), domain, 5).unwrap();
    let verifier = issuer.verifier_material();
    let mut ledger = Ledger::default();

    let old_path = path("old");
    let mut old = GenerationTransitionJournal::open(&old_path, 5, 7, key()).unwrap();
    old.prepare(9, 10).unwrap();
    let permit = issue_recovery_permit(&issuer, domain, 7, 9, 9, 10, 100, [1; 16]);
    reconcile_generation_transition(
        &mut old,
        &verifier,
        domain,
        binding(),
        50,
        &permit,
        GenerationRecoveryObservation {
            record_slot: 9,
            anchor_slot: 9,
            generation_at_target: false,
        },
        &mut ledger,
    )
    .unwrap();
    assert_eq!(old.state(), GenerationTransitionState::Clean);
    drop(old);
    fs::remove_file(old_path).unwrap();

    let new_path = path("new");
    let mut new = GenerationTransitionJournal::open(&new_path, 5, 7, key()).unwrap();
    new.prepare(9, 10).unwrap();
    let permit = issue_recovery_permit(&issuer, domain, 7, 10, 10, 10, 100, [2; 16]);
    reconcile_generation_transition(
        &mut new,
        &verifier,
        domain,
        binding(),
        50,
        &permit,
        GenerationRecoveryObservation {
            record_slot: 10,
            anchor_slot: 10,
            generation_at_target: true,
        },
        &mut ledger,
    )
    .unwrap();
    assert_eq!(new.state(), GenerationTransitionState::Clean);
    drop(new);
    fs::remove_file(new_path).unwrap();
}

#[test]
fn mixed_state_expired_and_replayed_permits_fail_closed() {
    let path = path("reject");
    let domain = ServiceBinding([8; 16]);
    let issuer = derive_issuer_keys(&CryptographicRootSecret::new([9; 32]), domain, 5).unwrap();
    let verifier = issuer.verifier_material();
    let mut journal = GenerationTransitionJournal::open(&path, 5, 7, key()).unwrap();
    journal.prepare(9, 10).unwrap();
    let permit = issue_recovery_permit(&issuer, domain, 7, 10, 9, 10, 40, [3; 16]);
    let observation = GenerationRecoveryObservation {
        record_slot: 10,
        anchor_slot: 9,
        generation_at_target: true,
    };
    let mut ledger = Ledger::default();
    assert!(matches!(
        reconcile_generation_transition(
            &mut journal,
            &verifier,
            domain,
            binding(),
            20,
            &permit,
            observation,
            &mut ledger
        ),
        Err(GenerationReconciliationError::Ambiguous)
    ));
    assert!(matches!(
        reconcile_generation_transition(
            &mut journal,
            &verifier,
            domain,
            binding(),
            41,
            &permit,
            observation,
            &mut ledger
        ),
        Err(GenerationReconciliationError::Expired)
    ));
    drop(journal);
    fs::remove_file(path).unwrap();
}
