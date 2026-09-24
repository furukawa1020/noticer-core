use crate::{
    durable_recovery_ledger::FileRecoveryLedger,
    generation_transition_journal::{
        GenerationTransitionJournal, GenerationTransitionJournalError, GenerationTransitionState,
    },
    journal_head_anchor::{AnchoredGenerationTransitionJournal, JournalHeadAnchor},
    monotonic_anchor::AnchorBinding,
    recovery::{permit_message, RecoveryLedger, RecoveryPermit},
};
use noticer_aetp::ServiceBinding;
use noticer_crypto::{CryptoError, StateAuthenticationKey, VerifierKeyMaterial};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationRecoveryObservation {
    pub record_slot: u64,
    pub anchor_slot: u64,
    pub generation_at_target: bool,
}

#[derive(Debug)]
pub enum GenerationReconciliationError {
    NoTransition,
    Binding,
    Expired,
    Signature(CryptoError),
    Ambiguous,
    Replay,
    Ledger,
    Journal,
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_generation_transition<L: RecoveryLedger>(
    journal: &mut J,
    verifier: &VerifierKeyMaterial,
    expected_operator_domain: ServiceBinding,
    binding: AnchorBinding,
    now: u64,
    permit: &RecoveryPermit,
    observation: GenerationRecoveryObservation,
    ledger: &mut L,
) -> Result<(), GenerationReconciliationError> {
    let (from_slot, to_slot, committed) = match journal.reconciliation_state() {
        GenerationTransitionState::Clean => {
            return Err(GenerationReconciliationError::NoTransition)
        }
        GenerationTransitionState::Prepared { from_slot, to_slot } => (from_slot, to_slot, false),
        GenerationTransitionState::Committed { from_slot, to_slot } => (from_slot, to_slot, true),
    };
    if permit.operator_domain != expected_operator_domain
        || permit.epoch != binding.epoch
        || permit.generation != binding.generation
        || permit.record_slot != observation.record_slot
        || permit.anchor_slot != observation.anchor_slot
        || permit.target_slot != to_slot
    {
        return Err(GenerationReconciliationError::Binding);
    }
    if now > permit.expires_at {
        return Err(GenerationReconciliationError::Expired);
    }
    let all_old = observation.record_slot == from_slot
        && observation.anchor_slot == from_slot
        && !observation.generation_at_target;
    let all_new = observation.record_slot == to_slot
        && observation.anchor_slot == to_slot
        && observation.generation_at_target;
    let consistent = if committed {
        all_new
    } else {
        all_old || all_new
    };
    if !consistent {
        return Err(GenerationReconciliationError::Ambiguous);
    }
    verifier
        .verify(&permit_message(permit), &permit.signature)
        .map_err(GenerationReconciliationError::Signature)?;
    let permit_id = permit.signature[..16].try_into().expect("fixed permit id");
    if !ledger
        .consume(permit_id)
        .map_err(|_| GenerationReconciliationError::Ledger)?
    {
        return Err(GenerationReconciliationError::Replay);
    }
    if all_old {
        journal
            .abort()
            .map_err(GenerationReconciliationError::Journal)
    } else {
        if !committed {
            journal
                .commit()
                .map_err(GenerationReconciliationError::Journal)?;
        }
        journal
            .clear()
            .map_err(GenerationReconciliationError::Journal)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_generation_transition_with_durable_ledger<A: JournalHeadAnchor>(
    journal_path: impl AsRef<Path>,
    journal_key: StateAuthenticationKey,
    journal_anchor: A,
    ledger_path: impl AsRef<Path>,
    ledger_key: StateAuthenticationKey,
    verifier: &VerifierKeyMaterial,
    expected_operator_domain: ServiceBinding,
    binding: AnchorBinding,
    now: u64,
    permit: &RecoveryPermit,
    observation: GenerationRecoveryObservation,
) -> Result<(), GenerationReconciliationError> {
    let journal = GenerationTransitionJournal::open(
        journal_path,
        binding.epoch,
        binding.generation,
        journal_key,
    )
    .map_err(|_| GenerationReconciliationError::Journal)?;
    let mut journal = AnchoredGenerationTransitionJournal::open(journal, journal_anchor, binding)
        .map_err(|_| GenerationReconciliationError::Journal)?;
    let mut ledger =
        FileRecoveryLedger::open(ledger_path, binding.epoch, binding.generation, ledger_key)
            .map_err(|_| GenerationReconciliationError::Ledger)?;
    reconcile_generation_transition(
        &mut journal,
        verifier,
        expected_operator_domain,
        binding,
        now,
        permit,
        observation,
        &mut ledger,
    )
}
