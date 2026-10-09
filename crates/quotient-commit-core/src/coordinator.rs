use crate::ledger::{DurableJournal, DurableStore, JournalError, RecordKind};
use crate::sha256::sha256;
use crate::{
    BudgetReservation, CommitError, CommitEvidence, MonitorAcceptance, ReleaseBindings,
    ReleasePermit, ReleaseTransaction, TransactionId, TransactionState,
};

const EVIDENCE_DOMAIN: &[u8] = b"noticer.quotient-commit.coordinator-evidence.v1\0";

#[derive(Debug)]
pub struct DurableCoordinator<S> {
    transaction: ReleaseTransaction,
    journal: DurableJournal<S>,
}

impl<S: DurableStore> DurableCoordinator<S> {
    pub fn new(
        bindings: ReleaseBindings,
        store: S,
        authentication_key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, CoordinatorError> {
        let transaction =
            ReleaseTransaction::prepare(bindings).map_err(CoordinatorError::Commit)?;
        let mut journal = DurableJournal::new(store, authentication_key, maximum_records)
            .map_err(CoordinatorError::Journal)?;
        if journal.state(transaction.id()).is_some() {
            return Err(CoordinatorError::RecoveryRequired);
        }
        journal
            .append(
                transaction.id(),
                RecordKind::Prepare,
                evidence_digest(RecordKind::Prepare, &[&transaction.id().0]),
            )
            .map_err(CoordinatorError::Journal)?;
        Ok(Self {
            transaction,
            journal,
        })
    }

    pub fn accept_monitor(&mut self, evidence: MonitorAcceptance) -> Result<(), CoordinatorError> {
        self.require_alignment()?;
        let mut candidate = self.transaction;
        candidate
            .accept_monitor(evidence)
            .map_err(CoordinatorError::Commit)?;
        let digest = evidence_digest(
            RecordKind::MonitorAccept,
            &[
                &evidence.transaction_id.0,
                &evidence.certificate_digest,
                &evidence.relation_digest,
            ],
        );
        self.persist_candidate(candidate, RecordKind::MonitorAccept, digest)
    }

    pub fn reserve_budget(&mut self, evidence: BudgetReservation) -> Result<(), CoordinatorError> {
        self.require_alignment()?;
        let mut candidate = self.transaction;
        candidate
            .reserve_budget(evidence)
            .map_err(CoordinatorError::Commit)?;
        let digest = evidence_digest(
            RecordKind::BudgetReserve,
            &[
                &evidence.transaction_id.0,
                &evidence.profile_digest,
                &evidence.reservation_digest,
            ],
        );
        self.persist_candidate(candidate, RecordKind::BudgetReserve, digest)
    }

    pub fn commit(&mut self, evidence: CommitEvidence) -> Result<ReleasePermit, CoordinatorError> {
        self.require_alignment()?;
        let mut candidate = self.transaction;
        let permit = candidate
            .commit(evidence)
            .map_err(CoordinatorError::Commit)?;
        let digest = evidence_digest(
            RecordKind::Commit,
            &[
                &evidence.transaction_id.0,
                &evidence.public_trace_digest,
                &evidence.reservation_digest,
            ],
        );
        self.persist_candidate(candidate, RecordKind::Commit, digest)?;
        if self.release_permit() != Some(permit) {
            return Err(CoordinatorError::StateMismatch);
        }
        Ok(permit)
    }

    pub fn reject(&mut self) -> Result<(), CoordinatorError> {
        self.finish_without_release(RecordKind::Reject)
    }

    pub fn abort(&mut self) -> Result<(), CoordinatorError> {
        self.finish_without_release(RecordKind::Abort)
    }

    #[must_use]
    pub const fn state(&self) -> TransactionState {
        self.transaction.state()
    }

    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction.id()
    }

    #[must_use]
    pub fn release_permit(&self) -> Option<ReleasePermit> {
        if self.journal.state(self.transaction.id()) != Some(self.transaction.state())
            || !self.journal.release_committed(self.transaction.id())
        {
            return None;
        }
        self.transaction.release_permit()
    }

    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal.sequence()
    }

    pub fn store_mut(&mut self) -> &mut S {
        self.journal.store_mut()
    }

    pub fn into_store(self) -> S {
        self.journal.into_store()
    }

    fn finish_without_release(&mut self, kind: RecordKind) -> Result<(), CoordinatorError> {
        self.require_alignment()?;
        let mut candidate = self.transaction;
        match kind {
            RecordKind::Reject => candidate
                .reject(candidate.id())
                .map_err(CoordinatorError::Commit)?,
            RecordKind::Abort => candidate
                .abort(candidate.id())
                .map_err(CoordinatorError::Commit)?,
            _ => return Err(CoordinatorError::InvalidTerminalKind),
        }
        let digest = evidence_digest(kind, &[&candidate.id().0]);
        self.persist_candidate(candidate, kind, digest)
    }

    fn persist_candidate(
        &mut self,
        candidate: ReleaseTransaction,
        kind: RecordKind,
        digest: [u8; 32],
    ) -> Result<(), CoordinatorError> {
        self.journal
            .append(self.transaction.id(), kind, digest)
            .map_err(CoordinatorError::Journal)?;
        self.transaction = candidate;
        self.require_alignment()
    }

    fn require_alignment(&self) -> Result<(), CoordinatorError> {
        if self.journal.state(self.transaction.id()) == Some(self.transaction.state()) {
            Ok(())
        } else {
            Err(CoordinatorError::StateMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
    Commit(CommitError),
    Journal(JournalError),
    RecoveryRequired,
    StateMismatch,
    InvalidTerminalKind,
}

fn evidence_digest(kind: RecordKind, fields: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    bytes.push(kind as u8);
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    sha256(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{MemoryStore, StoreError};

    const KEY: [u8; 32] = [9; 32];

    fn bindings() -> ReleaseBindings {
        ReleaseBindings {
            certificate_digest: [1; 32],
            relation_digest: [2; 32],
            profile_digest: [3; 32],
            public_trace_digest: [4; 32],
            release_sequence: 7,
            policy_epoch: 9,
        }
    }

    fn coordinator() -> DurableCoordinator<MemoryStore> {
        DurableCoordinator::new(bindings(), MemoryStore::default(), KEY, 16).unwrap()
    }

    fn monitor(coordinator: &DurableCoordinator<MemoryStore>) -> MonitorAcceptance {
        MonitorAcceptance {
            transaction_id: coordinator.transaction_id(),
            certificate_digest: [1; 32],
            relation_digest: [2; 32],
        }
    }

    fn reservation(coordinator: &DurableCoordinator<MemoryStore>) -> BudgetReservation {
        BudgetReservation {
            transaction_id: coordinator.transaction_id(),
            profile_digest: [3; 32],
            reservation_digest: [5; 32],
        }
    }

    #[test]
    fn permit_is_returned_only_after_durable_commit() {
        let mut coordinator = coordinator();
        coordinator.accept_monitor(monitor(&coordinator)).unwrap();
        coordinator
            .reserve_budget(reservation(&coordinator))
            .unwrap();
        assert_eq!(coordinator.release_permit(), None);
        let permit = coordinator
            .commit(CommitEvidence {
                transaction_id: coordinator.transaction_id(),
                public_trace_digest: [4; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(coordinator.release_permit(), Some(permit));
        assert_eq!(coordinator.journal_sequence(), 4);
    }

    #[test]
    fn failed_sync_leaves_live_state_unchanged() {
        let mut coordinator = coordinator();
        coordinator.store_mut().fail_next_sync();
        assert_eq!(
            coordinator.accept_monitor(monitor(&coordinator)),
            Err(CoordinatorError::Journal(JournalError::Store(
                StoreError::IoFailure
            )))
        );
        assert_eq!(coordinator.state(), TransactionState::Prepared);
        assert_eq!(coordinator.journal_sequence(), 1);
        assert_eq!(coordinator.release_permit(), None);
    }

    #[test]
    fn binding_mismatch_is_rejected_before_journal_append() {
        let mut coordinator = coordinator();
        let mut evidence = monitor(&coordinator);
        evidence.relation_digest = [8; 32];
        assert_eq!(
            coordinator.accept_monitor(evidence),
            Err(CoordinatorError::Commit(
                CommitError::MonitorBindingMismatch
            ))
        );
        assert_eq!(coordinator.journal_sequence(), 1);
    }

    #[test]
    fn double_commit_cannot_append_or_reissue_a_permit() {
        let mut coordinator = coordinator();
        coordinator.accept_monitor(monitor(&coordinator)).unwrap();
        coordinator
            .reserve_budget(reservation(&coordinator))
            .unwrap();
        let evidence = CommitEvidence {
            transaction_id: coordinator.transaction_id(),
            public_trace_digest: [4; 32],
            reservation_digest: [5; 32],
        };
        coordinator.commit(evidence).unwrap();
        assert_eq!(
            coordinator.commit(evidence),
            Err(CoordinatorError::Commit(CommitError::TerminalState))
        );
        assert_eq!(coordinator.journal_sequence(), 4);
    }

    #[test]
    fn durable_rejection_never_exposes_a_permit() {
        let mut coordinator = coordinator();
        coordinator.accept_monitor(monitor(&coordinator)).unwrap();
        coordinator.reject().unwrap();
        assert_eq!(coordinator.state(), TransactionState::Rejected);
        assert_eq!(coordinator.release_permit(), None);
        assert_eq!(coordinator.journal_sequence(), 3);
    }
}
