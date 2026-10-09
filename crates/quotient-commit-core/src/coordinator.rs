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
    permit: Option<ReleasePermit>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryEvidence {
    pub monitor: Option<MonitorAcceptance>,
    pub reservation: Option<BudgetReservation>,
    pub commit: Option<CommitEvidence>,
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
            permit: None,
        })
    }

    pub fn recover(
        bindings: ReleaseBindings,
        store: S,
        authentication_key: [u8; 32],
        maximum_records: usize,
        evidence: RecoveryEvidence,
    ) -> Result<Self, CoordinatorError> {
        let mut transaction =
            ReleaseTransaction::prepare(bindings).map_err(CoordinatorError::Commit)?;
        let journal = DurableJournal::new(store, authentication_key, maximum_records)
            .map_err(CoordinatorError::Journal)?;
        let records = journal
            .records_for(transaction.id())
            .map_err(CoordinatorError::Journal)?;
        if records.is_empty() {
            return Err(CoordinatorError::RecoveryRecordMissing);
        }
        for (index, record) in records.iter().enumerate() {
            let expected = match record.kind {
                RecordKind::Prepare if index == 0 => {
                    evidence_digest(RecordKind::Prepare, &[&transaction.id().0])
                }
                RecordKind::Prepare => return Err(CoordinatorError::InvalidRecoveryRecord),
                RecordKind::MonitorAccept => {
                    let value = evidence
                        .monitor
                        .ok_or(CoordinatorError::RecoveryEvidenceMissing)?;
                    transaction
                        .accept_monitor(value)
                        .map_err(CoordinatorError::Commit)?;
                    evidence_digest(
                        RecordKind::MonitorAccept,
                        &[
                            &value.transaction_id.0,
                            &value.certificate_digest,
                            &value.relation_digest,
                        ],
                    )
                }
                RecordKind::BudgetReserve => {
                    let value = evidence
                        .reservation
                        .ok_or(CoordinatorError::RecoveryEvidenceMissing)?;
                    transaction
                        .reserve_budget(value)
                        .map_err(CoordinatorError::Commit)?;
                    evidence_digest(
                        RecordKind::BudgetReserve,
                        &[
                            &value.transaction_id.0,
                            &value.profile_digest,
                            &value.reservation_digest,
                        ],
                    )
                }
                RecordKind::Commit => {
                    let value = evidence
                        .commit
                        .ok_or(CoordinatorError::RecoveryEvidenceMissing)?;
                    transaction
                        .commit(value)
                        .map_err(CoordinatorError::Commit)?;
                    evidence_digest(
                        RecordKind::Commit,
                        &[
                            &value.transaction_id.0,
                            &value.public_trace_digest,
                            &value.reservation_digest,
                        ],
                    )
                }
                RecordKind::Reject => {
                    transaction
                        .reject(transaction.id())
                        .map_err(CoordinatorError::Commit)?;
                    evidence_digest(RecordKind::Reject, &[&transaction.id().0])
                }
                RecordKind::Abort => {
                    transaction
                        .abort(transaction.id())
                        .map_err(CoordinatorError::Commit)?;
                    evidence_digest(RecordKind::Abort, &[&transaction.id().0])
                }
            };
            if record.evidence_digest != expected {
                return Err(CoordinatorError::RecoveryEvidenceMismatch);
            }
        }
        if journal.state(transaction.id()) != Some(transaction.state()) {
            return Err(CoordinatorError::StateMismatch);
        }
        Ok(Self {
            transaction,
            journal,
            permit: None,
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

    pub fn commit(&mut self, evidence: CommitEvidence) -> Result<(), CoordinatorError> {
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
        if !self.journal.release_committed(self.transaction.id()) {
            return Err(CoordinatorError::StateMismatch);
        }
        self.permit = Some(permit);
        Ok(())
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
    pub fn take_release_permit(&mut self) -> Option<ReleasePermit> {
        if self.journal.state(self.transaction.id()) != Some(self.transaction.state())
            || !self.journal.release_committed(self.transaction.id())
        {
            return None;
        }
        self.permit.take()
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
    RecoveryRecordMissing,
    RecoveryEvidenceMissing,
    RecoveryEvidenceMismatch,
    InvalidRecoveryRecord,
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
        assert_eq!(coordinator.take_release_permit(), None);
        coordinator
            .commit(CommitEvidence {
                transaction_id: coordinator.transaction_id(),
                public_trace_digest: [4; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert!(coordinator.take_release_permit().is_some());
        assert_eq!(coordinator.take_release_permit(), None);
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
        assert_eq!(coordinator.take_release_permit(), None);
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
        assert_eq!(coordinator.take_release_permit(), None);
        assert_eq!(coordinator.journal_sequence(), 3);
    }

    #[test]
    fn reserved_recovery_restores_state_without_a_permit() {
        let mut coordinator = coordinator();
        let monitor = monitor(&coordinator);
        let reservation = reservation(&coordinator);
        coordinator.accept_monitor(monitor).unwrap();
        coordinator.reserve_budget(reservation).unwrap();
        let mut recovered = DurableCoordinator::recover(
            bindings(),
            coordinator.into_store(),
            KEY,
            16,
            RecoveryEvidence {
                monitor: Some(monitor),
                reservation: Some(reservation),
                commit: None,
            },
        )
        .unwrap();
        assert_eq!(recovered.state(), TransactionState::BudgetReserved);
        assert_eq!(recovered.take_release_permit(), None);
    }

    #[test]
    fn committed_recovery_never_reissues_an_ambiguous_permit() {
        let mut coordinator = coordinator();
        let monitor = monitor(&coordinator);
        let reservation = reservation(&coordinator);
        let commit = CommitEvidence {
            transaction_id: coordinator.transaction_id(),
            public_trace_digest: [4; 32],
            reservation_digest: [5; 32],
        };
        coordinator.accept_monitor(monitor).unwrap();
        coordinator.reserve_budget(reservation).unwrap();
        coordinator.commit(commit).unwrap();
        let mut recovered = DurableCoordinator::recover(
            bindings(),
            coordinator.into_store(),
            KEY,
            16,
            RecoveryEvidence {
                monitor: Some(monitor),
                reservation: Some(reservation),
                commit: Some(commit),
            },
        )
        .unwrap();
        assert_eq!(recovered.state(), TransactionState::Committed);
        assert_eq!(recovered.take_release_permit(), None);
    }

    #[test]
    fn recovery_rejects_substituted_evidence() {
        let mut coordinator = coordinator();
        let monitor = monitor(&coordinator);
        coordinator.accept_monitor(monitor).unwrap();
        let mut substituted = monitor;
        substituted.relation_digest = [8; 32];
        assert_eq!(
            DurableCoordinator::recover(
                bindings(),
                coordinator.into_store(),
                KEY,
                16,
                RecoveryEvidence {
                    monitor: Some(substituted),
                    reservation: None,
                    commit: None,
                },
            )
            .unwrap_err(),
            CoordinatorError::Commit(CommitError::MonitorBindingMismatch)
        );
    }
}
