#![forbid(unsafe_code)]

pub mod ledger;
mod sha256;

const TRANSACTION_DOMAIN: &[u8] = b"noticer.quotient-commit.transaction.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransactionId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseBindings {
    pub certificate_digest: [u8; 32],
    pub relation_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub public_trace_digest: [u8; 32],
    pub release_sequence: u64,
    pub policy_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorAcceptance {
    pub transaction_id: TransactionId,
    pub certificate_digest: [u8; 32],
    pub relation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetReservation {
    pub transaction_id: TransactionId,
    pub profile_digest: [u8; 32],
    pub reservation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitEvidence {
    pub transaction_id: TransactionId,
    pub public_trace_digest: [u8; 32],
    pub reservation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePermit {
    pub transaction_id: TransactionId,
    pub public_trace_digest: [u8; 32],
    pub reservation_digest: [u8; 32],
    pub release_sequence: u64,
    pub policy_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionState {
    Prepared,
    MonitorAccepted,
    BudgetReserved,
    Committed,
    Rejected,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseTransaction {
    id: TransactionId,
    bindings: ReleaseBindings,
    state: TransactionState,
    reservation_digest: Option<[u8; 32]>,
}

impl ReleaseTransaction {
    pub fn prepare(bindings: ReleaseBindings) -> Result<Self, CommitError> {
        validate_bindings(bindings)?;
        Ok(Self {
            id: transaction_id(bindings),
            bindings,
            state: TransactionState::Prepared,
            reservation_digest: None,
        })
    }

    #[must_use]
    pub const fn id(&self) -> TransactionId {
        self.id
    }

    #[must_use]
    pub const fn state(&self) -> TransactionState {
        self.state
    }

    pub fn accept_monitor(&mut self, evidence: MonitorAcceptance) -> Result<(), CommitError> {
        self.require_state(TransactionState::Prepared)?;
        self.require_transaction(evidence.transaction_id)?;
        if evidence.certificate_digest != self.bindings.certificate_digest
            || evidence.relation_digest != self.bindings.relation_digest
        {
            return Err(CommitError::MonitorBindingMismatch);
        }
        self.state = TransactionState::MonitorAccepted;
        Ok(())
    }

    pub fn reserve_budget(&mut self, evidence: BudgetReservation) -> Result<(), CommitError> {
        self.require_state(TransactionState::MonitorAccepted)?;
        self.require_transaction(evidence.transaction_id)?;
        if evidence.profile_digest != self.bindings.profile_digest {
            return Err(CommitError::ProfileBindingMismatch);
        }
        if is_zero(evidence.reservation_digest) {
            return Err(CommitError::InvalidReservation);
        }
        self.reservation_digest = Some(evidence.reservation_digest);
        self.state = TransactionState::BudgetReserved;
        Ok(())
    }

    pub fn commit(&mut self, evidence: CommitEvidence) -> Result<ReleasePermit, CommitError> {
        self.require_state(TransactionState::BudgetReserved)?;
        self.require_transaction(evidence.transaction_id)?;
        if evidence.public_trace_digest != self.bindings.public_trace_digest {
            return Err(CommitError::TraceBindingMismatch);
        }
        let reservation_digest = self
            .reservation_digest
            .ok_or(CommitError::MissingReservation)?;
        if evidence.reservation_digest != reservation_digest {
            return Err(CommitError::ReservationBindingMismatch);
        }
        self.state = TransactionState::Committed;
        Ok(ReleasePermit {
            transaction_id: self.id,
            public_trace_digest: self.bindings.public_trace_digest,
            reservation_digest,
            release_sequence: self.bindings.release_sequence,
            policy_epoch: self.bindings.policy_epoch,
        })
    }

    pub fn reject(&mut self, transaction_id: TransactionId) -> Result<(), CommitError> {
        self.finish_without_release(transaction_id, TransactionState::Rejected)
    }

    pub fn abort(&mut self, transaction_id: TransactionId) -> Result<(), CommitError> {
        self.finish_without_release(transaction_id, TransactionState::Aborted)
    }

    #[must_use]
    pub fn release_permit(&self) -> Option<ReleasePermit> {
        if self.state != TransactionState::Committed {
            return None;
        }
        Some(ReleasePermit {
            transaction_id: self.id,
            public_trace_digest: self.bindings.public_trace_digest,
            reservation_digest: self.reservation_digest?,
            release_sequence: self.bindings.release_sequence,
            policy_epoch: self.bindings.policy_epoch,
        })
    }

    fn finish_without_release(
        &mut self,
        transaction_id: TransactionId,
        terminal: TransactionState,
    ) -> Result<(), CommitError> {
        if matches!(
            self.state,
            TransactionState::Committed | TransactionState::Rejected | TransactionState::Aborted
        ) {
            return Err(CommitError::TerminalState);
        }
        self.require_transaction(transaction_id)?;
        self.state = terminal;
        Ok(())
    }

    fn require_state(&self, expected: TransactionState) -> Result<(), CommitError> {
        if self.state == expected {
            Ok(())
        } else if matches!(
            self.state,
            TransactionState::Committed | TransactionState::Rejected | TransactionState::Aborted
        ) {
            Err(CommitError::TerminalState)
        } else {
            Err(CommitError::InvalidTransition)
        }
    }

    fn require_transaction(&self, transaction_id: TransactionId) -> Result<(), CommitError> {
        if transaction_id == self.id {
            Ok(())
        } else {
            Err(CommitError::TransactionMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    ZeroBinding,
    InvalidPolicyEpoch,
    TransactionMismatch,
    MonitorBindingMismatch,
    ProfileBindingMismatch,
    TraceBindingMismatch,
    ReservationBindingMismatch,
    InvalidReservation,
    MissingReservation,
    InvalidTransition,
    TerminalState,
}

fn validate_bindings(bindings: ReleaseBindings) -> Result<(), CommitError> {
    if is_zero(bindings.certificate_digest)
        || is_zero(bindings.relation_digest)
        || is_zero(bindings.profile_digest)
        || is_zero(bindings.public_trace_digest)
    {
        return Err(CommitError::ZeroBinding);
    }
    if bindings.policy_epoch == 0 {
        return Err(CommitError::InvalidPolicyEpoch);
    }
    Ok(())
}

fn transaction_id(bindings: ReleaseBindings) -> TransactionId {
    let mut bytes = Vec::with_capacity(TRANSACTION_DOMAIN.len() + 32 * 4 + 8 * 2);
    bytes.extend_from_slice(TRANSACTION_DOMAIN);
    bytes.extend_from_slice(&bindings.certificate_digest);
    bytes.extend_from_slice(&bindings.relation_digest);
    bytes.extend_from_slice(&bindings.profile_digest);
    bytes.extend_from_slice(&bindings.public_trace_digest);
    bytes.extend_from_slice(&bindings.release_sequence.to_be_bytes());
    bytes.extend_from_slice(&bindings.policy_epoch.to_be_bytes());
    TransactionId(sha256::sha256(&bytes))
}

const fn is_zero(value: [u8; 32]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn accepted_transaction() -> ReleaseTransaction {
        let mut transaction = ReleaseTransaction::prepare(bindings()).unwrap();
        transaction
            .accept_monitor(MonitorAcceptance {
                transaction_id: transaction.id(),
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
            })
            .unwrap();
        transaction
    }

    #[test]
    fn release_permit_exists_only_after_ordered_commit() {
        let mut transaction = accepted_transaction();
        assert_eq!(transaction.release_permit(), None);
        transaction
            .reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(transaction.release_permit(), None);
        let permit = transaction
            .commit(CommitEvidence {
                transaction_id: transaction.id(),
                public_trace_digest: [4; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(permit.release_sequence, 7);
        assert_eq!(transaction.release_permit(), Some(permit));
    }

    #[test]
    fn out_of_order_and_replayed_transitions_fail_closed() {
        let mut transaction = ReleaseTransaction::prepare(bindings()).unwrap();
        assert_eq!(
            transaction.reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::InvalidTransition)
        );
        transaction.abort(transaction.id()).unwrap();
        assert_eq!(
            transaction.abort(transaction.id()),
            Err(CommitError::TerminalState)
        );
        assert_eq!(transaction.release_permit(), None);
    }

    #[test]
    fn cross_transaction_and_binding_substitution_are_rejected() {
        let mut transaction = ReleaseTransaction::prepare(bindings()).unwrap();
        let other = ReleaseTransaction::prepare(ReleaseBindings {
            release_sequence: 8,
            ..bindings()
        })
        .unwrap();
        assert_eq!(
            transaction.accept_monitor(MonitorAcceptance {
                transaction_id: other.id(),
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
            }),
            Err(CommitError::TransactionMismatch)
        );
        assert_eq!(transaction.state(), TransactionState::Prepared);
        assert_eq!(
            transaction.accept_monitor(MonitorAcceptance {
                transaction_id: transaction.id(),
                certificate_digest: [9; 32],
                relation_digest: [2; 32],
            }),
            Err(CommitError::MonitorBindingMismatch)
        );
        assert_eq!(transaction.state(), TransactionState::Prepared);
    }

    #[test]
    fn reservation_and_trace_substitution_are_rejected_without_release() {
        let mut transaction = accepted_transaction();
        assert_eq!(
            transaction.reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [8; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::ProfileBindingMismatch)
        );
        transaction
            .reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(
            transaction.commit(CommitEvidence {
                transaction_id: transaction.id(),
                public_trace_digest: [8; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::TraceBindingMismatch)
        );
        assert_eq!(transaction.release_permit(), None);
    }

    #[test]
    fn terminal_rejection_cannot_be_promoted_to_release() {
        let mut transaction = accepted_transaction();
        transaction.reject(transaction.id()).unwrap();
        assert_eq!(transaction.state(), TransactionState::Rejected);
        assert_eq!(transaction.release_permit(), None);
        assert_eq!(
            transaction.reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::TerminalState)
        );
    }

    #[test]
    fn invalid_bindings_never_create_a_transaction() {
        assert_eq!(
            ReleaseTransaction::prepare(ReleaseBindings {
                certificate_digest: [0; 32],
                ..bindings()
            }),
            Err(CommitError::ZeroBinding)
        );
        assert_eq!(
            ReleaseTransaction::prepare(ReleaseBindings {
                policy_epoch: 0,
                ..bindings()
            }),
            Err(CommitError::InvalidPolicyEpoch)
        );
    }
}
