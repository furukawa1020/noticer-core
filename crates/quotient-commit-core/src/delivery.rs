//! Delivery ceremony for a committed public release.
//!
//! This module does not claim generic exactly-once delivery. Its guarantee is
//! conditional on a sink that durably deduplicates transaction identifiers
//! and rejects conflicting bindings.

use crate::coordinator::DurableCoordinator;
use crate::ledger::DurableStore;
use crate::{ReleasePermit, TransactionId};

/// Result reported by an idempotent sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// The sink durably accepted the effect for the first time.
    Delivered,
    /// The sink had already accepted the identical transaction binding.
    AlreadyDelivered,
}

/// Failures a sink may report without weakening transaction binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkError {
    /// Delivery status is unknown or the sink is temporarily unavailable.
    Unavailable,
    /// The transaction ID was previously bound to another public trace.
    BindingConflict,
}

/// A sink that durably deduplicates on the transaction identifier.
pub trait IdempotentSink {
    /// Accepts an effect once, or confirms that the identical effect exists.
    fn deliver_once(&mut self, permit: &ReleasePermit) -> Result<DeliveryOutcome, SinkError>;
}

/// Errors from the release delivery ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    /// No one-shot permit is available on the live coordinator.
    NoPermit,
    /// Recovery did not establish a committed public descriptor.
    NoCommittedDescriptor,
    /// The sink rejected or could not confirm delivery.
    Sink(SinkError),
}

/// Public receipt for a delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    pub transaction_id: TransactionId,
    pub public_trace_digest: [u8; 32],
    pub release_sequence: u64,
    pub policy_epoch: u64,
    pub outcome: DeliveryOutcome,
}

impl DeliveryReceipt {
    const fn from_permit(permit: ReleasePermit, outcome: DeliveryOutcome) -> Self {
        Self {
            transaction_id: permit.transaction_id,
            public_trace_digest: permit.public_trace_digest,
            release_sequence: permit.release_sequence,
            policy_epoch: permit.policy_epoch,
            outcome,
        }
    }
}

/// Consumes the live coordinator's one-shot permit before contacting the sink.
///
/// If the sink response is lost, callers must recover from the journal and use
/// [`reconcile_committed`] rather than retrying this function.
pub fn deliver_once<S: DurableStore, K: IdempotentSink>(
    coordinator: &mut DurableCoordinator<S>,
    sink: &mut K,
) -> Result<DeliveryReceipt, DeliveryError> {
    let permit = coordinator
        .take_release_permit()
        .ok_or(DeliveryError::NoPermit)?;
    let outcome = sink.deliver_once(&permit).map_err(DeliveryError::Sink)?;
    Ok(DeliveryReceipt::from_permit(permit, outcome))
}

/// Reconciles a recovered COMMITTED transaction with an idempotent sink.
///
/// The descriptor is never exposed as a fresh permit. Repetition is safe only
/// under the [`IdempotentSink`] contract.
pub fn reconcile_committed<S: DurableStore, K: IdempotentSink>(
    coordinator: &DurableCoordinator<S>,
    sink: &mut K,
) -> Result<DeliveryReceipt, DeliveryError> {
    let permit = coordinator
        .committed_descriptor()
        .ok_or(DeliveryError::NoCommittedDescriptor)?;
    let outcome = sink.deliver_once(&permit).map_err(DeliveryError::Sink)?;
    Ok(DeliveryReceipt::from_permit(permit, outcome))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::coordinator::RecoveryEvidence;
    use crate::ledger::MemoryStore;
    use crate::{
        BudgetReservation, CommitEvidence, MonitorAcceptance, ReleaseBindings, TransactionState,
    };

    const KEY: [u8; 32] = [9; 32];

    #[derive(Default)]
    struct MemorySink {
        accepted: BTreeMap<TransactionId, ReleasePermit>,
        effects: usize,
        lose_next_acknowledgement: bool,
    }

    impl IdempotentSink for MemorySink {
        fn deliver_once(&mut self, permit: &ReleasePermit) -> Result<DeliveryOutcome, SinkError> {
            if let Some(existing) = self.accepted.get(&permit.transaction_id) {
                return if existing == permit {
                    Ok(DeliveryOutcome::AlreadyDelivered)
                } else {
                    Err(SinkError::BindingConflict)
                };
            }
            self.accepted.insert(permit.transaction_id, *permit);
            self.effects += 1;
            if self.lose_next_acknowledgement {
                self.lose_next_acknowledgement = false;
                return Err(SinkError::Unavailable);
            }
            Ok(DeliveryOutcome::Delivered)
        }
    }

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

    fn evidence(
        transaction_id: TransactionId,
    ) -> (MonitorAcceptance, BudgetReservation, CommitEvidence) {
        (
            MonitorAcceptance {
                transaction_id,
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
            },
            BudgetReservation {
                transaction_id,
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            },
            CommitEvidence {
                transaction_id,
                public_trace_digest: [4; 32],
                reservation_digest: [5; 32],
            },
        )
    }

    fn committed() -> (
        DurableCoordinator<MemoryStore>,
        MonitorAcceptance,
        BudgetReservation,
        CommitEvidence,
    ) {
        let mut coordinator =
            DurableCoordinator::new(bindings(), MemoryStore::default(), KEY, 16).unwrap();
        let (monitor, reservation, commit) = evidence(coordinator.transaction_id());
        coordinator.accept_monitor(monitor).unwrap();
        coordinator.reserve_budget(reservation).unwrap();
        coordinator.commit(commit).unwrap();
        (coordinator, monitor, reservation, commit)
    }

    #[test]
    fn live_permit_causes_one_effect_and_is_consumed() {
        let (mut coordinator, _, _, _) = committed();
        let mut sink = MemorySink::default();
        let receipt = deliver_once(&mut coordinator, &mut sink).unwrap();
        assert_eq!(receipt.outcome, DeliveryOutcome::Delivered);
        assert_eq!(receipt.public_trace_digest, [4; 32]);
        assert_eq!(sink.effects, 1);
        assert_eq!(
            deliver_once(&mut coordinator, &mut sink),
            Err(DeliveryError::NoPermit)
        );
    }

    #[test]
    fn lost_acknowledgement_is_reconciled_without_a_second_effect() {
        let (mut coordinator, monitor, reservation, commit) = committed();
        let mut sink = MemorySink {
            lose_next_acknowledgement: true,
            ..MemorySink::default()
        };
        assert_eq!(
            deliver_once(&mut coordinator, &mut sink),
            Err(DeliveryError::Sink(SinkError::Unavailable))
        );
        assert_eq!(sink.effects, 1);

        let recovered = DurableCoordinator::recover(
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
        let receipt = reconcile_committed(&recovered, &mut sink).unwrap();
        assert_eq!(receipt.outcome, DeliveryOutcome::AlreadyDelivered);
        assert_eq!(sink.effects, 1);
    }

    #[test]
    fn committed_recovery_can_complete_a_previously_undelivered_effect() {
        let (coordinator, monitor, reservation, commit) = committed();
        let recovered = DurableCoordinator::recover(
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
        let mut sink = MemorySink::default();
        assert_eq!(
            reconcile_committed(&recovered, &mut sink).unwrap().outcome,
            DeliveryOutcome::Delivered
        );
        assert_eq!(sink.effects, 1);
    }

    #[test]
    fn reconciliation_rejects_non_committed_state_and_conflicting_binding() {
        let prepared =
            DurableCoordinator::new(bindings(), MemoryStore::default(), KEY, 16).unwrap();
        let mut sink = MemorySink::default();
        assert_eq!(
            reconcile_committed(&prepared, &mut sink),
            Err(DeliveryError::NoCommittedDescriptor)
        );

        let (committed, _, _, _) = committed();
        let mut conflicting = committed.committed_descriptor().unwrap();
        conflicting.public_trace_digest = [8; 32];
        sink.accepted
            .insert(committed.transaction_id(), conflicting);
        assert_eq!(
            reconcile_committed(&committed, &mut sink),
            Err(DeliveryError::Sink(SinkError::BindingConflict))
        );
        assert_eq!(sink.effects, 0);
    }
}
