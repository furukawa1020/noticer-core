//! Integrated one-shot delivery, receipt sealing, and durable audit ceremony.

use crate::coordinator::DurableCoordinator;
use crate::delivery::{DeliveryReceipt, IdempotentSink, SinkError};
use crate::delivery_outbox::{DeliveryIntent, DeliveryOutbox, OutboxError, OutboxStore};
use crate::keyring::{KeyringError, ReceiptKeyring};
use crate::ledger::DurableStore;
use crate::receipt::SealedReceipt;
use crate::receipt_coordinator::{DurableReceiptLog, ReceiptCoordinatorError};
use crate::receipt_file::ReceiptStore;
use crate::receipt_log::ReceiptLogRecord;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditedDelivery {
    pub receipt: SealedReceipt,
    pub audit_record: ReceiptLogRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditReconciliation {
    Recorded(ReceiptLogRecord),
    AlreadyRecorded(ReceiptLogRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditReconciliationError {
    InvalidReceipt,
    ConflictingReceipt,
    Audit(ReceiptCoordinatorError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditedDeliveryError {
    NotReady(KeyringError),
    NoPermit,
    Sink(SinkError),
    DeliveredButUnsealed {
        receipt: DeliveryReceipt,
        cause: KeyringError,
    },
    DeliveredButUnaudited {
        receipt: Box<SealedReceipt>,
        cause: ReceiptCoordinatorError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboxedDeliveryError {
    NotReady(KeyringError),
    NoPermit,
    OutboxBeforeDelivery(OutboxError),
    PendingSinkFailure(SinkError),
    DeliveredButOutboxPending {
        receipt: Box<SealedReceipt>,
        cause: OutboxError,
    },
    DeliveredButUnaudited {
        receipt: Box<SealedReceipt>,
        cause: ReceiptCoordinatorError,
    },
    AuditedButOutboxIncomplete {
        delivery: Box<AuditedDelivery>,
        cause: OutboxError,
    },
}

pub fn deliver_and_audit<C, K, A>(
    coordinator: &mut DurableCoordinator<C>,
    sink: &mut K,
    keyring: &ReceiptKeyring,
    audit: &mut DurableReceiptLog<A>,
) -> Result<AuditedDelivery, AuditedDeliveryError>
where
    C: DurableStore,
    K: IdempotentSink,
    A: ReceiptStore,
{
    if keyring.active_epoch().is_none() {
        return Err(AuditedDeliveryError::NotReady(KeyringError::NoActiveEpoch));
    }
    let permit = coordinator
        .take_release_permit()
        .ok_or(AuditedDeliveryError::NoPermit)?;
    let outcome = sink
        .deliver_once(&permit)
        .map_err(AuditedDeliveryError::Sink)?;
    let receipt = DeliveryReceipt {
        transaction_id: permit.transaction_id,
        public_trace_digest: permit.public_trace_digest,
        release_sequence: permit.release_sequence,
        policy_epoch: permit.policy_epoch,
        outcome,
    };
    let sealed = keyring
        .seal(receipt)
        .map_err(|cause| AuditedDeliveryError::DeliveredButUnsealed { receipt, cause })?;
    let audit_record =
        audit
            .append(sealed)
            .map_err(|cause| AuditedDeliveryError::DeliveredButUnaudited {
                receipt: Box::new(sealed),
                cause,
            })?;
    Ok(AuditedDelivery {
        receipt: sealed,
        audit_record,
    })
}

pub fn reconcile_audit<A: ReceiptStore>(
    receipt: SealedReceipt,
    keyring: &ReceiptKeyring,
    audit: &mut DurableReceiptLog<A>,
) -> Result<AuditReconciliation, AuditReconciliationError> {
    if !keyring.verify(&receipt) {
        return Err(AuditReconciliationError::InvalidReceipt);
    }
    for record in audit.records() {
        if record.receipt.authenticator == receipt.authenticator {
            return Ok(AuditReconciliation::AlreadyRecorded(*record));
        }
        if record.receipt.receipt.transaction_id == receipt.receipt.transaction_id {
            return Err(AuditReconciliationError::ConflictingReceipt);
        }
    }
    audit
        .append(receipt)
        .map(AuditReconciliation::Recorded)
        .map_err(AuditReconciliationError::Audit)
}

pub fn deliver_with_outbox<C, K, A, O>(
    coordinator: &mut DurableCoordinator<C>,
    sink: &mut K,
    keyring: &ReceiptKeyring,
    audit: &mut DurableReceiptLog<A>,
    outbox: &mut DeliveryOutbox<O>,
) -> Result<AuditedDelivery, OutboxedDeliveryError>
where
    C: DurableStore,
    K: IdempotentSink,
    A: ReceiptStore,
    O: OutboxStore,
{
    let receipt_epoch = keyring
        .active_epoch()
        .ok_or(OutboxedDeliveryError::NotReady(KeyringError::NoActiveEpoch))?;
    let descriptor = coordinator
        .pending_release_descriptor()
        .ok_or(OutboxedDeliveryError::NoPermit)?;
    outbox
        .prepare(DeliveryIntent {
            transaction_id: descriptor.transaction_id,
            public_trace_digest: descriptor.public_trace_digest,
            release_sequence: descriptor.release_sequence,
            policy_epoch: descriptor.policy_epoch,
            receipt_epoch,
        })
        .map_err(OutboxedDeliveryError::OutboxBeforeDelivery)?;
    let permit = coordinator
        .take_release_permit()
        .ok_or(OutboxedDeliveryError::NoPermit)?;
    let outcome = sink
        .deliver_once(&permit)
        .map_err(OutboxedDeliveryError::PendingSinkFailure)?;
    let receipt = DeliveryReceipt {
        transaction_id: permit.transaction_id,
        public_trace_digest: permit.public_trace_digest,
        release_sequence: permit.release_sequence,
        policy_epoch: permit.policy_epoch,
        outcome,
    };
    let sealed = keyring
        .seal(receipt)
        .map_err(OutboxedDeliveryError::NotReady)?;
    outbox
        .mark_delivered(permit.transaction_id, sealed.authenticator)
        .map_err(|cause| OutboxedDeliveryError::DeliveredButOutboxPending {
            receipt: Box::new(sealed),
            cause,
        })?;
    let audit_record =
        audit
            .append(sealed)
            .map_err(|cause| OutboxedDeliveryError::DeliveredButUnaudited {
                receipt: Box::new(sealed),
                cause,
            })?;
    let delivery = AuditedDelivery {
        receipt: sealed,
        audit_record,
    };
    outbox
        .mark_audited(permit.transaction_id, sealed.authenticator)
        .map_err(|cause| OutboxedDeliveryError::AuditedButOutboxIncomplete {
            delivery: Box::new(delivery),
            cause,
        })?;
    Ok(delivery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, IdempotentSink};
    use crate::delivery_outbox::{OutboxRecord, OutboxState};
    use crate::ledger::MemoryStore;
    use crate::receipt_file::ReceiptFileError;
    use crate::{
        BudgetReservation, CommitEvidence, MonitorAcceptance, ReleaseBindings, ReleasePermit,
    };

    const KEY: [u8; 32] = [7; 32];

    #[derive(Default)]
    struct MemorySink {
        effects: usize,
        fail: bool,
    }

    impl IdempotentSink for MemorySink {
        fn deliver_once(&mut self, _permit: &ReleasePermit) -> Result<DeliveryOutcome, SinkError> {
            if self.fail {
                return Err(SinkError::Unavailable);
            }
            self.effects += 1;
            Ok(DeliveryOutcome::Delivered)
        }
    }

    #[derive(Debug, Default)]
    struct MemoryAuditStore {
        records: Vec<ReceiptLogRecord>,
        fail: bool,
    }

    #[derive(Debug, Default)]
    struct MemoryOutboxStore {
        records: Vec<OutboxRecord>,
        fail_next: bool,
    }

    impl OutboxStore for MemoryOutboxStore {
        fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(OutboxError::IoFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<OutboxRecord>, OutboxError> {
            Ok(self.records.clone())
        }
    }

    impl ReceiptStore for MemoryAuditStore {
        fn append_and_sync(&mut self, record: ReceiptLogRecord) -> Result<(), ReceiptFileError> {
            if self.fail {
                return Err(ReceiptFileError::IoFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<ReceiptLogRecord>, ReceiptFileError> {
            Ok(self.records.clone())
        }
    }

    fn committed_coordinator() -> DurableCoordinator<MemoryStore> {
        let bindings = ReleaseBindings {
            certificate_digest: [1; 32],
            relation_digest: [2; 32],
            profile_digest: [3; 32],
            public_trace_digest: [4; 32],
            release_sequence: 5,
            policy_epoch: 6,
        };
        let mut coordinator =
            DurableCoordinator::new(bindings, MemoryStore::default(), [9; 32], 16).unwrap();
        let transaction_id = coordinator.transaction_id();
        coordinator
            .accept_monitor(MonitorAcceptance {
                transaction_id,
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
            })
            .unwrap();
        coordinator
            .reserve_budget(BudgetReservation {
                transaction_id,
                profile_digest: [3; 32],
                reservation_digest: [8; 32],
            })
            .unwrap();
        coordinator
            .commit(CommitEvidence {
                transaction_id,
                public_trace_digest: [4; 32],
                reservation_digest: [8; 32],
            })
            .unwrap();
        coordinator
    }

    fn keyring() -> ReceiptKeyring {
        let mut keyring = ReceiptKeyring::new();
        keyring.register(1, KEY).unwrap();
        keyring.activate(1).unwrap();
        keyring
    }

    #[test]
    fn successful_delivery_is_sealed_and_durably_audited() {
        let mut coordinator = committed_coordinator();
        let mut sink = MemorySink::default();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        let result =
            deliver_and_audit(&mut coordinator, &mut sink, &keyring(), &mut audit).unwrap();
        assert_eq!(sink.effects, 1);
        assert_eq!(audit.records().len(), 1);
        assert_eq!(result.audit_record.receipt, result.receipt);
        assert_eq!(
            deliver_and_audit(&mut coordinator, &mut sink, &keyring(), &mut audit),
            Err(AuditedDeliveryError::NoPermit)
        );
    }

    #[test]
    fn preflight_failure_does_not_consume_permit() {
        let mut coordinator = committed_coordinator();
        let mut sink = MemorySink::default();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        assert_eq!(
            deliver_and_audit(
                &mut coordinator,
                &mut sink,
                &ReceiptKeyring::new(),
                &mut audit
            ),
            Err(AuditedDeliveryError::NotReady(KeyringError::NoActiveEpoch))
        );
        assert!(deliver_and_audit(&mut coordinator, &mut sink, &keyring(), &mut audit).is_ok());
    }

    #[test]
    fn sink_and_post_delivery_audit_failures_remain_distinguishable() {
        let mut failed_sink = MemorySink {
            fail: true,
            effects: 0,
        };
        let mut coordinator = committed_coordinator();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        assert_eq!(
            deliver_and_audit(&mut coordinator, &mut failed_sink, &keyring(), &mut audit),
            Err(AuditedDeliveryError::Sink(SinkError::Unavailable))
        );
        assert!(audit.records().is_empty());

        let mut coordinator = committed_coordinator();
        let mut sink = MemorySink::default();
        let store = MemoryAuditStore {
            fail: true,
            records: Vec::new(),
        };
        let mut audit = DurableReceiptLog::open(store, KEY, 8).unwrap();
        let error =
            deliver_and_audit(&mut coordinator, &mut sink, &keyring(), &mut audit).unwrap_err();
        assert!(matches!(
            error,
            AuditedDeliveryError::DeliveredButUnaudited { .. }
        ));
        assert_eq!(sink.effects, 1);
        assert!(audit.records().is_empty());
    }

    #[test]
    fn unaudited_receipt_reconciliation_is_idempotent() {
        let keyring = keyring();
        let receipt = keyring
            .seal(DeliveryReceipt {
                transaction_id: crate::TransactionId([1; 32]),
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            })
            .unwrap();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        assert!(matches!(
            reconcile_audit(receipt, &keyring, &mut audit),
            Ok(AuditReconciliation::Recorded(_))
        ));
        assert!(matches!(
            reconcile_audit(receipt, &keyring, &mut audit),
            Ok(AuditReconciliation::AlreadyRecorded(_))
        ));
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn conflicting_invalid_and_store_failed_reconciliation_fail_closed() {
        let keyring = keyring();
        let original = keyring
            .seal(DeliveryReceipt {
                transaction_id: crate::TransactionId([1; 32]),
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            })
            .unwrap();
        let conflicting = keyring
            .seal(DeliveryReceipt {
                outcome: DeliveryOutcome::AlreadyDelivered,
                ..original.receipt
            })
            .unwrap();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        reconcile_audit(original, &keyring, &mut audit).unwrap();
        assert_eq!(
            reconcile_audit(conflicting, &keyring, &mut audit),
            Err(AuditReconciliationError::ConflictingReceipt)
        );

        let mut invalid = original;
        invalid.authenticator[0] ^= 1;
        assert_eq!(
            reconcile_audit(invalid, &keyring, &mut audit),
            Err(AuditReconciliationError::InvalidReceipt)
        );

        let mut failed = DurableReceiptLog::open(
            MemoryAuditStore {
                records: Vec::new(),
                fail: true,
            },
            KEY,
            8,
        )
        .unwrap();
        assert!(matches!(
            reconcile_audit(original, &keyring, &mut failed),
            Err(AuditReconciliationError::Audit(_))
        ));
        assert!(failed.records().is_empty());
    }

    #[test]
    fn outbox_ceremony_reaches_audited_terminal_state() {
        let mut coordinator = committed_coordinator();
        let mut sink = MemorySink::default();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        let mut outbox = DeliveryOutbox::open(MemoryOutboxStore::default(), [6; 32], 8).unwrap();
        let delivery = deliver_with_outbox(
            &mut coordinator,
            &mut sink,
            &keyring(),
            &mut audit,
            &mut outbox,
        )
        .unwrap();
        assert_eq!(sink.effects, 1);
        assert_eq!(audit.records().len(), 1);
        assert_eq!(delivery.receipt, audit.records()[0].receipt);
        assert!(outbox.recoverable().is_empty());
    }

    #[test]
    fn outbox_preflight_failure_preserves_permit_and_blocks_sink() {
        let mut coordinator = committed_coordinator();
        let mut sink = MemorySink::default();
        let mut audit = DurableReceiptLog::open(MemoryAuditStore::default(), KEY, 8).unwrap();
        let store = MemoryOutboxStore {
            fail_next: true,
            records: Vec::new(),
        };
        let mut outbox = DeliveryOutbox::open(store, [6; 32], 8).unwrap();
        assert_eq!(
            deliver_with_outbox(
                &mut coordinator,
                &mut sink,
                &keyring(),
                &mut audit,
                &mut outbox,
            ),
            Err(OutboxedDeliveryError::OutboxBeforeDelivery(
                OutboxError::IoFailure
            ))
        );
        assert_eq!(sink.effects, 0);
        assert!(deliver_and_audit(&mut coordinator, &mut sink, &keyring(), &mut audit).is_ok());
    }

    #[test]
    fn audit_failure_leaves_delivered_outbox_recoverable() {
        let mut coordinator = committed_coordinator();
        let mut sink = MemorySink::default();
        let mut audit = DurableReceiptLog::open(
            MemoryAuditStore {
                records: Vec::new(),
                fail: true,
            },
            KEY,
            8,
        )
        .unwrap();
        let mut outbox = DeliveryOutbox::open(MemoryOutboxStore::default(), [6; 32], 8).unwrap();
        assert!(matches!(
            deliver_with_outbox(
                &mut coordinator,
                &mut sink,
                &keyring(),
                &mut audit,
                &mut outbox,
            ),
            Err(OutboxedDeliveryError::DeliveredButUnaudited { .. })
        ));
        let recoverable = outbox.recoverable();
        assert_eq!(recoverable.len(), 1);
        assert_eq!(recoverable[0].1, OutboxState::Delivered);
    }
}
