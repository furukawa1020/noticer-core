//! Integrated one-shot delivery, receipt sealing, and durable audit ceremony.

use crate::coordinator::DurableCoordinator;
use crate::delivery::{DeliveryReceipt, IdempotentSink, SinkError};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, IdempotentSink};
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
}
