//! Live delivery ceremony with durable sealed-receipt handoff.

use crate::coordinator::DurableCoordinator;
use crate::delivery::{DeliveryReceipt, IdempotentSink, SinkError};
use crate::delivery_outbox::{DeliveryIntent, DeliveryOutbox, OutboxError, OutboxStore};
use crate::keyring::{KeyringError, ReceiptKeyring};
use crate::ledger::DurableStore;
use crate::receipt::SealedReceipt;
use crate::receipt_coordinator::{DurableReceiptLog, ReceiptCoordinatorError};
use crate::receipt_file::ReceiptStore;
use crate::receipt_log::ReceiptLogRecord;
use crate::sealed_receipt_vault::{
    DurableSealedReceiptVault, SealedReceiptVaultError, SealedReceiptVaultStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultedAuditedDelivery {
    pub receipt: SealedReceipt,
    pub audit_record: ReceiptLogRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultedDeliveryError {
    NotReady(KeyringError),
    NoPermit,
    OutboxBeforeDelivery(OutboxError),
    PendingSinkFailure(SinkError),
    DeliveredButUnsealed {
        receipt: DeliveryReceipt,
        cause: KeyringError,
    },
    DeliveredButUnvaulted {
        receipt: Box<SealedReceipt>,
        cause: SealedReceiptVaultError,
    },
    VaultedButOutboxPending {
        receipt: Box<SealedReceipt>,
        cause: OutboxError,
    },
    DeliveredButUnaudited {
        receipt: Box<SealedReceipt>,
        cause: ReceiptCoordinatorError,
    },
    AuditedButOutboxIncomplete {
        delivery: Box<VaultedAuditedDelivery>,
        cause: OutboxError,
    },
}

pub fn deliver_with_vault<C, K, O, V, A>(
    coordinator: &mut DurableCoordinator<C>,
    sink: &mut K,
    keyring: &ReceiptKeyring,
    outbox: &mut DeliveryOutbox<O>,
    vault: &mut DurableSealedReceiptVault<V>,
    audit: &mut DurableReceiptLog<A>,
) -> Result<VaultedAuditedDelivery, VaultedDeliveryError>
where
    C: DurableStore,
    K: IdempotentSink,
    O: OutboxStore,
    V: SealedReceiptVaultStore,
    A: ReceiptStore,
{
    let receipt_epoch = keyring
        .active_epoch()
        .ok_or(VaultedDeliveryError::NotReady(KeyringError::NoActiveEpoch))?;
    let descriptor = coordinator
        .pending_release_descriptor()
        .ok_or(VaultedDeliveryError::NoPermit)?;
    let pending = outbox
        .prepare(DeliveryIntent {
            transaction_id: descriptor.transaction_id,
            public_trace_digest: descriptor.public_trace_digest,
            release_sequence: descriptor.release_sequence,
            policy_epoch: descriptor.policy_epoch,
            receipt_epoch,
        })
        .map_err(VaultedDeliveryError::OutboxBeforeDelivery)?;
    let permit = coordinator
        .take_release_permit()
        .ok_or(VaultedDeliveryError::NoPermit)?;
    let outcome = sink
        .deliver_once(&permit)
        .map_err(VaultedDeliveryError::PendingSinkFailure)?;
    let receipt = DeliveryReceipt {
        transaction_id: permit.transaction_id,
        public_trace_digest: permit.public_trace_digest,
        release_sequence: permit.release_sequence,
        policy_epoch: permit.policy_epoch,
        outcome,
    };
    let sealed = keyring
        .seal(receipt)
        .map_err(|cause| VaultedDeliveryError::DeliveredButUnsealed { receipt, cause })?;
    vault.bind_pending(pending, sealed).map_err(|cause| {
        VaultedDeliveryError::DeliveredButUnvaulted {
            receipt: Box::new(sealed),
            cause,
        }
    })?;
    outbox
        .mark_delivered(permit.transaction_id, sealed.authenticator)
        .map_err(|cause| VaultedDeliveryError::VaultedButOutboxPending {
            receipt: Box::new(sealed),
            cause,
        })?;
    let audit_record =
        audit
            .append(sealed)
            .map_err(|cause| VaultedDeliveryError::DeliveredButUnaudited {
                receipt: Box::new(sealed),
                cause,
            })?;
    let delivery = VaultedAuditedDelivery {
        receipt: sealed,
        audit_record,
    };
    outbox
        .mark_audited(permit.transaction_id, sealed.authenticator)
        .map_err(|cause| VaultedDeliveryError::AuditedButOutboxIncomplete {
            delivery: Box::new(delivery),
            cause,
        })?;
    Ok(delivery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, SinkError};
    use crate::delivery_outbox::{OutboxRecord, OutboxState};
    use crate::ledger::MemoryStore;
    use crate::pending_recovery::recover_pending_delivery;
    use crate::receipt_file::ReceiptFileError;
    use crate::sealed_receipt_vault::SealedReceiptRecord;
    use crate::{
        BudgetReservation, CommitEvidence, MonitorAcceptance, ReleaseBindings, ReleasePermit,
        TransactionId,
    };
    use std::collections::BTreeMap;

    const TRANSACTION_KEY: [u8; 32] = [6; 32];
    const RECEIPT_KEY: [u8; 32] = [7; 32];
    const OUTBOX_KEY: [u8; 32] = [8; 32];
    const VAULT_KEY: [u8; 32] = [9; 32];

    #[derive(Default)]
    struct MemorySink {
        accepted: BTreeMap<TransactionId, ReleasePermit>,
        effects: usize,
        calls: usize,
    }

    impl IdempotentSink for MemorySink {
        fn deliver_once(&mut self, permit: &ReleasePermit) -> Result<DeliveryOutcome, SinkError> {
            self.calls += 1;
            if let Some(existing) = self.accepted.get(&permit.transaction_id) {
                return if existing == permit {
                    Ok(DeliveryOutcome::AlreadyDelivered)
                } else {
                    Err(SinkError::BindingConflict)
                };
            }
            self.accepted.insert(permit.transaction_id, *permit);
            self.effects += 1;
            Ok(DeliveryOutcome::Delivered)
        }
    }

    #[derive(Debug, Default)]
    struct MemoryOutboxStore {
        records: Vec<OutboxRecord>,
        count: usize,
        fail_on: Option<usize>,
    }

    impl OutboxStore for MemoryOutboxStore {
        fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError> {
            self.count += 1;
            if self.fail_on == Some(self.count) {
                self.fail_on = None;
                return Err(OutboxError::IoFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<OutboxRecord>, OutboxError> {
            Ok(self.records.clone())
        }
    }

    #[derive(Debug, Default)]
    struct MemoryVaultStore {
        records: Vec<SealedReceiptRecord>,
        fail_next: bool,
    }

    impl SealedReceiptVaultStore for MemoryVaultStore {
        fn append_and_sync(
            &mut self,
            record: SealedReceiptRecord,
        ) -> Result<(), SealedReceiptVaultError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(SealedReceiptVaultError::IoFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<SealedReceiptRecord>, SealedReceiptVaultError> {
            Ok(self.records.clone())
        }
    }

    #[derive(Debug, Default)]
    struct MemoryAuditStore(Vec<ReceiptLogRecord>);

    impl ReceiptStore for MemoryAuditStore {
        fn append_and_sync(&mut self, record: ReceiptLogRecord) -> Result<(), ReceiptFileError> {
            self.0.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<ReceiptLogRecord>, ReceiptFileError> {
            Ok(self.0.clone())
        }
    }

    fn committed() -> DurableCoordinator<MemoryStore> {
        let mut coordinator = DurableCoordinator::new(
            ReleaseBindings {
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
                profile_digest: [3; 32],
                public_trace_digest: [4; 32],
                release_sequence: 7,
                policy_epoch: 9,
            },
            MemoryStore::default(),
            TRANSACTION_KEY,
            16,
        )
        .unwrap();
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
                reservation_digest: [5; 32],
            })
            .unwrap();
        coordinator
            .commit(CommitEvidence {
                transaction_id,
                public_trace_digest: [4; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        coordinator
    }

    fn keyring() -> ReceiptKeyring {
        let mut keyring = ReceiptKeyring::new();
        keyring.register(5, RECEIPT_KEY).unwrap();
        keyring.activate(5).unwrap();
        keyring
    }

    #[test]
    fn live_delivery_reaches_vault_audit_and_terminal_outbox() {
        let mut coordinator = committed();
        let transaction_id = coordinator.transaction_id();
        let mut sink = MemorySink::default();
        let keyring = keyring();
        let mut outbox = DeliveryOutbox::open(MemoryOutboxStore::default(), OUTBOX_KEY, 8).unwrap();
        let mut vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        let mut audit =
            DurableReceiptLog::open(MemoryAuditStore::default(), RECEIPT_KEY, 8).unwrap();
        let delivery = deliver_with_vault(
            &mut coordinator,
            &mut sink,
            &keyring,
            &mut outbox,
            &mut vault,
            &mut audit,
        )
        .unwrap();
        assert_eq!(vault.get(transaction_id), Some(delivery.receipt));
        assert_eq!(
            outbox.status(transaction_id).unwrap().1,
            OutboxState::Audited
        );
        assert_eq!(audit.records().len(), 1);
        assert_eq!(sink.effects, 1);
    }

    #[test]
    fn delivered_sync_failure_hands_off_without_second_sink_call() {
        let mut coordinator = committed();
        let transaction_id = coordinator.transaction_id();
        let mut sink = MemorySink::default();
        let keyring = keyring();
        let mut outbox = DeliveryOutbox::open(
            MemoryOutboxStore {
                fail_on: Some(2),
                ..MemoryOutboxStore::default()
            },
            OUTBOX_KEY,
            8,
        )
        .unwrap();
        let mut vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        let mut audit =
            DurableReceiptLog::open(MemoryAuditStore::default(), RECEIPT_KEY, 8).unwrap();
        assert!(matches!(
            deliver_with_vault(
                &mut coordinator,
                &mut sink,
                &keyring,
                &mut outbox,
                &mut vault,
                &mut audit
            ),
            Err(VaultedDeliveryError::VaultedButOutboxPending { .. })
        ));
        assert_eq!(
            outbox.status(transaction_id).unwrap().1,
            OutboxState::Pending
        );
        recover_pending_delivery(&coordinator, &mut sink, &keyring, &mut outbox, &mut vault)
            .unwrap();
        assert_eq!(sink.calls, 1);
        assert_eq!(sink.effects, 1);
        assert_eq!(
            outbox.status(transaction_id).unwrap().1,
            OutboxState::Delivered
        );
    }
}
