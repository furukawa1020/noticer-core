//! Restart-safe reconciliation of pending public deliveries.

use crate::coordinator::DurableCoordinator;
use crate::delivery::{DeliveryReceipt, IdempotentSink, SinkError};
use crate::delivery_outbox::{DeliveryOutbox, OutboxError, OutboxState, OutboxStore};
use crate::keyring::{KeyringError, ReceiptKeyring};
use crate::ledger::DurableStore;
use crate::receipt::SealedReceipt;
use crate::sealed_receipt_vault::{
    DurableSealedReceiptVault, SealedReceiptVaultError, SealedReceiptVaultStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingRecoveryError {
    NoCommittedDescriptor,
    UnknownIntent,
    NotPending,
    NoActiveReceiptEpoch,
    BindingMismatch,
    InvalidVaultReceipt,
    Sink(SinkError),
    Keyring(KeyringError),
    Vault(SealedReceiptVaultError),
    Outbox(OutboxError),
}

pub fn recover_pending_delivery<C, K, O, V>(
    coordinator: &DurableCoordinator<C>,
    sink: &mut K,
    keyring: &ReceiptKeyring,
    outbox: &mut DeliveryOutbox<O>,
    vault: &mut DurableSealedReceiptVault<V>,
) -> Result<SealedReceipt, PendingRecoveryError>
where
    C: DurableStore,
    K: IdempotentSink,
    O: OutboxStore,
    V: SealedReceiptVaultStore,
{
    let permit = coordinator
        .committed_descriptor()
        .ok_or(PendingRecoveryError::NoCommittedDescriptor)?;
    let pending = outbox
        .latest_record(permit.transaction_id)
        .ok_or(PendingRecoveryError::UnknownIntent)?;
    if pending.state != OutboxState::Pending {
        return Err(PendingRecoveryError::NotPending);
    }
    let receipt_epoch = keyring
        .active_epoch()
        .ok_or(PendingRecoveryError::NoActiveReceiptEpoch)?;
    if pending.intent.public_trace_digest != permit.public_trace_digest
        || pending.intent.release_sequence != permit.release_sequence
        || pending.intent.policy_epoch != permit.policy_epoch
        || pending.intent.receipt_epoch != receipt_epoch
    {
        return Err(PendingRecoveryError::BindingMismatch);
    }

    if let Some(receipt) = vault.get(permit.transaction_id) {
        if !keyring.verify(&receipt) || !matches_receipt(receipt, pending.intent) {
            return Err(PendingRecoveryError::InvalidVaultReceipt);
        }
        outbox
            .mark_delivered(permit.transaction_id, receipt.authenticator)
            .map_err(PendingRecoveryError::Outbox)?;
        return Ok(receipt);
    }

    let outcome = sink
        .deliver_once(&permit)
        .map_err(PendingRecoveryError::Sink)?;
    let receipt = keyring
        .seal(DeliveryReceipt {
            transaction_id: permit.transaction_id,
            public_trace_digest: permit.public_trace_digest,
            release_sequence: permit.release_sequence,
            policy_epoch: permit.policy_epoch,
            outcome,
        })
        .map_err(PendingRecoveryError::Keyring)?;
    vault
        .bind_pending(pending, receipt)
        .map_err(PendingRecoveryError::Vault)?;
    outbox
        .mark_delivered(permit.transaction_id, receipt.authenticator)
        .map_err(PendingRecoveryError::Outbox)?;
    Ok(receipt)
}

fn matches_receipt(receipt: SealedReceipt, intent: crate::delivery_outbox::DeliveryIntent) -> bool {
    receipt.receipt.transaction_id == intent.transaction_id
        && receipt.receipt.public_trace_digest == intent.public_trace_digest
        && receipt.receipt.release_sequence == intent.release_sequence
        && receipt.receipt.policy_epoch == intent.policy_epoch
        && receipt.sink_epoch == intent.receipt_epoch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::DeliveryOutcome;
    use crate::delivery_outbox::{DeliveryIntent, OutboxRecord};
    use crate::ledger::MemoryStore;
    use crate::sealed_receipt_vault::{SealedReceiptRecord, SealedReceiptVaultStore};
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
        append_count: usize,
        fail_on_append: Option<usize>,
    }

    impl OutboxStore for MemoryOutboxStore {
        fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError> {
            self.append_count += 1;
            if self.fail_on_append == Some(self.append_count) {
                self.fail_on_append = None;
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
    struct MemoryVaultStore(Vec<SealedReceiptRecord>);

    impl SealedReceiptVaultStore for MemoryVaultStore {
        fn append_and_sync(
            &mut self,
            record: SealedReceiptRecord,
        ) -> Result<(), SealedReceiptVaultError> {
            self.0.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<SealedReceiptRecord>, SealedReceiptVaultError> {
            Ok(self.0.clone())
        }
    }

    fn committed() -> DurableCoordinator<MemoryStore> {
        let bindings = ReleaseBindings {
            certificate_digest: [1; 32],
            relation_digest: [2; 32],
            profile_digest: [3; 32],
            public_trace_digest: [4; 32],
            release_sequence: 7,
            policy_epoch: 9,
        };
        let mut coordinator =
            DurableCoordinator::new(bindings, MemoryStore::default(), TRANSACTION_KEY, 16).unwrap();
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

    fn outbox(
        coordinator: &DurableCoordinator<MemoryStore>,
        fail_delivered_sync: bool,
    ) -> DeliveryOutbox<MemoryOutboxStore> {
        let store = MemoryOutboxStore {
            fail_on_append: fail_delivered_sync.then_some(2),
            ..MemoryOutboxStore::default()
        };
        let mut outbox = DeliveryOutbox::open(store, OUTBOX_KEY, 8).unwrap();
        let permit = coordinator.committed_descriptor().unwrap();
        outbox
            .prepare(DeliveryIntent {
                transaction_id: permit.transaction_id,
                public_trace_digest: permit.public_trace_digest,
                release_sequence: permit.release_sequence,
                policy_epoch: permit.policy_epoch,
                receipt_epoch: 5,
            })
            .unwrap();
        outbox
    }

    #[test]
    fn pending_delivery_reaches_vault_and_delivered_state_once() {
        let coordinator = committed();
        let keyring = keyring();
        let mut outbox = outbox(&coordinator, false);
        let mut vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        let mut sink = MemorySink::default();
        let receipt =
            recover_pending_delivery(&coordinator, &mut sink, &keyring, &mut outbox, &mut vault)
                .unwrap();
        assert_eq!(sink.effects, 1);
        assert_eq!(sink.calls, 1);
        assert_eq!(vault.get(receipt.receipt.transaction_id), Some(receipt));
        assert_eq!(
            outbox.status(receipt.receipt.transaction_id).unwrap().1,
            OutboxState::Delivered
        );
    }

    #[test]
    fn delivered_sync_failure_retries_from_vault_without_sink_call() {
        let coordinator = committed();
        let keyring = keyring();
        let mut outbox = outbox(&coordinator, true);
        let mut vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        let mut sink = MemorySink::default();
        assert!(matches!(
            recover_pending_delivery(&coordinator, &mut sink, &keyring, &mut outbox, &mut vault),
            Err(PendingRecoveryError::Outbox(OutboxError::IoFailure))
        ));
        assert_eq!(sink.effects, 1);
        assert_eq!(sink.calls, 1);
        recover_pending_delivery(&coordinator, &mut sink, &keyring, &mut outbox, &mut vault)
            .unwrap();
        assert_eq!(sink.effects, 1);
        assert_eq!(sink.calls, 1);
    }

    #[test]
    fn mismatched_receipt_epoch_fails_before_sink() {
        let coordinator = committed();
        let keyring = keyring();
        let mut outbox = DeliveryOutbox::open(MemoryOutboxStore::default(), OUTBOX_KEY, 8).unwrap();
        let permit = coordinator.committed_descriptor().unwrap();
        outbox
            .prepare(DeliveryIntent {
                transaction_id: permit.transaction_id,
                public_trace_digest: permit.public_trace_digest,
                release_sequence: permit.release_sequence,
                policy_epoch: permit.policy_epoch,
                receipt_epoch: 6,
            })
            .unwrap();
        let mut vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        let mut sink = MemorySink::default();
        assert_eq!(
            recover_pending_delivery(&coordinator, &mut sink, &keyring, &mut outbox, &mut vault),
            Err(PendingRecoveryError::BindingMismatch)
        );
        assert_eq!(sink.calls, 0);
    }
}
