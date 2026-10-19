//! Restart-safe recovery of delivered receipts into the durable audit log.

use crate::audited_delivery::{reconcile_audit, AuditReconciliation, AuditReconciliationError};
use crate::delivery_outbox::{DeliveryOutbox, OutboxError, OutboxState, OutboxStore};
use crate::keyring::ReceiptKeyring;
use crate::receipt_coordinator::DurableReceiptLog;
use crate::receipt_file::ReceiptStore;
use crate::sealed_receipt_vault::{DurableSealedReceiptVault, SealedReceiptVaultStore};
use crate::TransactionId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditRecoveryOutcome {
    Recovered { already_recorded: bool },
    AlreadyCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditRecoveryError {
    UnknownTransaction,
    NotDelivered,
    MissingReceipt,
    BindingMismatch,
    Audit(AuditReconciliationError),
    Outbox(OutboxError),
}

pub fn recover_delivered_audit<O, V, A>(
    transaction_id: TransactionId,
    outbox: &mut DeliveryOutbox<O>,
    vault: &DurableSealedReceiptVault<V>,
    keyring: &ReceiptKeyring,
    audit: &mut DurableReceiptLog<A>,
) -> Result<AuditRecoveryOutcome, AuditRecoveryError>
where
    O: OutboxStore,
    V: SealedReceiptVaultStore,
    A: ReceiptStore,
{
    let (intent, state, receipt_authenticator) = outbox
        .status(transaction_id)
        .ok_or(AuditRecoveryError::UnknownTransaction)?;
    let receipt = vault
        .get(transaction_id)
        .ok_or(AuditRecoveryError::MissingReceipt)?;
    if receipt.receipt.transaction_id != intent.transaction_id
        || receipt.receipt.public_trace_digest != intent.public_trace_digest
        || receipt.receipt.release_sequence != intent.release_sequence
        || receipt.receipt.policy_epoch != intent.policy_epoch
        || receipt.sink_epoch != intent.receipt_epoch
        || receipt.authenticator != receipt_authenticator
    {
        return Err(AuditRecoveryError::BindingMismatch);
    }
    match state {
        OutboxState::Pending => Err(AuditRecoveryError::NotDelivered),
        OutboxState::Audited => Ok(AuditRecoveryOutcome::AlreadyCompleted),
        OutboxState::Delivered => {
            let reconciliation =
                reconcile_audit(receipt, keyring, audit).map_err(AuditRecoveryError::Audit)?;
            let already_recorded =
                matches!(reconciliation, AuditReconciliation::AlreadyRecorded(_));
            outbox
                .mark_audited(transaction_id, receipt.authenticator)
                .map_err(AuditRecoveryError::Outbox)?;
            Ok(AuditRecoveryOutcome::Recovered { already_recorded })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
    use crate::delivery_outbox::{DeliveryIntent, OutboxRecord};
    use crate::receipt::SealedReceipt;
    use crate::receipt_file::ReceiptFileError;
    use crate::receipt_log::ReceiptLogRecord;
    use crate::sealed_receipt_vault::{SealedReceiptRecord, SealedReceiptVaultError};

    const RECEIPT_KEY: [u8; 32] = [7; 32];
    const OUTBOX_KEY: [u8; 32] = [8; 32];
    const VAULT_KEY: [u8; 32] = [9; 32];
    const TRANSACTION: TransactionId = TransactionId([1; 32]);

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
    struct MemoryVaultStore {
        records: Vec<SealedReceiptRecord>,
    }

    impl SealedReceiptVaultStore for MemoryVaultStore {
        fn append_and_sync(
            &mut self,
            record: SealedReceiptRecord,
        ) -> Result<(), SealedReceiptVaultError> {
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<SealedReceiptRecord>, SealedReceiptVaultError> {
            Ok(self.records.clone())
        }
    }

    #[derive(Debug, Default)]
    struct MemoryReceiptStore {
        records: Vec<ReceiptLogRecord>,
        fail_next: bool,
    }

    impl ReceiptStore for MemoryReceiptStore {
        fn append_and_sync(&mut self, record: ReceiptLogRecord) -> Result<(), ReceiptFileError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(ReceiptFileError::IoFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<ReceiptLogRecord>, ReceiptFileError> {
            Ok(self.records.clone())
        }
    }

    fn keyring() -> ReceiptKeyring {
        let mut keyring = ReceiptKeyring::new();
        keyring.register(5, RECEIPT_KEY).unwrap();
        keyring.activate(5).unwrap();
        keyring
    }

    fn receipt(keyring: &ReceiptKeyring) -> SealedReceipt {
        keyring
            .seal(DeliveryReceipt {
                transaction_id: TRANSACTION,
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            })
            .unwrap()
    }

    fn fixture(
        fail_audited_sync: bool,
    ) -> (
        DeliveryOutbox<MemoryOutboxStore>,
        DurableSealedReceiptVault<MemoryVaultStore>,
        ReceiptKeyring,
    ) {
        let keyring = keyring();
        let receipt = receipt(&keyring);
        let store = MemoryOutboxStore {
            fail_on_append: fail_audited_sync.then_some(3),
            ..MemoryOutboxStore::default()
        };
        let mut outbox = DeliveryOutbox::open(store, OUTBOX_KEY, 8).unwrap();
        outbox
            .prepare(DeliveryIntent {
                transaction_id: TRANSACTION,
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                receipt_epoch: 5,
            })
            .unwrap();
        let delivered = outbox
            .mark_delivered(TRANSACTION, receipt.authenticator)
            .unwrap();
        let mut vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        vault.bind_delivered(delivered, receipt).unwrap();
        (outbox, vault, keyring)
    }

    #[test]
    fn delivered_receipt_reaches_audited_and_completed_retry_is_idempotent() {
        let (mut outbox, vault, keyring) = fixture(false);
        let mut audit =
            DurableReceiptLog::open(MemoryReceiptStore::default(), RECEIPT_KEY, 8).unwrap();
        assert!(matches!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit),
            Ok(AuditRecoveryOutcome::Recovered {
                already_recorded: false
            })
        ));
        assert_eq!(audit.records().len(), 1);
        assert_eq!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit),
            Ok(AuditRecoveryOutcome::AlreadyCompleted)
        );
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn audit_failure_leaves_delivered_for_retry() {
        let (mut outbox, vault, keyring) = fixture(false);
        let mut audit = DurableReceiptLog::open(
            MemoryReceiptStore {
                fail_next: true,
                ..MemoryReceiptStore::default()
            },
            RECEIPT_KEY,
            8,
        )
        .unwrap();
        assert!(matches!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit),
            Err(AuditRecoveryError::Audit(_))
        ));
        assert_eq!(
            outbox.status(TRANSACTION).unwrap().1,
            OutboxState::Delivered
        );
        assert!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit).is_ok()
        );
    }

    #[test]
    fn audited_sync_failure_reuses_existing_audit_record() {
        let (mut outbox, vault, keyring) = fixture(true);
        let mut audit =
            DurableReceiptLog::open(MemoryReceiptStore::default(), RECEIPT_KEY, 8).unwrap();
        assert!(matches!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit),
            Err(AuditRecoveryError::Outbox(OutboxError::IoFailure))
        ));
        assert_eq!(audit.records().len(), 1);
        assert!(matches!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit),
            Ok(AuditRecoveryOutcome::Recovered {
                already_recorded: true
            })
        ));
        assert_eq!(audit.records().len(), 1);
        assert_eq!(outbox.status(TRANSACTION).unwrap().1, OutboxState::Audited);
    }

    #[test]
    fn missing_receipt_and_pending_state_fail_without_audit() {
        let mut outbox = DeliveryOutbox::open(MemoryOutboxStore::default(), OUTBOX_KEY, 8).unwrap();
        outbox
            .prepare(DeliveryIntent {
                transaction_id: TRANSACTION,
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                receipt_epoch: 5,
            })
            .unwrap();
        let vault =
            DurableSealedReceiptVault::open(MemoryVaultStore::default(), VAULT_KEY, 8).unwrap();
        let keyring = keyring();
        let mut audit =
            DurableReceiptLog::open(MemoryReceiptStore::default(), RECEIPT_KEY, 8).unwrap();
        assert_eq!(
            recover_delivered_audit(TRANSACTION, &mut outbox, &vault, &keyring, &mut audit),
            Err(AuditRecoveryError::MissingReceipt)
        );
        assert!(audit.records().is_empty());
    }
}
