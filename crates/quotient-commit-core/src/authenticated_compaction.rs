//! Authenticated, crash-safe compaction of completed delivery state.

use crate::delivery_outbox::{DeliveryIntent, OutboxRecord, OutboxState};
use crate::receipt::hmac_sha256;
use crate::sealed_receipt_vault::SealedReceiptRecord;
use std::collections::{BTreeMap, BTreeSet};

const CHECKPOINT_DOMAIN: &[u8] = b"noticer.quotient-commit.compaction-checkpoint.v1\0";
const BEFORE_DOMAIN: &[u8] = b"noticer.quotient-commit.compaction-before.v1\0";
const RETAINED_DOMAIN: &[u8] = b"noticer.quotient-commit.compaction-retained.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedTransaction {
    pub intent: DeliveryIntent,
    pub state: OutboxState,
    pub receipt_authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionCheckpoint {
    pub generation: u64,
    pub previous_checkpoint: [u8; 32],
    pub source_outbox_records: u64,
    pub source_vault_records: u64,
    pub retained_transactions: u64,
    pub retained_receipts: u64,
    pub removed_audited_transactions: u64,
    pub before_digest: [u8; 32],
    pub retained_digest: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionImage {
    pub transactions: Vec<RetainedTransaction>,
    pub receipts: Vec<SealedReceiptRecord>,
    pub checkpoint: CompactionCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionError {
    InvalidKey,
    InvalidGeneration,
    MalformedSource,
    DuplicateReceipt,
    OrphanReceipt,
    MissingReceipt,
    AuthenticationFailed,
    PreviousCheckpointMismatch,
    RollbackDetected,
    StoreFailure,
}

pub trait AtomicCompactionStore {
    /// Durably writes an inactive candidate without changing the active image.
    fn stage_and_sync(&mut self, image: CompactionImage) -> Result<(), CompactionError>;

    /// Atomically changes the active generation to the staged candidate.
    fn activate_and_sync(&mut self) -> Result<(), CompactionError>;

    fn active(&self) -> Option<&CompactionImage>;

    /// Removes an uncommitted candidate left by a crash.
    fn discard_staged(&mut self) -> Result<(), CompactionError>;
}

pub fn build_compaction_image(
    outbox: &[OutboxRecord],
    vault: &[SealedReceiptRecord],
    generation: u64,
    previous_checkpoint: [u8; 32],
    key: [u8; 32],
) -> Result<CompactionImage, CompactionError> {
    validate_parameters(generation, key)?;
    let mut latest = BTreeMap::new();
    for (index, record) in outbox.iter().enumerate() {
        if record.sequence != index as u64 + 1 {
            return Err(CompactionError::MalformedSource);
        }
        latest.insert(record.intent.transaction_id, *record);
    }

    let transactions: Vec<_> = latest
        .values()
        .filter(|record| record.state != OutboxState::Audited)
        .map(|record| RetainedTransaction {
            intent: record.intent,
            state: record.state,
            receipt_authenticator: record.receipt_authenticator,
        })
        .collect();
    let retained_ids: BTreeSet<_> = transactions
        .iter()
        .map(|record| record.intent.transaction_id)
        .collect();

    let mut receipt_ids = BTreeSet::new();
    let mut receipts = Vec::new();
    for record in vault {
        let transaction_id = record.receipt.receipt.transaction_id;
        let Some(outbox_record) = latest.get(&transaction_id) else {
            return Err(CompactionError::OrphanReceipt);
        };
        if outbox_record.state != OutboxState::Audited {
            if !receipt_ids.insert(transaction_id) {
                return Err(CompactionError::DuplicateReceipt);
            }
            receipts.push(*record);
        }
    }
    for transaction in &transactions {
        if transaction.state == OutboxState::Delivered
            && !receipt_ids.contains(&transaction.intent.transaction_id)
        {
            return Err(CompactionError::MissingReceipt);
        }
    }
    if !receipt_ids.is_subset(&retained_ids) {
        return Err(CompactionError::OrphanReceipt);
    }

    let before_digest = digest_source(outbox, vault, key);
    let retained_digest = digest_retained(&transactions, &receipts, key);
    let mut checkpoint = CompactionCheckpoint {
        generation,
        previous_checkpoint,
        source_outbox_records: outbox.len() as u64,
        source_vault_records: vault.len() as u64,
        retained_transactions: transactions.len() as u64,
        retained_receipts: receipts.len() as u64,
        removed_audited_transactions: (latest.len() - transactions.len()) as u64,
        before_digest,
        retained_digest,
        authenticator: [0; 32],
    };
    checkpoint.authenticator = authenticate_checkpoint(checkpoint, key);
    Ok(CompactionImage {
        transactions,
        receipts,
        checkpoint,
    })
}

pub fn verify_compaction_image(
    image: &CompactionImage,
    expected_previous: [u8; 32],
    minimum_generation: u64,
    key: [u8; 32],
) -> Result<(), CompactionError> {
    validate_parameters(image.checkpoint.generation, key)?;
    if image.checkpoint.generation < minimum_generation {
        return Err(CompactionError::RollbackDetected);
    }
    if image.checkpoint.previous_checkpoint != expected_previous {
        return Err(CompactionError::PreviousCheckpointMismatch);
    }
    if image.checkpoint.authenticator != authenticate_checkpoint(image.checkpoint, key) {
        return Err(CompactionError::AuthenticationFailed);
    }
    if image.checkpoint.retained_transactions != image.transactions.len() as u64
        || image.checkpoint.retained_receipts != image.receipts.len() as u64
        || image.checkpoint.retained_digest
            != digest_retained(&image.transactions, &image.receipts, key)
    {
        return Err(CompactionError::AuthenticationFailed);
    }
    Ok(())
}

pub fn install_compaction<S: AtomicCompactionStore>(
    store: &mut S,
    image: CompactionImage,
) -> Result<(), CompactionError> {
    store.stage_and_sync(image)?;
    store.activate_and_sync()
}

pub fn recover_compaction<S: AtomicCompactionStore>(
    store: &mut S,
    expected_previous: [u8; 32],
    minimum_generation: u64,
    key: [u8; 32],
) -> Result<Option<CompactionCheckpoint>, CompactionError> {
    store.discard_staged()?;
    let Some(active) = store.active() else {
        return Ok(None);
    };
    verify_compaction_image(active, expected_previous, minimum_generation, key)?;
    Ok(Some(active.checkpoint))
}

fn validate_parameters(generation: u64, key: [u8; 32]) -> Result<(), CompactionError> {
    if key == [0; 32] {
        return Err(CompactionError::InvalidKey);
    }
    if generation == 0 {
        return Err(CompactionError::InvalidGeneration);
    }
    Ok(())
}

fn digest_source(
    outbox: &[OutboxRecord],
    vault: &[SealedReceiptRecord],
    key: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(outbox.len() as u64).to_be_bytes());
    for record in outbox {
        bytes.extend_from_slice(&record.sequence.to_be_bytes());
        bytes.extend_from_slice(&record.authenticator);
    }
    bytes.extend_from_slice(&(vault.len() as u64).to_be_bytes());
    for record in vault {
        bytes.extend_from_slice(&record.receipt.receipt.transaction_id.0);
        bytes.extend_from_slice(&record.authenticator);
    }
    authenticate_bytes(BEFORE_DOMAIN, &bytes, key)
}

fn digest_retained(
    transactions: &[RetainedTransaction],
    receipts: &[SealedReceiptRecord],
    key: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(transactions.len() as u64).to_be_bytes());
    for record in transactions {
        bytes.extend_from_slice(&record.intent.transaction_id.0);
        bytes.extend_from_slice(&record.intent.public_trace_digest);
        bytes.extend_from_slice(&record.intent.release_sequence.to_be_bytes());
        bytes.extend_from_slice(&record.intent.policy_epoch.to_be_bytes());
        bytes.extend_from_slice(&record.intent.receipt_epoch.to_be_bytes());
        bytes.push(record.state as u8);
        bytes.extend_from_slice(&record.receipt_authenticator);
    }
    bytes.extend_from_slice(&(receipts.len() as u64).to_be_bytes());
    for record in receipts {
        bytes.extend_from_slice(&record.receipt.receipt.transaction_id.0);
        bytes.extend_from_slice(&record.authenticator);
    }
    authenticate_bytes(RETAINED_DOMAIN, &bytes, key)
}

fn authenticate_checkpoint(mut value: CompactionCheckpoint, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    bytes.extend_from_slice(&value.previous_checkpoint);
    bytes.extend_from_slice(&value.source_outbox_records.to_be_bytes());
    bytes.extend_from_slice(&value.source_vault_records.to_be_bytes());
    bytes.extend_from_slice(&value.retained_transactions.to_be_bytes());
    bytes.extend_from_slice(&value.retained_receipts.to_be_bytes());
    bytes.extend_from_slice(&value.removed_audited_transactions.to_be_bytes());
    bytes.extend_from_slice(&value.before_digest);
    bytes.extend_from_slice(&value.retained_digest);
    authenticate_bytes(CHECKPOINT_DOMAIN, &bytes, key)
}

fn authenticate_bytes(domain: &[u8], bytes: &[u8], key: [u8; 32]) -> [u8; 32] {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    hmac_sha256(key, &message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
    use crate::receipt::SealedReceipt;
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    #[derive(Default)]
    struct MemoryStore {
        active: Option<CompactionImage>,
        staged: Option<CompactionImage>,
    }

    impl AtomicCompactionStore for MemoryStore {
        fn stage_and_sync(&mut self, image: CompactionImage) -> Result<(), CompactionError> {
            self.staged = Some(image);
            Ok(())
        }

        fn activate_and_sync(&mut self) -> Result<(), CompactionError> {
            self.active = self.staged.take();
            Ok(())
        }

        fn active(&self) -> Option<&CompactionImage> {
            self.active.as_ref()
        }

        fn discard_staged(&mut self) -> Result<(), CompactionError> {
            self.staged = None;
            Ok(())
        }
    }

    fn intent(value: u8) -> DeliveryIntent {
        DeliveryIntent {
            transaction_id: TransactionId([value; 32]),
            public_trace_digest: [value + 10; 32],
            release_sequence: u64::from(value),
            policy_epoch: 4,
            receipt_epoch: 5,
        }
    }

    fn outbox(sequence: u64, value: u8, state: OutboxState) -> OutboxRecord {
        OutboxRecord {
            sequence,
            intent: intent(value),
            state,
            receipt_authenticator: if state == OutboxState::Pending {
                [0; 32]
            } else {
                [value + 20; 32]
            },
            previous_authenticator: [value + 30; 32],
            authenticator: [value + 40; 32],
        }
    }

    fn vault(value: u8) -> SealedReceiptRecord {
        SealedReceiptRecord {
            receipt: SealedReceipt {
                receipt: DeliveryReceipt {
                    transaction_id: TransactionId([value; 32]),
                    public_trace_digest: [value + 10; 32],
                    release_sequence: u64::from(value),
                    policy_epoch: 4,
                    outcome: DeliveryOutcome::Delivered,
                },
                sink_epoch: 5,
                authenticator: [value + 20; 32],
            },
            outbox_authenticator: [value + 40; 32],
            authenticator: [value + 50; 32],
        }
    }

    fn fixture() -> (Vec<OutboxRecord>, Vec<SealedReceiptRecord>) {
        (
            vec![
                outbox(1, 1, OutboxState::Pending),
                outbox(2, 1, OutboxState::Delivered),
                outbox(3, 1, OutboxState::Audited),
                outbox(4, 2, OutboxState::Pending),
                outbox(5, 3, OutboxState::Pending),
                outbox(6, 3, OutboxState::Delivered),
            ],
            vec![vault(1), vault(3)],
        )
    }

    #[test]
    fn only_audited_transactions_are_removed() {
        let (outbox, vault_records) = fixture();
        let image = build_compaction_image(&outbox, &vault_records, 1, [0; 32], KEY).unwrap();
        assert_eq!(image.checkpoint.removed_audited_transactions, 1);
        assert_eq!(image.transactions.len(), 2);
        assert!(image
            .transactions
            .iter()
            .any(|value| value.state == OutboxState::Pending));
        assert!(image
            .transactions
            .iter()
            .any(|value| value.state == OutboxState::Delivered));
        assert_eq!(image.receipts, vec![vault(3)]);
        assert_eq!(verify_compaction_image(&image, [0; 32], 1, KEY), Ok(()));
    }

    #[test]
    fn tampering_and_rollback_fail_closed() {
        let (outbox, vault) = fixture();
        let image = build_compaction_image(&outbox, &vault, 3, [9; 32], KEY).unwrap();
        assert_eq!(
            verify_compaction_image(&image, [9; 32], 4, KEY),
            Err(CompactionError::RollbackDetected)
        );
        let mut tampered = image;
        tampered.transactions[0].intent.policy_epoch += 1;
        assert_eq!(
            verify_compaction_image(&tampered, [9; 32], 3, KEY),
            Err(CompactionError::AuthenticationFailed)
        );
    }

    #[test]
    fn crash_before_activation_preserves_old_generation() {
        let (outbox, vault) = fixture();
        let first = build_compaction_image(&outbox, &vault, 1, [0; 32], KEY).unwrap();
        let mut store = MemoryStore::default();
        install_compaction(&mut store, first).unwrap();
        let first_authenticator = store.active().unwrap().checkpoint.authenticator;
        let second = build_compaction_image(&outbox, &vault, 2, first_authenticator, KEY).unwrap();
        store.stage_and_sync(second).unwrap();

        let recovered = recover_compaction(&mut store, [0; 32], 1, KEY)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, 1);
        assert!(store.staged.is_none());
    }

    #[test]
    fn missing_delivered_receipt_is_rejected() {
        let (outbox, _) = fixture();
        assert_eq!(
            build_compaction_image(&outbox, &[], 1, [0; 32], KEY),
            Err(CompactionError::MissingReceipt)
        );
    }
}
