//! Durable storage for sealed public delivery receipts awaiting audit.

use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
use crate::delivery_outbox::{OutboxRecord, OutboxState};
use crate::receipt::{hmac_sha256, SealedReceipt};
use crate::TransactionId;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DOMAIN: &[u8] = b"noticer.quotient-commit.sealed-receipt-vault.v1\0";
const MAGIC: [u8; 4] = *b"QCSV";
const VERSION: u8 = 1;
pub const SEALED_RECEIPT_RECORD_SIZE: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedReceiptRecord {
    pub receipt: SealedReceipt,
    pub outbox_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealedReceiptVaultError {
    InvalidKey,
    InvalidBinding,
    DuplicateConflict,
    AuthenticationFailed,
    MalformedRecord,
    IoFailure,
    LockUnavailable,
    ResourceLimit,
}

pub trait SealedReceiptVaultStore {
    fn append_and_sync(
        &mut self,
        record: SealedReceiptRecord,
    ) -> Result<(), SealedReceiptVaultError>;

    fn load(&self) -> Result<Vec<SealedReceiptRecord>, SealedReceiptVaultError>;
}

#[derive(Debug)]
pub struct DurableSealedReceiptVault<S> {
    store: S,
    key: [u8; 32],
    maximum_records: usize,
    receipts: BTreeMap<TransactionId, SealedReceiptRecord>,
}

impl<S: SealedReceiptVaultStore> DurableSealedReceiptVault<S> {
    pub fn open(
        store: S,
        key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, SealedReceiptVaultError> {
        if key == [0; 32] {
            return Err(SealedReceiptVaultError::InvalidKey);
        }
        if maximum_records == 0 {
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        let records = store.load()?;
        if records.len() > maximum_records {
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        let mut receipts = BTreeMap::new();
        for record in records {
            validate_record(record, key)?;
            let transaction_id = record.receipt.receipt.transaction_id;
            if receipts.insert(transaction_id, record).is_some() {
                return Err(SealedReceiptVaultError::DuplicateConflict);
            }
        }
        Ok(Self {
            store,
            key,
            maximum_records,
            receipts,
        })
    }

    pub fn bind_delivered(
        &mut self,
        outbox_record: OutboxRecord,
        receipt: SealedReceipt,
    ) -> Result<SealedReceiptRecord, SealedReceiptVaultError> {
        validate_binding(outbox_record, receipt)?;
        let transaction_id = receipt.receipt.transaction_id;
        if let Some(existing) = self.receipts.get(&transaction_id).copied() {
            if existing.receipt == receipt
                && existing.outbox_authenticator == outbox_record.authenticator
            {
                return Ok(existing);
            }
            return Err(SealedReceiptVaultError::DuplicateConflict);
        }
        if self.receipts.len() >= self.maximum_records {
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        let mut record = SealedReceiptRecord {
            receipt,
            outbox_authenticator: outbox_record.authenticator,
            authenticator: [0; 32],
        };
        record.authenticator = authenticate(record, self.key);
        self.store.append_and_sync(record)?;
        self.receipts.insert(transaction_id, record);
        Ok(record)
    }

    #[must_use]
    pub fn get(&self, transaction_id: TransactionId) -> Option<SealedReceipt> {
        self.receipts
            .get(&transaction_id)
            .map(|record| record.receipt)
    }
}

fn validate_binding(
    outbox_record: OutboxRecord,
    receipt: SealedReceipt,
) -> Result<(), SealedReceiptVaultError> {
    if outbox_record.state != OutboxState::Delivered
        || outbox_record.intent.transaction_id != receipt.receipt.transaction_id
        || outbox_record.intent.public_trace_digest != receipt.receipt.public_trace_digest
        || outbox_record.intent.release_sequence != receipt.receipt.release_sequence
        || outbox_record.intent.policy_epoch != receipt.receipt.policy_epoch
        || outbox_record.intent.receipt_epoch != receipt.sink_epoch
        || outbox_record.receipt_authenticator != receipt.authenticator
        || outbox_record.authenticator == [0; 32]
    {
        return Err(SealedReceiptVaultError::InvalidBinding);
    }
    Ok(())
}

fn validate_record(
    record: SealedReceiptRecord,
    key: [u8; 32],
) -> Result<(), SealedReceiptVaultError> {
    let receipt = record.receipt;
    if receipt.receipt.transaction_id.0 == [0; 32]
        || receipt.receipt.public_trace_digest == [0; 32]
        || receipt.receipt.policy_epoch == 0
        || receipt.sink_epoch == 0
        || receipt.authenticator == [0; 32]
        || record.outbox_authenticator == [0; 32]
    {
        return Err(SealedReceiptVaultError::MalformedRecord);
    }
    if record.authenticator != authenticate(record, key) {
        return Err(SealedReceiptVaultError::AuthenticationFailed);
    }
    Ok(())
}

fn authenticate(mut record: SealedReceiptRecord, key: [u8; 32]) -> [u8; 32] {
    record.authenticator = [0; 32];
    let mut message = Vec::with_capacity(DOMAIN.len() + SEALED_RECEIPT_RECORD_SIZE);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&encode(record));
    hmac_sha256(key, &message)
}

#[derive(Debug)]
pub struct FileSealedReceiptVault {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_bytes: u64,
    _lock: File,
}

impl FileSealedReceiptVault {
    pub fn open(
        path: impl AsRef<Path>,
        maximum_bytes: u64,
    ) -> Result<Self, SealedReceiptVaultError> {
        if maximum_bytes < SEALED_RECEIPT_RECORD_SIZE as u64 {
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path(&path);
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| SealedReceiptVaultError::LockUnavailable)?;
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_err()
        {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(SealedReceiptVaultError::IoFailure);
        }
        if fs::metadata(&path)
            .map_err(|_| SealedReceiptVaultError::IoFailure)?
            .len()
            > maximum_bytes
        {
            let _ = fs::remove_file(&lock_path);
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        Ok(Self {
            path,
            lock_path,
            maximum_bytes,
            _lock: lock,
        })
    }
}

impl SealedReceiptVaultStore for FileSealedReceiptVault {
    fn append_and_sync(
        &mut self,
        record: SealedReceiptRecord,
    ) -> Result<(), SealedReceiptVaultError> {
        let current = fs::metadata(&self.path)
            .map_err(|_| SealedReceiptVaultError::IoFailure)?
            .len();
        if current.saturating_add(SEALED_RECEIPT_RECORD_SIZE as u64) > self.maximum_bytes {
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| SealedReceiptVaultError::IoFailure)?;
        file.write_all(&encode(record))
            .map_err(|_| SealedReceiptVaultError::IoFailure)?;
        file.sync_data()
            .map_err(|_| SealedReceiptVaultError::IoFailure)
    }

    fn load(&self) -> Result<Vec<SealedReceiptRecord>, SealedReceiptVaultError> {
        let bytes = fs::read(&self.path).map_err(|_| SealedReceiptVaultError::IoFailure)?;
        if bytes.len() as u64 > self.maximum_bytes {
            return Err(SealedReceiptVaultError::ResourceLimit);
        }
        if bytes.len() % SEALED_RECEIPT_RECORD_SIZE != 0 {
            return Err(SealedReceiptVaultError::MalformedRecord);
        }
        bytes
            .chunks_exact(SEALED_RECEIPT_RECORD_SIZE)
            .map(decode)
            .collect()
    }
}

impl Drop for FileSealedReceiptVault {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

fn encode(record: SealedReceiptRecord) -> [u8; SEALED_RECEIPT_RECORD_SIZE] {
    let mut bytes = [0_u8; SEALED_RECEIPT_RECORD_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[5] = match record.receipt.receipt.outcome {
        DeliveryOutcome::Delivered => 1,
        DeliveryOutcome::AlreadyDelivered => 2,
    };
    bytes[8..40].copy_from_slice(&record.receipt.receipt.transaction_id.0);
    bytes[40..72].copy_from_slice(&record.receipt.receipt.public_trace_digest);
    bytes[72..80].copy_from_slice(&record.receipt.receipt.release_sequence.to_be_bytes());
    bytes[80..88].copy_from_slice(&record.receipt.receipt.policy_epoch.to_be_bytes());
    bytes[88..96].copy_from_slice(&record.receipt.sink_epoch.to_be_bytes());
    bytes[96..128].copy_from_slice(&record.receipt.authenticator);
    bytes[128..160].copy_from_slice(&record.outbox_authenticator);
    bytes[160..192].copy_from_slice(&record.authenticator);
    bytes
}

fn decode(bytes: &[u8]) -> Result<SealedReceiptRecord, SealedReceiptVaultError> {
    if bytes.len() != SEALED_RECEIPT_RECORD_SIZE
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
        || bytes[192..200] != [0; 8]
    {
        return Err(SealedReceiptVaultError::MalformedRecord);
    }
    let outcome = match bytes[5] {
        1 => DeliveryOutcome::Delivered,
        2 => DeliveryOutcome::AlreadyDelivered,
        _ => return Err(SealedReceiptVaultError::MalformedRecord),
    };
    Ok(SealedReceiptRecord {
        receipt: SealedReceipt {
            receipt: DeliveryReceipt {
                transaction_id: TransactionId(read_array(bytes, 8..40)?),
                public_trace_digest: read_array(bytes, 40..72)?,
                release_sequence: u64::from_be_bytes(read_array(bytes, 72..80)?),
                policy_epoch: u64::from_be_bytes(read_array(bytes, 80..88)?),
                outcome,
            },
            sink_epoch: u64::from_be_bytes(read_array(bytes, 88..96)?),
            authenticator: read_array(bytes, 96..128)?,
        },
        outbox_authenticator: read_array(bytes, 128..160)?,
        authenticator: read_array(bytes, 160..192)?,
    })
}

fn read_array<const N: usize>(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<[u8; N], SealedReceiptVaultError> {
    bytes[range]
        .try_into()
        .map_err(|_| SealedReceiptVaultError::MalformedRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_outbox::{DeliveryIntent, OutboxRecord};
    use crate::receipt::seal_receipt;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KEY: [u8; 32] = [7; 32];
    const RECEIPT_KEY: [u8; 32] = [8; 32];

    fn sealed() -> SealedReceipt {
        seal_receipt(
            DeliveryReceipt {
                transaction_id: TransactionId([1; 32]),
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            },
            5,
            RECEIPT_KEY,
        )
        .unwrap()
    }

    fn outbox(receipt: SealedReceipt) -> OutboxRecord {
        OutboxRecord {
            sequence: 2,
            intent: DeliveryIntent {
                transaction_id: receipt.receipt.transaction_id,
                public_trace_digest: receipt.receipt.public_trace_digest,
                release_sequence: receipt.receipt.release_sequence,
                policy_epoch: receipt.receipt.policy_epoch,
                receipt_epoch: receipt.sink_epoch,
            },
            state: OutboxState::Delivered,
            receipt_authenticator: receipt.authenticator,
            previous_authenticator: [6; 32],
            authenticator: [9; 32],
        }
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "quotient-sealed-vault-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn restart_recovers_exact_sealed_receipt() {
        let path = temporary_path("restart");
        let receipt = sealed();
        let mut vault = DurableSealedReceiptVault::open(
            FileSealedReceiptVault::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        vault.bind_delivered(outbox(receipt), receipt).unwrap();
        drop(vault);
        let vault = DurableSealedReceiptVault::open(
            FileSealedReceiptVault::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        assert_eq!(vault.get(receipt.receipt.transaction_id), Some(receipt));
        drop(vault);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn identical_retry_is_idempotent_and_substitution_is_rejected() {
        let path = temporary_path("idempotent");
        let receipt = sealed();
        let mut vault = DurableSealedReceiptVault::open(
            FileSealedReceiptVault::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        let first = vault.bind_delivered(outbox(receipt), receipt).unwrap();
        assert_eq!(vault.bind_delivered(outbox(receipt), receipt), Ok(first));
        let mut substituted = receipt;
        substituted.receipt.outcome = DeliveryOutcome::AlreadyDelivered;
        assert_eq!(
            vault.bind_delivered(outbox(substituted), substituted),
            Err(SealedReceiptVaultError::DuplicateConflict)
        );
        drop(vault);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cross_transaction_tampering_and_truncation_fail_closed() {
        let path = temporary_path("failures");
        let receipt = sealed();
        let mut wrong = outbox(receipt);
        wrong.intent.transaction_id = TransactionId([3; 32]);
        let mut vault = DurableSealedReceiptVault::open(
            FileSealedReceiptVault::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        assert_eq!(
            vault.bind_delivered(wrong, receipt),
            Err(SealedReceiptVaultError::InvalidBinding)
        );
        vault.bind_delivered(outbox(receipt), receipt).unwrap();
        drop(vault);
        let mut bytes = fs::read(&path).unwrap();
        bytes[40] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            DurableSealedReceiptVault::open(
                FileSealedReceiptVault::open(&path, 4096).unwrap(),
                KEY,
                8,
            )
            .unwrap_err(),
            SealedReceiptVaultError::AuthenticationFailed
        );
        fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(
            DurableSealedReceiptVault::open(
                FileSealedReceiptVault::open(&path, 4096).unwrap(),
                KEY,
                8,
            )
            .unwrap_err(),
            SealedReceiptVaultError::MalformedRecord
        );
        fs::remove_file(path).unwrap();
    }
}
