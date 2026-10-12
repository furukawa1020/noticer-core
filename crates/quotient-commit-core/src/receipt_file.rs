//! Fixed-record filesystem storage for receipt audit chains.

use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
use crate::receipt::SealedReceipt;
use crate::receipt_log::ReceiptLogRecord;
use crate::TransactionId;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const RECEIPT_FILE_RECORD_SIZE: usize = 208;
const MAGIC: [u8; 4] = *b"QCRL";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptFileError {
    IoFailure,
    LockUnavailable,
    MalformedRecord,
    ResourceLimit,
}

pub trait ReceiptStore {
    fn append_and_sync(&mut self, record: ReceiptLogRecord) -> Result<(), ReceiptFileError>;
    fn load(&self) -> Result<Vec<ReceiptLogRecord>, ReceiptFileError>;
}

#[derive(Debug)]
pub struct ReceiptFile {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_bytes: u64,
    _lock: File,
}

impl ReceiptFile {
    pub fn open(path: impl AsRef<Path>, maximum_bytes: u64) -> Result<Self, ReceiptFileError> {
        if maximum_bytes < RECEIPT_FILE_RECORD_SIZE as u64 {
            return Err(ReceiptFileError::ResourceLimit);
        }
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path(&path);
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| ReceiptFileError::LockUnavailable)?;
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_err()
        {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(ReceiptFileError::IoFailure);
        }
        let length = fs::metadata(&path)
            .map_err(|_| ReceiptFileError::IoFailure)?
            .len();
        if length > maximum_bytes {
            let _ = fs::remove_file(&lock_path);
            return Err(ReceiptFileError::ResourceLimit);
        }
        Ok(Self {
            path,
            lock_path,
            maximum_bytes,
            _lock: lock,
        })
    }
}

impl ReceiptStore for ReceiptFile {
    fn append_and_sync(&mut self, record: ReceiptLogRecord) -> Result<(), ReceiptFileError> {
        let current = fs::metadata(&self.path)
            .map_err(|_| ReceiptFileError::IoFailure)?
            .len();
        let next = current
            .checked_add(RECEIPT_FILE_RECORD_SIZE as u64)
            .ok_or(ReceiptFileError::ResourceLimit)?;
        if next > self.maximum_bytes {
            return Err(ReceiptFileError::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| ReceiptFileError::IoFailure)?;
        file.write_all(&encode(record))
            .map_err(|_| ReceiptFileError::IoFailure)?;
        file.sync_data().map_err(|_| ReceiptFileError::IoFailure)
    }

    fn load(&self) -> Result<Vec<ReceiptLogRecord>, ReceiptFileError> {
        let bytes = fs::read(&self.path).map_err(|_| ReceiptFileError::IoFailure)?;
        if bytes.len() as u64 > self.maximum_bytes {
            return Err(ReceiptFileError::ResourceLimit);
        }
        if bytes.len() % RECEIPT_FILE_RECORD_SIZE != 0 {
            return Err(ReceiptFileError::MalformedRecord);
        }
        bytes
            .chunks_exact(RECEIPT_FILE_RECORD_SIZE)
            .map(decode)
            .collect()
    }
}

impl Drop for ReceiptFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

fn encode(record: ReceiptLogRecord) -> [u8; RECEIPT_FILE_RECORD_SIZE] {
    let mut bytes = [0_u8; RECEIPT_FILE_RECORD_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[5] = match record.receipt.receipt.outcome {
        DeliveryOutcome::Delivered => 1,
        DeliveryOutcome::AlreadyDelivered => 2,
    };
    bytes[8..16].copy_from_slice(&record.sequence.to_be_bytes());
    bytes[16..48].copy_from_slice(&record.previous_authenticator);
    bytes[48..80].copy_from_slice(&record.receipt.receipt.transaction_id.0);
    bytes[80..112].copy_from_slice(&record.receipt.receipt.public_trace_digest);
    bytes[112..120].copy_from_slice(&record.receipt.receipt.release_sequence.to_be_bytes());
    bytes[120..128].copy_from_slice(&record.receipt.receipt.policy_epoch.to_be_bytes());
    bytes[128..136].copy_from_slice(&record.receipt.sink_epoch.to_be_bytes());
    bytes[136..168].copy_from_slice(&record.receipt.authenticator);
    bytes[168..200].copy_from_slice(&record.authenticator);
    bytes
}

fn decode(bytes: &[u8]) -> Result<ReceiptLogRecord, ReceiptFileError> {
    if bytes.len() != RECEIPT_FILE_RECORD_SIZE
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
        || bytes[200..208] != [0; 8]
    {
        return Err(ReceiptFileError::MalformedRecord);
    }
    let outcome = match bytes[5] {
        1 => DeliveryOutcome::Delivered,
        2 => DeliveryOutcome::AlreadyDelivered,
        _ => return Err(ReceiptFileError::MalformedRecord),
    };
    Ok(ReceiptLogRecord {
        sequence: u64::from_be_bytes(read_array(bytes, 8..16)?),
        previous_authenticator: read_array(bytes, 16..48)?,
        receipt: SealedReceipt {
            receipt: DeliveryReceipt {
                transaction_id: TransactionId(read_array(bytes, 48..80)?),
                public_trace_digest: read_array(bytes, 80..112)?,
                release_sequence: u64::from_be_bytes(read_array(bytes, 112..120)?),
                policy_epoch: u64::from_be_bytes(read_array(bytes, 120..128)?),
                outcome,
            },
            sink_epoch: u64::from_be_bytes(read_array(bytes, 128..136)?),
            authenticator: read_array(bytes, 136..168)?,
        },
        authenticator: read_array(bytes, 168..200)?,
    })
}

fn read_array<const N: usize>(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<[u8; N], ReceiptFileError> {
    bytes[range]
        .try_into()
        .map_err(|_| ReceiptFileError::MalformedRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::seal_receipt;
    use crate::receipt_log::ReceiptLog;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KEY: [u8; 32] = [7; 32];

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "quotient-receipts-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }

    fn record() -> ReceiptLogRecord {
        let receipt = seal_receipt(
            DeliveryReceipt {
                transaction_id: TransactionId([1; 32]),
                public_trace_digest: [2; 32],
                release_sequence: 3,
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            },
            5,
            KEY,
        )
        .unwrap();
        let mut log = ReceiptLog::new(KEY, 4).unwrap();
        log.append(receipt).unwrap()
    }

    #[test]
    fn restart_loads_a_chain_that_replays() {
        let path = temporary_path("restart");
        let mut file = ReceiptFile::open(&path, 4096).unwrap();
        file.append_and_sync(record()).unwrap();
        drop(file);
        let file = ReceiptFile::open(&path, 4096).unwrap();
        let records = file.load().unwrap();
        assert!(ReceiptLog::replay(records, KEY, 4).is_ok());
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn lock_truncation_tampering_and_capacity_fail_closed() {
        let path = temporary_path("failures");
        let mut file = ReceiptFile::open(&path, RECEIPT_FILE_RECORD_SIZE as u64).unwrap();
        assert_eq!(
            ReceiptFile::open(&path, 4096).unwrap_err(),
            ReceiptFileError::LockUnavailable
        );
        file.append_and_sync(record()).unwrap();
        assert_eq!(
            file.append_and_sync(record()),
            Err(ReceiptFileError::ResourceLimit)
        );
        drop(file);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[1])
            .unwrap();
        let file = ReceiptFile::open(&path, 4096).unwrap();
        assert_eq!(file.load(), Err(ReceiptFileError::MalformedRecord));
        drop(file);
        fs::remove_file(path).unwrap();
    }
}
