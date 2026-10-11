use crate::ledger::{DurableStore, JournalRecord, RecordKind, StoreError};
use crate::TransactionId;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FILE_RECORD_SIZE: usize = 144;
const MAGIC: [u8; 4] = *b"QCJL";
const VERSION: u8 = 1;

#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_bytes: u64,
    _lock: File,
}

impl FileStore {
    pub fn open(path: impl AsRef<Path>, maximum_bytes: u64) -> Result<Self, StoreError> {
        if maximum_bytes < FILE_RECORD_SIZE as u64 {
            return Err(StoreError::ResourceLimit);
        }
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path(&path);
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| StoreError::LockUnavailable)?;
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_err()
        {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(StoreError::IoFailure);
        }
        let store = Self {
            path,
            lock_path,
            maximum_bytes,
            _lock: lock,
        };
        let length = fs::metadata(&store.path)
            .map_err(|_| StoreError::IoFailure)?
            .len();
        if length > maximum_bytes {
            return Err(StoreError::ResourceLimit);
        }
        Ok(store)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DurableStore for FileStore {
    fn append_and_sync(&mut self, record: JournalRecord) -> Result<(), StoreError> {
        let current = fs::metadata(&self.path)
            .map_err(|_| StoreError::IoFailure)?
            .len();
        let next = current
            .checked_add(FILE_RECORD_SIZE as u64)
            .ok_or(StoreError::ResourceLimit)?;
        if next > self.maximum_bytes {
            return Err(StoreError::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| StoreError::IoFailure)?;
        file.write_all(&encode(record))
            .map_err(|_| StoreError::IoFailure)?;
        file.sync_data().map_err(|_| StoreError::IoFailure)
    }

    fn load(&self) -> Result<Vec<JournalRecord>, StoreError> {
        let bytes = fs::read(&self.path).map_err(|_| StoreError::IoFailure)?;
        if bytes.len() as u64 > self.maximum_bytes {
            return Err(StoreError::ResourceLimit);
        }
        if bytes.len() % FILE_RECORD_SIZE != 0 {
            return Err(StoreError::MalformedRecord);
        }
        bytes.chunks_exact(FILE_RECORD_SIZE).map(decode).collect()
    }
}

impl Drop for FileStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

fn encode(record: JournalRecord) -> [u8; FILE_RECORD_SIZE] {
    let mut bytes = [0_u8; FILE_RECORD_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[5] = record.kind as u8;
    bytes[8..16].copy_from_slice(&record.sequence.to_be_bytes());
    bytes[16..48].copy_from_slice(&record.transaction_id.0);
    bytes[48..80].copy_from_slice(&record.evidence_digest);
    bytes[80..112].copy_from_slice(&record.previous_authenticator);
    bytes[112..144].copy_from_slice(&record.authenticator);
    bytes
}

fn decode(bytes: &[u8]) -> Result<JournalRecord, StoreError> {
    if bytes.len() != FILE_RECORD_SIZE
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
    {
        return Err(StoreError::MalformedRecord);
    }
    let kind = match bytes[5] {
        1 => RecordKind::Prepare,
        2 => RecordKind::MonitorAccept,
        3 => RecordKind::BudgetReserve,
        4 => RecordKind::Commit,
        5 => RecordKind::Reject,
        6 => RecordKind::Abort,
        _ => return Err(StoreError::MalformedRecord),
    };
    Ok(JournalRecord {
        sequence: u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| StoreError::MalformedRecord)?,
        ),
        transaction_id: TransactionId(
            bytes[16..48]
                .try_into()
                .map_err(|_| StoreError::MalformedRecord)?,
        ),
        kind,
        evidence_digest: bytes[48..80]
            .try_into()
            .map_err(|_| StoreError::MalformedRecord)?,
        previous_authenticator: bytes[80..112]
            .try_into()
            .map_err(|_| StoreError::MalformedRecord)?,
        authenticator: bytes[112..144]
            .try_into()
            .map_err(|_| StoreError::MalformedRecord)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{DurableJournal, JournalError};
    use std::time::{SystemTime, UNIX_EPOCH};

    const KEY: [u8; 32] = [9; 32];
    const TX: TransactionId = TransactionId([7; 32]);

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "quotient-commit-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn restart_replays_synced_records() {
        let path = temporary_path("restart");
        let store = FileStore::open(&path, 4096).unwrap();
        let mut journal = DurableJournal::new(store, KEY, 8).unwrap();
        journal.append(TX, RecordKind::Prepare, [1; 32]).unwrap();
        journal
            .append(TX, RecordKind::MonitorAccept, [2; 32])
            .unwrap();
        drop(journal);
        let recovered = DurableJournal::new(FileStore::open(&path, 4096).unwrap(), KEY, 8).unwrap();
        assert_eq!(
            recovered.state(TX),
            Some(crate::TransactionState::MonitorAccepted)
        );
        drop(recovered);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncated_tail_is_never_silently_discarded() {
        let path = temporary_path("truncated");
        let store = FileStore::open(&path, 4096).unwrap();
        let mut journal = DurableJournal::new(store, KEY, 8).unwrap();
        journal.append(TX, RecordKind::Prepare, [1; 32]).unwrap();
        drop(journal);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0x55])
            .unwrap();
        assert_eq!(
            DurableJournal::new(FileStore::open(&path, 4096).unwrap(), KEY, 8).unwrap_err(),
            JournalError::Store(StoreError::MalformedRecord)
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn authenticated_payload_tampering_fails_replay() {
        let path = temporary_path("tamper");
        let store = FileStore::open(&path, 4096).unwrap();
        let mut journal = DurableJournal::new(store, KEY, 8).unwrap();
        journal.append(TX, RecordKind::Prepare, [1; 32]).unwrap();
        drop(journal);
        let mut bytes = fs::read(&path).unwrap();
        bytes[48] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            DurableJournal::new(FileStore::open(&path, 4096).unwrap(), KEY, 8).unwrap_err(),
            JournalError::AuthenticationFailed
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_writer_and_capacity_excess_are_rejected() {
        let path = temporary_path("lock");
        let mut first = FileStore::open(&path, FILE_RECORD_SIZE as u64).unwrap();
        assert_eq!(
            FileStore::open(&path, 4096).unwrap_err(),
            StoreError::LockUnavailable
        );
        let record = JournalRecord {
            sequence: 1,
            transaction_id: TX,
            kind: RecordKind::Prepare,
            evidence_digest: [1; 32],
            previous_authenticator: [0; 32],
            authenticator: [2; 32],
        };
        first.append_and_sync(record).unwrap();
        assert_eq!(
            first.append_and_sync(record),
            Err(StoreError::ResourceLimit)
        );
        drop(first);
        fs::remove_file(path).unwrap();
    }
}
