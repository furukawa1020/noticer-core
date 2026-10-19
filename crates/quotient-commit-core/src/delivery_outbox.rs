//! Authenticated durable outbox for public delivery intents.

use crate::receipt::hmac_sha256;
use crate::TransactionId;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DOMAIN: &[u8] = b"noticer.quotient-commit.delivery-outbox.v1\0";
pub const OUTBOX_RECORD_SIZE: usize = 208;
const MAGIC: [u8; 4] = *b"QCOB";
const VERSION: u8 = 1;
type IntentStatus = (DeliveryIntent, OutboxState, [u8; 32]);
type IntentStates = BTreeMap<TransactionId, IntentStatus>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryIntent {
    pub transaction_id: TransactionId,
    pub public_trace_digest: [u8; 32],
    pub release_sequence: u64,
    pub policy_epoch: u64,
    pub receipt_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OutboxState {
    Pending = 1,
    Delivered = 2,
    Audited = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxRecord {
    pub sequence: u64,
    pub intent: DeliveryIntent,
    pub state: OutboxState,
    pub receipt_authenticator: [u8; 32],
    pub previous_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxError {
    InvalidKey,
    InvalidIntent,
    DuplicateIntent,
    UnknownIntent,
    InvalidTransition,
    ReceiptMismatch,
    AuthenticationFailed,
    MalformedRecord,
    IoFailure,
    LockUnavailable,
    ResourceLimit,
}

pub trait OutboxStore {
    fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError>;
    fn load(&self) -> Result<Vec<OutboxRecord>, OutboxError>;
}

#[derive(Debug)]
pub struct DeliveryOutbox<S> {
    store: S,
    key: [u8; 32],
    maximum_records: usize,
    records: Vec<OutboxRecord>,
    states: IntentStates,
}

impl<S: OutboxStore> DeliveryOutbox<S> {
    pub fn open(store: S, key: [u8; 32], maximum_records: usize) -> Result<Self, OutboxError> {
        if key == [0; 32] {
            return Err(OutboxError::InvalidKey);
        }
        if maximum_records == 0 {
            return Err(OutboxError::ResourceLimit);
        }
        let records = store.load()?;
        if records.len() > maximum_records {
            return Err(OutboxError::ResourceLimit);
        }
        let states = replay(&records, key)?;
        Ok(Self {
            store,
            key,
            maximum_records,
            records,
            states,
        })
    }

    pub fn prepare(&mut self, intent: DeliveryIntent) -> Result<OutboxRecord, OutboxError> {
        validate_intent(intent)?;
        if self.states.contains_key(&intent.transaction_id) {
            return Err(OutboxError::DuplicateIntent);
        }
        self.append(intent, OutboxState::Pending, [0; 32])
    }

    pub fn mark_delivered(
        &mut self,
        transaction_id: TransactionId,
        receipt_authenticator: [u8; 32],
    ) -> Result<OutboxRecord, OutboxError> {
        if receipt_authenticator == [0; 32] {
            return Err(OutboxError::ReceiptMismatch);
        }
        let (intent, state, _) = self
            .states
            .get(&transaction_id)
            .copied()
            .ok_or(OutboxError::UnknownIntent)?;
        if state != OutboxState::Pending {
            return Err(OutboxError::InvalidTransition);
        }
        self.append(intent, OutboxState::Delivered, receipt_authenticator)
    }

    pub fn mark_audited(
        &mut self,
        transaction_id: TransactionId,
        receipt_authenticator: [u8; 32],
    ) -> Result<OutboxRecord, OutboxError> {
        let (intent, state, expected) = self
            .states
            .get(&transaction_id)
            .copied()
            .ok_or(OutboxError::UnknownIntent)?;
        if state != OutboxState::Delivered {
            return Err(OutboxError::InvalidTransition);
        }
        if receipt_authenticator == [0; 32] || receipt_authenticator != expected {
            return Err(OutboxError::ReceiptMismatch);
        }
        self.append(intent, OutboxState::Audited, receipt_authenticator)
    }

    #[must_use]
    pub fn recoverable(&self) -> Vec<(DeliveryIntent, OutboxState, [u8; 32])> {
        self.states
            .values()
            .filter(|(_, state, _)| *state != OutboxState::Audited)
            .copied()
            .collect()
    }

    fn append(
        &mut self,
        intent: DeliveryIntent,
        state: OutboxState,
        receipt_authenticator: [u8; 32],
    ) -> Result<OutboxRecord, OutboxError> {
        if self.records.len() >= self.maximum_records {
            return Err(OutboxError::ResourceLimit);
        }
        let sequence = self.records.len() as u64 + 1;
        let previous_authenticator = self
            .records
            .last()
            .map_or([0; 32], |record| record.authenticator);
        let mut record = OutboxRecord {
            sequence,
            intent,
            state,
            receipt_authenticator,
            previous_authenticator,
            authenticator: [0; 32],
        };
        record.authenticator = authenticate(record, self.key);
        self.store.append_and_sync(record)?;
        self.records.push(record);
        self.states.insert(
            intent.transaction_id,
            (intent, state, receipt_authenticator),
        );
        Ok(record)
    }
}

fn replay(records: &[OutboxRecord], key: [u8; 32]) -> Result<IntentStates, OutboxError> {
    let mut states = BTreeMap::new();
    let mut previous = [0; 32];
    for (index, record) in records.iter().enumerate() {
        if record.sequence != index as u64 + 1 || record.previous_authenticator != previous {
            return Err(OutboxError::MalformedRecord);
        }
        validate_intent(record.intent)?;
        if record.authenticator != authenticate(*record, key) {
            return Err(OutboxError::AuthenticationFailed);
        }
        match states.get(&record.intent.transaction_id).copied() {
            None if record.state == OutboxState::Pending
                && record.receipt_authenticator == [0; 32] => {}
            Some((intent, OutboxState::Pending, _))
                if intent == record.intent
                    && record.state == OutboxState::Delivered
                    && record.receipt_authenticator != [0; 32] => {}
            Some((intent, OutboxState::Delivered, receipt))
                if intent == record.intent
                    && record.state == OutboxState::Audited
                    && record.receipt_authenticator == receipt => {}
            _ => return Err(OutboxError::InvalidTransition),
        }
        states.insert(
            record.intent.transaction_id,
            (record.intent, record.state, record.receipt_authenticator),
        );
        previous = record.authenticator;
    }
    Ok(states)
}

fn validate_intent(intent: DeliveryIntent) -> Result<(), OutboxError> {
    if intent.transaction_id.0 == [0; 32]
        || intent.public_trace_digest == [0; 32]
        || intent.policy_epoch == 0
        || intent.receipt_epoch == 0
    {
        return Err(OutboxError::InvalidIntent);
    }
    Ok(())
}

fn authenticate(mut record: OutboxRecord, key: [u8; 32]) -> [u8; 32] {
    record.authenticator = [0; 32];
    let mut message = Vec::with_capacity(DOMAIN.len() + OUTBOX_RECORD_SIZE);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&encode(record));
    hmac_sha256(key, &message)
}

#[derive(Debug)]
pub struct FileOutbox {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_bytes: u64,
    _lock: File,
}

impl FileOutbox {
    pub fn open(path: impl AsRef<Path>, maximum_bytes: u64) -> Result<Self, OutboxError> {
        if maximum_bytes < OUTBOX_RECORD_SIZE as u64 {
            return Err(OutboxError::ResourceLimit);
        }
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path(&path);
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| OutboxError::LockUnavailable)?;
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_err()
        {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(OutboxError::IoFailure);
        }
        if fs::metadata(&path)
            .map_err(|_| OutboxError::IoFailure)?
            .len()
            > maximum_bytes
        {
            let _ = fs::remove_file(&lock_path);
            return Err(OutboxError::ResourceLimit);
        }
        Ok(Self {
            path,
            lock_path,
            maximum_bytes,
            _lock: lock,
        })
    }
}

impl OutboxStore for FileOutbox {
    fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError> {
        let current = fs::metadata(&self.path)
            .map_err(|_| OutboxError::IoFailure)?
            .len();
        if current.saturating_add(OUTBOX_RECORD_SIZE as u64) > self.maximum_bytes {
            return Err(OutboxError::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| OutboxError::IoFailure)?;
        file.write_all(&encode(record))
            .map_err(|_| OutboxError::IoFailure)?;
        file.sync_data().map_err(|_| OutboxError::IoFailure)
    }

    fn load(&self) -> Result<Vec<OutboxRecord>, OutboxError> {
        let bytes = fs::read(&self.path).map_err(|_| OutboxError::IoFailure)?;
        if bytes.len() as u64 > self.maximum_bytes {
            return Err(OutboxError::ResourceLimit);
        }
        if bytes.len() % OUTBOX_RECORD_SIZE != 0 {
            return Err(OutboxError::MalformedRecord);
        }
        bytes.chunks_exact(OUTBOX_RECORD_SIZE).map(decode).collect()
    }
}

impl Drop for FileOutbox {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

fn encode(record: OutboxRecord) -> [u8; OUTBOX_RECORD_SIZE] {
    let mut bytes = [0_u8; OUTBOX_RECORD_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[5] = record.state as u8;
    bytes[8..16].copy_from_slice(&record.sequence.to_be_bytes());
    bytes[16..48].copy_from_slice(&record.intent.transaction_id.0);
    bytes[48..80].copy_from_slice(&record.intent.public_trace_digest);
    bytes[80..88].copy_from_slice(&record.intent.release_sequence.to_be_bytes());
    bytes[88..96].copy_from_slice(&record.intent.policy_epoch.to_be_bytes());
    bytes[96..104].copy_from_slice(&record.intent.receipt_epoch.to_be_bytes());
    bytes[104..136].copy_from_slice(&record.receipt_authenticator);
    bytes[136..168].copy_from_slice(&record.previous_authenticator);
    bytes[168..200].copy_from_slice(&record.authenticator);
    bytes
}

fn decode(bytes: &[u8]) -> Result<OutboxRecord, OutboxError> {
    if bytes.len() != OUTBOX_RECORD_SIZE
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
        || bytes[200..208] != [0; 8]
    {
        return Err(OutboxError::MalformedRecord);
    }
    let state = match bytes[5] {
        1 => OutboxState::Pending,
        2 => OutboxState::Delivered,
        3 => OutboxState::Audited,
        _ => return Err(OutboxError::MalformedRecord),
    };
    Ok(OutboxRecord {
        sequence: u64::from_be_bytes(read_array(bytes, 8..16)?),
        intent: DeliveryIntent {
            transaction_id: TransactionId(read_array(bytes, 16..48)?),
            public_trace_digest: read_array(bytes, 48..80)?,
            release_sequence: u64::from_be_bytes(read_array(bytes, 80..88)?),
            policy_epoch: u64::from_be_bytes(read_array(bytes, 88..96)?),
            receipt_epoch: u64::from_be_bytes(read_array(bytes, 96..104)?),
        },
        state,
        receipt_authenticator: read_array(bytes, 104..136)?,
        previous_authenticator: read_array(bytes, 136..168)?,
        authenticator: read_array(bytes, 168..200)?,
    })
}

fn read_array<const N: usize>(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<[u8; N], OutboxError> {
    bytes[range]
        .try_into()
        .map_err(|_| OutboxError::MalformedRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    const KEY: [u8; 32] = [7; 32];
    fn intent() -> DeliveryIntent {
        DeliveryIntent {
            transaction_id: TransactionId([1; 32]),
            public_trace_digest: [2; 32],
            release_sequence: 3,
            policy_epoch: 4,
            receipt_epoch: 5,
        }
    }
    fn temporary_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "quotient-outbox-{}-{nonce}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn restart_recovers_pending_and_delivered_intents() {
        let path = temporary_path();
        let mut outbox =
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap();
        outbox.prepare(intent()).unwrap();
        drop(outbox);
        let mut recovered =
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap();
        assert_eq!(recovered.recoverable()[0].1, OutboxState::Pending);
        recovered
            .mark_delivered(intent().transaction_id, [8; 32])
            .unwrap();
        drop(recovered);
        let recovered =
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap();
        assert_eq!(recovered.recoverable()[0].1, OutboxState::Delivered);
        drop(recovered);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn transition_replay_and_receipt_substitution_fail_closed() {
        let path = temporary_path();
        let mut outbox =
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap();
        outbox.prepare(intent()).unwrap();
        assert_eq!(outbox.prepare(intent()), Err(OutboxError::DuplicateIntent));
        outbox
            .mark_delivered(intent().transaction_id, [8; 32])
            .unwrap();
        assert_eq!(
            outbox.mark_delivered(intent().transaction_id, [8; 32]),
            Err(OutboxError::InvalidTransition)
        );
        assert_eq!(
            outbox.mark_audited(intent().transaction_id, [9; 32]),
            Err(OutboxError::ReceiptMismatch)
        );
        outbox
            .mark_audited(intent().transaction_id, [8; 32])
            .unwrap();
        assert!(outbox.recoverable().is_empty());
        drop(outbox);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn tampering_and_truncation_are_rejected_on_restart() {
        let path = temporary_path();
        let mut outbox =
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap();
        outbox.prepare(intent()).unwrap();
        drop(outbox);
        let mut bytes = fs::read(&path).unwrap();
        bytes[48] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap_err(),
            OutboxError::AuthenticationFailed
        );
        fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(
            DeliveryOutbox::open(FileOutbox::open(&path, 4096).unwrap(), KEY, 8).unwrap_err(),
            OutboxError::MalformedRecord
        );
        fs::remove_file(path).unwrap();
    }
}
