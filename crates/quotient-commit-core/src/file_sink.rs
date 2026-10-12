//! Single-writer filesystem reference implementation of an idempotent sink.

use crate::delivery::{DeliveryOutcome, IdempotentSink, SinkError};
use crate::{ReleasePermit, TransactionId};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SINK_RECORD_SIZE: usize = 128;
const MAGIC: [u8; 4] = *b"QCSK";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSinkError {
    IoFailure,
    LockUnavailable,
    MalformedRecord,
    ResourceLimit,
    BindingConflict,
}

#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_bytes: u64,
    accepted: BTreeMap<TransactionId, ReleasePermit>,
    _lock: File,
}

impl FileSink {
    pub fn open(path: impl AsRef<Path>, maximum_bytes: u64) -> Result<Self, FileSinkError> {
        if maximum_bytes < SINK_RECORD_SIZE as u64 {
            return Err(FileSinkError::ResourceLimit);
        }
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path(&path);
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| FileSinkError::LockUnavailable)?;
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_err()
        {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(FileSinkError::IoFailure);
        }
        let result = Self::load(&path, maximum_bytes).map(|accepted| Self {
            path,
            lock_path: lock_path.clone(),
            maximum_bytes,
            accepted,
            _lock: lock,
        });
        if result.is_err() {
            let _ = fs::remove_file(&lock_path);
        }
        result
    }

    fn load(
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<BTreeMap<TransactionId, ReleasePermit>, FileSinkError> {
        let bytes = fs::read(path).map_err(|_| FileSinkError::IoFailure)?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(FileSinkError::ResourceLimit);
        }
        if bytes.len() % SINK_RECORD_SIZE != 0 {
            return Err(FileSinkError::MalformedRecord);
        }
        let mut accepted = BTreeMap::new();
        for bytes in bytes.chunks_exact(SINK_RECORD_SIZE) {
            let permit = decode(bytes)?;
            if let Some(existing) = accepted.insert(permit.transaction_id, permit) {
                if existing != permit {
                    return Err(FileSinkError::BindingConflict);
                }
            }
        }
        Ok(accepted)
    }
}

impl IdempotentSink for FileSink {
    fn deliver_once(&mut self, permit: &ReleasePermit) -> Result<DeliveryOutcome, SinkError> {
        if let Some(existing) = self.accepted.get(&permit.transaction_id) {
            return if existing == permit {
                Ok(DeliveryOutcome::AlreadyDelivered)
            } else {
                Err(SinkError::BindingConflict)
            };
        }
        let current = fs::metadata(&self.path)
            .map_err(|_| SinkError::Unavailable)?
            .len();
        let next = current
            .checked_add(SINK_RECORD_SIZE as u64)
            .ok_or(SinkError::Unavailable)?;
        if next > self.maximum_bytes {
            return Err(SinkError::Unavailable);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| SinkError::Unavailable)?;
        file.write_all(&encode(*permit))
            .map_err(|_| SinkError::Unavailable)?;
        file.sync_data().map_err(|_| SinkError::Unavailable)?;
        self.accepted.insert(permit.transaction_id, *permit);
        Ok(DeliveryOutcome::Delivered)
    }
}

impl Drop for FileSink {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

fn encode(permit: ReleasePermit) -> [u8; SINK_RECORD_SIZE] {
    let mut bytes = [0_u8; SINK_RECORD_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[8..40].copy_from_slice(&permit.transaction_id.0);
    bytes[40..72].copy_from_slice(&permit.public_trace_digest);
    bytes[72..104].copy_from_slice(&permit.reservation_digest);
    bytes[104..112].copy_from_slice(&permit.release_sequence.to_be_bytes());
    bytes[112..120].copy_from_slice(&permit.policy_epoch.to_be_bytes());
    bytes
}

fn decode(bytes: &[u8]) -> Result<ReleasePermit, FileSinkError> {
    if bytes.len() != SINK_RECORD_SIZE
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[5..8] != [0; 3]
        || bytes[120..128] != [0; 8]
    {
        return Err(FileSinkError::MalformedRecord);
    }
    Ok(ReleasePermit {
        transaction_id: TransactionId(
            bytes[8..40]
                .try_into()
                .map_err(|_| FileSinkError::MalformedRecord)?,
        ),
        public_trace_digest: bytes[40..72]
            .try_into()
            .map_err(|_| FileSinkError::MalformedRecord)?,
        reservation_digest: bytes[72..104]
            .try_into()
            .map_err(|_| FileSinkError::MalformedRecord)?,
        release_sequence: u64::from_be_bytes(
            bytes[104..112]
                .try_into()
                .map_err(|_| FileSinkError::MalformedRecord)?,
        ),
        policy_epoch: u64::from_be_bytes(
            bytes[112..120]
                .try_into()
                .map_err(|_| FileSinkError::MalformedRecord)?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "quotient-sink-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }

    fn permit() -> ReleasePermit {
        ReleasePermit {
            transaction_id: TransactionId([1; 32]),
            public_trace_digest: [2; 32],
            reservation_digest: [3; 32],
            release_sequence: 4,
            policy_epoch: 5,
        }
    }

    #[test]
    fn restart_deduplicates_identical_delivery() {
        let path = temporary_path("restart");
        let mut sink = FileSink::open(&path, 4096).unwrap();
        assert_eq!(sink.deliver_once(&permit()), Ok(DeliveryOutcome::Delivered));
        drop(sink);
        let mut recovered = FileSink::open(&path, 4096).unwrap();
        assert_eq!(
            recovered.deliver_once(&permit()),
            Ok(DeliveryOutcome::AlreadyDelivered)
        );
        drop(recovered);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn conflicting_binding_and_concurrent_writer_fail_closed() {
        let path = temporary_path("conflict");
        let mut sink = FileSink::open(&path, 4096).unwrap();
        sink.deliver_once(&permit()).unwrap();
        assert_eq!(
            FileSink::open(&path, 4096).unwrap_err(),
            FileSinkError::LockUnavailable
        );
        let mut conflict = permit();
        conflict.public_trace_digest = [9; 32];
        assert_eq!(
            sink.deliver_once(&conflict),
            Err(SinkError::BindingConflict)
        );
        drop(sink);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_truncated_and_oversized_files_are_rejected() {
        let path = temporary_path("malformed");
        fs::write(&path, [0x55]).unwrap();
        assert_eq!(
            FileSink::open(&path, 4096).unwrap_err(),
            FileSinkError::MalformedRecord
        );
        fs::write(&path, [0_u8; SINK_RECORD_SIZE * 2]).unwrap();
        assert_eq!(
            FileSink::open(&path, SINK_RECORD_SIZE as u64).unwrap_err(),
            FileSinkError::ResourceLimit
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn capacity_is_checked_before_append() {
        let path = temporary_path("capacity");
        let mut sink = FileSink::open(&path, SINK_RECORD_SIZE as u64).unwrap();
        sink.deliver_once(&permit()).unwrap();
        let mut second = permit();
        second.transaction_id = TransactionId([8; 32]);
        assert_eq!(sink.deliver_once(&second), Err(SinkError::Unavailable));
        drop(sink);
        fs::remove_file(path).unwrap();
    }
}
