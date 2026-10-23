//! Fixed-length durable file backend for rollback anchors.

use crate::rollback_anchor::{
    RollbackAnchorError, RollbackAnchorRecord, RollbackAnchorStore, StoreHeads,
};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: [u8; 4] = *b"QCRA";
const VERSION: u8 = 1;
pub const ROLLBACK_ANCHOR_RECORD_SIZE: usize = 176;

#[derive(Debug)]
pub struct FileRollbackAnchorStore {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_bytes: u64,
    _lock: File,
}

impl FileRollbackAnchorStore {
    pub fn open(path: impl AsRef<Path>, maximum_bytes: u64) -> Result<Self, RollbackAnchorError> {
        if maximum_bytes < ROLLBACK_ANCHOR_RECORD_SIZE as u64 {
            return Err(RollbackAnchorError::ResourceLimit);
        }
        let path = path.as_ref().to_path_buf();
        let lock_path = lock_path(&path);
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| RollbackAnchorError::StoreFailure)?;
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_err()
        {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(RollbackAnchorError::StoreFailure);
        }
        let length = fs::metadata(&path)
            .map_err(|_| RollbackAnchorError::StoreFailure)?
            .len();
        if length > maximum_bytes {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(RollbackAnchorError::ResourceLimit);
        }
        Ok(Self {
            path,
            lock_path,
            maximum_bytes,
            _lock: lock,
        })
    }
}

impl RollbackAnchorStore for FileRollbackAnchorStore {
    fn append_and_sync(&mut self, record: RollbackAnchorRecord) -> Result<(), RollbackAnchorError> {
        let current = fs::metadata(&self.path)
            .map_err(|_| RollbackAnchorError::StoreFailure)?
            .len();
        if current.saturating_add(ROLLBACK_ANCHOR_RECORD_SIZE as u64) > self.maximum_bytes {
            return Err(RollbackAnchorError::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| RollbackAnchorError::StoreFailure)?;
        file.write_all(&encode(record))
            .map_err(|_| RollbackAnchorError::StoreFailure)?;
        file.sync_data()
            .map_err(|_| RollbackAnchorError::StoreFailure)
    }

    fn load(&self) -> Result<Vec<RollbackAnchorRecord>, RollbackAnchorError> {
        let bytes = fs::read(&self.path).map_err(|_| RollbackAnchorError::StoreFailure)?;
        if bytes.len() as u64 > self.maximum_bytes {
            return Err(RollbackAnchorError::ResourceLimit);
        }
        if bytes.len() % ROLLBACK_ANCHOR_RECORD_SIZE != 0 {
            return Err(RollbackAnchorError::StoreFailure);
        }
        bytes
            .chunks_exact(ROLLBACK_ANCHOR_RECORD_SIZE)
            .map(decode)
            .collect()
    }
}

impl Drop for FileRollbackAnchorStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

fn encode(record: RollbackAnchorRecord) -> [u8; ROLLBACK_ANCHOR_RECORD_SIZE] {
    let mut bytes = [0; ROLLBACK_ANCHOR_RECORD_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[8..16].copy_from_slice(&record.generation.to_be_bytes());
    bytes[16..48].copy_from_slice(&record.heads.outbox);
    bytes[48..80].copy_from_slice(&record.heads.vault);
    bytes[80..112].copy_from_slice(&record.heads.audit);
    bytes[112..144].copy_from_slice(&record.previous_authenticator);
    bytes[144..176].copy_from_slice(&record.authenticator);
    bytes
}

fn decode(bytes: &[u8]) -> Result<RollbackAnchorRecord, RollbackAnchorError> {
    if bytes.len() != ROLLBACK_ANCHOR_RECORD_SIZE
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[5..8] != [0; 3]
    {
        return Err(RollbackAnchorError::StoreFailure);
    }
    Ok(RollbackAnchorRecord {
        generation: u64::from_be_bytes(read(bytes, 8..16)?),
        heads: StoreHeads {
            outbox: read(bytes, 16..48)?,
            vault: read(bytes, 48..80)?,
            audit: read(bytes, 80..112)?,
        },
        previous_authenticator: read(bytes, 112..144)?,
        authenticator: read(bytes, 144..176)?,
    })
}

fn read<const N: usize>(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<[u8; N], RollbackAnchorError> {
    bytes[range]
        .try_into()
        .map_err(|_| RollbackAnchorError::StoreFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback_anchor::DurableRollbackAnchor;
    use std::time::{SystemTime, UNIX_EPOCH};
    const KEY: [u8; 32] = [7; 32];

    fn path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "quotient-anchor-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }
    fn heads(value: u8) -> StoreHeads {
        StoreHeads {
            outbox: [value; 32],
            vault: [value + 1; 32],
            audit: [value + 2; 32],
        }
    }

    #[test]
    fn restart_recovers_authenticated_head() {
        let path = path("restart");
        let mut anchor = DurableRollbackAnchor::open(
            FileRollbackAnchorStore::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        let expected = anchor.advance(heads(1)).unwrap();
        drop(anchor);
        let recovered = DurableRollbackAnchor::open(
            FileRollbackAnchorStore::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        assert_eq!(recovered.head(), Some(expected));
        drop(recovered);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncation_and_tampering_fail_closed() {
        let path = path("failure");
        let mut anchor = DurableRollbackAnchor::open(
            FileRollbackAnchorStore::open(&path, 4096).unwrap(),
            KEY,
            8,
        )
        .unwrap();
        anchor.advance(heads(1)).unwrap();
        drop(anchor);
        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(DurableRollbackAnchor::open(
            FileRollbackAnchorStore::open(&path, 4096).unwrap(),
            KEY,
            8
        )
        .is_err());
        fs::write(&path, &original).unwrap();
        let mut changed = original;
        changed[16] ^= 1;
        fs::write(&path, changed).unwrap();
        assert_eq!(
            DurableRollbackAnchor::open(
                FileRollbackAnchorStore::open(&path, 4096).unwrap(),
                KEY,
                8
            )
            .unwrap_err(),
            RollbackAnchorError::AuthenticationFailed
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_writer_and_capacity_overflow_are_rejected() {
        let path = path("limits");
        let store =
            FileRollbackAnchorStore::open(&path, ROLLBACK_ANCHOR_RECORD_SIZE as u64).unwrap();
        assert!(FileRollbackAnchorStore::open(&path, 4096).is_err());
        let mut anchor = DurableRollbackAnchor::open(store, KEY, 2).unwrap();
        anchor.advance(heads(1)).unwrap();
        assert_eq!(
            anchor.advance(heads(4)),
            Err(RollbackAnchorError::ResourceLimit)
        );
        drop(anchor);
        fs::remove_file(path).unwrap();
    }
}
