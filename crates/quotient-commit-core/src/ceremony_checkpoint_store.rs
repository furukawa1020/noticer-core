//! Dual-slot durable storage for authenticated recovery ceremony checkpoints.

use crate::receipt::hmac_sha256;
use crate::recovery_ceremony::{CeremonyCheckpoint, CeremonyPhase, RecoveryCeremony};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"QCCS";
const VERSION: u8 = 1;
const SIZE: usize = 248;
const DOMAIN: &[u8] = b"noticer.quotient-commit.ceremony-checkpoint-slot.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    A,
    B,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredCheckpoint {
    pub generation: u64,
    pub slot: Slot,
    pub checkpoint: CeremonyCheckpoint,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointStoreError {
    InvalidKey,
    Malformed,
    AuthenticationFailed,
    NoValidSlot,
    IoFailure,
}

#[derive(Debug)]
pub struct DualSlotCheckpointStore {
    root: PathBuf,
    key: [u8; 32],
    current: Option<StoredCheckpoint>,
}
impl DualSlotCheckpointStore {
    pub fn open(root: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, CheckpointStoreError> {
        if key == [0; 32] {
            return Err(CheckpointStoreError::InvalidKey);
        }
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|_| CheckpointStoreError::IoFailure)?;
        let candidates = load_candidates(&root, key)?;
        let current = candidates.into_iter().max_by_key(|v| v.generation);
        Ok(Self { root, key, current })
    }
    pub fn open_required(
        root: impl AsRef<Path>,
        key: [u8; 32],
    ) -> Result<Self, CheckpointStoreError> {
        let store = Self::open(root, key)?;
        if store.current.is_none() {
            return Err(CheckpointStoreError::NoValidSlot);
        }
        Ok(store)
    }
    pub fn persist(
        &mut self,
        checkpoint: CeremonyCheckpoint,
    ) -> Result<StoredCheckpoint, CheckpointStoreError> {
        RecoveryCeremony::resume(checkpoint, self.key)
            .map_err(|_| CheckpointStoreError::AuthenticationFailed)?;
        let generation = self.current.map_or(1, |v| v.generation + 1);
        let slot = if generation % 2 == 1 {
            Slot::A
        } else {
            Slot::B
        };
        let mut value = StoredCheckpoint {
            generation,
            slot,
            checkpoint,
            authenticator: [0; 32],
        };
        value.authenticator = authenticate(value, self.key);
        let path = slot_path(&self.root, slot, generation);
        atomic_create(&path, &encode(value))?;
        if let Some(previous) = self.current.filter(|v| v.slot == slot) {
            let _ = fs::remove_file(slot_path(&self.root, previous.slot, previous.generation));
        }
        self.current = Some(value);
        Ok(value)
    }
    #[must_use]
    pub const fn current(&self) -> Option<StoredCheckpoint> {
        self.current
    }
}

fn load_candidates(
    root: &Path,
    key: [u8; 32],
) -> Result<Vec<StoredCheckpoint>, CheckpointStoreError> {
    let mut found = Vec::new();
    let mut slot_files = 0;
    for entry in fs::read_dir(root)
        .map_err(|_| CheckpointStoreError::IoFailure)?
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("slot-a-") || name.starts_with("slot-b-")) || !name.ends_with(".bin")
        {
            continue;
        }
        slot_files += 1;
        let bytes = match fs::read(entry.path()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(value) = decode(&bytes, key) {
            if RecoveryCeremony::resume(value.checkpoint, key).is_ok() {
                found.push(value);
            }
        }
    }
    if slot_files > 0 && found.is_empty() {
        return Err(CheckpointStoreError::NoValidSlot);
    }
    Ok(found)
}
fn slot_path(root: &Path, slot: Slot, generation: u64) -> PathBuf {
    root.join(format!(
        "slot-{}-{generation:020}.bin",
        if slot == Slot::A { 'a' } else { 'b' }
    ))
}
fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), CheckpointStoreError> {
    let mut temp = OsString::from(path.as_os_str());
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|_| CheckpointStoreError::IoFailure)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_data())
        .map_err(|_| CheckpointStoreError::IoFailure)?;
    drop(file);
    fs::rename(temp, path).map_err(|_| CheckpointStoreError::IoFailure)
}
fn encode(v: StoredCheckpoint) -> [u8; SIZE] {
    let mut b = [0; SIZE];
    b[..4].copy_from_slice(MAGIC);
    b[4] = VERSION;
    b[5] = if v.slot == Slot::A { 1 } else { 2 };
    b[8..16].copy_from_slice(&v.generation.to_be_bytes());
    let c = v.checkpoint;
    b[16..48].copy_from_slice(&c.ceremony_id);
    b[48] = c.phase as u8;
    b[56..88].copy_from_slice(&c.certificate_authenticator);
    b[88..120].copy_from_slice(&c.anchor_authenticator);
    b[120..152].copy_from_slice(&c.admission_authenticator);
    b[152..184].copy_from_slice(&c.witness_authenticator);
    b[184..216].copy_from_slice(&c.authenticator);
    b[216..248].copy_from_slice(&v.authenticator);
    b
}
fn decode(b: &[u8], key: [u8; 32]) -> Result<StoredCheckpoint, CheckpointStoreError> {
    if b.len() != SIZE
        || &b[..4] != MAGIC
        || b[4] != VERSION
        || b[6..8] != [0; 2]
        || b[49..56] != [0; 7]
    {
        return Err(CheckpointStoreError::Malformed);
    }
    let slot = match b[5] {
        1 => Slot::A,
        2 => Slot::B,
        _ => return Err(CheckpointStoreError::Malformed),
    };
    let phase = match b[48] {
        1 => CeremonyPhase::Initialized,
        2 => CeremonyPhase::SecurityAuthorized,
        3 => CeremonyPhase::AdmissionAuthorized,
        4 => CeremonyPhase::RecoveryWitnessed,
        5 => CeremonyPhase::Complete,
        _ => return Err(CheckpointStoreError::Malformed),
    };
    let v = StoredCheckpoint {
        generation: u64::from_be_bytes(array(b, 8, 16)?),
        slot,
        checkpoint: CeremonyCheckpoint {
            ceremony_id: array(b, 16, 48)?,
            phase,
            certificate_authenticator: array(b, 56, 88)?,
            anchor_authenticator: array(b, 88, 120)?,
            admission_authenticator: array(b, 120, 152)?,
            witness_authenticator: array(b, 152, 184)?,
            authenticator: array(b, 184, 216)?,
        },
        authenticator: array(b, 216, 248)?,
    };
    if v.authenticator != authenticate(v, key) {
        return Err(CheckpointStoreError::AuthenticationFailed);
    }
    Ok(v)
}
fn authenticate(mut v: StoredCheckpoint, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let b = encode(v);
    let mut m = Vec::with_capacity(DOMAIN.len() + 216);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(&b[..216]);
    hmac_sha256(key, &m)
}
fn array<const N: usize>(b: &[u8], s: usize, e: usize) -> Result<[u8; N], CheckpointStoreError> {
    b.get(s..e)
        .ok_or(CheckpointStoreError::Malformed)?
        .try_into()
        .map_err(|_| CheckpointStoreError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    const KEY: [u8; 32] = [7; 32];
    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ceremony-slots-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn checkpoint(id: u8) -> CeremonyCheckpoint {
        RecoveryCeremony::begin([id; 32], KEY).unwrap().checkpoint()
    }
    #[test]
    fn newest_complete_slot_survives_restart() {
        let root = path();
        let mut s = DualSlotCheckpointStore::open(&root, KEY).unwrap();
        s.persist(checkpoint(1)).unwrap();
        s.persist(checkpoint(2)).unwrap();
        drop(s);
        let s = DualSlotCheckpointStore::open_required(&root, KEY).unwrap();
        assert_eq!(s.current().unwrap().generation, 2);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn torn_latest_slot_falls_back_to_previous() {
        let root = path();
        let mut s = DualSlotCheckpointStore::open(&root, KEY).unwrap();
        let first = s.persist(checkpoint(1)).unwrap();
        let second = s.persist(checkpoint(2)).unwrap();
        drop(s);
        fs::write(slot_path(&root, second.slot, second.generation), [1, 2, 3]).unwrap();
        let s = DualSlotCheckpointStore::open_required(&root, KEY).unwrap();
        assert_eq!(s.current(), Some(first));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn both_corrupt_slots_fail_closed() {
        let root = path();
        let mut s = DualSlotCheckpointStore::open(&root, KEY).unwrap();
        let a = s.persist(checkpoint(1)).unwrap();
        let b = s.persist(checkpoint(2)).unwrap();
        drop(s);
        fs::write(slot_path(&root, a.slot, a.generation), [1]).unwrap();
        fs::write(slot_path(&root, b.slot, b.generation), [2]).unwrap();
        assert_eq!(
            DualSlotCheckpointStore::open_required(&root, KEY).unwrap_err(),
            CheckpointStoreError::NoValidSlot
        );
        fs::remove_dir_all(root).unwrap();
    }
}
