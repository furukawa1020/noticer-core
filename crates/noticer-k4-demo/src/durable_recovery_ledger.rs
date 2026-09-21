use crate::recovery::{RecoveryLedger, RecoveryLedgerError};
use noticer_crypto::{authenticate_state, verify_state_authentication, StateAuthenticationKey};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const MAGIC: &[u8; 16] = b"NOTICER_RECOVL01";
const HEADER: usize = 60;
const RECORD: usize = 56;
#[derive(Debug)]
pub enum FileRecoveryLedgerError {
    Io(io::Error),
    Corrupt,
    Authentication,
    EpochMismatch,
    GenerationMismatch,
    Poisoned,
}
impl From<io::Error> for FileRecoveryLedgerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
struct Lock {
    path: PathBuf,
    _file: File,
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryLedgerHead {
    pub sequence: u64,
    pub tag: [u8; 32],
}
pub struct FileRecoveryLedger {
    file: File,
    _lock: Lock,
    key: StateAuthenticationKey,
    epoch: u32,
    generation: u64,
    ids: HashSet<[u8; 16]>,
    last_tag: [u8; 32],
    poisoned: bool,
}
impl FileRecoveryLedger {
    pub fn open(
        path: impl AsRef<Path>,
        epoch: u32,
        generation: u64,
        key: StateAuthenticationKey,
    ) -> Result<Self, FileRecoveryLedgerError> {
        let path = path.as_ref();
        let mut lp = path.as_os_str().to_os_string();
        lp.push(".lock");
        let lp = PathBuf::from(lp);
        let lock = Lock {
            path: lp.clone(),
            _file: OpenOptions::new().write(true).create_new(true).open(lp)?,
        };
        let (mut file, new) = match OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(path)
        {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (
                OpenOptions::new().read(true).append(true).open(path)?,
                false,
            ),
            Err(e) => return Err(e.into()),
        };
        if new {
            let h = header(epoch, generation, &key);
            file.write_all(&h)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::Start(0))?;
        let bytes = {
            let mut b = Vec::new();
            file.read_to_end(&mut b)?;
            b
        };
        if bytes.len() < HEADER || (bytes.len() - HEADER) % RECORD != 0 {
            return Err(FileRecoveryLedgerError::Corrupt);
        }
        if &bytes[..16] != MAGIC {
            return Err(FileRecoveryLedgerError::Corrupt);
        }
        if !verify_state_authentication(&key, &bytes[..28], &bytes[28..60]) {
            return Err(FileRecoveryLedgerError::Authentication);
        }
        let stored_epoch = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let stored_generation = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        if stored_epoch != epoch {
            return Err(FileRecoveryLedgerError::EpochMismatch);
        }
        if stored_generation != generation {
            return Err(FileRecoveryLedgerError::GenerationMismatch);
        }
        let mut ids = HashSet::new();
        let mut previous: [u8; 32] = bytes[28..60].try_into().unwrap();
        for (index, r) in bytes[HEADER..].chunks_exact(RECORD).enumerate() {
            let sequence = u64::from_le_bytes(r[..8].try_into().unwrap());
            if sequence != index as u64 {
                return Err(FileRecoveryLedgerError::Corrupt);
            }
            let id: [u8; 16] = r[8..24].try_into().unwrap();
            let message = record_message(epoch, generation, &previous, sequence, &id);
            if !verify_state_authentication(&key, &message, &r[24..]) || !ids.insert(id) {
                return Err(FileRecoveryLedgerError::Authentication);
            }
            previous.copy_from_slice(&r[24..]);
        }
        Ok(Self {
            file,
            _lock: lock,
            key,
            epoch,
            generation,
            ids,
            last_tag: previous,
            poisoned: false,
        })
    }
    pub fn head(&self) -> RecoveryLedgerHead {
        RecoveryLedgerHead {
            sequence: self.ids.len() as u64,
            tag: self.last_tag,
        }
    }
    fn consume_inner(&mut self, id: [u8; 16]) -> Result<bool, FileRecoveryLedgerError> {
        if self.poisoned {
            return Err(FileRecoveryLedgerError::Poisoned);
        }
        if self.ids.contains(&id) {
            return Ok(false);
        }
        let sequence = self.ids.len() as u64;
        let message = record_message(self.epoch, self.generation, &self.last_tag, sequence, &id);
        let tag = authenticate_state(&self.key, &message);
        let mut record = [0u8; RECORD];
        record[..8].copy_from_slice(&sequence.to_le_bytes());
        record[8..24].copy_from_slice(&id);
        record[24..].copy_from_slice(&tag);
        if let Err(e) = self
            .file
            .write_all(&record)
            .and_then(|_| self.file.sync_data())
        {
            self.poisoned = true;
            return Err(e.into());
        }
        self.ids.insert(id);
        self.last_tag = tag;
        Ok(true)
    }
}
impl RecoveryLedger for FileRecoveryLedger {
    fn consume(&mut self, id: [u8; 16]) -> Result<bool, RecoveryLedgerError> {
        self.consume_inner(id)
            .map_err(|_| RecoveryLedgerError::Storage)
    }
}
fn header(epoch: u32, generation: u64, key: &StateAuthenticationKey) -> [u8; HEADER] {
    let mut h = [0; HEADER];
    h[..16].copy_from_slice(MAGIC);
    h[16..20].copy_from_slice(&epoch.to_le_bytes());
    h[20..28].copy_from_slice(&generation.to_le_bytes());
    let tag = authenticate_state(key, &h[..28]);
    h[28..].copy_from_slice(&tag);
    h
}
fn record_message(
    epoch: u32,
    generation: u64,
    previous: &[u8; 32],
    sequence: u64,
    id: &[u8; 16],
) -> [u8; 68] {
    let mut m = [0; 68];
    m[..4].copy_from_slice(&epoch.to_le_bytes());
    m[4..12].copy_from_slice(&generation.to_le_bytes());
    m[12..44].copy_from_slice(previous);
    m[44..52].copy_from_slice(&sequence.to_le_bytes());
    m[52..].copy_from_slice(id);
    m
}
