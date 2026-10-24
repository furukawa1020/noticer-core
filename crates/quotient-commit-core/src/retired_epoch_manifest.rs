//! Authenticated monotonic persistence for irreversibly retired key epochs.

use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"QREM";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"noticer.quotient-commit.retired-epoch-manifest.v1\0";
const HEADER_SIZE: usize = 56;
const TRAILER_SIZE: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredEpochManifest {
    pub generation: u64,
    pub previous_authenticator: [u8; 32],
    pub retired_epochs: BTreeSet<u64>,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetiredEpochManifestError {
    InvalidKey,
    InvalidEpoch,
    InvalidLimit,
    DuplicateEpoch,
    RollbackDetected,
    AuthenticationFailed,
    MalformedManifest,
    ResourceLimit,
    IoFailure,
    LockUnavailable,
}

#[derive(Debug)]
pub struct FileRetiredEpochManifest {
    root: PathBuf,
    key: [u8; 32],
    maximum_epochs: usize,
    current: RetiredEpochManifest,
    _lock: File,
    lock_path: PathBuf,
}

impl FileRetiredEpochManifest {
    pub fn open(
        root: impl AsRef<Path>,
        key: [u8; 32],
        minimum_generation: u64,
        maximum_epochs: usize,
    ) -> Result<Self, RetiredEpochManifestError> {
        if key == [0; 32] {
            return Err(RetiredEpochManifestError::InvalidKey);
        }
        if maximum_epochs == 0 {
            return Err(RetiredEpochManifestError::InvalidLimit);
        }
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|_| RetiredEpochManifestError::IoFailure)?;
        let lock_path = root.join("manifest.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| RetiredEpochManifestError::LockUnavailable)?;
        let current = match load_latest(&root, key, maximum_epochs) {
            Ok(Some(value)) => value,
            Ok(None) => empty_manifest(key),
            Err(error) => {
                drop(lock);
                let _ = fs::remove_file(&lock_path);
                return Err(error);
            }
        };
        if current.generation < minimum_generation {
            drop(lock);
            let _ = fs::remove_file(&lock_path);
            return Err(RetiredEpochManifestError::RollbackDetected);
        }
        Ok(Self {
            root,
            key,
            maximum_epochs,
            current,
            _lock: lock,
            lock_path,
        })
    }

    pub fn retire(
        &mut self,
        epoch: u64,
    ) -> Result<RetiredEpochManifest, RetiredEpochManifestError> {
        if epoch == 0 {
            return Err(RetiredEpochManifestError::InvalidEpoch);
        }
        if self.current.retired_epochs.contains(&epoch) {
            return Err(RetiredEpochManifestError::DuplicateEpoch);
        }
        if self.current.retired_epochs.len() >= self.maximum_epochs {
            return Err(RetiredEpochManifestError::ResourceLimit);
        }
        let mut epochs = self.current.retired_epochs.clone();
        epochs.insert(epoch);
        let mut next = RetiredEpochManifest {
            generation: self.current.generation + 1,
            previous_authenticator: self.current.authenticator,
            retired_epochs: epochs,
            authenticator: [0; 32],
        };
        next.authenticator = authenticate(&next, self.key);
        write_immutable(&manifest_path(&self.root, next.generation), &encode(&next))?;
        self.current = next.clone();
        Ok(next)
    }

    #[must_use]
    pub fn current(&self) -> &RetiredEpochManifest {
        &self.current
    }
}

impl Drop for FileRetiredEpochManifest {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn empty_manifest(key: [u8; 32]) -> RetiredEpochManifest {
    let mut value = RetiredEpochManifest {
        generation: 0,
        previous_authenticator: [0; 32],
        retired_epochs: BTreeSet::new(),
        authenticator: [0; 32],
    };
    value.authenticator = authenticate(&value, key);
    value
}

fn load_latest(
    root: &Path,
    key: [u8; 32],
    maximum_epochs: usize,
) -> Result<Option<RetiredEpochManifest>, RetiredEpochManifestError> {
    let mut paths = fs::read_dir(root)
        .map_err(|_| RetiredEpochManifestError::IoFailure)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.strip_prefix("manifest-")?
                .strip_suffix(".bin")?
                .parse::<u64>()
                .ok()
                .map(|generation| (generation, entry.path()))
        })
        .collect::<Vec<_>>();
    paths.sort_by_key(|value| value.0);
    let mut previous = empty_manifest(key);
    for (generation, path) in paths {
        let bytes = fs::read(path).map_err(|_| RetiredEpochManifestError::IoFailure)?;
        let value = decode(&bytes, key, maximum_epochs)?;
        if generation != value.generation
            || value.generation != previous.generation + 1
            || value.previous_authenticator != previous.authenticator
            || !previous.retired_epochs.is_subset(&value.retired_epochs)
        {
            return Err(RetiredEpochManifestError::RollbackDetected);
        }
        previous = value;
    }
    if previous.generation == 0 {
        Ok(None)
    } else {
        Ok(Some(previous))
    }
}

fn manifest_path(root: &Path, generation: u64) -> PathBuf {
    root.join(format!("manifest-{generation:020}.bin"))
}
fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), RetiredEpochManifestError> {
    let mut temporary = OsString::from(path.as_os_str());
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| RetiredEpochManifestError::IoFailure)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_data())
        .map_err(|_| RetiredEpochManifestError::IoFailure)?;
    drop(file);
    fs::rename(temporary, path).map_err(|_| RetiredEpochManifestError::IoFailure)
}

fn encode(value: &RetiredEpochManifest) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_SIZE];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4] = VERSION;
    bytes[8..16].copy_from_slice(&value.generation.to_be_bytes());
    bytes[16..24].copy_from_slice(&(value.retired_epochs.len() as u64).to_be_bytes());
    bytes[24..56].copy_from_slice(&value.previous_authenticator);
    for epoch in &value.retired_epochs {
        bytes.extend_from_slice(&epoch.to_be_bytes());
    }
    bytes.extend_from_slice(&value.authenticator);
    bytes
}

fn decode(
    bytes: &[u8],
    key: [u8; 32],
    maximum_epochs: usize,
) -> Result<RetiredEpochManifest, RetiredEpochManifestError> {
    if bytes.len() < HEADER_SIZE + TRAILER_SIZE
        || &bytes[..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[5..8] != [0; 3]
    {
        return Err(RetiredEpochManifestError::MalformedManifest);
    }
    let generation = u64::from_be_bytes(array(bytes, 8, 16)?);
    let count = u64::from_be_bytes(array(bytes, 16, 24)?) as usize;
    if count > maximum_epochs {
        return Err(RetiredEpochManifestError::ResourceLimit);
    }
    if bytes.len() != HEADER_SIZE + count * 8 + TRAILER_SIZE {
        return Err(RetiredEpochManifestError::MalformedManifest);
    }
    let mut retired_epochs = BTreeSet::new();
    for index in 0..count {
        let start = HEADER_SIZE + index * 8;
        let epoch = u64::from_be_bytes(array(bytes, start, start + 8)?);
        if epoch == 0 || !retired_epochs.insert(epoch) {
            return Err(RetiredEpochManifestError::MalformedManifest);
        }
    }
    let value = RetiredEpochManifest {
        generation,
        previous_authenticator: array(bytes, 24, 56)?,
        retired_epochs,
        authenticator: array(bytes, bytes.len() - 32, bytes.len())?,
    };
    if value.authenticator != authenticate(&value, key) {
        return Err(RetiredEpochManifestError::AuthenticationFailed);
    }
    Ok(value)
}

fn authenticate(value: &RetiredEpochManifest, key: [u8; 32]) -> [u8; 32] {
    let mut copy = value.clone();
    copy.authenticator = [0; 32];
    let bytes = encode(&copy);
    let mut message = Vec::with_capacity(DOMAIN.len() + bytes.len() - 32);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&bytes[..bytes.len() - 32]);
    hmac_sha256(key, &message)
}
fn array<const N: usize>(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<[u8; N], RetiredEpochManifestError> {
    bytes
        .get(start..end)
        .ok_or(RetiredEpochManifestError::MalformedManifest)?
        .try_into()
        .map_err(|_| RetiredEpochManifestError::MalformedManifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::{KeyringError, ReceiptKeyring};
    use std::time::{SystemTime, UNIX_EPOCH};
    const KEY: [u8; 32] = [7; 32];
    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "retired-epochs-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    fn restart_keeps_retirement_irreversible() {
        let root = path();
        let mut store = FileRetiredEpochManifest::open(&root, KEY, 0, 8).unwrap();
        store.retire(3).unwrap();
        drop(store);
        let store = FileRetiredEpochManifest::open(&root, KEY, 1, 8).unwrap();
        let mut ring =
            ReceiptKeyring::with_retired_epochs(&store.current().retired_epochs).unwrap();
        assert_eq!(ring.register(3, [3; 32]), Err(KeyringError::RetiredEpoch));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn deleting_latest_generation_is_detected_by_anchor() {
        let root = path();
        let mut store = FileRetiredEpochManifest::open(&root, KEY, 0, 8).unwrap();
        store.retire(1).unwrap();
        store.retire(2).unwrap();
        drop(store);
        fs::remove_file(manifest_path(&root, 2)).unwrap();
        assert_eq!(
            FileRetiredEpochManifest::open(&root, KEY, 2, 8).unwrap_err(),
            RetiredEpochManifestError::RollbackDetected
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn tampering_fails_closed() {
        let root = path();
        let mut store = FileRetiredEpochManifest::open(&root, KEY, 0, 8).unwrap();
        store.retire(1).unwrap();
        drop(store);
        let path = manifest_path(&root, 1);
        let mut bytes = fs::read(&path).unwrap();
        bytes[56] ^= 1;
        fs::write(path, bytes).unwrap();
        assert_eq!(
            FileRetiredEpochManifest::open(&root, KEY, 1, 8).unwrap_err(),
            RetiredEpochManifestError::AuthenticationFailed
        );
        fs::remove_dir_all(root).unwrap();
    }
}
