//! File-backed atomic store for authenticated compaction images.

use crate::authenticated_compaction::{
    AtomicCompactionStore, CompactionCheckpoint, CompactionError, CompactionImage,
    RetainedTransaction,
};
use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
use crate::delivery_outbox::{DeliveryIntent, OutboxState};
use crate::receipt::{hmac_sha256, SealedReceipt};
use crate::sealed_receipt_vault::SealedReceiptRecord;
use crate::TransactionId;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const IMAGE_MAGIC: &[u8; 4] = b"QCCI";
const MANIFEST_MAGIC: &[u8; 4] = b"QCCM";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 200;
const TRANSACTION_SIZE: usize = 128;
const RECEIPT_SIZE: usize = 192;
const MANIFEST_SIZE: usize = 112;
const IMAGE_DOMAIN: &[u8] = b"noticer.quotient-commit.compaction-file-image.v1\0";
const MANIFEST_DOMAIN: &[u8] = b"noticer.quotient-commit.compaction-file-manifest.v1\0";

#[derive(Clone, Copy)]
struct Manifest {
    generation: u64,
    checkpoint_authenticator: [u8; 32],
    image_authenticator: [u8; 32],
    authenticator: [u8; 32],
}

#[derive(Debug)]
pub struct FileAtomicCompactionStore {
    root: PathBuf,
    key: [u8; 32],
    maximum_bytes: u64,
    active: Option<CompactionImage>,
    staged: Option<CompactionImage>,
    _lock: File,
    lock_path: PathBuf,
}

impl FileAtomicCompactionStore {
    pub fn open(
        root: impl AsRef<Path>,
        key: [u8; 32],
        maximum_bytes: u64,
    ) -> Result<Self, CompactionError> {
        if key == [0; 32] || maximum_bytes < HEADER_SIZE as u64 {
            return Err(CompactionError::StoreFailure);
        }
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|_| CompactionError::StoreFailure)?;
        let lock_path = root.join("store.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| CompactionError::StoreFailure)?;
        let active = match load_active(&root, key, maximum_bytes) {
            Ok(value) => value,
            Err(error) => {
                drop(lock);
                let _ = fs::remove_file(&lock_path);
                return Err(error);
            }
        };
        Ok(Self {
            root,
            key,
            maximum_bytes,
            active,
            staged: None,
            _lock: lock,
            lock_path,
        })
    }
}

impl AtomicCompactionStore for FileAtomicCompactionStore {
    fn stage_and_sync(&mut self, image: CompactionImage) -> Result<(), CompactionError> {
        let bytes = encode_image(&image);
        if bytes.len() as u64 > self.maximum_bytes {
            return Err(CompactionError::StoreFailure);
        }
        let image_authenticator = authenticate(IMAGE_DOMAIN, &bytes, self.key);
        let manifest = seal_manifest(
            image.checkpoint.generation,
            image.checkpoint.authenticator,
            image_authenticator,
            self.key,
        );
        write_immutable(&image_path(&self.root, image.checkpoint.generation), &bytes)?;
        atomic_write(
            &self.root.join("staged.manifest"),
            &encode_manifest(manifest),
        )?;
        self.staged = Some(image);
        Ok(())
    }

    fn activate_and_sync(&mut self) -> Result<(), CompactionError> {
        let image = self.staged.as_ref().ok_or(CompactionError::StoreFailure)?;
        let bytes = encode_image(image);
        let manifest = seal_manifest(
            image.checkpoint.generation,
            image.checkpoint.authenticator,
            authenticate(IMAGE_DOMAIN, &bytes, self.key),
            self.key,
        );
        atomic_write(
            &active_manifest_path(&self.root, manifest.generation),
            &encode_manifest(manifest),
        )?;
        self.active = self.staged.take();
        remove_if_exists(&self.root.join("staged.manifest"))?;
        Ok(())
    }

    fn active(&self) -> Option<&CompactionImage> {
        self.active.as_ref()
    }

    fn discard_staged(&mut self) -> Result<(), CompactionError> {
        let staged_generation = self
            .staged
            .as_ref()
            .map(|image| image.checkpoint.generation)
            .or_else(|| {
                read_manifest_file(&self.root.join("staged.manifest"), self.key)
                    .ok()
                    .flatten()
                    .map(|value| value.generation)
            });
        remove_if_exists(&self.root.join("staged.manifest"))?;
        if let Some(generation) = staged_generation {
            let active_generation = self
                .active
                .as_ref()
                .map(|image| image.checkpoint.generation);
            if active_generation != Some(generation) {
                remove_if_exists(&image_path(&self.root, generation))?;
            }
        }
        self.staged = None;
        Ok(())
    }
}

impl Drop for FileAtomicCompactionStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn load_active(
    root: &Path,
    key: [u8; 32],
    maximum_bytes: u64,
) -> Result<Option<CompactionImage>, CompactionError> {
    let mut manifests = fs::read_dir(root)
        .map_err(|_| CompactionError::StoreFailure)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.strip_prefix("active-")?
                .strip_suffix(".manifest")?
                .parse::<u64>()
                .ok()
                .map(|generation| (generation, entry.path()))
        })
        .collect::<Vec<_>>();
    manifests.sort_by_key(|value| value.0);
    let Some((_, path)) = manifests.last() else {
        return Ok(None);
    };
    let manifest = read_manifest_file(path, key)?.ok_or(CompactionError::StoreFailure)?;
    let bytes = fs::read(image_path(root, manifest.generation))
        .map_err(|_| CompactionError::StoreFailure)?;
    if bytes.len() as u64 > maximum_bytes
        || authenticate(IMAGE_DOMAIN, &bytes, key) != manifest.image_authenticator
    {
        return Err(CompactionError::AuthenticationFailed);
    }
    let image = decode_image(&bytes)?;
    if image.checkpoint.generation != manifest.generation
        || image.checkpoint.authenticator != manifest.checkpoint_authenticator
    {
        return Err(CompactionError::AuthenticationFailed);
    }
    Ok(Some(image))
}

fn image_path(root: &Path, generation: u64) -> PathBuf {
    root.join(format!("image-{generation:020}.bin"))
}
fn active_manifest_path(root: &Path, generation: u64) -> PathBuf {
    root.join(format!("active-{generation:020}.manifest"))
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), CompactionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| CompactionError::StoreFailure)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_data())
        .map_err(|_| CompactionError::StoreFailure)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CompactionError> {
    let mut temporary = OsString::from(path.as_os_str());
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut file = File::create(&temporary).map_err(|_| CompactionError::StoreFailure)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_data())
        .map_err(|_| CompactionError::StoreFailure)?;
    drop(file);
    if path.exists() {
        return Err(CompactionError::StoreFailure);
    }
    fs::rename(&temporary, path).map_err(|_| CompactionError::StoreFailure)
}

fn remove_if_exists(path: &Path) -> Result<(), CompactionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CompactionError::StoreFailure),
    }
}

fn seal_manifest(
    generation: u64,
    checkpoint_authenticator: [u8; 32],
    image_authenticator: [u8; 32],
    key: [u8; 32],
) -> Manifest {
    let mut value = Manifest {
        generation,
        checkpoint_authenticator,
        image_authenticator,
        authenticator: [0; 32],
    };
    value.authenticator = authenticate(MANIFEST_DOMAIN, &encode_manifest(value)[..80], key);
    value
}

fn encode_manifest(value: Manifest) -> [u8; MANIFEST_SIZE] {
    let mut bytes = [0; MANIFEST_SIZE];
    bytes[..4].copy_from_slice(MANIFEST_MAGIC);
    bytes[4] = VERSION;
    bytes[8..16].copy_from_slice(&value.generation.to_be_bytes());
    bytes[16..48].copy_from_slice(&value.checkpoint_authenticator);
    bytes[48..80].copy_from_slice(&value.image_authenticator);
    bytes[80..112].copy_from_slice(&value.authenticator);
    bytes
}

fn read_manifest_file(path: &Path, key: [u8; 32]) -> Result<Option<Manifest>, CompactionError> {
    let bytes = match fs::read(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CompactionError::StoreFailure),
    };
    if bytes.len() != MANIFEST_SIZE
        || &bytes[..4] != MANIFEST_MAGIC
        || bytes[4] != VERSION
        || bytes[5..8] != [0; 3]
    {
        return Err(CompactionError::StoreFailure);
    }
    let value = Manifest {
        generation: u64::from_be_bytes(array(&bytes, 8, 16)?),
        checkpoint_authenticator: array(&bytes, 16, 48)?,
        image_authenticator: array(&bytes, 48, 80)?,
        authenticator: array(&bytes, 80, 112)?,
    };
    if value.authenticator != authenticate(MANIFEST_DOMAIN, &bytes[..80], key) {
        return Err(CompactionError::AuthenticationFailed);
    }
    Ok(Some(value))
}

fn encode_image(image: &CompactionImage) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_SIZE];
    bytes[..4].copy_from_slice(IMAGE_MAGIC);
    bytes[4] = VERSION;
    bytes[8..16].copy_from_slice(&(image.transactions.len() as u64).to_be_bytes());
    bytes[16..24].copy_from_slice(&(image.receipts.len() as u64).to_be_bytes());
    encode_checkpoint(image.checkpoint, &mut bytes[24..200]);
    for value in &image.transactions {
        encode_transaction(*value, &mut bytes);
    }
    for value in &image.receipts {
        encode_receipt(*value, &mut bytes);
    }
    bytes
}

fn decode_image(bytes: &[u8]) -> Result<CompactionImage, CompactionError> {
    if bytes.len() < HEADER_SIZE
        || &bytes[..4] != IMAGE_MAGIC
        || bytes[4] != VERSION
        || bytes[5..8] != [0; 3]
    {
        return Err(CompactionError::StoreFailure);
    }
    let transaction_count = u64::from_be_bytes(array(bytes, 8, 16)?) as usize;
    let receipt_count = u64::from_be_bytes(array(bytes, 16, 24)?) as usize;
    let expected = HEADER_SIZE
        .checked_add(
            transaction_count
                .checked_mul(TRANSACTION_SIZE)
                .ok_or(CompactionError::StoreFailure)?,
        )
        .and_then(|value| value.checked_add(receipt_count.checked_mul(RECEIPT_SIZE)?))
        .ok_or(CompactionError::StoreFailure)?;
    if bytes.len() != expected {
        return Err(CompactionError::StoreFailure);
    }
    let checkpoint = decode_checkpoint(&bytes[24..200])?;
    let mut offset = HEADER_SIZE;
    let mut transactions = Vec::with_capacity(transaction_count);
    for _ in 0..transaction_count {
        transactions.push(decode_transaction(
            &bytes[offset..offset + TRANSACTION_SIZE],
        )?);
        offset += TRANSACTION_SIZE;
    }
    let mut receipts = Vec::with_capacity(receipt_count);
    for _ in 0..receipt_count {
        receipts.push(decode_receipt(&bytes[offset..offset + RECEIPT_SIZE])?);
        offset += RECEIPT_SIZE;
    }
    Ok(CompactionImage {
        transactions,
        receipts,
        checkpoint,
    })
}

fn encode_checkpoint(value: CompactionCheckpoint, bytes: &mut [u8]) {
    bytes[..8].copy_from_slice(&value.generation.to_be_bytes());
    bytes[8..40].copy_from_slice(&value.previous_checkpoint);
    for (index, number) in [
        value.source_outbox_records,
        value.source_vault_records,
        value.retained_transactions,
        value.retained_receipts,
        value.removed_audited_transactions,
    ]
    .into_iter()
    .enumerate()
    {
        let start = 40 + index * 8;
        bytes[start..start + 8].copy_from_slice(&number.to_be_bytes());
    }
    bytes[80..112].copy_from_slice(&value.before_digest);
    bytes[112..144].copy_from_slice(&value.retained_digest);
    bytes[144..176].copy_from_slice(&value.authenticator);
}
fn decode_checkpoint(bytes: &[u8]) -> Result<CompactionCheckpoint, CompactionError> {
    Ok(CompactionCheckpoint {
        generation: u64::from_be_bytes(array(bytes, 0, 8)?),
        previous_checkpoint: array(bytes, 8, 40)?,
        source_outbox_records: u64::from_be_bytes(array(bytes, 40, 48)?),
        source_vault_records: u64::from_be_bytes(array(bytes, 48, 56)?),
        retained_transactions: u64::from_be_bytes(array(bytes, 56, 64)?),
        retained_receipts: u64::from_be_bytes(array(bytes, 64, 72)?),
        removed_audited_transactions: u64::from_be_bytes(array(bytes, 72, 80)?),
        before_digest: array(bytes, 80, 112)?,
        retained_digest: array(bytes, 112, 144)?,
        authenticator: array(bytes, 144, 176)?,
    })
}

fn encode_transaction(value: RetainedTransaction, output: &mut Vec<u8>) {
    let mut b = [0; TRANSACTION_SIZE];
    b[..32].copy_from_slice(&value.intent.transaction_id.0);
    b[32..64].copy_from_slice(&value.intent.public_trace_digest);
    b[64..72].copy_from_slice(&value.intent.release_sequence.to_be_bytes());
    b[72..80].copy_from_slice(&value.intent.policy_epoch.to_be_bytes());
    b[80..88].copy_from_slice(&value.intent.receipt_epoch.to_be_bytes());
    b[88] = value.state as u8;
    b[96..128].copy_from_slice(&value.receipt_authenticator);
    output.extend_from_slice(&b);
}
fn decode_transaction(b: &[u8]) -> Result<RetainedTransaction, CompactionError> {
    let state = match b[88] {
        1 => OutboxState::Pending,
        2 => OutboxState::Delivered,
        3 => OutboxState::Audited,
        _ => return Err(CompactionError::StoreFailure),
    };
    if b[89..96] != [0; 7] {
        return Err(CompactionError::StoreFailure);
    }
    Ok(RetainedTransaction {
        intent: DeliveryIntent {
            transaction_id: TransactionId(array(b, 0, 32)?),
            public_trace_digest: array(b, 32, 64)?,
            release_sequence: u64::from_be_bytes(array(b, 64, 72)?),
            policy_epoch: u64::from_be_bytes(array(b, 72, 80)?),
            receipt_epoch: u64::from_be_bytes(array(b, 80, 88)?),
        },
        state,
        receipt_authenticator: array(b, 96, 128)?,
    })
}
fn encode_receipt(value: SealedReceiptRecord, output: &mut Vec<u8>) {
    let mut b = [0; RECEIPT_SIZE];
    let r = value.receipt.receipt;
    b[..32].copy_from_slice(&r.transaction_id.0);
    b[32..64].copy_from_slice(&r.public_trace_digest);
    b[64..72].copy_from_slice(&r.release_sequence.to_be_bytes());
    b[72..80].copy_from_slice(&r.policy_epoch.to_be_bytes());
    b[80] = match r.outcome {
        DeliveryOutcome::Delivered => 1,
        DeliveryOutcome::AlreadyDelivered => 2,
    };
    b[88..96].copy_from_slice(&value.receipt.sink_epoch.to_be_bytes());
    b[96..128].copy_from_slice(&value.receipt.authenticator);
    b[128..160].copy_from_slice(&value.outbox_authenticator);
    b[160..192].copy_from_slice(&value.authenticator);
    output.extend_from_slice(&b);
}
fn decode_receipt(b: &[u8]) -> Result<SealedReceiptRecord, CompactionError> {
    let outcome = match b[80] {
        1 => DeliveryOutcome::Delivered,
        2 => DeliveryOutcome::AlreadyDelivered,
        _ => return Err(CompactionError::StoreFailure),
    };
    if b[81..88] != [0; 7] {
        return Err(CompactionError::StoreFailure);
    }
    Ok(SealedReceiptRecord {
        receipt: SealedReceipt {
            receipt: DeliveryReceipt {
                transaction_id: TransactionId(array(b, 0, 32)?),
                public_trace_digest: array(b, 32, 64)?,
                release_sequence: u64::from_be_bytes(array(b, 64, 72)?),
                policy_epoch: u64::from_be_bytes(array(b, 72, 80)?),
                outcome,
            },
            sink_epoch: u64::from_be_bytes(array(b, 88, 96)?),
            authenticator: array(b, 96, 128)?,
        },
        outbox_authenticator: array(b, 128, 160)?,
        authenticator: array(b, 160, 192)?,
    })
}
fn array<const N: usize>(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<[u8; N], CompactionError> {
    bytes
        .get(start..end)
        .ok_or(CompactionError::StoreFailure)?
        .try_into()
        .map_err(|_| CompactionError::StoreFailure)
}
fn authenticate(domain: &[u8], bytes: &[u8], key: [u8; 32]) -> [u8; 32] {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    hmac_sha256(key, &message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    const KEY: [u8; 32] = [7; 32];
    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "quotient-compaction-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn image(generation: u64, previous: [u8; 32]) -> CompactionImage {
        CompactionImage {
            transactions: vec![],
            receipts: vec![],
            checkpoint: CompactionCheckpoint {
                generation,
                previous_checkpoint: previous,
                source_outbox_records: 0,
                source_vault_records: 0,
                retained_transactions: 0,
                retained_receipts: 0,
                removed_audited_transactions: 0,
                before_digest: [1; 32],
                retained_digest: [2; 32],
                authenticator: [generation as u8; 32],
            },
        }
    }
    #[test]
    fn crash_before_activation_keeps_old_image() {
        let root = path();
        let mut store = FileAtomicCompactionStore::open(&root, KEY, 4096).unwrap();
        store.stage_and_sync(image(1, [0; 32])).unwrap();
        store.activate_and_sync().unwrap();
        store.stage_and_sync(image(2, [1; 32])).unwrap();
        drop(store);
        let mut reopened = FileAtomicCompactionStore::open(&root, KEY, 4096).unwrap();
        assert_eq!(reopened.active().unwrap().checkpoint.generation, 1);
        reopened.discard_staged().unwrap();
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn activation_survives_restart() {
        let root = path();
        let mut store = FileAtomicCompactionStore::open(&root, KEY, 4096).unwrap();
        store.stage_and_sync(image(2, [9; 32])).unwrap();
        store.activate_and_sync().unwrap();
        drop(store);
        let reopened = FileAtomicCompactionStore::open(&root, KEY, 4096).unwrap();
        assert_eq!(reopened.active().unwrap(), &image(2, [9; 32]));
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn tampered_active_image_fails_closed() {
        let root = path();
        let mut store = FileAtomicCompactionStore::open(&root, KEY, 4096).unwrap();
        store.stage_and_sync(image(1, [0; 32])).unwrap();
        store.activate_and_sync().unwrap();
        drop(store);
        let file = image_path(&root, 1);
        let mut bytes = fs::read(&file).unwrap();
        bytes[24] ^= 1;
        fs::write(file, bytes).unwrap();
        assert!(FileAtomicCompactionStore::open(&root, KEY, 4096).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
