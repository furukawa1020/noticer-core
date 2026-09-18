#![forbid(unsafe_code)]

//! Fail-closed, one-shot ATv2 verification with atomic replay state.

use noticer_aetp::{required_claim, ClaimBound};
use noticer_crypto::VerifierKeyMaterial;
use noticer_protocol::{InnerBody, KeyId, TokenId, WireServiceAlias};
use noticer_types::{ActionCode, PolicyHash};
use noticer_verifier_core::{
    self as verifier_core, KeySource as CoreKeySource, PolicySource as CorePolicySource,
    ReplayGuard as CoreReplayGuard, RevocationSource as CoreRevocationSource,
};
pub use noticer_verifier_core::{AuthorizedAction, VerificationResult, VerifierContext};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use thiserror::Error;

#[derive(Default)]
pub struct KeyRegistry {
    entries: BTreeMap<(WireServiceAlias, KeyId, u32), VerifierKeyMaterial>,
}

impl KeyRegistry {
    pub fn insert(&mut self, material: VerifierKeyMaterial) -> Result<(), RegistryError> {
        let key = (material.wire_alias(), material.key_id(), material.epoch());
        if self.entries.insert(key, material).is_some() {
            return Err(RegistryError::Duplicate);
        }
        Ok(())
    }

    fn get(
        &self,
        alias: WireServiceAlias,
        key_id: KeyId,
        epoch: u32,
    ) -> Option<&VerifierKeyMaterial> {
        self.entries.get(&(alias, key_id, epoch))
    }
}

impl CoreKeySource for KeyRegistry {
    fn get(
        &self,
        alias: WireServiceAlias,
        key_id: KeyId,
        epoch: u32,
    ) -> Option<&VerifierKeyMaterial> {
        self.get(alias, key_id, epoch)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RegistryError {
    #[error("duplicate verifier key registration")]
    Duplicate,
}

#[derive(Clone, Debug)]
struct PolicyEntry {
    action: ActionCode,
    maximum_claim: ClaimBound,
    semantics_tags: BTreeSet<[u8; 16]>,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyAllowlist {
    entries: BTreeMap<PolicyHash, PolicyEntry>,
}

impl PolicyAllowlist {
    pub fn allow(
        &mut self,
        policy_hash: PolicyHash,
        action: ActionCode,
        maximum_claim: ClaimBound,
        semantics_tag: [u8; 16],
    ) -> Result<(), PolicyError> {
        let entry = self
            .entries
            .entry(policy_hash)
            .or_insert_with(|| PolicyEntry {
                action,
                maximum_claim,
                semantics_tags: BTreeSet::new(),
            });
        if entry.action != action || entry.maximum_claim != maximum_claim {
            return Err(PolicyError::Conflict);
        }
        entry.semantics_tags.insert(semantics_tag);
        Ok(())
    }

    fn permits(&self, body: &InnerBody) -> bool {
        self.entries.get(&body.policy_hash).is_some_and(|entry| {
            entry.action == body.action
                && body.claim_bound.permits(required_claim(body.action))
                && entry.maximum_claim.permits(body.claim_bound)
                && entry.semantics_tags.contains(&body.semantics_tag)
        })
    }
}

impl CorePolicySource for PolicyAllowlist {
    fn permits(&self, body: &InnerBody) -> bool {
        self.permits(body)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("conflicting policy allowlist entry")]
    Conflict,
}

#[derive(Clone, Debug, Default)]
pub struct RevocationSnapshot {
    revoked_keys: BTreeSet<KeyId>,
    revoked_policies: BTreeSet<PolicyHash>,
}

impl RevocationSnapshot {
    pub fn revoke_key(&mut self, key_id: KeyId) {
        self.revoked_keys.insert(key_id);
    }

    pub fn revoke_policy(&mut self, policy_hash: PolicyHash) {
        self.revoked_policies.insert(policy_hash);
    }

    fn key_is_revoked(&self, key_id: KeyId) -> bool {
        self.revoked_keys.contains(&key_id)
    }

    fn policy_is_revoked(&self, policy_hash: PolicyHash) -> bool {
        self.revoked_policies.contains(&policy_hash)
    }
}

impl CoreRevocationSource for RevocationSnapshot {
    fn key_is_revoked(&self, key_id: KeyId) -> bool {
        self.key_is_revoked(key_id)
    }

    fn policy_is_revoked(&self, policy_hash: PolicyHash) -> bool {
        self.policy_is_revoked(policy_hash)
    }
}

pub trait ReplayStore: Send + Sync {
    /// Atomically returns true only for the first `(epoch, token_id)` use.
    fn accept_once(&self, epoch: u32, token_id: TokenId) -> bool;
}

struct ReplayAdapter<'a>(&'a dyn ReplayStore);

impl CoreReplayGuard for ReplayAdapter<'_> {
    fn accept_once(&self, epoch: u32, token_id: TokenId) -> bool {
        self.0.accept_once(epoch, token_id)
    }
}

const REPLAY_FILE_MAGIC: [u8; 16] = *b"NOTICER_REPLAY01";
const REPLAY_HEADER_BYTES: u64 = 20;
const REPLAY_RECORD_BYTES: u64 = 32;
const MAX_REPLAY_RECORDS: usize = 100_000;

#[derive(Debug, Error)]
pub enum FileReplayError {
    #[error("durable replay storage is unavailable")]
    Io(#[from] std::io::Error),
    #[error("durable replay file is incomplete or corrupted")]
    Corrupt,
    #[error("durable replay epoch does not match")]
    EpochMismatch,
    #[error("durable replay capacity is exhausted")]
    Capacity,
}

struct ReplayFileLock {
    file: Option<File>,
    path: PathBuf,
}

impl ReplayFileLock {
    fn acquire(path: &Path) -> std::io::Result<Self> {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        let path = PathBuf::from(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }
}

impl Drop for ReplayFileLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

struct FileReplayState {
    file: File,
    ids: BTreeSet<TokenId>,
    expected_len: u64,
    poisoned: bool,
}

/// Single-writer, epoch-bound replay ledger. A stale lock blocks restart until
/// an operator verifies the previous process has stopped; no automatic repair.
pub struct FileReplayStore {
    epoch: u32,
    state: Mutex<FileReplayState>,
    _lock: ReplayFileLock,
}

impl FileReplayStore {
    // Preserve the workspace Rust 1.85 MSRV; is_multiple_of is newer.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn open(path: impl AsRef<Path>, epoch: u32) -> Result<Self, FileReplayError> {
        let path = path.as_ref();
        let lock = ReplayFileLock::acquire(path)?;
        let (mut file, fresh) = match OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new().read(true).append(true).open(path)?,
                false,
            ),
            Err(error) => return Err(error.into()),
        };
        let mut ids = BTreeSet::new();
        let expected_len = if fresh {
            file.write_all(&REPLAY_FILE_MAGIC)?;
            file.write_all(&epoch.to_le_bytes())?;
            file.sync_all()?;
            REPLAY_HEADER_BYTES
        } else {
            let length = file.metadata()?.len();
            let maximum = REPLAY_HEADER_BYTES + REPLAY_RECORD_BYTES * MAX_REPLAY_RECORDS as u64;
            if length > maximum {
                return Err(FileReplayError::Capacity);
            }
            if length < REPLAY_HEADER_BYTES
                || (length - REPLAY_HEADER_BYTES) % REPLAY_RECORD_BYTES != 0
            {
                return Err(FileReplayError::Corrupt);
            }
            file.seek(SeekFrom::Start(0))?;
            let mut header = [0_u8; REPLAY_HEADER_BYTES as usize];
            file.read_exact(&mut header)?;
            if header[..16] != REPLAY_FILE_MAGIC {
                return Err(FileReplayError::Corrupt);
            }
            if header[16..20] != epoch.to_le_bytes() {
                return Err(FileReplayError::EpochMismatch);
            }
            for _ in 0..((length - REPLAY_HEADER_BYTES) / REPLAY_RECORD_BYTES) {
                let mut record = [0_u8; REPLAY_RECORD_BYTES as usize];
                file.read_exact(&mut record)?;
                if record[16..]
                    .iter()
                    .zip(&record[..16])
                    .any(|(check, id)| *check != !*id)
                {
                    return Err(FileReplayError::Corrupt);
                }
                let mut bytes = [0_u8; 16];
                bytes.copy_from_slice(&record[..16]);
                if !ids.insert(TokenId(bytes)) {
                    return Err(FileReplayError::Corrupt);
                }
            }
            file.seek(SeekFrom::End(0))?;
            length
        };
        Ok(Self {
            epoch,
            state: Mutex::new(FileReplayState {
                file,
                ids,
                expected_len,
                poisoned: false,
            }),
            _lock: lock,
        })
    }
}

impl ReplayStore for FileReplayStore {
    fn accept_once(&self, epoch: u32, token_id: TokenId) -> bool {
        if epoch != self.epoch {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.poisoned || state.ids.contains(&token_id) || state.ids.len() >= MAX_REPLAY_RECORDS
        {
            return false;
        }
        if !matches!(state.file.metadata(), Ok(metadata) if metadata.len() == state.expected_len) {
            state.poisoned = true;
            return false;
        }
        let mut record = [0_u8; REPLAY_RECORD_BYTES as usize];
        record[..16].copy_from_slice(&token_id.0);
        for (check, id) in record[16..].iter_mut().zip(token_id.0) {
            *check = !id;
        }
        if state.file.write_all(&record).is_err() || state.file.sync_data().is_err() {
            state.poisoned = true;
            return false;
        }
        state.expected_len += REPLAY_RECORD_BYTES;
        state.ids.insert(token_id)
    }
}
#[derive(Default)]
pub struct InMemoryReplayStore {
    entries: Mutex<BTreeSet<(u32, TokenId)>>,
}

impl ReplayStore for InMemoryReplayStore {
    fn accept_once(&self, epoch: u32, token_id: TokenId) -> bool {
        self.entries
            .lock()
            .map(|mut entries| entries.insert((epoch, token_id)))
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplaySnapshot {
    pub schema_version: u16,
    pub epoch: u32,
    pub token_ids: Vec<[u8; 16]>,
}

impl InMemoryReplayStore {
    pub fn export_json(&self, epoch: u32) -> Result<String, SnapshotError> {
        let entries = self.entries.lock().map_err(|_| SnapshotError::State)?;
        let token_ids = entries
            .iter()
            .filter(|(entry_epoch, _)| *entry_epoch == epoch)
            .map(|(_, token_id)| token_id.0)
            .collect();
        serde_json::to_string_pretty(&ReplaySnapshot {
            schema_version: 1,
            epoch,
            token_ids,
        })
        .map_err(|_| SnapshotError::Encoding)
    }

    pub fn import_json(expected_epoch: u32, json: &str) -> Result<Self, SnapshotError> {
        let snapshot: ReplaySnapshot =
            serde_json::from_str(json).map_err(|_| SnapshotError::Encoding)?;
        if snapshot.schema_version != 1 || snapshot.epoch != expected_epoch {
            return Err(SnapshotError::EpochOrSchema);
        }
        let mut entries = BTreeSet::new();
        for token_id in snapshot.token_ids {
            if !entries.insert((snapshot.epoch, TokenId(token_id))) {
                return Err(SnapshotError::Duplicate);
            }
        }
        Ok(Self {
            entries: Mutex::new(entries),
        })
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SnapshotError {
    #[error("replay state unavailable")]
    State,
    #[error("replay snapshot encoding is invalid")]
    Encoding,
    #[error("replay snapshot epoch or schema mismatch")]
    EpochOrSchema,
    #[error("replay snapshot contains duplicate IDs")]
    Duplicate,
}

pub struct TokenVerifier {
    registry: KeyRegistry,
    policies: PolicyAllowlist,
    revocations: RevocationSnapshot,
    replay: Arc<dyn ReplayStore>,
}

impl TokenVerifier {
    pub fn new(
        registry: KeyRegistry,
        policies: PolicyAllowlist,
        revocations: RevocationSnapshot,
        replay: Arc<dyn ReplayStore>,
    ) -> Self {
        Self {
            registry,
            policies,
            revocations,
            replay,
        }
    }

    /// Returns a deliberately normalized external result. Detailed failures are
    /// retained only inside `verify_detailed` to avoid a verifier oracle.
    pub fn verify(&self, bytes: &[u8], context: VerifierContext) -> VerificationResult {
        let replay = ReplayAdapter(self.replay.as_ref());
        verifier_core::verify(
            bytes,
            context,
            &self.registry,
            &self.policies,
            &self.revocations,
            &replay,
        )
        .unwrap_or(VerificationResult::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{required_claim, ActionObligation, BucketId, ServiceBinding};
    use noticer_crypto::CryptographicRootSecret;
    use noticer_protocol::AtypicalityTokenEnvelope;
    use noticer_token::{semantics_tag, TokenIssuer};
    use noticer_trace_shaper::PublicFrameIdentity;
    use noticer_types::LogicalSlot;
    use std::thread;

    fn fixture() -> (
        AtypicalityTokenEnvelope,
        TokenVerifier,
        VerifierContext,
        PolicyHash,
    ) {
        let service = ServiceBinding([3; 16]);
        let policy_hash = PolicyHash([4; 32]);
        let obligation = ActionObligation {
            service,
            action: ActionCode::RenderAmbientPulse,
            public_bucket: BucketId(1),
            admission_cutoff: LogicalSlot(8),
            release_window_start: LogicalSlot(9),
            release_deadline: LogicalSlot(12),
            max_uses: 1,
            policy_hash,
        };
        let claim = required_claim(obligation.action);
        let issuer =
            TokenIssuer::new(CryptographicRootSecret::new([9; 32]), 5, &[service]).unwrap();
        let identity = PublicFrameIdentity {
            service,
            public_epoch: 5,
            public_bucket: 1,
            slot_in_bucket: 0,
            sequence: 7,
            absolute_slot: LogicalSlot(10),
        };
        let envelope = issuer
            .issue_action_frame(identity, &obligation, claim)
            .unwrap();
        let mut registry = KeyRegistry::default();
        registry
            .insert(issuer.verifier_material(service).unwrap())
            .unwrap();
        let mut policies = PolicyAllowlist::default();
        policies
            .allow(
                policy_hash,
                obligation.action,
                claim,
                semantics_tag(&obligation, claim),
            )
            .unwrap();
        let verifier = TokenVerifier::new(
            registry,
            policies,
            RevocationSnapshot::default(),
            Arc::new(InMemoryReplayStore::default()),
        );
        (
            envelope,
            verifier,
            VerifierContext {
                expected_service: service,
                expected_epoch: 5,
                now_slot: 10,
            },
            policy_hash,
        )
    }

    #[test]
    fn accepts_once_then_rejects_replay() {
        let (token, verifier, context, _) = fixture();
        assert!(matches!(
            verifier.verify(token.as_bytes(), context),
            VerificationResult::Authorized(_)
        ));
        assert_eq!(
            verifier.verify(token.as_bytes(), context),
            VerificationResult::Rejected
        );
    }

    #[test]
    fn rejects_mutation_wrong_service_and_expiry() {
        let (token, verifier, context, _) = fixture();
        let mut mutated = token.0;
        mutated[200] ^= 1;
        assert_eq!(
            verifier.verify(&mutated, context),
            VerificationResult::Rejected
        );
        let mut wrong_service = context;
        wrong_service.expected_service = ServiceBinding([8; 16]);
        assert_eq!(
            verifier.verify(token.as_bytes(), wrong_service),
            VerificationResult::Rejected
        );
        let mut wrong_epoch = context;
        wrong_epoch.expected_epoch = 6;
        assert_eq!(
            verifier.verify(token.as_bytes(), wrong_epoch),
            VerificationResult::Rejected
        );
        let mut expired = context;
        expired.now_slot = 13;
        assert_eq!(
            verifier.verify(token.as_bytes(), expired),
            VerificationResult::Rejected
        );
    }

    #[test]
    fn rejects_key_policy_revocation_and_claim_ceiling_violation() {
        let (token, mut verifier, context, policy_hash) = fixture();
        verifier.revocations.revoke_policy(policy_hash);
        assert_eq!(
            verifier.verify(token.as_bytes(), context),
            VerificationResult::Rejected
        );

        let (token, mut verifier, context, _) = fixture();
        verifier
            .revocations
            .revoke_key(token.outer().unwrap().key_id);
        assert_eq!(
            verifier.verify(token.as_bytes(), context),
            VerificationResult::Rejected
        );

        let (token, mut verifier, context, policy_hash) = fixture();
        verifier
            .policies
            .entries
            .get_mut(&policy_hash)
            .unwrap()
            .maximum_claim = ClaimBound::NONE;
        assert_eq!(
            verifier.verify(token.as_bytes(), context),
            VerificationResult::Rejected
        );
    }

    #[test]
    fn canonical_cover_has_no_privileged_action() {
        let service = ServiceBinding([3; 16]);
        let issuer =
            TokenIssuer::new(CryptographicRootSecret::new([9; 32]), 5, &[service]).unwrap();
        let token = issuer
            .issue_cover_frame(PublicFrameIdentity {
                service,
                public_epoch: 5,
                public_bucket: 1,
                slot_in_bucket: 0,
                sequence: 9,
                absolute_slot: LogicalSlot(10),
            })
            .unwrap();
        let mut registry = KeyRegistry::default();
        registry
            .insert(issuer.verifier_material(service).unwrap())
            .unwrap();
        let verifier = TokenVerifier::new(
            registry,
            PolicyAllowlist::default(),
            RevocationSnapshot::default(),
            Arc::new(InMemoryReplayStore::default()),
        );
        assert_eq!(
            verifier.verify(
                token.as_bytes(),
                VerifierContext {
                    expected_service: service,
                    expected_epoch: 5,
                    now_slot: 10,
                },
            ),
            VerificationResult::Cover
        );
    }

    #[test]
    fn atomic_replay_race_authorizes_exactly_once() {
        let (token, verifier, context, _) = fixture();
        let verifier = Arc::new(verifier);
        let token = Arc::new(token.0);
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let verifier = Arc::clone(&verifier);
                let token = Arc::clone(&token);
                thread::spawn(move || verifier.verify(token.as_ref(), context))
            })
            .collect();
        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|result| matches!(result, VerificationResult::Authorized(_)))
            .count();
        assert_eq!(accepted, 1);
    }

    #[test]
    fn replay_snapshot_round_trip_and_corruption_rejection() {
        let store = InMemoryReplayStore::default();
        assert!(store.accept_once(7, TokenId([2; 16])));
        let json = store.export_json(7).unwrap();
        let restored = InMemoryReplayStore::import_json(7, &json).unwrap();
        assert!(!restored.accept_once(7, TokenId([2; 16])));
        assert!(InMemoryReplayStore::import_json(8, &json).is_err());
        assert!(InMemoryReplayStore::import_json(7, "{broken").is_err());
    }
}
