#![forbid(unsafe_code)]

//! Fail-closed, one-shot ATv2 verification with atomic replay state.

use noticer_aetp::{required_claim, ClaimBound, ServiceBinding};
use noticer_crypto::VerifierKeyMaterial;
use noticer_protocol::{
    parse_inner, AtypicalityTokenEnvelope, FrameKind, InnerBody, KeyId, TokenId, WireServiceAlias,
    INNER_BODY_SIZE, OUTER_HEADER_SIZE, SIGNATURE_SIZE,
};
use noticer_types::{ActionCode, PolicyHash};
use serde::{Deserialize, Serialize};
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

pub trait ReplayStore: Send + Sync {
    /// Atomically returns true only for the first `(epoch, token_id)` use.
    fn accept_once(&self, epoch: u32, token_id: TokenId) -> bool;
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

#[derive(Clone, Copy, Debug)]
pub struct VerifierContext {
    pub expected_service: ServiceBinding,
    pub expected_epoch: u32,
    pub now_slot: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedAction {
    pub action: ActionCode,
    pub token_id: TokenId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationResult {
    Cover,
    Authorized(AuthorizedAction),
    Rejected,
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
        self.verify_detailed(bytes, context)
            .unwrap_or(VerificationResult::Rejected)
    }

    fn verify_detailed(
        &self,
        bytes: &[u8],
        context: VerifierContext,
    ) -> Result<VerificationResult, VerifyError> {
        let envelope =
            AtypicalityTokenEnvelope::from_slice(bytes).map_err(|_| VerifyError::Framing)?;
        let outer = envelope.outer().map_err(|_| VerifyError::Framing)?;
        if outer.public_epoch != context.expected_epoch {
            return Err(VerifyError::Binding);
        }
        let material = self
            .registry
            .get(outer.service_alias, outer.key_id, outer.public_epoch)
            .ok_or(VerifyError::UnknownKey)?;
        if material.service() != context.expected_service
            || material.epoch() != context.expected_epoch
        {
            return Err(VerifyError::Binding);
        }
        if material.expected_nonce(outer.public_bucket, outer.sequence) != outer.nonce {
            return Err(VerifyError::Nonce);
        }
        let outer_bytes = outer.encode();
        let plaintext = material
            .open(&outer.nonce, &outer_bytes, envelope.ciphertext())
            .map_err(|_| VerifyError::Authentication)?;
        let inner_bytes: [u8; INNER_BODY_SIZE] = plaintext[..INNER_BODY_SIZE]
            .try_into()
            .map_err(|_| VerifyError::Framing)?;
        let signature: [u8; SIGNATURE_SIZE] = plaintext[INNER_BODY_SIZE..]
            .try_into()
            .map_err(|_| VerifyError::Framing)?;
        let mut signed_message = [0_u8; OUTER_HEADER_SIZE + INNER_BODY_SIZE];
        signed_message[..OUTER_HEADER_SIZE].copy_from_slice(&outer_bytes);
        signed_message[OUTER_HEADER_SIZE..].copy_from_slice(&inner_bytes);
        material
            .verify(&signed_message, &signature)
            .map_err(|_| VerifyError::Signature)?;
        let body = parse_inner(&inner_bytes, outer.kind).map_err(|_| VerifyError::Body)?;
        if self.revocations.key_is_revoked(outer.key_id) {
            return Err(VerifyError::Revoked);
        }
        if outer.kind == FrameKind::Cover {
            return Ok(VerificationResult::Cover);
        }
        if context.now_slot < body.valid_from || context.now_slot > body.valid_until {
            return Err(VerifyError::Freshness);
        }
        if self.revocations.policy_is_revoked(body.policy_hash) {
            return Err(VerifyError::Revoked);
        }
        if !self.policies.permits(&body) {
            return Err(VerifyError::ClaimOrPolicy);
        }
        if !self.replay.accept_once(outer.public_epoch, body.token_id) {
            return Err(VerifyError::Replay);
        }
        Ok(VerificationResult::Authorized(AuthorizedAction {
            action: body.action,
            token_id: body.token_id,
        }))
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum VerifyError {
    #[error("framing")]
    Framing,
    #[error("unknown key")]
    UnknownKey,
    #[error("service or epoch binding")]
    Binding,
    #[error("nonce")]
    Nonce,
    #[error("authentication")]
    Authentication,
    #[error("signature")]
    Signature,
    #[error("body")]
    Body,
    #[error("freshness")]
    Freshness,
    #[error("revoked")]
    Revoked,
    #[error("claim or policy")]
    ClaimOrPolicy,
    #[error("replay")]
    Replay,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{required_claim, ActionObligation, BucketId};
    use noticer_crypto::CryptographicRootSecret;
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
