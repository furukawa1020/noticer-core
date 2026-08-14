#![forbid(unsafe_code)]

//! Fixed-size Noticer Provenance Lease v1 (NPL1).
//!
//! A production lease can only be issued from an opaque
//! `AppraisedProvenance`; descriptive assurance values are insufficient.
//!
//! ~~~compile_fail
//! use noticer_provenance_lease::ValidatedProvenanceLease;
//! let _ = ValidatedProvenanceLease { _private: () };
//! ~~~

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use noticer_nepp::PairwiseServiceAlias;
use noticer_provenance::{AssuranceProfileDigest, PipelineMeasurementHash};
use noticer_provenance_verifier::AppraisedProvenance;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const NPL1_SIZE: usize = 256;
pub const NPL1_BODY_SIZE: usize = 192;
pub const NPL1_SIGNATURE_SIZE: usize = 64;
pub const NPL1_PROFILE_ID: [u8; 4] = *b"NPL1";
pub const NPL1_VERSION: u8 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"NOTICER_NPL1_ED25519_V1";
const KEY_ID_DOMAIN: &[u8] = b"NOTICER_NPL1_VERIFIER_KEY_ID_V1";

const PROFILE_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 5;
const VERIFIER_KEY_ID_OFFSET: usize = 8;
const SERVICE_ALIAS_OFFSET: usize = 16;
const EPOCH_OFFSET: usize = 32;
const ISSUED_SLOT_OFFSET: usize = 36;
const EXPIRES_SLOT_OFFSET: usize = 40;
const ATV2_KEY_ID_OFFSET: usize = 44;
const PIPELINE_OFFSET: usize = 52;
const ASSURANCE_OFFSET: usize = 84;
const POLICY_OFFSET: usize = 116;
const COLLECTOR_SESSION_OFFSET: usize = 148;
const NONCE_OFFSET: usize = 180;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeaseVerifierKeyId(pub [u8; 8]);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LeaseNonce([u8; 12]);

impl LeaseNonce {
    pub fn new(value: [u8; 12]) -> Result<Self, LeaseError> {
        if value == [0; 12] {
            return Err(LeaseError::InvalidNonce);
        }
        Ok(Self(value))
    }

    pub const fn as_bytes(self) -> [u8; 12] {
        self.0
    }
}

impl fmt::Debug for LeaseNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeaseNonce(REDACTED)")
    }
}

pub struct LeaseSigningKey {
    key: SigningKey,
    key_id: LeaseVerifierKeyId,
}

impl LeaseSigningKey {
    pub fn from_secret_bytes(mut secret: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        let key_id = lease_key_id(&key.verifying_key());
        Self { key, key_id }
    }

    pub const fn key_id(&self) -> LeaseVerifierKeyId {
        self.key_id
    }

    pub fn verifier_key(&self) -> LeaseVerifierKey {
        LeaseVerifierKey {
            key_id: self.key_id,
            key: self.key.verifying_key(),
        }
    }
}

impl fmt::Debug for LeaseSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseSigningKey")
            .field("key_id", &self.key_id)
            .field("secret", &"REDACTED")
            .finish()
    }
}

#[derive(Clone)]
pub struct LeaseVerifierKey {
    key_id: LeaseVerifierKeyId,
    key: VerifyingKey,
}

impl LeaseVerifierKey {
    pub const fn key_id(&self) -> LeaseVerifierKeyId {
        self.key_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicLeaseSchedule {
    pub period_slots: u32,
    pub phase_slot: u32,
}

impl PublicLeaseSchedule {
    pub fn validate(self) -> Result<Self, LeaseError> {
        if self.period_slots == 0 || self.phase_slot >= self.period_slots {
            return Err(LeaseError::InvalidSchedule);
        }
        Ok(self)
    }

    pub const fn contains(self, public_slot: u32) -> bool {
        public_slot >= self.phase_slot && (public_slot - self.phase_slot) % self.period_slots == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseIssuancePolicy {
    pub maximum_lifetime_slots: u32,
    pub schedule: PublicLeaseSchedule,
}

impl LeaseIssuancePolicy {
    pub fn validate(self) -> Result<Self, LeaseError> {
        if self.maximum_lifetime_slots == 0 {
            return Err(LeaseError::InvalidLifetimePolicy);
        }
        self.schedule.validate()?;
        Ok(self)
    }
}

pub struct ProvenanceLeaseIssuer {
    key: LeaseSigningKey,
    policy: LeaseIssuancePolicy,
}

impl ProvenanceLeaseIssuer {
    pub fn new(key: LeaseSigningKey, policy: LeaseIssuancePolicy) -> Result<Self, LeaseError> {
        Ok(Self {
            key,
            policy: policy.validate()?,
        })
    }

    pub fn issue(
        &self,
        appraisal: &AppraisedProvenance,
        public_epoch: u32,
        issued_public_slot: u32,
        nonce: LeaseNonce,
    ) -> Result<ProvenanceLease, LeaseError> {
        if u64::from(public_epoch) != appraisal.epoch() {
            return Err(LeaseError::EpochMismatch);
        }
        if !self.policy.schedule.contains(issued_public_slot) {
            return Err(LeaseError::OffScheduleIssuance);
        }
        if u64::from(issued_public_slot) < appraisal.created_public_slot()
            || u64::from(issued_public_slot) >= appraisal.expires_public_slot()
        {
            return Err(LeaseError::AppraisalNotCurrent);
        }
        let policy_expiry = issued_public_slot
            .checked_add(self.policy.maximum_lifetime_slots)
            .ok_or(LeaseError::SlotOverflow)?;
        let appraisal_expiry =
            u32::try_from(appraisal.expires_public_slot()).map_err(|_| LeaseError::SlotOverflow)?;
        let expires_public_slot = policy_expiry.min(appraisal_expiry);
        if expires_public_slot <= issued_public_slot {
            return Err(LeaseError::InvalidLeaseLifetime);
        }
        let claims = LeaseClaims {
            verifier_key_id: self.key.key_id(),
            service_alias: appraisal.service_alias(),
            public_epoch,
            issued_public_slot,
            expires_public_slot,
            atv2_issuer_key_id: appraisal.atv2_issuer_key_id(),
            pipeline: appraisal.pipeline(),
            assurance: appraisal.profile().digest(),
            policy_hash: appraisal.policy_hash(),
            collector_session_public_key_hash: appraisal.collector_session_public_key_hash(),
            nonce,
        };
        let body = encode_body(claims);
        let signature = self.key.key.sign(&signature_message(&body));
        let mut bytes = [0; NPL1_SIZE];
        bytes[..NPL1_BODY_SIZE].copy_from_slice(&body);
        bytes[NPL1_BODY_SIZE..].copy_from_slice(&signature.to_bytes());
        Ok(ProvenanceLease(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseClaims {
    pub verifier_key_id: LeaseVerifierKeyId,
    pub service_alias: PairwiseServiceAlias,
    pub public_epoch: u32,
    pub issued_public_slot: u32,
    pub expires_public_slot: u32,
    pub atv2_issuer_key_id: [u8; 8],
    pub pipeline: PipelineMeasurementHash,
    pub assurance: AssuranceProfileDigest,
    pub policy_hash: [u8; 32],
    pub collector_session_public_key_hash: [u8; 32],
    pub nonce: LeaseNonce,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProvenanceLease([u8; NPL1_SIZE]);

impl ProvenanceLease {
    pub fn from_bytes(bytes: [u8; NPL1_SIZE]) -> Result<Self, LeaseError> {
        parse_body(&bytes[..NPL1_BODY_SIZE])?;
        Signature::from_slice(&bytes[NPL1_BODY_SIZE..])
            .map_err(|_| LeaseError::MalformedSignature)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; NPL1_SIZE] {
        &self.0
    }

    pub fn claims(&self) -> Result<LeaseClaims, LeaseError> {
        parse_body(&self.0[..NPL1_BODY_SIZE])
    }
}

impl fmt::Debug for ProvenanceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvenanceLease")
            .field("profile", &"NPL1")
            .field("size", &NPL1_SIZE)
            .field("private_measurement", &"ABSENT")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedLeaseBindings {
    pub verifier_key_id: LeaseVerifierKeyId,
    pub service_alias: PairwiseServiceAlias,
    pub public_epoch: u32,
    pub atv2_issuer_key_id: [u8; 8],
    pub pipeline: PipelineMeasurementHash,
    pub assurance: AssuranceProfileDigest,
    pub policy_hash: [u8; 32],
    pub collector_session_public_key_hash: [u8; 32],
    pub current_public_slot: u32,
}

pub trait LeaseReplayGuard: Send + Sync {
    fn accept_once(&self, public_epoch: u32, nonce: LeaseNonce) -> bool;
}

#[derive(Default)]
pub struct InMemoryLeaseReplayGuard {
    seen: Mutex<HashSet<(u32, LeaseNonce)>>,
}

impl LeaseReplayGuard for InMemoryLeaseReplayGuard {
    fn accept_once(&self, public_epoch: u32, nonce: LeaseNonce) -> bool {
        self.seen
            .lock()
            .map(|mut seen| seen.insert((public_epoch, nonce)))
            .unwrap_or(false)
    }
}

pub fn validate_lease(
    lease: &ProvenanceLease,
    key: &LeaseVerifierKey,
    expected: ExpectedLeaseBindings,
    replay: &dyn LeaseReplayGuard,
) -> Result<ValidatedProvenanceLease, LeaseError> {
    let claims = parse_body(&lease.0[..NPL1_BODY_SIZE])?;
    if claims.verifier_key_id != key.key_id || claims.verifier_key_id != expected.verifier_key_id {
        return Err(LeaseError::WrongVerifierKey);
    }
    let signature = Signature::from_slice(&lease.0[NPL1_BODY_SIZE..])
        .map_err(|_| LeaseError::MalformedSignature)?;
    key.key
        .verify(&signature_message(&lease.0[..NPL1_BODY_SIZE]), &signature)
        .map_err(|_| LeaseError::InvalidSignature)?;
    if claims.service_alias != expected.service_alias {
        return Err(LeaseError::WrongService);
    }
    if claims.public_epoch != expected.public_epoch {
        return Err(LeaseError::EpochMismatch);
    }
    if claims.atv2_issuer_key_id != expected.atv2_issuer_key_id {
        return Err(LeaseError::WrongAtv2Key);
    }
    if claims.pipeline != expected.pipeline {
        return Err(LeaseError::WrongPipeline);
    }
    if claims.assurance != expected.assurance {
        return Err(LeaseError::WrongAssurance);
    }
    if claims.policy_hash != expected.policy_hash {
        return Err(LeaseError::WrongPolicy);
    }
    if claims.collector_session_public_key_hash != expected.collector_session_public_key_hash {
        return Err(LeaseError::WrongCollectorSession);
    }
    if expected.current_public_slot < claims.issued_public_slot
        || expected.current_public_slot >= claims.expires_public_slot
    {
        return Err(LeaseError::LeaseExpired);
    }
    if !replay.accept_once(claims.public_epoch, claims.nonce) {
        return Err(LeaseError::Replay);
    }
    Ok(ValidatedProvenanceLease {
        claims,
        _private: (),
    })
}

/// Sealed relying-party capability produced only after signature, binding,
/// lifetime, and replay validation.
pub struct ValidatedProvenanceLease {
    claims: LeaseClaims,
    _private: (),
}

impl ValidatedProvenanceLease {
    pub const fn claims(&self) -> LeaseClaims {
        self.claims
    }
}

impl fmt::Debug for ValidatedProvenanceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedProvenanceLease")
            .field("public_epoch", &self.claims.public_epoch)
            .field("expires_public_slot", &self.claims.expires_public_slot)
            .field("bindings", &"VALIDATED")
            .finish()
    }
}

fn encode_body(claims: LeaseClaims) -> [u8; NPL1_BODY_SIZE] {
    let mut body = [0; NPL1_BODY_SIZE];
    body[PROFILE_OFFSET..VERSION_OFFSET].copy_from_slice(&NPL1_PROFILE_ID);
    body[VERSION_OFFSET] = NPL1_VERSION;
    body[FLAGS_OFFSET] = 0;
    body[VERIFIER_KEY_ID_OFFSET..SERVICE_ALIAS_OFFSET].copy_from_slice(&claims.verifier_key_id.0);
    body[SERVICE_ALIAS_OFFSET..EPOCH_OFFSET].copy_from_slice(&claims.service_alias.0);
    body[EPOCH_OFFSET..ISSUED_SLOT_OFFSET].copy_from_slice(&claims.public_epoch.to_be_bytes());
    body[ISSUED_SLOT_OFFSET..EXPIRES_SLOT_OFFSET]
        .copy_from_slice(&claims.issued_public_slot.to_be_bytes());
    body[EXPIRES_SLOT_OFFSET..ATV2_KEY_ID_OFFSET]
        .copy_from_slice(&claims.expires_public_slot.to_be_bytes());
    body[ATV2_KEY_ID_OFFSET..PIPELINE_OFFSET].copy_from_slice(&claims.atv2_issuer_key_id);
    body[PIPELINE_OFFSET..ASSURANCE_OFFSET].copy_from_slice(&claims.pipeline.0);
    body[ASSURANCE_OFFSET..POLICY_OFFSET].copy_from_slice(&claims.assurance.0);
    body[POLICY_OFFSET..COLLECTOR_SESSION_OFFSET].copy_from_slice(&claims.policy_hash);
    body[COLLECTOR_SESSION_OFFSET..NONCE_OFFSET]
        .copy_from_slice(&claims.collector_session_public_key_hash);
    body[NONCE_OFFSET..NPL1_BODY_SIZE].copy_from_slice(&claims.nonce.0);
    body
}

fn parse_body(body: &[u8]) -> Result<LeaseClaims, LeaseError> {
    if body.len() != NPL1_BODY_SIZE {
        return Err(LeaseError::MalformedLength);
    }
    if body[PROFILE_OFFSET..VERSION_OFFSET] != NPL1_PROFILE_ID {
        return Err(LeaseError::UnknownProfile);
    }
    if body[VERSION_OFFSET] != NPL1_VERSION {
        return Err(LeaseError::UnknownVersion);
    }
    if body[FLAGS_OFFSET..VERIFIER_KEY_ID_OFFSET]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(LeaseError::NonCanonicalEncoding);
    }
    let claims = LeaseClaims {
        verifier_key_id: LeaseVerifierKeyId(copy_array(body, VERIFIER_KEY_ID_OFFSET)?),
        service_alias: PairwiseServiceAlias(copy_array(body, SERVICE_ALIAS_OFFSET)?),
        public_epoch: u32::from_be_bytes(copy_array(body, EPOCH_OFFSET)?),
        issued_public_slot: u32::from_be_bytes(copy_array(body, ISSUED_SLOT_OFFSET)?),
        expires_public_slot: u32::from_be_bytes(copy_array(body, EXPIRES_SLOT_OFFSET)?),
        atv2_issuer_key_id: copy_array(body, ATV2_KEY_ID_OFFSET)?,
        pipeline: PipelineMeasurementHash(copy_array(body, PIPELINE_OFFSET)?),
        assurance: AssuranceProfileDigest(copy_array(body, ASSURANCE_OFFSET)?),
        policy_hash: copy_array(body, POLICY_OFFSET)?,
        collector_session_public_key_hash: copy_array(body, COLLECTOR_SESSION_OFFSET)?,
        nonce: LeaseNonce(copy_array(body, NONCE_OFFSET)?),
    };
    if claims.verifier_key_id.0 == [0; 8]
        || claims.service_alias.0 == [0; 16]
        || claims.issued_public_slot >= claims.expires_public_slot
        || claims.atv2_issuer_key_id == [0; 8]
        || claims.pipeline.0 == [0; 32]
        || claims.assurance.0 == [0; 32]
        || claims.policy_hash == [0; 32]
        || claims.collector_session_public_key_hash == [0; 32]
        || claims.nonce.0 == [0; 12]
    {
        return Err(LeaseError::InvalidBinding);
    }
    Ok(claims)
}

fn copy_array<const N: usize>(body: &[u8], offset: usize) -> Result<[u8; N], LeaseError> {
    body.get(offset..offset + N)
        .ok_or(LeaseError::MalformedLength)?
        .try_into()
        .map_err(|_| LeaseError::MalformedLength)
}

fn signature_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(body);
    message
}

fn lease_key_id(key: &VerifyingKey) -> LeaseVerifierKeyId {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    LeaseVerifierKeyId(digest[..8].try_into().expect("fixed digest prefix"))
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseError {
    #[error("lease nonce must not be all zero")]
    InvalidNonce,
    #[error("public lease schedule is invalid")]
    InvalidSchedule,
    #[error("maximum lease lifetime is invalid")]
    InvalidLifetimePolicy,
    #[error("appraisal epoch and public lease epoch differ")]
    EpochMismatch,
    #[error("lease issuance attempted outside the public schedule")]
    OffScheduleIssuance,
    #[error("appraisal is not current at the issuance slot")]
    AppraisalNotCurrent,
    #[error("public slot cannot be represented in NPL1")]
    SlotOverflow,
    #[error("lease lifetime is empty")]
    InvalidLeaseLifetime,
    #[error("NPL1 input length is invalid")]
    MalformedLength,
    #[error("NPL1 signature bytes are malformed")]
    MalformedSignature,
    #[error("NPL1 profile is unknown")]
    UnknownProfile,
    #[error("NPL1 version is unknown")]
    UnknownVersion,
    #[error("NPL1 flags or reserved bytes are non-canonical")]
    NonCanonicalEncoding,
    #[error("NPL1 contains an invalid all-zero or lifetime binding")]
    InvalidBinding,
    #[error("NPL1 verifier key binding is wrong")]
    WrongVerifierKey,
    #[error("NPL1 Ed25519 signature is invalid")]
    InvalidSignature,
    #[error("NPL1 service binding is wrong")]
    WrongService,
    #[error("NPL1 ATv2 issuer key binding is wrong")]
    WrongAtv2Key,
    #[error("NPL1 pipeline binding is wrong")]
    WrongPipeline,
    #[error("NPL1 assurance binding is wrong")]
    WrongAssurance,
    #[error("NPL1 policy binding is wrong")]
    WrongPolicy,
    #[error("NPL1 collector session binding is wrong")]
    WrongCollectorSession,
    #[error("NPL1 is not valid at the current public slot")]
    LeaseExpired,
    #[error("NPL1 nonce was already accepted")]
    Replay,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use noticer_nepp::{
        ChallengeStore, ExpectedBindings, NeppClaims, ReferenceSoftwareAttester, VerifierChallenge,
        VerifierOnlyClaims,
    };
    use noticer_provenance::{
        AssuranceProfile, BootStateAssurance, CollectorKeyAssurance, FreshnessAssurance,
        PipelineAssurance, SourceAssurance,
    };
    use noticer_provenance_verifier::{
        AppraisalRequest, PlatformEvidence, ProvenanceAppraiser, ReferenceValueStore,
        SourceEvidence,
    };
    use proptest::prelude::*;

    const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([3; 32]);
    const POLICY: [u8; 32] = [8; 32];
    const ATV2_ID: [u8; 8] = [5; 8];
    const ATV2_HASH: [u8; 32] = [6; 32];
    const SESSION_HASH: [u8; 32] = [4; 32];

    fn appraisal() -> AppraisedProvenance {
        let attester = ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap();
        let challenge = VerifierChallenge::new([1; 32]).unwrap();
        let private = VerifierOnlyClaims::new(b"tier=a".to_vec()).unwrap();
        let profile = AssuranceProfile {
            source: SourceAssurance::synthetic_replay(),
            collector_key: CollectorKeyAssurance::software(),
            boot_state: BootStateAssurance::unknown(),
            pipeline: PipelineAssurance::self_declared(),
            freshness: FreshnessAssurance::appraised_verifier_challenge(),
        };
        let evidence = attester
            .sign(NeppClaims {
                challenge,
                service_alias: PairwiseServiceAlias([2; 16]),
                epoch: 9,
                pipeline: PIPELINE,
                assurance: profile.digest(),
                collector_session_public_key_hash: SESSION_HASH,
                atv2_issuer_key_id: ATV2_ID,
                atv2_issuer_public_key_hash: ATV2_HASH,
                policy_hash: POLICY,
                created_public_slot: 96,
                expires_public_slot: 120,
                verifier_only_claims: private.digest(),
            })
            .unwrap();
        let expected = ExpectedBindings {
            challenge,
            service_alias: PairwiseServiceAlias([2; 16]),
            epoch: 9,
            pipeline: PIPELINE,
            atv2_issuer_key_id: ATV2_ID,
            atv2_issuer_public_key_hash: ATV2_HASH,
            policy_hash: POLICY,
            current_public_slot: 100,
        };
        let references = ReferenceValueStore::new(
            BTreeSet::from([attester.key_id()]),
            BTreeSet::new(),
            BTreeSet::from([PIPELINE]),
            BTreeSet::from([POLICY]),
            BTreeSet::new(),
            BTreeSet::from([(ATV2_ID, ATV2_HASH)]),
        )
        .unwrap();
        let mut challenges = ChallengeStore::new(4).unwrap();
        challenges.issue(challenge, 110).unwrap();
        ProvenanceAppraiser::new(references, challenges)
            .appraise(AppraisalRequest {
                evidence: &evidence,
                verifier_key: &attester.verifier(),
                expected: &expected,
                verifier_only_claims: &private,
                platform: PlatformEvidence::ReferenceSoftware,
                source: SourceEvidence::SyntheticReplay,
                minimum_assurance: profile,
            })
            .unwrap()
    }

    fn issuer(maximum_lifetime_slots: u32) -> ProvenanceLeaseIssuer {
        ProvenanceLeaseIssuer::new(
            LeaseSigningKey::from_secret_bytes([11; 32]),
            LeaseIssuancePolicy {
                maximum_lifetime_slots,
                schedule: PublicLeaseSchedule {
                    period_slots: 10,
                    phase_slot: 0,
                },
            },
        )
        .unwrap()
    }

    fn expected(
        lease: &ProvenanceLease,
        verifier: &LeaseVerifierKey,
        current_public_slot: u32,
    ) -> ExpectedLeaseBindings {
        let claims = lease.claims().unwrap();
        ExpectedLeaseBindings {
            verifier_key_id: verifier.key_id(),
            service_alias: claims.service_alias,
            public_epoch: claims.public_epoch,
            atv2_issuer_key_id: claims.atv2_issuer_key_id,
            pipeline: claims.pipeline,
            assurance: claims.assurance,
            policy_hash: claims.policy_hash,
            collector_session_public_key_hash: claims.collector_session_public_key_hash,
            current_public_slot,
        }
    }

    #[test]
    fn lease_is_exactly_256_bytes_and_validates_once() {
        let appraisal = appraisal();
        let issuer = issuer(10);
        let lease = issuer
            .issue(&appraisal, 9, 100, LeaseNonce::new([1; 12]).unwrap())
            .unwrap();
        let verifier = issuer.key.verifier_key();
        assert_eq!(lease.as_bytes().len(), 256);
        let replay = InMemoryLeaseReplayGuard::default();
        let validated =
            validate_lease(&lease, &verifier, expected(&lease, &verifier, 105), &replay).unwrap();
        assert_eq!(validated.claims().expires_public_slot, 110);
        assert_eq!(
            validate_lease(&lease, &verifier, expected(&lease, &verifier, 105), &replay)
                .unwrap_err(),
            LeaseError::Replay
        );
    }

    #[test]
    fn policy_and_appraisal_cap_the_lease_lifetime() {
        let appraisal = appraisal();
        let policy_capped = issuer(7)
            .issue(&appraisal, 9, 100, LeaseNonce::new([2; 12]).unwrap())
            .unwrap();
        assert_eq!(policy_capped.claims().unwrap().expires_public_slot, 107);
        let appraisal_capped = issuer(100)
            .issue(&appraisal, 9, 100, LeaseNonce::new([3; 12]).unwrap())
            .unwrap();
        assert_eq!(appraisal_capped.claims().unwrap().expires_public_slot, 120);
    }

    #[test]
    fn mutation_signature_expiry_and_binding_mismatch_are_rejected() {
        let appraisal = appraisal();
        let issuer = issuer(10);
        let lease = issuer
            .issue(&appraisal, 9, 100, LeaseNonce::new([4; 12]).unwrap())
            .unwrap();
        let verifier = issuer.key.verifier_key();

        let mut mutation = lease.as_bytes().to_owned();
        mutation[PIPELINE_OFFSET] ^= 1;
        let mutation = ProvenanceLease::from_bytes(mutation).unwrap();
        assert_eq!(
            validate_lease(
                &mutation,
                &verifier,
                expected(&lease, &verifier, 105),
                &InMemoryLeaseReplayGuard::default(),
            )
            .unwrap_err(),
            LeaseError::InvalidSignature
        );

        let mut signature = lease.as_bytes().to_owned();
        signature[NPL1_BODY_SIZE] ^= 1;
        let signature = ProvenanceLease::from_bytes(signature).unwrap();
        assert_eq!(
            validate_lease(
                &signature,
                &verifier,
                expected(&lease, &verifier, 105),
                &InMemoryLeaseReplayGuard::default(),
            )
            .unwrap_err(),
            LeaseError::InvalidSignature
        );

        assert_eq!(
            validate_lease(
                &lease,
                &verifier,
                expected(&lease, &verifier, 110),
                &InMemoryLeaseReplayGuard::default(),
            )
            .unwrap_err(),
            LeaseError::LeaseExpired
        );

        let mut wrong = expected(&lease, &verifier, 105);
        wrong.policy_hash = [99; 32];
        assert_eq!(
            validate_lease(
                &lease,
                &verifier,
                wrong,
                &InMemoryLeaseReplayGuard::default(),
            )
            .unwrap_err(),
            LeaseError::WrongPolicy
        );
    }

    #[test]
    fn issuance_must_follow_the_public_schedule() {
        assert_eq!(
            issuer(10)
                .issue(&appraisal(), 9, 101, LeaseNonce::new([5; 12]).unwrap())
                .unwrap_err(),
            LeaseError::OffScheduleIssuance
        );
    }

    #[test]
    fn artifact_schema_has_no_private_measurement_or_stable_identifier() {
        let fields = [
            "verifier_key_id",
            "service_alias",
            "public_epoch",
            "issued_public_slot",
            "expires_public_slot",
            "atv2_issuer_key_id",
            "pipeline",
            "assurance",
            "policy_hash",
            "collector_session_public_key_hash",
            "nonce",
        ];
        for forbidden in [
            "raw_ppg",
            "raw_acc",
            "exact_sample_count",
            "exact_acquisition_time",
            "sensor_serial",
            "ble_address",
            "stable_android_id",
            "private_baseline",
        ] {
            assert!(!fields.contains(&forbidden));
        }
    }

    proptest! {
        #[test]
        fn arbitrary_fixed_bytes_never_panic(bytes in any::<[u8; NPL1_SIZE]>()) {
            let _ = ProvenanceLease::from_bytes(bytes);
        }
    }
}
