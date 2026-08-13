#![forbid(unsafe_code)]

//! Noticer Evidence Provenance Profile version 1 (NEPP-v1).
//!
//! This is an EAT-inspired application profile, not a generic EAT or RATS
//! implementation. The reference signer is a software P-256 attester and does
//! not claim hardware-backed key assurance.

use std::collections::{HashMap, HashSet};
use std::fmt;

use noticer_provenance::{
    AssuranceProfile, AssuranceProfileDigest, PipelineMeasurementHash, SoftwareAttesterClaim,
};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const NEPP_PROFILE_ID: [u8; 4] = *b"NEPP";
pub const NEPP_VERSION: u8 = 1;
pub const NEPP_BODY_SIZE: usize = 320;
pub const NEPP_SIGNATURE_SIZE: usize = 64;
pub const NEPP_EVIDENCE_SIZE: usize = NEPP_BODY_SIZE + NEPP_SIGNATURE_SIZE;
const SIGNATURE_DOMAIN: &[u8] = b"NOTICER_NEPP_V1_P256_SHA256";
const COLLECTOR_KEY_DOMAIN: &[u8] = b"NOTICER_NEPP_COLLECTOR_KEY_ID_V1";

const PROFILE_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 5;
const EPOCH_OFFSET: usize = 8;
const CREATED_OFFSET: usize = 16;
const EXPIRES_OFFSET: usize = 24;
const CHALLENGE_OFFSET: usize = 32;
const SERVICE_ALIAS_OFFSET: usize = 64;
const PIPELINE_OFFSET: usize = 80;
const ASSURANCE_OFFSET: usize = 112;
const COLLECTOR_KEY_OFFSET: usize = 144;
const COLLECTOR_SESSION_KEY_OFFSET: usize = 176;
const ATV2_ISSUER_KEY_ID_OFFSET: usize = 208;
const ATV2_PUBLIC_KEY_HASH_OFFSET: usize = 216;
const POLICY_OFFSET: usize = 248;
const VERIFIER_ONLY_DIGEST_OFFSET: usize = 280;
const RESERVED_OFFSET: usize = 312;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct VerifierChallenge([u8; 32]);

impl VerifierChallenge {
    pub fn new(value: [u8; 32]) -> Result<Self, NeppError> {
        if value == [0; 32] {
            return Err(NeppError::InvalidChallenge);
        }
        Ok(Self(value))
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for VerifierChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifierChallenge(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PairwiseServiceAlias(pub [u8; 16]);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectorKeyId([u8; 32]);

impl CollectorKeyId {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for CollectorKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CollectorKeyId(VERIFIER_ONLY)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerifierOnlyClaimsDigest([u8; 32]);

impl VerifierOnlyClaimsDigest {
    pub fn new(value: [u8; 32]) -> Result<Self, NeppError> {
        if value == [0; 32] {
            return Err(NeppError::InvalidVerifierOnlyDigest);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for VerifierOnlyClaimsDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifierOnlyClaimsDigest(VERIFIER_ONLY)")
    }
}

pub struct VerifierOnlyClaims {
    canonical_claims: Box<[u8]>,
}

impl VerifierOnlyClaims {
    pub fn new(canonical_claims: Vec<u8>) -> Result<Self, NeppError> {
        if canonical_claims.is_empty() || canonical_claims.len() > 4_096 {
            return Err(NeppError::InvalidVerifierOnlyClaims);
        }
        Ok(Self {
            canonical_claims: canonical_claims.into_boxed_slice(),
        })
    }

    pub fn digest(&self) -> VerifierOnlyClaimsDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"NOTICER_NEPP_VERIFIER_ONLY_CLAIMS_V1");
        hasher.update((self.canonical_claims.len() as u32).to_be_bytes());
        hasher.update(&self.canonical_claims);
        VerifierOnlyClaimsDigest(hasher.finalize().into())
    }
}

impl fmt::Debug for VerifierOnlyClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifierOnlyClaims(VERIFIER_ONLY)")
    }
}

impl Drop for VerifierOnlyClaims {
    fn drop(&mut self) {
        self.canonical_claims.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeppClaims {
    pub challenge: VerifierChallenge,
    pub service_alias: PairwiseServiceAlias,
    pub epoch: u64,
    pub pipeline: PipelineMeasurementHash,
    pub assurance: AssuranceProfileDigest,
    pub collector_session_public_key_hash: [u8; 32],
    pub atv2_issuer_key_id: [u8; 8],
    pub atv2_issuer_public_key_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub created_public_slot: u64,
    pub expires_public_slot: u64,
    pub verifier_only_claims: VerifierOnlyClaimsDigest,
}

impl NeppClaims {
    pub fn validate(self) -> Result<Self, NeppError> {
        if self.created_public_slot >= self.expires_public_slot {
            return Err(NeppError::InvalidLifetime);
        }
        if self.challenge.0 == [0; 32]
            || self.service_alias.0 == [0; 16]
            || self.pipeline.0 == [0; 32]
            || self.assurance.0 == [0; 32]
            || self.collector_session_public_key_hash == [0; 32]
            || self.atv2_issuer_key_id == [0; 8]
            || self.atv2_issuer_public_key_hash == [0; 32]
            || self.policy_hash == [0; 32]
            || self.verifier_only_claims.0 == [0; 32]
        {
            return Err(NeppError::InvalidBinding);
        }
        Ok(self)
    }
}

pub struct ReferenceSoftwareAttester {
    key: SigningKey,
    key_id: CollectorKeyId,
}

impl ReferenceSoftwareAttester {
    pub fn from_secret_bytes(mut secret: [u8; 32]) -> Result<Self, NeppError> {
        let key = SigningKey::from_bytes((&secret).into()).map_err(|_| NeppError::InvalidKey)?;
        secret.fill(0);
        let key_id = collector_key_id(key.verifying_key());
        Ok(Self { key, key_id })
    }

    pub const fn key_id(&self) -> CollectorKeyId {
        self.key_id
    }

    pub fn verifier(&self) -> NeppVerifierKey {
        NeppVerifierKey {
            key_id: self.key_id,
            key: *self.key.verifying_key(),
        }
    }

    pub fn maximum_assurance(&self) -> AssuranceProfile {
        AssuranceProfile {
            collector_key: SoftwareAttesterClaim::new().maximum_assurance(),
            ..AssuranceProfile::lab_reference()
        }
    }

    pub fn sign(&self, claims: NeppClaims) -> Result<NeppEvidence, NeppError> {
        let claims = claims.validate()?;
        let body = encode_body(claims, self.key_id);
        let message = signature_message(&body);
        let signature: Signature = self.key.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut bytes = [0; NEPP_EVIDENCE_SIZE];
        bytes[..NEPP_BODY_SIZE].copy_from_slice(&body);
        bytes[NEPP_BODY_SIZE..].copy_from_slice(&signature.to_bytes());
        Ok(NeppEvidence(bytes))
    }
}

impl fmt::Debug for ReferenceSoftwareAttester {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceSoftwareAttester")
            .field("key_id", &self.key_id)
            .field("key", &"SOFTWARE_KEY_REDACTED")
            .finish()
    }
}

#[derive(Clone)]
pub struct NeppVerifierKey {
    key_id: CollectorKeyId,
    key: VerifyingKey,
}

impl NeppVerifierKey {
    pub const fn key_id(&self) -> CollectorKeyId {
        self.key_id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NeppEvidence([u8; NEPP_EVIDENCE_SIZE]);

impl NeppEvidence {
    pub fn from_bytes(bytes: [u8; NEPP_EVIDENCE_SIZE]) -> Result<Self, NeppError> {
        parse_body(&bytes[..NEPP_BODY_SIZE])?;
        parse_canonical_signature(&bytes[NEPP_BODY_SIZE..])?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; NEPP_EVIDENCE_SIZE] {
        &self.0
    }

    pub fn claims(&self) -> Result<NeppClaims, NeppError> {
        parse_body(&self.0[..NEPP_BODY_SIZE]).map(|parsed| parsed.claims)
    }
}

impl fmt::Debug for NeppEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeppEvidence")
            .field("profile", &"NEPP-v1")
            .field("size", &NEPP_EVIDENCE_SIZE)
            .field("claims", &"VERIFIER_ONLY")
            .finish()
    }
}

pub struct ChallengeStore {
    pending: HashMap<VerifierChallenge, u64>,
    consumed: HashSet<VerifierChallenge>,
    maximum_pending: usize,
}

impl ChallengeStore {
    pub fn new(maximum_pending: usize) -> Result<Self, NeppError> {
        if maximum_pending == 0 || maximum_pending > 65_536 {
            return Err(NeppError::InvalidChallengeStore);
        }
        Ok(Self {
            pending: HashMap::new(),
            consumed: HashSet::new(),
            maximum_pending,
        })
    }

    pub fn issue(
        &mut self,
        challenge: VerifierChallenge,
        expires_public_slot: u64,
    ) -> Result<(), NeppError> {
        if expires_public_slot == 0
            || self.pending.len() >= self.maximum_pending
            || self.pending.contains_key(&challenge)
            || self.consumed.contains(&challenge)
        {
            return Err(NeppError::ChallengeUnavailable);
        }
        self.pending.insert(challenge, expires_public_slot);
        Ok(())
    }

    fn consume(
        &mut self,
        challenge: VerifierChallenge,
        current_public_slot: u64,
    ) -> Result<(), NeppError> {
        if self.consumed.contains(&challenge) {
            return Err(NeppError::ChallengeReplayed);
        }
        let expires = self
            .pending
            .remove(&challenge)
            .ok_or(NeppError::WrongChallenge)?;
        self.consumed.insert(challenge);
        if current_public_slot > expires {
            return Err(NeppError::StaleChallenge);
        }
        Ok(())
    }
}

pub struct ExpectedBindings {
    pub challenge: VerifierChallenge,
    pub service_alias: PairwiseServiceAlias,
    pub epoch: u64,
    pub pipeline: PipelineMeasurementHash,
    pub atv2_issuer_key_id: [u8; 8],
    pub atv2_issuer_public_key_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub current_public_slot: u64,
}

pub fn verify_nepp(
    evidence: &NeppEvidence,
    key: &NeppVerifierKey,
    expected: &ExpectedBindings,
    challenges: &mut ChallengeStore,
) -> Result<VerifiedNepp, NeppError> {
    let parsed = parse_body(&evidence.0[..NEPP_BODY_SIZE])?;
    if parsed.collector_key_id != key.key_id {
        return Err(NeppError::WrongCollectorKey);
    }
    let signature = parse_canonical_signature(&evidence.0[NEPP_BODY_SIZE..])?;
    key.key
        .verify(
            &signature_message(&evidence.0[..NEPP_BODY_SIZE]),
            &signature,
        )
        .map_err(|_| NeppError::InvalidSignature)?;
    let claims = parsed.claims;
    if claims.challenge != expected.challenge {
        return Err(NeppError::WrongChallenge);
    }
    if claims.service_alias != expected.service_alias {
        return Err(NeppError::WrongService);
    }
    if claims.epoch != expected.epoch {
        return Err(NeppError::WrongEpoch);
    }
    if claims.pipeline != expected.pipeline {
        return Err(NeppError::WrongPipeline);
    }
    if claims.atv2_issuer_key_id != expected.atv2_issuer_key_id
        || claims.atv2_issuer_public_key_hash != expected.atv2_issuer_public_key_hash
    {
        return Err(NeppError::WrongAtv2Key);
    }
    if claims.policy_hash != expected.policy_hash {
        return Err(NeppError::WrongPolicy);
    }
    if expected.current_public_slot < claims.created_public_slot
        || expected.current_public_slot > claims.expires_public_slot
    {
        return Err(NeppError::EvidenceExpired);
    }
    challenges.consume(claims.challenge, expected.current_public_slot)?;
    Ok(VerifiedNepp {
        claims,
        collector_key_id: parsed.collector_key_id,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNepp {
    claims: NeppClaims,
    collector_key_id: CollectorKeyId,
}

impl VerifiedNepp {
    pub const fn claims(self) -> NeppClaims {
        self.claims
    }

    pub const fn collector_key_id(self) -> CollectorKeyId {
        self.collector_key_id
    }
}

struct ParsedBody {
    claims: NeppClaims,
    collector_key_id: CollectorKeyId,
}

fn encode_body(claims: NeppClaims, collector_key_id: CollectorKeyId) -> [u8; NEPP_BODY_SIZE] {
    let mut body = [0; NEPP_BODY_SIZE];
    body[PROFILE_OFFSET..VERSION_OFFSET].copy_from_slice(&NEPP_PROFILE_ID);
    body[VERSION_OFFSET] = NEPP_VERSION;
    body[FLAGS_OFFSET] = 0;
    body[EPOCH_OFFSET..CREATED_OFFSET].copy_from_slice(&claims.epoch.to_be_bytes());
    body[CREATED_OFFSET..EXPIRES_OFFSET].copy_from_slice(&claims.created_public_slot.to_be_bytes());
    body[EXPIRES_OFFSET..CHALLENGE_OFFSET]
        .copy_from_slice(&claims.expires_public_slot.to_be_bytes());
    body[CHALLENGE_OFFSET..SERVICE_ALIAS_OFFSET].copy_from_slice(&claims.challenge.0);
    body[SERVICE_ALIAS_OFFSET..PIPELINE_OFFSET].copy_from_slice(&claims.service_alias.0);
    body[PIPELINE_OFFSET..ASSURANCE_OFFSET].copy_from_slice(&claims.pipeline.0);
    body[ASSURANCE_OFFSET..COLLECTOR_KEY_OFFSET].copy_from_slice(&claims.assurance.0);
    body[COLLECTOR_KEY_OFFSET..COLLECTOR_SESSION_KEY_OFFSET].copy_from_slice(&collector_key_id.0);
    body[COLLECTOR_SESSION_KEY_OFFSET..ATV2_ISSUER_KEY_ID_OFFSET]
        .copy_from_slice(&claims.collector_session_public_key_hash);
    body[ATV2_ISSUER_KEY_ID_OFFSET..ATV2_PUBLIC_KEY_HASH_OFFSET]
        .copy_from_slice(&claims.atv2_issuer_key_id);
    body[ATV2_PUBLIC_KEY_HASH_OFFSET..POLICY_OFFSET]
        .copy_from_slice(&claims.atv2_issuer_public_key_hash);
    body[POLICY_OFFSET..VERIFIER_ONLY_DIGEST_OFFSET].copy_from_slice(&claims.policy_hash);
    body[VERIFIER_ONLY_DIGEST_OFFSET..RESERVED_OFFSET]
        .copy_from_slice(&claims.verifier_only_claims.0);
    body
}

fn parse_body(body: &[u8]) -> Result<ParsedBody, NeppError> {
    if body.len() != NEPP_BODY_SIZE {
        return Err(NeppError::MalformedLength);
    }
    if body[PROFILE_OFFSET..VERSION_OFFSET] != NEPP_PROFILE_ID {
        return Err(NeppError::UnknownProfile);
    }
    if body[VERSION_OFFSET] != NEPP_VERSION {
        return Err(NeppError::UnknownVersion);
    }
    if body[FLAGS_OFFSET] != 0
        || body[FLAGS_OFFSET + 1..EPOCH_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        || body[RESERVED_OFFSET..].iter().any(|byte| *byte != 0)
    {
        return Err(NeppError::NonCanonicalEncoding);
    }
    let claims = NeppClaims {
        challenge: VerifierChallenge(copy_array(body, CHALLENGE_OFFSET)?),
        service_alias: PairwiseServiceAlias(copy_array(body, SERVICE_ALIAS_OFFSET)?),
        epoch: u64::from_be_bytes(copy_array(body, EPOCH_OFFSET)?),
        pipeline: PipelineMeasurementHash(copy_array(body, PIPELINE_OFFSET)?),
        assurance: AssuranceProfileDigest(copy_array(body, ASSURANCE_OFFSET)?),
        collector_session_public_key_hash: copy_array(body, COLLECTOR_SESSION_KEY_OFFSET)?,
        atv2_issuer_key_id: copy_array(body, ATV2_ISSUER_KEY_ID_OFFSET)?,
        atv2_issuer_public_key_hash: copy_array(body, ATV2_PUBLIC_KEY_HASH_OFFSET)?,
        policy_hash: copy_array(body, POLICY_OFFSET)?,
        created_public_slot: u64::from_be_bytes(copy_array(body, CREATED_OFFSET)?),
        expires_public_slot: u64::from_be_bytes(copy_array(body, EXPIRES_OFFSET)?),
        verifier_only_claims: VerifierOnlyClaimsDigest(copy_array(
            body,
            VERIFIER_ONLY_DIGEST_OFFSET,
        )?),
    }
    .validate()?;
    Ok(ParsedBody {
        claims,
        collector_key_id: CollectorKeyId(copy_array(body, COLLECTOR_KEY_OFFSET)?),
    })
}

fn copy_array<const N: usize>(body: &[u8], offset: usize) -> Result<[u8; N], NeppError> {
    body.get(offset..offset + N)
        .ok_or(NeppError::MalformedLength)?
        .try_into()
        .map_err(|_| NeppError::MalformedLength)
}

fn signature_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(body);
    message
}

fn parse_canonical_signature(bytes: &[u8]) -> Result<Signature, NeppError> {
    let signature = Signature::from_slice(bytes).map_err(|_| NeppError::MalformedSignature)?;
    if signature.normalize_s().is_some() {
        return Err(NeppError::NonCanonicalSignature);
    }
    Ok(signature)
}

fn collector_key_id(key: &VerifyingKey) -> CollectorKeyId {
    let mut hasher = Sha256::new();
    hasher.update(COLLECTOR_KEY_DOMAIN);
    hasher.update(key.to_encoded_point(false).as_bytes());
    CollectorKeyId(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NeppError {
    #[error("verifier challenge must not be all zero")]
    InvalidChallenge,
    #[error("verifier-only claims digest must not be all zero")]
    InvalidVerifierOnlyDigest,
    #[error("verifier-only claims container is empty or too large")]
    InvalidVerifierOnlyClaims,
    #[error("evidence lifetime is invalid")]
    InvalidLifetime,
    #[error("required evidence binding is all zero")]
    InvalidBinding,
    #[error("P-256 signing key is invalid")]
    InvalidKey,
    #[error("NEPP evidence length is invalid")]
    MalformedLength,
    #[error("NEPP signature encoding is malformed")]
    MalformedSignature,
    #[error("NEPP signature is validly shaped but not low-S canonical")]
    NonCanonicalSignature,
    #[error("NEPP profile identifier is unknown")]
    UnknownProfile,
    #[error("NEPP profile version is unknown")]
    UnknownVersion,
    #[error("NEPP reserved bytes or flags are non-canonical")]
    NonCanonicalEncoding,
    #[error("NEPP P-256 signature is invalid")]
    InvalidSignature,
    #[error("collector key does not match verifier key")]
    WrongCollectorKey,
    #[error("verifier challenge is wrong or unavailable")]
    WrongChallenge,
    #[error("verifier challenge was already consumed")]
    ChallengeReplayed,
    #[error("verifier challenge expired")]
    StaleChallenge,
    #[error("challenge store configuration is invalid")]
    InvalidChallengeStore,
    #[error("challenge cannot be issued")]
    ChallengeUnavailable,
    #[error("service alias does not match")]
    WrongService,
    #[error("epoch does not match")]
    WrongEpoch,
    #[error("pipeline measurement does not match")]
    WrongPipeline,
    #[error("ATv2 issuer key binding does not match")]
    WrongAtv2Key,
    #[error("policy hash does not match")]
    WrongPolicy,
    #[error("evidence is not valid at the current public slot")]
    EvidenceExpired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn attester() -> ReferenceSoftwareAttester {
        ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap()
    }

    fn challenge(value: u8) -> VerifierChallenge {
        VerifierChallenge::new([value; 32]).unwrap()
    }

    fn claims(challenge: VerifierChallenge) -> NeppClaims {
        NeppClaims {
            challenge,
            service_alias: PairwiseServiceAlias([2; 16]),
            epoch: 9,
            pipeline: PipelineMeasurementHash([3; 32]),
            assurance: attester().maximum_assurance().digest(),
            collector_session_public_key_hash: [4; 32],
            atv2_issuer_key_id: [5; 8],
            atv2_issuer_public_key_hash: [6; 32],
            policy_hash: [8; 32],
            created_public_slot: 100,
            expires_public_slot: 110,
            verifier_only_claims: VerifierOnlyClaims::new(b"boot=reported".to_vec())
                .unwrap()
                .digest(),
        }
    }

    fn expected(challenge: VerifierChallenge) -> ExpectedBindings {
        ExpectedBindings {
            challenge,
            service_alias: PairwiseServiceAlias([2; 16]),
            epoch: 9,
            pipeline: PipelineMeasurementHash([3; 32]),
            atv2_issuer_key_id: [5; 8],
            atv2_issuer_public_key_hash: [6; 32],
            policy_hash: [8; 32],
            current_public_slot: 105,
        }
    }

    fn store(challenge: VerifierChallenge, expiry: u64) -> ChallengeStore {
        let mut store = ChallengeStore::new(8).unwrap();
        store.issue(challenge, expiry).unwrap();
        store
    }

    #[test]
    fn valid_p256_signature_and_bindings_verify_once() {
        let challenge = challenge(1);
        let attester = attester();
        let evidence = attester.sign(claims(challenge)).unwrap();
        let mut challenges = store(challenge, 110);
        let verified = verify_nepp(
            &evidence,
            &attester.verifier(),
            &expected(challenge),
            &mut challenges,
        )
        .unwrap();
        assert_eq!(verified.claims(), claims(challenge));
        assert_eq!(verified.collector_key_id(), attester.key_id());
        assert_eq!(evidence.as_bytes().len(), NEPP_EVIDENCE_SIZE);
        assert_eq!(
            verify_nepp(
                &evidence,
                &attester.verifier(),
                &expected(challenge),
                &mut challenges,
            )
            .unwrap_err(),
            NeppError::ChallengeReplayed
        );
    }

    #[test]
    fn wrong_and_stale_challenges_are_rejected() {
        let signed_challenge = challenge(1);
        let wrong_challenge = challenge(2);
        let attester = attester();
        let evidence = attester.sign(claims(signed_challenge)).unwrap();
        let mut challenges = store(signed_challenge, 110);
        assert_eq!(
            verify_nepp(
                &evidence,
                &attester.verifier(),
                &expected(wrong_challenge),
                &mut challenges,
            )
            .unwrap_err(),
            NeppError::WrongChallenge
        );
        let stale_expected = expected(signed_challenge);
        let mut challenges = store(signed_challenge, 104);
        assert_eq!(
            verify_nepp(
                &evidence,
                &attester.verifier(),
                &stale_expected,
                &mut challenges,
            )
            .unwrap_err(),
            NeppError::StaleChallenge
        );
    }

    #[test]
    fn wrong_service_epoch_pipeline_atv2_key_and_policy_are_rejected() {
        let challenge = challenge(3);
        let attester = attester();
        let evidence = attester.sign(claims(challenge)).unwrap();

        let mut cases = Vec::new();
        let mut value = expected(challenge);
        value.service_alias = PairwiseServiceAlias([9; 16]);
        cases.push((value, NeppError::WrongService));
        let mut value = expected(challenge);
        value.epoch += 1;
        cases.push((value, NeppError::WrongEpoch));
        let mut value = expected(challenge);
        value.pipeline = PipelineMeasurementHash([9; 32]);
        cases.push((value, NeppError::WrongPipeline));
        let mut value = expected(challenge);
        value.atv2_issuer_key_id = [9; 8];
        cases.push((value, NeppError::WrongAtv2Key));
        let mut value = expected(challenge);
        value.policy_hash = [9; 32];
        cases.push((value, NeppError::WrongPolicy));

        for (expected, error) in cases {
            let mut challenges = store(challenge, 110);
            assert_eq!(
                verify_nepp(&evidence, &attester.verifier(), &expected, &mut challenges,)
                    .unwrap_err(),
                error
            );
        }
    }

    #[test]
    fn malformed_noncanonical_unknown_and_mutated_evidence_fail_closed() {
        let challenge = challenge(4);
        let attester = attester();
        let evidence = attester.sign(claims(challenge)).unwrap();

        let mut unknown = evidence.as_bytes().to_owned();
        unknown[0] = b'X';
        assert_eq!(
            NeppEvidence::from_bytes(unknown).unwrap_err(),
            NeppError::UnknownProfile
        );

        let mut version = evidence.as_bytes().to_owned();
        version[VERSION_OFFSET] = 99;
        assert_eq!(
            NeppEvidence::from_bytes(version).unwrap_err(),
            NeppError::UnknownVersion
        );

        let mut reserved = evidence.as_bytes().to_owned();
        reserved[RESERVED_OFFSET] = 1;
        assert_eq!(
            NeppEvidence::from_bytes(reserved).unwrap_err(),
            NeppError::NonCanonicalEncoding
        );

        let mut mutated = evidence.as_bytes().to_owned();
        mutated[PIPELINE_OFFSET] ^= 1;
        let mutated = NeppEvidence::from_bytes(mutated).unwrap();
        let mut challenges = store(challenge, 110);
        assert_eq!(
            verify_nepp(
                &mutated,
                &attester.verifier(),
                &expected(challenge),
                &mut challenges,
            )
            .unwrap_err(),
            NeppError::InvalidSignature
        );
    }

    #[test]
    fn software_reference_attester_never_claims_hardware_key() {
        let attester = attester();
        assert_eq!(
            attester.maximum_assurance().collector_key,
            SoftwareAttesterClaim::new().maximum_assurance()
        );
    }

    #[test]
    fn evidence_schema_contains_no_private_biosignal_or_k1_values() {
        let documented_fields = [
            "challenge",
            "service_alias",
            "epoch",
            "pipeline",
            "assurance",
            "collector_key_id",
            "collector_session_public_key_hash",
            "atv2_issuer_key_id",
            "atv2_issuer_public_key_hash",
            "policy_hash",
            "created_public_slot",
            "expires_public_slot",
            "verifier_only_claims_digest",
        ];
        for forbidden in [
            "raw_ppg",
            "raw_acc",
            "private_feature",
            "baseline_center",
            "baseline_scale",
            "evidence_permit",
            "p_value",
        ] {
            assert!(!documented_fields.contains(&forbidden));
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in any::<[u8; NEPP_EVIDENCE_SIZE]>()) {
            let _ = NeppEvidence::from_bytes(bytes);
        }
    }
}
