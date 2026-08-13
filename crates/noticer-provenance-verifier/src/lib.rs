#![forbid(unsafe_code)]

//! Conservative NEPP appraisal. Raw profiles are descriptive values; the
//! opaque `AppraisedProvenance` is the authority-bearing result.

use std::collections::BTreeSet;
use std::fmt;

use noticer_nepp::{
    verify_nepp, ChallengeStore, CollectorKeyId, ExpectedBindings, NeppEvidence, NeppVerifierKey,
    PairwiseServiceAlias, VerifiedNepp, VerifierOnlyClaims,
};
use noticer_provenance::{
    dominates, AssuranceProfile, BootStateAssurance, CollectorKeyAssurance, FreshnessAssurance,
    PipelineAssurance, PipelineMeasurementHash, SourceAssurance,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AndroidSecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidVerifiedBootState {
    Unknown,
    Unverified,
    SelfSigned,
    Verified,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationStatus {
    Unknown,
    Good,
    Revoked,
}

/// Parsed Android certificate-extension claims before chain validation.
///
/// The public constructor deliberately records every value as unverified.
/// Requested StrongBox and reported boot state are not appraisal results.
pub struct AndroidCertificateRecord {
    requested_security_level: AndroidSecurityLevel,
    reported_security_level: AndroidSecurityLevel,
    reported_boot_state: AndroidVerifiedBootState,
    reported_device_locked: bool,
    app_signing_certificate_sha256: [u8; 32],
    verified: Option<VerifiedAndroidRecord>,
}

impl AndroidCertificateRecord {
    pub fn from_unverified_extension(
        requested_security_level: AndroidSecurityLevel,
        reported_security_level: AndroidSecurityLevel,
        reported_boot_state: AndroidVerifiedBootState,
        reported_device_locked: bool,
        app_signing_certificate_sha256: [u8; 32],
    ) -> Result<Self, AppraisalError> {
        if app_signing_certificate_sha256 == [0; 32] {
            return Err(AppraisalError::MalformedAndroidRecord);
        }
        Ok(Self {
            requested_security_level,
            reported_security_level,
            reported_boot_state,
            reported_device_locked,
            app_signing_certificate_sha256,
            verified: None,
        })
    }

    pub const fn requested_security_level(&self) -> AndroidSecurityLevel {
        self.requested_security_level
    }

    pub const fn is_chain_verified(&self) -> bool {
        self.verified.is_some()
    }

    #[cfg(test)]
    fn verified_fixture(
        requested_security_level: AndroidSecurityLevel,
        verified_security_level: AndroidSecurityLevel,
        boot_state: AndroidVerifiedBootState,
        device_locked: bool,
        app_signing_certificate_sha256: [u8; 32],
        revocation: RevocationStatus,
    ) -> Self {
        Self {
            requested_security_level,
            reported_security_level: verified_security_level,
            reported_boot_state: boot_state,
            reported_device_locked: device_locked,
            app_signing_certificate_sha256,
            verified: Some(VerifiedAndroidRecord {
                security_level: verified_security_level,
                boot_state,
                device_locked,
                app_signing_certificate_sha256,
                revocation,
            }),
        }
    }
}

impl fmt::Debug for AndroidCertificateRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidCertificateRecord")
            .field("requested_security_level", &self.requested_security_level)
            .field("reported_security_level", &self.reported_security_level)
            .field("reported_boot_state", &self.reported_boot_state)
            .field("reported_device_locked", &self.reported_device_locked)
            .field(
                "app_identity_present",
                &(self.app_signing_certificate_sha256 != [0; 32]),
            )
            .field("app_identity", &"VERIFIER_ONLY")
            .field("chain_verified", &self.verified.is_some())
            .finish()
    }
}

#[derive(Clone, Copy)]
struct VerifiedAndroidRecord {
    security_level: AndroidSecurityLevel,
    boot_state: AndroidVerifiedBootState,
    device_locked: bool,
    app_signing_certificate_sha256: [u8; 32],
    revocation: RevocationStatus,
}

#[derive(Clone, Copy, Debug)]
pub enum PlatformEvidence<'a> {
    ReferenceSoftware,
    Android(&'a AndroidCertificateRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceEvidence {
    SyntheticReplay,
    LiveBleObserved,
    PairedCommercialSensor,
}

pub struct ReferenceValueStore {
    allowed_collector_keys: BTreeSet<CollectorKeyId>,
    revoked_collector_keys: BTreeSet<CollectorKeyId>,
    allowed_pipelines: BTreeSet<PipelineMeasurementHash>,
    allowed_policy_hashes: BTreeSet<[u8; 32]>,
    allowed_app_certificates: BTreeSet<[u8; 32]>,
    allowed_atv2_keys: BTreeSet<([u8; 8], [u8; 32])>,
}

impl ReferenceValueStore {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        allowed_collector_keys: BTreeSet<CollectorKeyId>,
        revoked_collector_keys: BTreeSet<CollectorKeyId>,
        allowed_pipelines: BTreeSet<PipelineMeasurementHash>,
        allowed_policy_hashes: BTreeSet<[u8; 32]>,
        allowed_app_certificates: BTreeSet<[u8; 32]>,
        allowed_atv2_keys: BTreeSet<([u8; 8], [u8; 32])>,
    ) -> Result<Self, AppraisalError> {
        if allowed_collector_keys.is_empty()
            || allowed_pipelines.is_empty()
            || allowed_policy_hashes.is_empty()
            || allowed_atv2_keys.is_empty()
            || allowed_collector_keys
                .iter()
                .any(|key| revoked_collector_keys.contains(key))
        {
            return Err(AppraisalError::InvalidReferenceValues);
        }
        Ok(Self {
            allowed_collector_keys,
            revoked_collector_keys,
            allowed_pipelines,
            allowed_policy_hashes,
            allowed_app_certificates,
            allowed_atv2_keys,
        })
    }
}

pub struct AppraisalRequest<'a> {
    pub evidence: &'a NeppEvidence,
    pub verifier_key: &'a NeppVerifierKey,
    pub expected: &'a ExpectedBindings,
    pub verifier_only_claims: &'a VerifierOnlyClaims,
    pub platform: PlatformEvidence<'a>,
    pub source: SourceEvidence,
    pub minimum_assurance: AssuranceProfile,
}

pub struct ProvenanceAppraiser {
    references: ReferenceValueStore,
    challenges: ChallengeStore,
}

impl ProvenanceAppraiser {
    pub const fn new(references: ReferenceValueStore, challenges: ChallengeStore) -> Self {
        Self {
            references,
            challenges,
        }
    }

    pub fn challenge_store_mut(&mut self) -> &mut ChallengeStore {
        &mut self.challenges
    }

    pub fn appraise(
        &mut self,
        request: AppraisalRequest<'_>,
    ) -> Result<AppraisedProvenance, AppraisalError> {
        self.check_reference_bindings(&request)?;
        let verified = verify_nepp(
            request.evidence,
            request.verifier_key,
            request.expected,
            &mut self.challenges,
        )
        .map_err(AppraisalError::Nepp)?;
        self.check_verifier_only_digest(verified, request.verifier_only_claims)?;
        let profile = self.derive_profile(request.source, request.platform)?;
        if verified.claims().assurance != profile.digest() {
            return Err(AppraisalError::AssuranceDigestMismatch);
        }
        if !dominates(&profile, &request.minimum_assurance) {
            return Err(AppraisalError::AssuranceBelowPolicy);
        }
        Ok(AppraisedProvenance {
            profile,
            collector_key_id: verified.collector_key_id(),
            pipeline: verified.claims().pipeline,
            service_alias: verified.claims().service_alias,
            epoch: verified.claims().epoch,
            atv2_issuer_key_id: verified.claims().atv2_issuer_key_id,
            policy_hash: verified.claims().policy_hash,
            created_public_slot: verified.claims().created_public_slot,
            expires_public_slot: verified.claims().expires_public_slot,
            _private: (),
        })
    }

    fn check_reference_bindings(
        &self,
        request: &AppraisalRequest<'_>,
    ) -> Result<(), AppraisalError> {
        let key_id = request.verifier_key.key_id();
        if self.references.revoked_collector_keys.contains(&key_id) {
            return Err(AppraisalError::CollectorKeyRevoked);
        }
        if !self.references.allowed_collector_keys.contains(&key_id) {
            return Err(AppraisalError::CollectorKeyUntrusted);
        }
        if !self
            .references
            .allowed_pipelines
            .contains(&request.expected.pipeline)
        {
            return Err(AppraisalError::PipelineUntrusted);
        }
        if !self
            .references
            .allowed_policy_hashes
            .contains(&request.expected.policy_hash)
        {
            return Err(AppraisalError::PolicyUntrusted);
        }
        if !self.references.allowed_atv2_keys.contains(&(
            request.expected.atv2_issuer_key_id,
            request.expected.atv2_issuer_public_key_hash,
        )) {
            return Err(AppraisalError::Atv2KeyUntrusted);
        }
        Ok(())
    }

    fn check_verifier_only_digest(
        &self,
        verified: VerifiedNepp,
        claims: &VerifierOnlyClaims,
    ) -> Result<(), AppraisalError> {
        if verified.claims().verifier_only_claims != claims.digest() {
            return Err(AppraisalError::VerifierOnlyDigestMismatch);
        }
        Ok(())
    }

    fn derive_profile(
        &self,
        source: SourceEvidence,
        platform: PlatformEvidence<'_>,
    ) -> Result<AssuranceProfile, AppraisalError> {
        let source = match source {
            SourceEvidence::SyntheticReplay => SourceAssurance::synthetic_replay(),
            SourceEvidence::LiveBleObserved => SourceAssurance::live_ble_observed(),
            SourceEvidence::PairedCommercialSensor => SourceAssurance::paired_commercial_sensor(),
        };
        let (collector_key, boot_state, pipeline) = match platform {
            PlatformEvidence::ReferenceSoftware => (
                CollectorKeyAssurance::software(),
                BootStateAssurance::unknown(),
                PipelineAssurance::self_declared(),
            ),
            PlatformEvidence::Android(record) => self.map_android(record)?,
        };
        Ok(AssuranceProfile {
            source,
            collector_key,
            boot_state,
            pipeline,
            freshness: FreshnessAssurance::appraised_verifier_challenge(),
        })
    }

    fn map_android(
        &self,
        record: &AndroidCertificateRecord,
    ) -> Result<(CollectorKeyAssurance, BootStateAssurance, PipelineAssurance), AppraisalError>
    {
        let Some(verified) = record.verified else {
            let boot = if record.reported_boot_state == AndroidVerifiedBootState::Unknown {
                BootStateAssurance::unknown()
            } else {
                BootStateAssurance::reported()
            };
            return Ok((
                CollectorKeyAssurance::software(),
                boot,
                PipelineAssurance::self_declared(),
            ));
        };
        if verified.revocation == RevocationStatus::Revoked {
            return Err(AppraisalError::AndroidCertificateRevoked);
        }
        if verified.revocation != RevocationStatus::Good {
            return Ok((
                CollectorKeyAssurance::software(),
                BootStateAssurance::reported(),
                PipelineAssurance::self_declared(),
            ));
        }
        if !self
            .references
            .allowed_app_certificates
            .contains(&verified.app_signing_certificate_sha256)
        {
            return Err(AppraisalError::AndroidAppIdentityUntrusted);
        }
        let collector = match verified.security_level {
            AndroidSecurityLevel::Software => CollectorKeyAssurance::software(),
            AndroidSecurityLevel::TrustedEnvironment => {
                CollectorKeyAssurance::appraised_tee_backed()
            }
            AndroidSecurityLevel::StrongBox => CollectorKeyAssurance::appraised_strongbox_backed(),
        };
        let boot = if verified.boot_state == AndroidVerifiedBootState::Verified
            && verified.device_locked
        {
            BootStateAssurance::appraised_hardware_locked()
        } else {
            BootStateAssurance::reported()
        };
        Ok((
            collector,
            boot,
            PipelineAssurance::appraised_static_manifest_bound(),
        ))
    }
}

/// Authority-bearing appraisal result. It has no public constructor and is
/// intentionally not serializable. K5-08 consumes this capability to mint a
/// signed fixed-size lease.
pub struct AppraisedProvenance {
    profile: AssuranceProfile,
    collector_key_id: CollectorKeyId,
    pipeline: PipelineMeasurementHash,
    service_alias: PairwiseServiceAlias,
    epoch: u64,
    atv2_issuer_key_id: [u8; 8],
    policy_hash: [u8; 32],
    created_public_slot: u64,
    expires_public_slot: u64,
    _private: (),
}

impl AppraisedProvenance {
    pub const fn profile(&self) -> AssuranceProfile {
        self.profile
    }

    pub const fn collector_key_id(&self) -> CollectorKeyId {
        self.collector_key_id
    }

    pub const fn pipeline(&self) -> PipelineMeasurementHash {
        self.pipeline
    }

    pub const fn service_alias(&self) -> PairwiseServiceAlias {
        self.service_alias
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn atv2_issuer_key_id(&self) -> [u8; 8] {
        self.atv2_issuer_key_id
    }

    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    pub const fn created_public_slot(&self) -> u64 {
        self.created_public_slot
    }

    pub const fn expires_public_slot(&self) -> u64 {
        self.expires_public_slot
    }
}

impl fmt::Debug for AppraisedProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppraisedProvenance")
            .field("profile", &self.profile)
            .field("collector_key_id", &self.collector_key_id)
            .field("pipeline", &self.pipeline)
            .field("service_alias", &self.service_alias)
            .field("epoch", &self.epoch)
            .field("atv2_issuer_key_id", &self.atv2_issuer_key_id)
            .field("policy_hash", &"REDACTED")
            .field("created_public_slot", &self.created_public_slot)
            .field("expires_public_slot", &self.expires_public_slot)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AppraisalError {
    #[error("reference value store is empty or contradictory")]
    InvalidReferenceValues,
    #[error("Android certificate record is malformed")]
    MalformedAndroidRecord,
    #[error("collector key is revoked")]
    CollectorKeyRevoked,
    #[error("collector key is not endorsed")]
    CollectorKeyUntrusted,
    #[error("pipeline measurement is not approved")]
    PipelineUntrusted,
    #[error("policy hash is not approved")]
    PolicyUntrusted,
    #[error("ATv2 issuer key is not approved")]
    Atv2KeyUntrusted,
    #[error("NEPP verification failed: {0}")]
    Nepp(#[from] noticer_nepp::NeppError),
    #[error("verifier-only claims digest does not match NEPP")]
    VerifierOnlyDigestMismatch,
    #[error("signed assurance digest does not match derived profile")]
    AssuranceDigestMismatch,
    #[error("derived assurance is below policy")]
    AssuranceBelowPolicy,
    #[error("Android certificate is revoked")]
    AndroidCertificateRevoked,
    #[error("Android app identity is not an approved reference value")]
    AndroidAppIdentityUntrusted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_nepp::{
        NeppClaims, ReferenceSoftwareAttester, VerifierChallenge, VerifierOnlyClaimsDigest,
    };

    const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([3; 32]);
    const POLICY: [u8; 32] = [8; 32];
    const ATV2_ID: [u8; 8] = [5; 8];
    const ATV2_HASH: [u8; 32] = [6; 32];
    const APP_CERT: [u8; 32] = [9; 32];

    fn challenge(value: u8) -> VerifierChallenge {
        VerifierChallenge::new([value; 32]).unwrap()
    }

    fn reference_profile(source: SourceEvidence) -> AssuranceProfile {
        AssuranceProfile {
            source: match source {
                SourceEvidence::SyntheticReplay => SourceAssurance::synthetic_replay(),
                SourceEvidence::LiveBleObserved => SourceAssurance::live_ble_observed(),
                SourceEvidence::PairedCommercialSensor => {
                    SourceAssurance::paired_commercial_sensor()
                }
            },
            collector_key: CollectorKeyAssurance::software(),
            boot_state: BootStateAssurance::unknown(),
            pipeline: PipelineAssurance::self_declared(),
            freshness: FreshnessAssurance::appraised_verifier_challenge(),
        }
    }

    fn unverified_android_profile(source: SourceEvidence) -> AssuranceProfile {
        AssuranceProfile {
            boot_state: BootStateAssurance::reported(),
            ..reference_profile(source)
        }
    }

    fn verified_android_profile(source: SourceEvidence) -> AssuranceProfile {
        AssuranceProfile {
            source: match source {
                SourceEvidence::SyntheticReplay => SourceAssurance::synthetic_replay(),
                SourceEvidence::LiveBleObserved => SourceAssurance::live_ble_observed(),
                SourceEvidence::PairedCommercialSensor => {
                    SourceAssurance::paired_commercial_sensor()
                }
            },
            collector_key: CollectorKeyAssurance::appraised_strongbox_backed(),
            boot_state: BootStateAssurance::appraised_hardware_locked(),
            pipeline: PipelineAssurance::appraised_static_manifest_bound(),
            freshness: FreshnessAssurance::appraised_verifier_challenge(),
        }
    }

    fn references(attester: &ReferenceSoftwareAttester) -> ReferenceValueStore {
        ReferenceValueStore::new(
            BTreeSet::from([attester.key_id()]),
            BTreeSet::new(),
            BTreeSet::from([PIPELINE]),
            BTreeSet::from([POLICY]),
            BTreeSet::from([APP_CERT]),
            BTreeSet::from([(ATV2_ID, ATV2_HASH)]),
        )
        .unwrap()
    }

    fn expected(challenge: VerifierChallenge) -> ExpectedBindings {
        ExpectedBindings {
            challenge,
            service_alias: PairwiseServiceAlias([2; 16]),
            epoch: 9,
            pipeline: PIPELINE,
            atv2_issuer_key_id: ATV2_ID,
            atv2_issuer_public_key_hash: ATV2_HASH,
            policy_hash: POLICY,
            current_public_slot: 105,
        }
    }

    fn claims(
        challenge: VerifierChallenge,
        profile: AssuranceProfile,
        verifier_only: VerifierOnlyClaimsDigest,
    ) -> NeppClaims {
        NeppClaims {
            challenge,
            service_alias: PairwiseServiceAlias([2; 16]),
            epoch: 9,
            pipeline: PIPELINE,
            assurance: profile.digest(),
            collector_session_public_key_hash: [4; 32],
            atv2_issuer_key_id: ATV2_ID,
            atv2_issuer_public_key_hash: ATV2_HASH,
            policy_hash: POLICY,
            created_public_slot: 100,
            expires_public_slot: 110,
            verifier_only_claims: verifier_only,
        }
    }

    fn appraiser(
        attester: &ReferenceSoftwareAttester,
        challenge: VerifierChallenge,
        challenge_expiry: u64,
    ) -> ProvenanceAppraiser {
        let mut challenges = ChallengeStore::new(8).unwrap();
        challenges.issue(challenge, challenge_expiry).unwrap();
        ProvenanceAppraiser::new(references(attester), challenges)
    }

    #[test]
    fn valid_reference_software_appraisal_returns_opaque_result() {
        let attester = ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap();
        let challenge = challenge(1);
        let private = VerifierOnlyClaims::new(b"tier=a".to_vec()).unwrap();
        let profile = reference_profile(SourceEvidence::SyntheticReplay);
        let evidence = attester
            .sign(claims(challenge, profile, private.digest()))
            .unwrap();
        let expected = expected(challenge);
        let mut appraiser = appraiser(&attester, challenge, 110);
        let result = appraiser
            .appraise(AppraisalRequest {
                evidence: &evidence,
                verifier_key: &attester.verifier(),
                expected: &expected,
                verifier_only_claims: &private,
                platform: PlatformEvidence::ReferenceSoftware,
                source: SourceEvidence::SyntheticReplay,
                minimum_assurance: profile,
            })
            .unwrap();
        assert_eq!(result.profile(), profile);
        assert_eq!(result.pipeline(), PIPELINE);
    }

    #[test]
    fn stale_challenge_acceptance_is_zero() {
        for index in 1..=32 {
            let attester = ReferenceSoftwareAttester::from_secret_bytes([index; 32]).unwrap();
            let challenge = challenge(index);
            let private = VerifierOnlyClaims::new(vec![index]).unwrap();
            let profile = reference_profile(SourceEvidence::SyntheticReplay);
            let evidence = attester
                .sign(claims(challenge, profile, private.digest()))
                .unwrap();
            let expected = expected(challenge);
            let mut appraiser = appraiser(&attester, challenge, 104);
            assert!(appraiser
                .appraise(AppraisalRequest {
                    evidence: &evidence,
                    verifier_key: &attester.verifier(),
                    expected: &expected,
                    verifier_only_claims: &private,
                    platform: PlatformEvidence::ReferenceSoftware,
                    source: SourceEvidence::SyntheticReplay,
                    minimum_assurance: profile,
                })
                .is_err());
        }
    }

    #[test]
    fn mismatch_and_downgrade_acceptance_is_zero() {
        let attester = ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap();
        let challenge = challenge(2);
        let private = VerifierOnlyClaims::new(b"tier=a".to_vec()).unwrap();
        let claimed = reference_profile(SourceEvidence::LiveBleObserved);
        let evidence = attester
            .sign(claims(challenge, claimed, private.digest()))
            .unwrap();
        let expected = expected(challenge);
        let mut appraiser = appraiser(&attester, challenge, 110);
        assert!(matches!(
            appraiser.appraise(AppraisalRequest {
                evidence: &evidence,
                verifier_key: &attester.verifier(),
                expected: &expected,
                verifier_only_claims: &private,
                platform: PlatformEvidence::ReferenceSoftware,
                source: SourceEvidence::SyntheticReplay,
                minimum_assurance: claimed,
            }),
            Err(AppraisalError::AssuranceDigestMismatch)
        ));
    }

    #[test]
    fn strongbox_request_alone_never_becomes_strongbox_backed() {
        let attester = ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap();
        let challenge = challenge(3);
        let private = VerifierOnlyClaims::new(b"android=unverified".to_vec()).unwrap();
        let android = AndroidCertificateRecord::from_unverified_extension(
            AndroidSecurityLevel::StrongBox,
            AndroidSecurityLevel::StrongBox,
            AndroidVerifiedBootState::Verified,
            true,
            APP_CERT,
        )
        .unwrap();
        let profile = unverified_android_profile(SourceEvidence::LiveBleObserved);
        let evidence = attester
            .sign(claims(challenge, profile, private.digest()))
            .unwrap();
        let expected = expected(challenge);
        let mut appraiser = appraiser(&attester, challenge, 110);
        let result = appraiser
            .appraise(AppraisalRequest {
                evidence: &evidence,
                verifier_key: &attester.verifier(),
                expected: &expected,
                verifier_only_claims: &private,
                platform: PlatformEvidence::Android(&android),
                source: SourceEvidence::LiveBleObserved,
                minimum_assurance: profile,
            })
            .unwrap();
        assert_eq!(
            result.profile().collector_key,
            CollectorKeyAssurance::software()
        );
        assert_eq!(result.profile().boot_state, BootStateAssurance::reported());
        assert_eq!(
            result.profile().pipeline,
            PipelineAssurance::self_declared()
        );
    }

    #[test]
    fn only_verified_chain_security_level_and_app_identity_can_upgrade() {
        let attester = ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap();
        let challenge = challenge(4);
        let private = VerifierOnlyClaims::new(b"android=verified-fixture".to_vec()).unwrap();
        let android = AndroidCertificateRecord::verified_fixture(
            AndroidSecurityLevel::Software,
            AndroidSecurityLevel::StrongBox,
            AndroidVerifiedBootState::Verified,
            true,
            APP_CERT,
            RevocationStatus::Good,
        );
        let profile = verified_android_profile(SourceEvidence::LiveBleObserved);
        let evidence = attester
            .sign(claims(challenge, profile, private.digest()))
            .unwrap();
        let expected = expected(challenge);
        let mut appraiser = appraiser(&attester, challenge, 110);
        let result = appraiser
            .appraise(AppraisalRequest {
                evidence: &evidence,
                verifier_key: &attester.verifier(),
                expected: &expected,
                verifier_only_claims: &private,
                platform: PlatformEvidence::Android(&android),
                source: SourceEvidence::LiveBleObserved,
                minimum_assurance: profile,
            })
            .unwrap();
        assert_eq!(result.profile(), profile);
    }

    #[test]
    fn debug_and_api_never_call_android_attestation_sample_origin_proof() {
        let record = AndroidCertificateRecord::from_unverified_extension(
            AndroidSecurityLevel::StrongBox,
            AndroidSecurityLevel::StrongBox,
            AndroidVerifiedBootState::Verified,
            true,
            APP_CERT,
        )
        .unwrap();
        let debug = format!("{record:?}").to_ascii_lowercase();
        assert!(!debug.contains("sample-origin"));
        assert!(!debug.contains("human proof"));
        assert!(debug.contains("chain_verified: false"));
    }
}
