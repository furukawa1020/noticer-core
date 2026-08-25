//! Fail-closed P0/P1 profile gate for a canonical release stack path.

use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    verify_canonical_release_path, AepaProfileAuthorization, DeploymentProfile, Digest,
    NoticerModuleId, ReleaseStackCompositionContract, ReleaseStackPathArtifact,
    ReleaseStackPathError, RELEASE_STACK_HARDWARE_STATUS,
};

pub const RELEASE_STACK_PROFILE_VERSION: &str = "noticer-release-stack-profile/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackProfileVerdict {
    Authorized,
    ProfileUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackProfileUnresolvedReason {
    ProfileTopology,
    MissingAepaAuthorization,
    UnexpectedAepaAuthorization,
    AuthorizationProfileMismatch,
    AuthorizationStepMismatch,
    AuthorizationEvidenceMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStackProfileArtifact {
    pub schema_version: String,
    pub composition_digest: Digest,
    pub path_artifact_digest: Digest,
    pub requested_profile: DeploymentProfile,
    pub effective_profile: Option<DeploymentProfile>,
    pub public_step: u32,
    pub verdict: ReleaseStackProfileVerdict,
    pub unresolved_reason: Option<ReleaseStackProfileUnresolvedReason>,
    pub manifest_evidence_digest: Option<Digest>,
    pub aepa_authorization_digest: Option<Digest>,
    pub hardware_status: String,
    pub artifact_digest: Digest,
}

pub fn evaluate_release_stack_profile(
    contract: &ReleaseStackCompositionContract,
    path: &ReleaseStackPathArtifact,
    requested_profile: DeploymentProfile,
    public_step: u32,
    aepa_authorization: Option<&AepaProfileAuthorization>,
) -> Result<ReleaseStackProfileArtifact, ReleaseStackProfileError> {
    verify_canonical_release_path(contract, path).map_err(ReleaseStackProfileError::Path)?;

    let aepa_binding = contract.manifest().binding(NoticerModuleId::Aepa);
    let manifest_evidence_digest = aepa_binding
        .p1_resource_evidence
        .as_ref()
        .map(|evidence| evidence.equivalence_certificate_digest);
    let aepa_authorization_digest = aepa_authorization.map(|value| value.authorization_digest());

    let unresolved_reason =
        profile_unresolved_reason(contract, requested_profile, public_step, aepa_authorization);
    let (verdict, effective_profile) = match unresolved_reason {
        Some(_) => (ReleaseStackProfileVerdict::ProfileUnresolved, None),
        None => (
            ReleaseStackProfileVerdict::Authorized,
            Some(requested_profile),
        ),
    };
    let artifact_digest = profile_artifact_digest(
        contract,
        path,
        requested_profile,
        effective_profile,
        public_step,
        verdict,
        unresolved_reason,
        manifest_evidence_digest,
        aepa_authorization_digest,
    );

    Ok(ReleaseStackProfileArtifact {
        schema_version: RELEASE_STACK_PROFILE_VERSION.to_owned(),
        composition_digest: contract.digest(),
        path_artifact_digest: path.artifact_digest,
        requested_profile,
        effective_profile,
        public_step,
        verdict,
        unresolved_reason,
        manifest_evidence_digest,
        aepa_authorization_digest,
        hardware_status: RELEASE_STACK_HARDWARE_STATUS.to_owned(),
        artifact_digest: Digest::new(artifact_digest),
    })
}

pub fn verify_release_stack_profile(
    contract: &ReleaseStackCompositionContract,
    path: &ReleaseStackPathArtifact,
    artifact: &ReleaseStackProfileArtifact,
    aepa_authorization: Option<&AepaProfileAuthorization>,
) -> Result<(), ReleaseStackProfileError> {
    if artifact.schema_version != RELEASE_STACK_PROFILE_VERSION
        || artifact.composition_digest != contract.digest()
        || artifact.path_artifact_digest != path.artifact_digest
    {
        return Err(ReleaseStackProfileError::Binding);
    }
    if artifact.hardware_status != RELEASE_STACK_HARDWARE_STATUS {
        return Err(ReleaseStackProfileError::HardwareStatus);
    }
    let expected = evaluate_release_stack_profile(
        contract,
        path,
        artifact.requested_profile,
        artifact.public_step,
        aepa_authorization,
    )?;
    if artifact.artifact_digest != expected.artifact_digest {
        return Err(ReleaseStackProfileError::ArtifactDigest);
    }
    if artifact != &expected {
        return Err(ReleaseStackProfileError::NonCanonical);
    }
    Ok(())
}

fn profile_unresolved_reason(
    contract: &ReleaseStackCompositionContract,
    requested_profile: DeploymentProfile,
    public_step: u32,
    authorization: Option<&AepaProfileAuthorization>,
) -> Option<ReleaseStackProfileUnresolvedReason> {
    let profile_topology_matches = contract.manifest().entries().iter().all(|binding| {
        let expected = if requested_profile == DeploymentProfile::P1SealedAdmission
            && binding.module_id == NoticerModuleId::Aepa
        {
            DeploymentProfile::P1SealedAdmission
        } else {
            DeploymentProfile::P0PublicQuotientOnly
        };
        binding.deployment_profile == expected
    });
    if !profile_topology_matches {
        return Some(ReleaseStackProfileUnresolvedReason::ProfileTopology);
    }

    match requested_profile {
        DeploymentProfile::P0PublicQuotientOnly => {
            if authorization.is_some() {
                Some(ReleaseStackProfileUnresolvedReason::UnexpectedAepaAuthorization)
            } else {
                None
            }
        }
        DeploymentProfile::P1SealedAdmission => {
            let Some(authorization) = authorization else {
                return Some(ReleaseStackProfileUnresolvedReason::MissingAepaAuthorization);
            };
            if authorization.profile() != DeploymentProfile::P1SealedAdmission {
                return Some(ReleaseStackProfileUnresolvedReason::AuthorizationProfileMismatch);
            }
            if authorization.public_step() != public_step {
                return Some(ReleaseStackProfileUnresolvedReason::AuthorizationStepMismatch);
            }
            let manifest_evidence = contract
                .manifest()
                .binding(NoticerModuleId::Aepa)
                .p1_resource_evidence
                .as_ref()
                .expect("P1 manifest validation requires evidence");
            if authorization.witness_digest()
                != Some(manifest_evidence.equivalence_certificate_digest)
                || authorization.authorization_digest() == Digest::zero()
            {
                return Some(ReleaseStackProfileUnresolvedReason::AuthorizationEvidenceMismatch);
            }
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn profile_artifact_digest(
    contract: &ReleaseStackCompositionContract,
    path: &ReleaseStackPathArtifact,
    requested_profile: DeploymentProfile,
    effective_profile: Option<DeploymentProfile>,
    public_step: u32,
    verdict: ReleaseStackProfileVerdict,
    reason: Option<ReleaseStackProfileUnresolvedReason>,
    manifest_evidence: Option<Digest>,
    authorization_digest: Option<Digest>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stack-profile-artifact/v1\0");
    hasher.update(contract.canonical_bytes());
    hasher.update(path.artifact_digest.as_bytes());
    hasher.update([requested_profile as u8]);
    update_optional_profile(&mut hasher, effective_profile);
    hasher.update(public_step.to_le_bytes());
    hasher.update([profile_verdict_code(verdict)]);
    hasher.update([reason.map_or(0, reason_code)]);
    update_optional_digest(&mut hasher, manifest_evidence);
    update_optional_digest(&mut hasher, authorization_digest);
    hasher.update(RELEASE_STACK_HARDWARE_STATUS.as_bytes());
    hasher.finalize().into()
}

fn update_optional_profile(hasher: &mut Sha256, profile: Option<DeploymentProfile>) {
    match profile {
        Some(value) => hasher.update([1, value as u8]),
        None => hasher.update([0, 0]),
    }
}

fn update_optional_digest(hasher: &mut Sha256, digest: Option<Digest>) {
    match digest {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => {
            hasher.update([0]);
            hasher.update([0; 32]);
        }
    }
}

const fn profile_verdict_code(verdict: ReleaseStackProfileVerdict) -> u8 {
    match verdict {
        ReleaseStackProfileVerdict::Authorized => 1,
        ReleaseStackProfileVerdict::ProfileUnresolved => 2,
    }
}

const fn reason_code(reason: ReleaseStackProfileUnresolvedReason) -> u8 {
    match reason {
        ReleaseStackProfileUnresolvedReason::ProfileTopology => 1,
        ReleaseStackProfileUnresolvedReason::MissingAepaAuthorization => 2,
        ReleaseStackProfileUnresolvedReason::UnexpectedAepaAuthorization => 3,
        ReleaseStackProfileUnresolvedReason::AuthorizationProfileMismatch => 4,
        ReleaseStackProfileUnresolvedReason::AuthorizationStepMismatch => 5,
        ReleaseStackProfileUnresolvedReason::AuthorizationEvidenceMismatch => 6,
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReleaseStackProfileError {
    #[error("release stack path verification failed: {0}")]
    Path(ReleaseStackPathError),
    #[error("release stack profile artifact binding is invalid")]
    Binding,
    #[error("release stack profile hardware status must remain NOT_VERIFIED")]
    HardwareStatus,
    #[error("release stack profile artifact digest does not recompute")]
    ArtifactDigest,
    #[error("release stack profile artifact is non-canonical")]
    NonCanonical,
}
