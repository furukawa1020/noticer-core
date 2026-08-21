use noticer_aetp::PairwiseServiceAlias;
use noticer_protocol::WireServiceAlias;
use noticer_provenance::{AssuranceProfileDigest, PipelineMeasurementHash};
use noticer_provenance_lease::{LeaseVerifierKeyId, NPL1_PROFILE_ID, NPL1_VERSION};
use noticer_types::{Epoch, PolicyHash};
use quotient_forge_caqt::{
    artifact_digest, verify, Certificate, CertificateLimits, CertificateVerdict, Digest,
    ExpectedContract,
};
use quotient_seal_abi::DeploymentProfile;
use thiserror::Error;

use crate::{aets::codegen_metadata, codegen_manifest_digest, NoticerModuleId, NoticerQsmManifest};

pub const AEPA_PUBLIC_SOURCE_FORMAT_VERSION: &str = "noticer-aepa-public-source/v1";
pub const AEPA_K7_SPEC_FAMILY: &str = "noticer_aepa_admission";
const SOURCE_MAGIC: &[u8; 8] = b"AEPASRC1";
const SOURCE_DOMAIN: &[u8] = b"noticer-aepa-public-source-v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AepaPublicState {
    Waiting = 0,
    Admitted = 1,
    CoverRequired = 2,
    Faulted = 3,
}

impl AepaPublicState {
    pub const ALL: [Self; 4] = [
        Self::Waiting,
        Self::Admitted,
        Self::CoverRequired,
        Self::Faulted,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AepaPublicInput {
    PublicTick = 0,
    ValidatedAdmission = 1,
    Replay = 2,
    Expired = 3,
    Downgrade = 4,
    WrongBinding = 5,
    Reset = 6,
    Handoff = 7,
    Fault = 8,
}

impl AepaPublicInput {
    pub const ALL: [Self; 9] = [
        Self::PublicTick,
        Self::ValidatedAdmission,
        Self::Replay,
        Self::Expired,
        Self::Downgrade,
        Self::WrongBinding,
        Self::Reset,
        Self::Handoff,
        Self::Fault,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AepaPublicOutput {
    Cover = 0,
    AdmitOnce = 1,
    Reject = 2,
    Fault = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaPublicTransition {
    from: AepaPublicState,
    input: AepaPublicInput,
    to: AepaPublicState,
    output: AepaPublicOutput,
}

impl AepaPublicTransition {
    #[must_use]
    pub const fn from(&self) -> AepaPublicState {
        self.from
    }

    #[must_use]
    pub const fn input(&self) -> AepaPublicInput {
        self.input
    }

    #[must_use]
    pub const fn to(&self) -> AepaPublicState {
        self.to
    }

    #[must_use]
    pub const fn output(&self) -> AepaPublicOutput {
        self.output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaPublicPolicyBinding {
    wire_service_alias: WireServiceAlias,
    pairwise_service_alias: PairwiseServiceAlias,
    epoch: Epoch,
    policy_hash: PolicyHash,
    lease_verifier_key_id: LeaseVerifierKeyId,
    pipeline_measurement_hash: PipelineMeasurementHash,
    assurance_profile_digest: AssuranceProfileDigest,
    atv2_issuer_key_id: [u8; 8],
    admission_window_start: u32,
    admission_window_end: u32,
}

impl AepaPublicPolicyBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire_service_alias: WireServiceAlias,
        pairwise_service_alias: PairwiseServiceAlias,
        epoch: Epoch,
        policy_hash: PolicyHash,
        lease_verifier_key_id: LeaseVerifierKeyId,
        pipeline_measurement_hash: PipelineMeasurementHash,
        assurance_profile_digest: AssuranceProfileDigest,
        atv2_issuer_key_id: [u8; 8],
        admission_window_start: u32,
        admission_window_end: u32,
    ) -> Result<Self, AepaBindingError> {
        if wire_service_alias.0 == [0; 8]
            || pairwise_service_alias.0 == [0; 32]
            || epoch.0 == 0
            || epoch.0 > u64::from(u32::MAX)
            || policy_hash.0 == [0; 32]
            || lease_verifier_key_id.0 == [0; 8]
            || pipeline_measurement_hash.0 == [0; 32]
            || assurance_profile_digest.0 == [0; 32]
            || atv2_issuer_key_id == [0; 8]
            || admission_window_start >= admission_window_end
        {
            return Err(AepaBindingError::InvalidPublicBinding);
        }
        Ok(Self {
            wire_service_alias,
            pairwise_service_alias,
            epoch,
            policy_hash,
            lease_verifier_key_id,
            pipeline_measurement_hash,
            assurance_profile_digest,
            atv2_issuer_key_id,
            admission_window_start,
            admission_window_end,
        })
    }

    #[must_use]
    pub const fn wire_service_alias(self) -> WireServiceAlias {
        self.wire_service_alias
    }

    #[must_use]
    pub const fn pairwise_service_alias(self) -> PairwiseServiceAlias {
        self.pairwise_service_alias
    }

    #[must_use]
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub const fn policy_hash(self) -> PolicyHash {
        self.policy_hash
    }

    #[must_use]
    pub const fn lease_verifier_key_id(self) -> LeaseVerifierKeyId {
        self.lease_verifier_key_id
    }

    #[must_use]
    pub const fn pipeline_measurement_hash(self) -> PipelineMeasurementHash {
        self.pipeline_measurement_hash
    }

    #[must_use]
    pub const fn assurance_profile_digest(self) -> AssuranceProfileDigest {
        self.assurance_profile_digest
    }

    #[must_use]
    pub const fn atv2_issuer_key_id(self) -> [u8; 8] {
        self.atv2_issuer_key_id
    }

    #[must_use]
    pub const fn admission_window(self) -> (u32, u32) {
        (self.admission_window_start, self.admission_window_end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaPublicSourceArtifact {
    canonical_bytes: Box<[u8]>,
    digest: Digest,
    binding: AepaPublicPolicyBinding,
    transitions: Box<[AepaPublicTransition]>,
}

impl AepaPublicSourceArtifact {
    pub fn new(binding: AepaPublicPolicyBinding) -> Result<Self, AepaBindingError> {
        let transitions = build_total_transitions();
        let transition_count =
            u16::try_from(transitions.len()).map_err(|_| AepaBindingError::PublicSourceTooLarge)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SOURCE_MAGIC);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&(AEPA_K7_SPEC_FAMILY.len() as u16).to_le_bytes());
        bytes.extend_from_slice(AEPA_K7_SPEC_FAMILY.as_bytes());
        bytes.extend_from_slice(&NPL1_PROFILE_ID);
        bytes.push(NPL1_VERSION);
        bytes.extend_from_slice(&binding.wire_service_alias.0);
        bytes.extend_from_slice(&binding.pairwise_service_alias.0);
        bytes.extend_from_slice(&binding.epoch.0.to_le_bytes());
        bytes.extend_from_slice(&binding.policy_hash.0);
        bytes.extend_from_slice(&binding.lease_verifier_key_id.0);
        bytes.extend_from_slice(&binding.pipeline_measurement_hash.0);
        bytes.extend_from_slice(&binding.assurance_profile_digest.0);
        bytes.extend_from_slice(&binding.atv2_issuer_key_id);
        bytes.extend_from_slice(&binding.admission_window_start.to_le_bytes());
        bytes.extend_from_slice(&binding.admission_window_end.to_le_bytes());
        bytes.extend_from_slice(&(AepaPublicState::ALL.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(AepaPublicInput::ALL.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&transition_count.to_le_bytes());
        for transition in &transitions {
            bytes.extend_from_slice(&[
                transition.from as u8,
                transition.input as u8,
                transition.to as u8,
                transition.output as u8,
            ]);
        }
        let digest = artifact_digest(SOURCE_DOMAIN, &bytes);
        Ok(Self {
            canonical_bytes: bytes.into_boxed_slice(),
            digest,
            binding,
            transitions: transitions.into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    #[must_use]
    pub const fn binding(&self) -> AepaPublicPolicyBinding {
        self.binding
    }

    #[must_use]
    pub fn transitions(&self) -> &[AepaPublicTransition] {
        &self.transitions
    }
}

fn build_total_transitions() -> Vec<AepaPublicTransition> {
    let mut transitions =
        Vec::with_capacity(AepaPublicState::ALL.len() * AepaPublicInput::ALL.len());
    for from in AepaPublicState::ALL {
        for input in AepaPublicInput::ALL {
            let (to, output) = transition(from, input);
            transitions.push(AepaPublicTransition {
                from,
                input,
                to,
                output,
            });
        }
    }
    transitions
}

const fn transition(
    from: AepaPublicState,
    input: AepaPublicInput,
) -> (AepaPublicState, AepaPublicOutput) {
    match input {
        AepaPublicInput::Reset | AepaPublicInput::Handoff => {
            (AepaPublicState::Waiting, AepaPublicOutput::Cover)
        }
        AepaPublicInput::Fault => (AepaPublicState::Faulted, AepaPublicOutput::Fault),
        _ => match from {
            AepaPublicState::Waiting => match input {
                AepaPublicInput::PublicTick => (AepaPublicState::Waiting, AepaPublicOutput::Cover),
                AepaPublicInput::ValidatedAdmission => {
                    (AepaPublicState::Admitted, AepaPublicOutput::AdmitOnce)
                }
                _ => (AepaPublicState::CoverRequired, AepaPublicOutput::Reject),
            },
            AepaPublicState::Admitted => match input {
                AepaPublicInput::PublicTick => (AepaPublicState::Admitted, AepaPublicOutput::Cover),
                _ => (AepaPublicState::CoverRequired, AepaPublicOutput::Reject),
            },
            AepaPublicState::CoverRequired => match input {
                AepaPublicInput::PublicTick => {
                    (AepaPublicState::CoverRequired, AepaPublicOutput::Cover)
                }
                _ => (AepaPublicState::CoverRequired, AepaPublicOutput::Reject),
            },
            AepaPublicState::Faulted => (AepaPublicState::Faulted, AepaPublicOutput::Fault),
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaK7Binding {
    source_digest: Digest,
    certificate_digest: Digest,
    generated_runtime_digest: Digest,
    certificate: Certificate,
    source_certificate: Box<[u8]>,
    quotient_inputs: u16,
    public_inputs: u16,
    fault_inputs: u16,
}

impl AepaK7Binding {
    #[must_use]
    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> Digest {
        self.certificate_digest
    }

    #[must_use]
    pub const fn generated_runtime_digest(&self) -> Digest {
        self.generated_runtime_digest
    }

    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    #[must_use]
    pub fn source_certificate(&self) -> &[u8] {
        &self.source_certificate
    }

    #[must_use]
    pub const fn input_axes(&self) -> (u16, u16, u16) {
        (self.quotient_inputs, self.public_inputs, self.fault_inputs)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaK7ManifestBinding {
    pub source_digest: Digest,
    pub certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    seal: AepaManifestSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AepaManifestSeal;

pub fn verify_aepa_k7(
    source: &AepaPublicSourceArtifact,
    certificate_bytes: &[u8],
    expected_contract: ExpectedContract,
    certificate_limits: CertificateLimits,
    generated_runtime_manifest: &[u8],
) -> Result<AepaK7Binding, AepaBindingError> {
    let certificate_digest = match verify(certificate_bytes, expected_contract, certificate_limits)
    {
        CertificateVerdict::Valid(report) => report.certificate_digest,
        verdict => {
            return Err(AepaBindingError::CertificateRejected(format!(
                "{verdict:?}"
            )))
        }
    };
    let certificate = Certificate::decode(certificate_bytes, certificate_limits)
        .map_err(|error| AepaBindingError::CertificateParse(error.to_string()))?;
    let metadata = codegen_metadata(generated_runtime_manifest)
        .map_err(|_| AepaBindingError::InvalidCodegenManifest)?;
    if metadata.certificate_digest != certificate_digest {
        return Err(AepaBindingError::CodegenCertificateMismatch);
    }
    let input_product = u32::from(metadata.quotient_inputs)
        .checked_mul(u32::from(metadata.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(metadata.fault_inputs)))
        .ok_or(AepaBindingError::CodegenInputAxes)?;
    if input_product != certificate.input_count {
        return Err(AepaBindingError::CodegenInputAxes);
    }
    Ok(AepaK7Binding {
        source_digest: source.digest(),
        certificate_digest,
        generated_runtime_digest: codegen_manifest_digest(generated_runtime_manifest),
        certificate,
        source_certificate: certificate_bytes.to_vec().into_boxed_slice(),
        quotient_inputs: metadata.quotient_inputs,
        public_inputs: metadata.public_inputs,
        fault_inputs: metadata.fault_inputs,
    })
}

pub fn bind_aepa_k7_manifest(
    manifest: &NoticerQsmManifest,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
) -> Result<AepaK7ManifestBinding, AepaBindingError> {
    let entry = manifest.binding(NoticerModuleId::Aepa);
    if entry.deployment_profile != DeploymentProfile::P0PublicQuotientOnly {
        return Err(AepaBindingError::ProfileNotP0);
    }
    if entry.p1_resource_evidence.is_some() {
        return Err(AepaBindingError::UnexpectedP1Evidence);
    }
    let binding = source.binding();
    if entry.service_alias != binding.wire_service_alias() {
        return Err(AepaBindingError::ServiceAliasMismatch);
    }
    if entry.epoch != binding.epoch() {
        return Err(AepaBindingError::EpochMismatch);
    }
    if entry.policy_hash != binding.policy_hash() {
        return Err(AepaBindingError::PolicyMismatch);
    }
    ensure_digest("k7_source", source.digest(), k7.source_digest())?;
    ensure_digest("source", entry.source_digest, source.digest())?;
    ensure_digest(
        "certificate",
        entry.source_certificate_digest,
        k7.certificate_digest(),
    )?;
    ensure_digest(
        "generated_runtime",
        entry.generated_runtime_digest,
        k7.generated_runtime_digest(),
    )?;
    Ok(AepaK7ManifestBinding {
        source_digest: source.digest(),
        certificate_digest: k7.certificate_digest(),
        generated_runtime_digest: k7.generated_runtime_digest(),
        seal: AepaManifestSeal,
    })
}

fn ensure_digest(
    field: &'static str,
    expected: Digest,
    actual: Digest,
) -> Result<(), AepaBindingError> {
    if expected != actual {
        return Err(AepaBindingError::DigestMismatch { field });
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AepaBindingError {
    #[error("AEPA public binding is invalid")]
    InvalidPublicBinding,
    #[error("AEPA public source exceeds its canonical integer fields")]
    PublicSourceTooLarge,
    #[error("K7 certificate was rejected: {0}")]
    CertificateRejected(String),
    #[error("K7 certificate parse failed: {0}")]
    CertificateParse(String),
    #[error("generated runtime manifest is invalid")]
    InvalidCodegenManifest,
    #[error("generated runtime names a different K7 certificate")]
    CodegenCertificateMismatch,
    #[error("generated runtime input axes differ from the K7 certificate")]
    CodegenInputAxes,
    #[error("AEPA manifest deployment profile is not P0")]
    ProfileNotP0,
    #[error("AEPA P0 manifest unexpectedly contains P1 resource evidence")]
    UnexpectedP1Evidence,
    #[error("AEPA service alias differs from the registry")]
    ServiceAliasMismatch,
    #[error("AEPA public epoch differs from the registry")]
    EpochMismatch,
    #[error("AEPA policy hash differs from the registry")]
    PolicyMismatch,
    #[error("AEPA digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
}
